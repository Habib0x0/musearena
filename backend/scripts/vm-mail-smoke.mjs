/**
 * Live P3 mail smoke — IMAP authenticates against FreeIPA on a domain member.
 *
 *   node scripts/vm-mail-smoke.mjs
 *
 * Rocky dc-01 (FreeIPA, persona p1 seeded) + Debian mail-01 (postfix +
 * dovecot, dependsOn dc-01, joined). After configure:
 *   - local probe roundtrip still works (SMTP delivery + IMAP read as `probe`)
 *   - p1 logs in to IMAP with its IPA password (Dovecot LDAP passdb, auth_bind)
 *   - a wrong password for p1 is refused by 389-ds, not by a local file
 *   - dovecot's auth log shows the LDAP request (the proof is the directory,
 *     not a shadow entry)
 */
import { execFile } from "node:child_process";
import { mkdir, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { detectHost } from "../dist/provisioner/kvm.js";
import { ensureGoldenImage, ensureRockyGoldenImage } from "../dist/provisioner/images.js";
import { destroyRunVms, startRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { execInGuest, probeGuestIdentity, waitForLabAddress, vmTargetsFromState } from "../dist/configurator/vm-ssh.js";
import { inventoryFor, parseRecap, playbookFor } from "../dist/configurator/ansible.js";
import { checkSpecReadiness } from "../dist/configurator/readiness.js";
import { labSecret, ipaUserIdFor, ipaUserSecret } from "../dist/configurator/lab.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-mail-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel);

const spec = {
  version: 1, name: "mail-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "mail-01", name: "mail-01", role: "mail", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "smtp", impl: "postfix", port: 25, readyWhen: "smtp-imap-roundtrip" },
                      { kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 10 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "mail-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [], requiredTelemetry: [], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const uid = ipaUserIdFor("p1");
const userPw = ipaUserSecret(runId, "p1");
const probePw = labSecret(runId, "mail-probe");

let primaryError = null;
try {
  const [rocky, debian] = await Promise.all([ensureRockyGoldenImage(host.hostArch), ensureGoldenImage(host.hostArch)]);
  const res = await startRunVms(spec, { ...lifecycle, goldenByFamily: { rocky, debian } }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const state = res.state;
  for (const inst of Object.values(state.instances)) {
    await probeGuestIdentity(inst, { runId }, { attempts: 60, delayMs: 2000, timeoutMs: 15000 });
    await waitForLabAddress(inst);
    console.log(`${inst.hostId}: ready lab=${inst.lab?.address}`);
  }
  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  console.log("configure: ansible-playbook over SSH…");
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 45 * 60_000, maxBuffer: 32 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [h, r] of recap) console.log(`${h}: ${r.line}`);
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed:\n${stdout.slice(-3000)}`);

  const mail = state.instances["mail-01"];
  const exec = (cmd, t = 90_000) => execInGuest(mail, cmd, { timeoutMs: t }).then((r) => r.stdout);
  const { labDomainFor } = await import("../dist/configurator/dns.js");
  const domainName = labDomainFor(spec);

  // End-to-end as the domain user: SMTP delivery to p1@<domain>, then IMAP
  // read by p1 with its IPA credential (the only passdb on this member).
  const local = await exec(`swaks --to ${uid}@${domainName} --server 127.0.0.1 --port 25 --silent 3 && ok=0 && for i in $(seq 1 20); do curl -fsS --max-time 5 -u '${uid}:${userPw}' imap://127.0.0.1:143/INBOX >/dev/null && { ok=1; break; }; sleep 1; done; echo roundtrip=$ok`);
  console.log("domain roundtrip:", local.trim().split("\n").slice(-1)[0] || "(no answer)");
  if (!local.includes("roundtrip=1")) throw new Error("SMTP→IMAP roundtrip as the domain user failed");

  const good = await exec(`curl -fsS --max-time 10 -u '${uid}:${userPw}' imap://127.0.0.1:143/INBOX >/dev/null 2>&1 && echo DOMAIN-OK || echo DOMAIN-FAIL`);
  console.log(`domain user ${uid} IMAP:`, good.trim());
  if (!good.includes("DOMAIN-OK")) throw new Error("IMAP login as the domain user failed");

  const bad = await exec(`curl -fsS --max-time 10 -u '${uid}:wrong-password' imap://127.0.0.1:143/INBOX >/dev/null 2>&1 && echo WRONG-ACCEPTED || echo WRONG-REFUSED`);
  console.log("wrong password:", bad.trim());
  if (!bad.includes("WRONG-REFUSED")) throw new Error("a wrong password was accepted");

  const log = await exec(`sudo -n grep -iE 'ldap|auth failed|imap-login' /var/log/mail.log 2>/dev/null | tail -12 || sudo -n journalctl -u dovecot --no-pager -n 40 2>/dev/null | tail -12`);
  console.log("dovecot auth log:\n" + log.trim().slice(0, 1200));

  // The claim is the *directory* path, so the effective Dovecot config must
  // have no PAM passdb and Dovecot's own auth test must accept the domain
  // credential (p1 has no /etc/passwd entry on this host).
  const conf = await exec("sudo -n doveconf -n 2>/dev/null | grep -cE 'driver = (pam|ldap)' ; sudo -n doveconf -n 2>/dev/null | grep -E 'driver = (pam|ldap)' | tr -d ' '");
  console.log("dovecot passdbs:\n" + conf.trim());
  if (/pam/.test(conf)) throw new Error("PAM passdb still active: directory auth not proven");
  const doveadm = await exec(`sudo -n doveadm auth test ${uid} '${userPw}' 2>&1 | head -3`);
  console.log("doveadm auth test:", doveadm.trim());
  if (!/auth succeeded/i.test(doveadm)) throw new Error("doveadm could not authenticate the domain user via LDAP");

  const readiness = await checkSpecReadiness({
    spec, runId,
    sshUserOf: () => mail.ssh?.user ?? "arena",
    exec: async (hostId, command, timeoutMs) => {
      const inst = state.instances[hostId];
      if (!inst) throw new Error(`no VM ${hostId}`);
      return (await execInGuest(inst, command, { timeoutMs })).stdout;
    },
  });
  for (const h of readiness) for (const c of h.checks) console.log(`${h.hostId}: ${c.ok ? "PASS" : "FAIL"} ${c.kind}/${c.probe} — ${c.detail}`);
  if (readiness.some((h) => !h.ok)) throw new Error(`readiness failed: ${JSON.stringify(readiness.filter((h) => !h.ok))}`);
  console.log("VM MAIL SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message.slice(0, 2500) : err);
} finally {
  if (process.env.MAIL_KEEP === "1" && primaryError) console.log(`kept: ${path.join(stateRoot, "kvm", runId)}`);
  else {
    await destroyRunVms(lifecycle).catch(() => undefined);
    const leaked = await run("pgrep", ["-f", `musearena-${runId}-`]).then(() => true).catch(() => false);
    if (leaked && !primaryError) primaryError = new Error("leaked QEMU");
    console.log(leaked ? "LEAKED QEMU" : "destroyed: no leaked QEMU");
  }
}
if (primaryError) process.exit(1);

/**
 * DISPROOF HARNESS (O-4): Samba member join against FreeIPA.
 *
 *   node scripts/vm-samba-smoke.mjs
 *
 * This does not pass, and its failure is the recorded evidence: Samba's SRV
 * discovery succeeds (the dc._msdcs records are served), then the AD NetLogon
 * CLDAP ping gets no reply because the FreeIPA server has no CLDAP listener,
 * so `net ads join` reports "failed to find DC". `file/samba` was removed from
 * the runtime catalog as a result; see T-32 in tasks.md and O-4 in
 * system-design-linux-ad.md. Kept so the negative result stays reproducible.
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
import { ipaUserIdFor, ipaUserSecret } from "../dist/configurator/lab.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-samba-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel);

const spec = {
  version: 1, name: "samba-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "fs-01", name: "fs-01", role: "fileserver", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "file", impl: "samba", port: 445, readyWhen: "smb-domain-auth" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 10 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "fs-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [], requiredTelemetry: [], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const uid = ipaUserIdFor("p1");
const userPw = ipaUserSecret(runId, "p1");

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
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed:\n${stdout.slice(-3500)}`);

  const fs = state.instances["fs-01"];
  const exec = (cmd, t = 90_000) => execInGuest(fs, cmd, { timeoutMs: t }).then((r) => r.stdout);

  const join = await exec("sudo -n net ads testjoin 2>&1; sudo -n wbinfo -t 2>&1");
  console.log("join:", join.trim().replace(/\n/g, " | "));
  if (!/Join is OK/i.test(join)) throw new Error("Samba is not joined to the realm");

  const write = await exec(`sudo -n smbclient //127.0.0.1/share -U '${uid}%${userPw}' -W IPA -c 'put /etc/hostname arena-check.txt; ls' 2>&1`);
  console.log("domain write:\n" + write.trim().slice(0, 800));
  if (!/arena-check\.txt/.test(write)) throw new Error("a domain user could not write to the share");

  const bad = await exec(`sudo -n smbclient //127.0.0.1/share -U '${uid}%wrong-password' -W IPA -c ls >/dev/null 2>&1 && echo WRONG-ACCEPTED || echo WRONG-REFUSED`);
  console.log("wrong password:", bad.trim());
  if (!bad.includes("WRONG-REFUSED")) throw new Error("the share accepted a wrong password");

  const anon = await exec(`sudo -n smbclient //127.0.0.1/share -N -c ls >/dev/null 2>&1 && echo ANON-ACCEPTED || echo ANON-REFUSED`);
  console.log("anonymous:", anon.trim());
  if (!anon.includes("ANON-REFUSED")) throw new Error("the share allows anonymous access");

  const readiness = await checkSpecReadiness({
    spec, runId,
    sshUserOf: () => fs.ssh?.user ?? "arena",
    exec: async (hostId, command, timeoutMs) => {
      const inst = state.instances[hostId];
      if (!inst) throw new Error(`no VM ${hostId}`);
      return (await execInGuest(inst, command, { timeoutMs })).stdout;
    },
  });
  for (const h of readiness) for (const c of h.checks) console.log(`${h.hostId}: ${c.ok ? "PASS" : "FAIL"} ${c.kind}/${c.probe} — ${c.detail}`);
  if (readiness.some((h) => !h.ok)) throw new Error(`readiness failed: ${JSON.stringify(readiness.filter((h) => !h.ok))}`);
  console.log("VM SAMBA SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message.slice(0, 2500) : err);
} finally {
  if (process.env.SAMBA_KEEP === "1" && primaryError) console.log(`kept: ${path.join(stateRoot, "kvm", runId)}`);
  else {
    await destroyRunVms(lifecycle).catch(() => undefined);
    const leaked = await run("pgrep", ["-f", `musearena-${runId}-`]).then(() => true).catch(() => false);
    if (leaked && !primaryError) primaryError = new Error("leaked QEMU");
    console.log(leaked ? "LEAKED QEMU" : "destroyed: no leaked QEMU");
  }
}
if (primaryError) process.exit(1);

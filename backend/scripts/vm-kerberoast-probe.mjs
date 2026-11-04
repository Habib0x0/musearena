/**
 * Kerberoast feasibility probe (O-3) — does FreeIPA let a *user* carry an SPN,
 * and can a peer persona obtain a crackable TGS for it?
 *
 *   node scripts/vm-kerberoast-probe.mjs
 *
 * Reuses the FreeIPA smoke shape (Rocky dc-01 + Debian ws-01). After join it
 * experiments, reporting each step's real output rather than asserting:
 *   1. persona p1 can kinit with its seeded password (closes O-6 if true)
 *   2. admin creates svc-report with a deliberately weak password
 *   3. SPN HTTP/ws-01.<ipaDomain> attached to the user (user-mod --addattr)
 *   4. p1 requests the service ticket (kvno) and we inspect enctypes (klist -e)
 * The crack itself is a separate step once the ticket shape is known.
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
import { labSecret } from "../dist/configurator/lab.js";
import { labDomainFor, ipaDomainFor, ipaRealmFor } from "../dist/configurator/dns.js";
import { labPlanFor } from "../dist/provisioner/lab-network.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-kroast-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel);

const spec = {
  version: 1, name: "kroast-probe", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "ws-01", name: "ws-01", role: "workstation", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [], dependsOn: ["dc-01"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "ws-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [], requiredTelemetry: [], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const domain = labDomainFor(spec);
const ipaDomain = ipaDomainFor(spec);
const realm = ipaRealmFor(spec);
const adminPw = labSecret(runId, "ipa-admin");
const p1Pw = labSecret(runId, "ipa-user-p1");
const svcPw = "Summer2024!";
const spn = `HTTP/ws-01.${ipaDomain}`;

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
    console.log(`${inst.hostId}: ready`);
  }
  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 45 * 60_000, maxBuffer: 32 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [h, r] of recap) console.log(`${h}: ${r.line}`);
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed:\n${stdout.slice(-3000)}`);

  const dc = state.instances["dc-01"], ws = state.instances["ws-01"];
  const exec = (inst, cmd, timeoutMs = 120_000) => execInGuest(inst, cmd, { timeoutMs }).then((r) => r.stdout).catch((e) => `ERR: ${e.message.slice(0, 500)}`);
  const step = async (label, inst, cmd) => console.log(`\n== ${label} ==\n${(await exec(inst, cmd)).trim().slice(0, 1500)}`);

  // Non-interactive password kinit: write a tiny pty helper (plain pipe
  // fails — MIT kinit insists on the tty for password entry), then use it.
  const helper = Buffer.from([
    "import pty,os,sys",
    "user,pw,ccache=sys.argv[1],sys.argv[2],sys.argv[3]",
    "os.environ['KRB5CCNAME']='FILE:'+ccache",
    "def read(fd):",
    "    d=os.read(fd,1024)",
    "    if b'assword' in d: os.write(fd,(pw+'\\n').encode())",
    "    return d",
    "pty.spawn(['kinit',user],read)",
    "",
  ].join("\n")).toString("base64");
  await step("install pty kinit helper", ws, `printf '%s' '${helper}' | base64 -d > /tmp/kinit-pty.py && echo helper-ready`);
  await step("p1 kinit with seeded password (O-6, file ccache)", ws,
    `python3 /tmp/kinit-pty.py p1 '${p1Pw}' /tmp/p1.ccache; KRB5CCNAME=FILE:/tmp/p1.ccache klist`);
  await step("create svc-report + weak password + SPN on user", dc, [
    `printf '%s\\n' '${adminPw}' | kinit admin >/dev/null`,
    `ipa user-show svc-report >/dev/null 2>&1 || ipa user-add svc-report --first=Service --last=Report --shell=/bin/bash`,
    `printf '%s\\n%s\\n' '${svcPw}' '${svcPw}' | ipa passwd svc-report`,
    `ipa user-mod svc-report --addattr=krbprincipalname='${spn}@${realm}' 2>&1 || ipa user-mod svc-report --setattr=krbprincipalname='${spn}@${realm}' 2>&1 || true`,
    `ipa user-show svc-report --all | grep -iE 'principal|uid:' | head -6`,
    "kdestroy",
  ].join("\n"));
  await step("p1 kvno SPN + klist -e (file ccache)", ws, [
    `export KRB5CCNAME=FILE:/tmp/p1.ccache`,
    `kvno '${spn}' 2>&1`,
    "klist -e 2>&1",
    // Kerberoast proper: request the TGS in RC4 (etype 23) — the classic
    // crackable form. Whether the KDC honours it for this user-key is the
    // O-3 question. Print the request result verbatim.
    `kvno -e rc4-hmac '${spn}' 2>&1; klist -e 2>&1 | tail -8`,
  ].join("\n"));
  console.log("\nKERBEROAST PROBE DONE");
} catch (err) {
  primaryError = err;
  console.error("PROBE FAILURE:", err instanceof Error ? err.message.slice(0, 2500) : err);
} finally {
  if (process.env.KROAST_KEEP === "1" && primaryError) console.log(`kept: ${path.join(stateRoot, "kvm", runId)}`);
  else {
    await destroyRunVms(lifecycle).catch(() => undefined);
    const leaked = await run("pgrep", ["-f", `musearena-${runId}-`]).then(() => true).catch(() => false);
    console.log(leaked ? "LEAKED QEMU" : "destroyed: no leaked QEMU");
    if (leaked && !primaryError) primaryError = new Error("leaked QEMU");
  }
}
if (primaryError) process.exit(1);

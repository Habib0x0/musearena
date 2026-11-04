/**
 * Live password-spray smoke (O-3 outcome + O-6) — FreeIPA edition.
 *
 *   node scripts/vm-spray-smoke.mjs
 *
 * O-3 verdict this encodes: classic Kerberoast (T1558.003, user-SPN TGS) is
 * refused by FreeIPA — `kvno` on a user-carried SPN returns "Server principal
 * valid for user2user only". The feasible, gated technique is password
 * spraying (T1110.003) against the planted weak service account.
 *
 * Rocky dc-01 (FreeIPA, weak-cred planted on the DC) + Debian ws-01 joined.
 * From ws-01: LDAP simple-bind spray of a small password list at svc-report —
 * every wrong password must fail, the planted one must succeed — then kinit
 * as svc-report with the sprayed password (pty helper; first use forces a
 * same-password change, which the helper answers). DC-side: dirsrv access
 * log must show the failed binds (detection evidence, not just client say-so).
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
import { labDomainFor, ipaDomainFor, ipaBaseFor } from "../dist/configurator/dns.js";
import { labPlanFor } from "../dist/provisioner/lab-network.js";
import { WEAK_IPA_USER, WEAK_IPA_PASSWORD } from "../dist/provisioner/roles.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-spray-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel);

const spec = {
  version: 1, name: "spray-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "ws-01", name: "ws-01", role: "workstation", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [], dependsOn: ["dc-01"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "ws-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [{ id: "o-spray", asset: "dc-01", techniqueId: "T1110.003", successSignal: "spray-success", points: 10 }],
  requiredTelemetry: [], plantedVulns: [{ id: "v-ipa", type: "weak-cred", techniqueId: "T1110.003", targetHostId: "dc-01", pinnedVersion: "4", proofAtomicGuid: "g-ipa", difficulty: "standard" }],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const domain = labDomainFor(spec);
const dcAddr = labPlanFor(spec, runId).find((e) => e.hostId === "dc-01").address;
const svcDn = `uid=${WEAK_IPA_USER},cn=users,cn=accounts,${ipaBaseFor(domain)}`;
const candidates = ["Winter2024!", "Password1!", WEAK_IPA_PASSWORD, "Spring2025!"];

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

  const ws = state.instances["ws-01"], dc = state.instances["dc-01"];
  const exec = (inst, cmd, timeoutMs = 60_000) => execInGuest(inst, cmd, { timeoutMs }).then((r) => r.stdout);

  // Spray: one bind per candidate; wrong ones must fail (49), planted succeeds.
  let sprayOk = null;
  for (const pw of candidates) {
    const out = await exec(ws, `ldapwhoami -x -H ldap://${dcAddr} -D '${svcDn}' -w '${pw}' 2>&1 || true`);
    const okBind = out.includes(`dn:${svcDn}`) || out.trim().startsWith("dn:");
    console.log(`spray ${WEAK_IPA_USER} / ${pw.replace(/./g, "*")}: ${okBind ? "BIND OK" : `fail (${out.trim().slice(0, 90)})`}`);
    if (pw === WEAK_IPA_PASSWORD) sprayOk = okBind;
    else if (okBind) throw new Error(`spray: wrong password ${pw} bound successfully`);
  }
  if (!sprayOk) throw new Error("spray: planted password did not bind");

  // Valid-account proof: kinit as the sprayed account (pty answers prompts).
  const helper = Buffer.from([
    "import pty,os,sys",
    "user,pw,ccache=sys.argv[1],sys.argv[2],sys.argv[3]",
    "os.environ['KRB5CCNAME']='FILE:'+ccache",
    "def read(fd):",
    "    d=os.read(fd,1024)",
    "    if b'assword' in d: os.write(fd,(pw+'\\n').encode())",
    "    return d",
    "pty.spawn(['kinit',user],read)", "",
  ].join("\n")).toString("base64");
  await exec(ws, `printf '%s' '${helper}' | base64 -d > /tmp/kinit-pty.py`);
  const klist = await exec(ws, `python3 /tmp/kinit-pty.py ${WEAK_IPA_USER} '${WEAK_IPA_PASSWORD}' /tmp/svc.ccache; KRB5CCNAME=FILE:/tmp/svc.ccache klist 2>&1`);
  console.log("kinit svc-report:\n" + klist.trim().slice(0, 400));
  if (!klist.includes(WEAK_IPA_USER)) throw new Error("kinit as sprayed account failed");

  // Detection evidence on the DC: failed binds land in the dirsrv access log
  // (path discovered, not assumed) and/or krb5kdc.log PREAUTH_FAILED lines.
  // dirsrv dir is root-only (glob must expand under sudo) and its access log
  // is buffered — poll briefly instead of demanding instant visibility.
  const fails = await exec(dc, `for i in $(seq 1 15); do n=$(sudo -n sh -c "grep -c err=49 /var/log/dirsrv/slapd-*/access 2>/dev/null | awk -F: '{s+=\\$NF} END {print s+0}'"); [ "$n" -ge 2 ] && break; sleep 2; done; echo dirsrv-err49: $n; sudo -n ls /var/log/dirsrv/ 2>/dev/null`, 90_000);
  console.log("dc telemetry:\n" + fails.trim());
  const totalFails = [...fails.matchAll(/: (\d+)$/gm)].reduce((n, m) => n + Number(m[1]), 0);
  if (totalFails < 2) throw new Error("failed binds not visible in DC telemetry");

  console.log("VM SPRAY SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message.slice(0, 2500) : err);
} finally {
  await destroyRunVms(lifecycle).catch(() => undefined);
  const leaked = await run("pgrep", ["-f", `musearena-${runId}-`]).then(() => true).catch(() => false);
  if (leaked && !primaryError) primaryError = new Error("leaked QEMU");
  console.log(leaked ? "LEAKED QEMU" : "destroyed: no leaked QEMU");
}
if (primaryError) process.exit(1);

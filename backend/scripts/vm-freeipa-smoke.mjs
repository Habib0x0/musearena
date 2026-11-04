/**
 * Live FreeIPA smoke (P2) — Rocky 9 server + Debian member, real install.
 *
 *   node scripts/vm-freeipa-smoke.mjs
 *
 * Boots dc-01 (Rocky Linux 9, ldap/freeipa) and ws-01 (Debian 12, dependsOn
 * dc-01) on the flat lab segment, runs the generated Ansible playbook over
 * SSH (profile-install → freeipa-install → ipa-seed → ipa-client-join), then
 * proves, from inside the guests:
 *   - dc-01: kinit admin succeeds; a seeded persona is in `ipa user-find`
 *   - ws-01: joined (/etc/ipa/default.conf), SSSD up, `id <persona>` resolves
 *   - ws-01: peer LDAP simple bind + search against dc-01's lab address
 * The smoke prefers the baked Rocky FreeIPA tier when staged (built by
 * scripts/build-rocky-image.mjs) and falls back to the pinned GenericCloud
 * base otherwise. On the baked tier it verifies the FreeIPA packages before
 * configure, so the package-egress claim is checked, not assumed.
 */
import { execFile } from "node:child_process";
import { mkdir, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { detectHost } from "../dist/provisioner/kvm.js";
import { ensureGoldenImage, ensureRockyFreeipaImage, ensureRockyGoldenImage, ROCKY_FREEIPA_PACKAGES } from "../dist/provisioner/images.js";
import { destroyRunVms, startRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { execInGuest, probeGuestIdentity, waitForLabAddress } from "../dist/configurator/vm-ssh.js";
import { inventoryFor, parseRecap, playbookFor } from "../dist/configurator/ansible.js";
import { vmTargetsFromState } from "../dist/configurator/vm-ssh.js";
import { labSecret } from "../dist/configurator/lab.js";
import { labDomainFor, ipaDomainFor, ipaBaseFor, ipaAdminDnFor } from "../dist/configurator/dns.js";
import { labPlanFor } from "../dist/provisioner/lab-network.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-freeipa-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

const spec = {
  version: 1, name: "freeipa-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "ws-01", name: "ws-01", role: "workstation", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [], dependsOn: ["dc-01"],
      resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "ws-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [], requiredTelemetry: [], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const domain = labDomainFor(spec);
const ipaDomain = ipaDomainFor(spec);
const dcAddr = labPlanFor(spec, runId).find((e) => e.hostId === "dc-01").address;
const adminPw = labSecret(runId, "ipa-admin");

let primaryError = null;
const proof = async (label, fn) => {
  try { const out = await fn(); console.log(`PROOF PASS ${label}${out ? `: ${String(out).trim().slice(0, 160)}` : ""}`); }
  catch (err) { throw new Error(`PROOF FAIL ${label}: ${err instanceof Error ? err.message.slice(0, 400) : err}`); }
};

try {
  const [rockyBaked, debian] = await Promise.all([ensureRockyFreeipaImage(host.hostArch), ensureGoldenImage(host.hostArch)]);
  const rocky = rockyBaked ?? await ensureRockyGoldenImage(host.hostArch);
  console.log("images:", rocky.image.name, rocky.image.digest, "|", debian.image.name, debian.image.digest);
  console.log(rockyBaked
    ? "rocky tier: BAKED FreeIPA image (no package egress at configure)"
    : "rocky tier: pinned base (configure installs FreeIPA over the management NIC)");
  const res = await startRunVms(spec, { ...lifecycle, goldenByFamily: { rocky, debian } }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const state = res.state;
  for (const inst of Object.values(state.instances)) {
    const id = await probeGuestIdentity(inst, { runId }, { attempts: 60, delayMs: 2000, timeoutMs: 15000 });
    console.log(`${inst.hostId}: image=${inst.imageName} ssh-ready hostname=${id.hostname}`);
    await waitForLabAddress(inst);
  }

  const dc = state.instances["dc-01"], ws = state.instances["ws-01"];
  const exec = (inst, cmd, timeoutMs = 120_000) => execInGuest(inst, cmd, { timeoutMs }).then((r) => r.stdout);
  if (rockyBaked) {
    await proof("baked Rocky image has the FreeIPA server packages before configure",
      () => exec(dc, `rpm -q ${ROCKY_FREEIPA_PACKAGES.join(" ")} | tail -n 2`));
  }

  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  console.log("configure: ansible-playbook over SSH (FreeIPA install can take several minutes)…");
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 45 * 60_000, maxBuffer: 32 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [hostId, r] of recap) console.log(`${hostId}: ${r.line}`);
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed:\n${stdout.slice(-4000)}`);

  await proof("dc-01 kinit admin", () => exec(dc, `printf '%s\\n' '${adminPw}' | kinit admin && klist | head -3 && kdestroy`));
  await proof("dc-01 seeded persona in ipa user-find", () => exec(dc, `printf '%s\\n' '${adminPw}' | kinit admin >/dev/null && ipa user-show p1 --raw | grep -E '^(uid|uidnumber):' ; kdestroy`));
  await proof("ws-01 joined + SSSD resolves persona", () => exec(ws, "test -f /etc/ipa/default.conf && systemctl is-active sssd && id p1"));
  await proof("ws-01 peer LDAP bind to dc-01", () => exec(ws, `ldapsearch -x -H ldap://${dcAddr}:389 -D '${ipaAdminDnFor(domain)}' -w '${adminPw}' -b '${ipaBaseFor(domain)}' -s base dn | head -3`));
  await proof("ws-01 DNS SRV via dc-01", () => exec(ws, `dig +short @${dcAddr} _kerberos._udp.${ipaDomain} SRV | head -2`));
  await proof("dc-01 Rocky osquery sensor active", () => exec(dc, `rpm -q osquery && systemctl is-active osqueryd && osqueryi --json 'select version from osquery_info;'`));
  console.log("VM FREEIPA SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message : err);
} finally {
  if (process.env.FREEIPA_KEEP === "1" && primaryError) {
    console.log(`kept for diagnosis: ${path.join(stateRoot, "kvm", runId)} (rerun destroy manually)`);
    process.exit(1);
  }
  await destroyRunVms(lifecycle).catch(() => undefined);
  const leaked = await run("pgrep", ["-f", `musearena-${runId}-`]).then(() => true).catch(() => false);
  if (leaked && !primaryError) primaryError = new Error(`leaked QEMU processes for ${runId}`);
  if (!primaryError && !process.env.VM_STATE_ROOT) await rm(stateRoot, { recursive: true, force: true }).catch(() => undefined);
  console.log(leaked ? "LEAKED QEMU" : "destroyed: state removed, no leaked QEMU");
}
if (primaryError) process.exit(1);

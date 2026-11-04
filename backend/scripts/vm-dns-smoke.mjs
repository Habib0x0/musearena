/**
 * Live gateway-DNS smoke (O-1) — guests resolve via the planned gateway.
 *
 *   node scripts/vm-dns-smoke.mjs
 *
 * gw-01 (dnsmasq) + web-01 + db-01 on the flat lab segment, Ansible configure,
 * then from web-01 prove via NSS/system resolver:
 *   getent hosts gw-01  → gateway lab address
 *   getent hosts db-01  → db lab address, answered by dnsmasq on the gateway
 *   dig @gateway + system dig → A records for every guest
 *   negative: a nonexistent lab name must NXDOMAIN/empty, not resolve via user-net
 */
import { execFile } from "node:child_process";
import { mkdir, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { detectHost } from "../dist/provisioner/kvm.js";
import { resolveGoldenImage } from "../dist/provisioner/images.js";
import { destroyRunVms, startRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { execInGuest, probeGuestIdentity, waitForLabAddress, vmTargetsFromState } from "../dist/configurator/vm-ssh.js";
import { inventoryFor, parseRecap, playbookFor } from "../dist/configurator/ansible.js";
import { checkSpecReadiness } from "../dist/configurator/readiness.js";
import { labPlanFor } from "../dist/provisioner/lab-network.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-dns-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel);

const spec = {
  version: 1, name: "dns-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "gw-01", name: "gw-01", role: "gateway", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "dns", impl: "dnsmasq" }], resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
    { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "http", impl: "apache-php" }], resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: ["app"],
      serviceDecls: [{ kind: "db", impl: "postgres" }], resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
  ],
  personas: [], objectives: [], requiredTelemetry: [], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

let primaryError = null;
try {
  const golden = await resolveGoldenImage(host.hostArch);
  console.log("image:", golden.image.name, golden.image.digest);
  const res = await startRunVms(spec, { ...lifecycle, golden }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const state = res.state;
  for (const inst of Object.values(state.instances)) {
    await probeGuestIdentity(inst, { runId }, { attempts: 60, delayMs: 2000, timeoutMs: 15000 });
    await waitForLabAddress(inst);
    console.log(`${inst.hostId}: ready lab=${inst.lab.address}`);
  }
  const plan = new Map(labPlanFor(spec, runId).map((e) => [e.hostId, e.address]));
  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 30 * 60_000, maxBuffer: 32 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [h, r] of recap) console.log(`${h}: ${r.line}`);
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed:\n${stdout.slice(-4000)}`);

  const exec = (hostId, cmd, timeoutMs = 30_000) => execInGuest(state.instances[hostId], cmd, { timeoutMs }).then((r) => r.stdout);
  console.log("resolv.conf web-01:\n" + await exec("web-01", "cat /etc/resolv.conf; resolvectl status 2>/dev/null | grep -A2 'Current DNS' | head -6"));
  const { labDomainFor } = await import("../dist/configurator/dns.js");
  const domain = labDomainFor(spec);
  const proofs = [
    ["getent gw-01 FQDN", `getent hosts gw-01.${domain} | grep -q '${plan.get("gw-01")}' && echo OK`],
    ["getent db-01 FQDN", `getent hosts db-01.${domain} | grep -q '${plan.get("db-01")}' && echo OK`],
    ["ping db-01 by FQDN", `ping -c2 -W2 db-01.${domain}`],
    ["nonexistent must fail", `getent hosts not-a-host-lab && echo UNEXPECTED-RESOLVED || echo NO-RESOLVE`],
  ];
  for (const [label, cmd] of proofs) {
    const out = (await exec("web-01", cmd)).trim();
    console.log(`web-01 ${label}: ${out.slice(0, 220)}`);
    if (label.startsWith("getent") && !out.includes("OK")) throw new Error(`${label} failed`);
    if (label === "nonexistent must fail" && !out.includes("NO-RESOLVE")) throw new Error("nonexistent lab name resolved — resolver leak");
    if (label.startsWith("ping") && !/2 received/.test(out)) throw new Error("ping by name failed");
  }
  const readiness = await checkSpecReadiness({ spec, runId, sshUserOf: (h) => state.instances[h]?.ssh?.user ?? "arena", exec });
  for (const h of readiness) for (const c of h.checks) console.log(`${h.hostId}: ${c.ok ? "PASS" : "FAIL"} ${c.kind}/${c.probe} — ${c.detail}`);
  console.log("VM DNS SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message.slice(0, 3000) : err);
} finally {
  if (process.env.DNS_KEEP === "1" && primaryError) { console.log(`kept: ${path.join(stateRoot, "kvm", runId)}`); }
  else await destroyRunVms(lifecycle).catch(() => undefined);
  const leaked = await run("pgrep", ["-f", `musearena-${runId}-`]).then(() => true).catch(() => false);
  if (leaked && !primaryError) primaryError = new Error(`leaked QEMU for ${runId}`);
  if (!primaryError && !process.env.VM_STATE_ROOT) await rm(stateRoot, { recursive: true, force: true }).catch(() => undefined);
  console.log(leaked ? "LEAKED QEMU" : "destroyed: no leaked QEMU");
}
if (primaryError) process.exit(1);

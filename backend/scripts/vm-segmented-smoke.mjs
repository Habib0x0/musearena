/**
 * Live segmented-lab smoke (P1 acceptance) — single site, two zones, router.
 *
 *   node scripts/vm-segmented-smoke.mjs
 *
 * Boots r-01 (router/nftables, multi-homed .1 in each zone), web-01 (edge,
 * http:80) and db-01 (server, postgres:5432), runs the Ansible playbook, then
 * the readiness gate — whose zone probes are the claim:
 *   - allowed: web-01 → db-01:5432 must connect through the router (route via .1, nftables accept)
 *   - denied:  db-01 → edge zone must fail (nftables drop / no service path)
 * Proves `nft list ruleset` on the router and the guests' cross-zone route.
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

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-seg-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

const spec = {
  version: 2, name: "seg-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: {
    cidr: "10.42.0.0/16", subnets: [], firewallRules: [],
    sites: [{ id: "hq", name: "HQ", kind: "hq" }],
    zones: [{ id: "edge", site: "hq", kind: "edge" }, { id: "server", site: "hq", kind: "server" }],
    links: [],
    policies: [{ from: "hq/edge", to: "hq/server", proto: "tcp", port: 5432, action: "allow", reason: "app to db" }],
  },
  instances: [
    { hostId: "r-01", name: "r-01", role: "router", runtime: "vm", os: "Debian 12", stack: [], services: ["router"], databases: [],
      site: "hq", zone: "edge", serviceDecls: [{ kind: "router", impl: "nftables", port: 22, readyWhen: "ssh-login" }],
      resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
    { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: ["http"], databases: [],
      site: "hq", zone: "edge", serviceDecls: [{ kind: "http", impl: "apache-php", port: 80, readyWhen: "http-2xx" }],
      resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: ["db"], databases: ["app"],
      site: "hq", zone: "server", serviceDecls: [{ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }],
      resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
  ],
  personas: [], objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary", points: 10 }],
  requiredTelemetry: [], plantedVulns: [],
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
  console.log("hubs:", (state.labHubs ?? []).map((h) => `${h.segment}:${h.port}`).join(", "));
  for (const inst of Object.values(state.instances)) {
    const id = await probeGuestIdentity(inst, { runId }, { attempts: 60, delayMs: 2000, timeoutMs: 15000 });
    console.log(`${inst.hostId}: ssh-ready hostname=${id.hostname} labs=${JSON.stringify(inst.labs ?? inst.lab)}`);
    await waitForLabAddress(inst);
  }

  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  console.log("configure: ansible-playbook over SSH…");
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 30 * 60_000, maxBuffer: 32 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [hostId, r] of recap) console.log(`${hostId}: ${r.line}`);
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed:\n${stdout.slice(-4000)}`);

  const exec = (hostId, command, timeoutMs = 30_000) => {
    const inst = state.instances[hostId];
    if (!inst) throw new Error(`no VM ${hostId}`);
    return execInGuest(inst, command, { timeoutMs }).then((r) => r.stdout);
  };
  console.log("router ruleset:\n" + await exec("r-01", "sudo -n nft list ruleset | head -20"));
  console.log("web-01 route: " + (await exec("web-01", "ip route get 10.42.1.10")).trim());
  console.log("db-01 route: " + (await exec("db-01", "ip route get 10.42.0.10")).trim());

  const readiness = await checkSpecReadiness({
    spec, runId,
    sshUserOf: (hostId) => state.instances[hostId]?.ssh?.user ?? "arena",
    exec,
  });
  for (const h of readiness) for (const c of h.checks) console.log(`${h.hostId}: ${c.ok ? "PASS" : "FAIL"} ${c.kind}/${c.probe} — ${c.detail}`);
  if (readiness.some((h) => !h.ok)) throw new Error(`readiness failed: ${JSON.stringify(readiness.filter((h) => !h.ok))}`);
  console.log("VM SEGMENTED SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message.slice(0, 3000) : err);
} finally {
  if (process.env.SEG_KEEP === "1" && primaryError) {
    console.log(`kept: ${path.join(stateRoot, "kvm", runId)}`);
  } else {
    await destroyRunVms(lifecycle).catch(() => undefined);
    const leaked = await run("pgrep", ["-f", `musearena-${runId}-`]).then(() => true).catch(() => false);
    if (leaked && !primaryError) primaryError = new Error(`leaked QEMU processes for ${runId}`);
    if (!primaryError && !process.env.VM_STATE_ROOT) await rm(stateRoot, { recursive: true, force: true }).catch(() => undefined);
    console.log(leaked ? "LEAKED QEMU" : "destroyed: state removed, no leaked QEMU");
  }
}
if (primaryError) process.exit(1);

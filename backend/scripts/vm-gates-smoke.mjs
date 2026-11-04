/**
 * Live VM gate smoke (T-18a) — real guest, real auditd + Apache telemetry.
 *
 *   node scripts/vm-gates-smoke.mjs
 *
 * Configures a web guest with a planted command injection, then runs the
 * sensor canary and the proof gate through the VM executors. Both read the
 * guest's own sensor output over SSH; exit codes are not trusted.
 *
 *   node scripts/vm-gates-smoke.mjs --blind-sensor
 *
 * After the positive gates pass, `--blind-sensor` stops auditd in the guest
 * and requires the canary to fail closed (T-18: a sensor-disabled VM is not
 * scored). Proving it on a guest that was healthy seconds earlier is the
 * point: a canary that always fails would prove nothing.
 */
import { execFile } from "node:child_process";
import { mkdir, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { detectHost } from "../dist/provisioner/kvm.js";
import { resolveGoldenImage } from "../dist/provisioner/images.js";
import { destroyRunVms, startRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { execInGuest, probeGuestIdentity, vmTargetsFromState } from "../dist/configurator/vm-ssh.js";
import { inventoryFor, parseRecap, playbookFor } from "../dist/configurator/ansible.js";
import { sensorCanary, proofGate } from "../dist/configurator/gates.js";
import { vmGateOptions } from "../dist/configurator/vm-executors.js";
import { EventStore } from "../dist/observability/events.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-gates-${Date.now().toString(36)}`;
const externalState = process.env.VM_STATE_DIR;
const stateRoot = externalState ?? path.join(process.cwd(), ".disposable");
// The gate executor resolves the registry through the same env the deploy uses.
process.env.VM_STATE_DIR = stateRoot;
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

const spec = {
  version: 1, name: "gates-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "http", impl: "apache-php" }], resources: { vcpu: 2, memoryMb: 1536, diskGb: 8 } },
  ],
  personas: [],
  objectives: [{ id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 10 }],
  requiredTelemetry: ["auditd"],
  plantedVulns: [{ id: "v1", type: "code-flaw", techniqueId: "T1059", targetHostId: "web-01", pinnedVersion: "8.2", proofAtomicGuid: "g1", difficulty: "standard" }],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

let primaryError = null;
try {
  const golden = await resolveGoldenImage(host.hostArch);
  console.log("image:", golden.image.name, golden.image.digest);
  const res = await startRunVms(spec, { ...lifecycle, golden }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const inst = res.state.instances["web-01"];
  const id = await probeGuestIdentity(inst, { runId }, { attempts: 45, delayMs: 2000, timeoutMs: 15000 });
  console.log(`web-01: ssh-ready hostname=${id.hostname} user=${id.user}`);

  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(res.state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 10 * 60_000, maxBuffer: 16 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  for (const [h, r] of parseRecap(stdout, ["web-01"])) console.log(`${h}: ${r.line}`);
  if (!parseRecap(stdout, ["web-01"]).get("web-01").ok) throw new Error(`configure failed: ${stdout.slice(-2000)}`);

  const store = new EventStore();
  const gates = vmGateOptions(spec, { runId, store });
  const canary = await sensorCanary(runId, "web-01", gates);
  console.log(`canary: ${canary.pass ? "PASS" : "FAIL"} — ${canary.details.join("; ")}`);
  if (!canary.pass) throw new Error("sensor canary failed");

  const proof = await proofGate({ runId, spec }, gates);
  console.log(`proof: ${proof.pass ? "PASS" : "FAIL"} — ${proof.details.join("; ")}`);
  if (!proof.pass) throw new Error("proof gate failed");

  const truth = store.groundTruth(runId);
  console.log(`ground truth: ${truth.length} event(s) — ${truth.map((e) => `${e.actor}:${e.kind}`).join(", ")}`);

  if (process.argv.includes("--blind-sensor")) {
    // The guest was healthy one gate ago; now blind it and require failure.
    await execInGuest(inst, "sudo -n systemctl stop auditd", { timeoutMs: 30_000 });
    const blind = await sensorCanary(runId, "web-01", gates);
    console.log(`blind canary: ${blind.pass ? "PASS (WRONG)" : "FAIL"} — ${blind.details.join("; ")}`);
    if (blind.pass) throw new Error("sensor canary passed with auditd stopped — the gate is not fail-closed");
    if (!/sensor blind/.test(blind.details.join(" "))) throw new Error(`unexpected blind-gate detail: ${blind.details.join("; ")}`);
    console.log("VM BLIND SENSOR OK");
  }
  console.log("VM GATES SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message : err);
} finally {
  await destroyRunVms(lifecycle);
  const leaked = await new Promise((resolve) => {
    import("node:child_process").then(({ execFileSync }) => {
      try { resolve(execFileSync("pgrep", ["-f", `musearena-${runId}-`], { encoding: "utf8" }).trim().length > 0); } catch { resolve(false); }
    }).catch(() => resolve(false));
  });
  if (leaked) primaryError ??= new Error(`leaked QEMU processes for ${runId}`);
  if (!primaryError) {
    await rm(path.join(stateRoot, "ansible", runId), { recursive: true, force: true });
    if (!externalState) await rm(stateRoot, { recursive: true, force: true }).catch(() => undefined);
  }
  console.log(leaked ? "LEAKED QEMU" : "destroyed: state removed, no leaked QEMU");
}
if (primaryError) process.exit(1);

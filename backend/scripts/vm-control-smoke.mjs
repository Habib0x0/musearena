/**
 * Benign-only control run on the VM runtime (T-14 acceptance): the VM
 * counterpart of `control-run.mjs`.
 *
 *   node scripts/vm-control-smoke.mjs
 *
 * Deploys and configures the clinic, passes readiness and the gates, then runs
 * the exercise with red disabled. Blue still sees the full collected stream —
 * persona noise, configure/proof artifacts and the guests' own auth chatter —
 * so every alert it raises is a false positive. The run must raise none.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { detectHost } from "../dist/provisioner/kvm.js";
import { resolveGoldenImage } from "../dist/provisioner/images.js";
import { destroyRunVms, startRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { execInGuest, probeGuestIdentity, vmTargetsFromState } from "../dist/configurator/vm-ssh.js";
import { inventoryFor, parseRecap, playbookFor } from "../dist/configurator/ansible.js";
import { checkSpecReadiness } from "../dist/configurator/readiness.js";
import { sensorCanary, proofGate } from "../dist/configurator/gates.js";
import { vmGateOptions } from "../dist/configurator/vm-executors.js";
import { runVmExercise } from "../dist/exercise/vm-live.js";
import { livePack } from "../dist/exercise/live.js";
import { EventStore } from "../dist/observability/events.js";
import { clinicOrgSpec } from "../dist/designer/clinic.js";
import { digestOf } from "../dist/designer/pipeline.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-control-${Date.now().toString(36)}`;
const externalState = process.env.VM_STATE_DIR;
const stateRoot = externalState ?? path.join(process.cwd(), ".disposable");
process.env.VM_STATE_DIR = stateRoot;
const lifecycle = { stateRoot, runId };
const spec = clinicOrgSpec();
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

let primaryError = null;
try {
  const golden = await resolveGoldenImage(host.hostArch);
  console.log("image:", golden.image.name, golden.image.digest);
  const res = await startRunVms(spec, { ...lifecycle, golden }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  for (const inst of Object.values(res.state.instances)) {
    const id = await probeGuestIdentity(inst, { runId }, { attempts: 45, delayMs: 2000, timeoutMs: 15000 });
    console.log(`${inst.hostId}: ssh-ready hostname=${id.hostname}`);
  }

  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(res.state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 15 * 60_000, maxBuffer: 16 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [h, r] of recap) console.log(`${h}: ${r.line}`);
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed: ${stdout.slice(-2500)}`);

  const readiness = await checkSpecReadiness({
    spec, runId,
    sshUserOf: (hostId) => res.state.instances[hostId]?.ssh?.user ?? "arena",
    exec: async (hostId, command, timeoutMs) => {
      const inst = res.state.instances[hostId];
      if (!inst) throw new Error(`no VM ${hostId}`);
      return (await execInGuest(inst, command, { timeoutMs })).stdout;
    },
  });
  if (readiness.some((h) => !h.ok)) throw new Error(`readiness failed: ${JSON.stringify(readiness.filter((h) => !h.ok))}`);
  console.log(`readiness: ${readiness.reduce((n, h) => n + h.checks.length, 0)} probes PASS`);

  const gateStore = new EventStore();
  const gates = vmGateOptions(spec, { runId, store: gateStore });
  for (const inst of spec.instances) {
    const c = await sensorCanary(runId, inst.hostId, gates);
    if (!c.pass) throw new Error(`canary failed on ${inst.hostId}: ${c.details.join("; ")}`);
  }
  const proof = await proofGate({ runId, spec }, gates);
  if (!proof.pass) throw new Error(`proof gate failed: ${proof.details.join("; ")}`);
  console.log("gates: canaries + proof PASS");

  // Red disabled: every alert from here is a false positive by construction.
  const store = new EventStore();
  const pack = await livePack();
  const runRec = {
    runId, orgId: "control-org", deploymentId: "control-dep", mode: "blind", specDigest: digestOf(spec),
    techniquePackVersion: "v1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm",
  };
  const ex = await runVmExercise({ spec, run: runRec }, { store, detections: pack.store, state: res.state, control: true });
  console.log(`benign events: ${ex.benignEvents} · alerts: ${ex.alerts.length} · false positives: ${ex.falsePositives}`);
  for (const a of ex.alerts) console.log(`  alert ${a.hostId} ${a.techniqueId} ${a.ruleId} @${a.at}`);
  assert.equal(ex.alerts.length, 0, "a benign-only run must raise no alerts");
  assert.equal(ex.falsePositives, 0);
  assert.equal(ex.scorecard.objectivesAchieved, 0, "control runs score nothing");
  console.log("VM CONTROL RUN OK");
} catch (err) {
  primaryError = err;
  console.error("CONTROL RUN FAILURE:", err instanceof Error ? err.message : err);
} finally {
  await destroyRunVms(lifecycle);
  const leaked = await new Promise((resolve) => {
    try {
      execFile("pgrep", ["-f", `musearena-${runId}-`], (e, out) => resolve(!e && out.trim().length > 0));
    } catch { resolve(false); }
  });
  if (leaked) primaryError ??= new Error(`leaked QEMU processes for ${runId}`);
  if (!primaryError) {
    await rm(path.join(stateRoot, "ansible", runId), { recursive: true, force: true });
    if (!externalState) await rm(stateRoot, { recursive: true, force: true }).catch(() => undefined);
  }
  console.log(leaked ? "LEAKED QEMU" : "destroyed: state removed, no leaked QEMU");
}
if (primaryError) process.exit(1);

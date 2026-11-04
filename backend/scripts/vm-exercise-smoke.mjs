/**
 * Live VM end-to-end smoke (T-18b): baked image → configure over SSH →
 * readiness → gates → scripted red/blue → verified dataset export → teardown.
 *
 *   node scripts/vm-exercise-smoke.mjs
 *
 * Web (command injection) and DB (weak credential) objectives run scripted.
 * Dataset export is local (no Supabase); the same export code is used by the
 * worker, so the content hash and proof/noise exclusion are the real checks.
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
import { runVmAgentExercise } from "../dist/exercise/vm-agents.js";
import { modalPersonaClient } from "../dist/lib/model.js";
import { livePack } from "../dist/exercise/live.js";
import { exportDataset } from "../dist/observability/export.js";
import { assertExportIntegrity } from "../dist/traces/integrity.js";
import { EventStore } from "../dist/observability/events.js";
import { deployability } from "../dist/provisioner/capability.js";

const run = promisify(execFile);
// Glimmer scales to zero: start its warm-up in parallel with provisioning so
// persona shifts do not stall on a cold endpoint.
const agentsEnabled = process.env.MUSEARENA_AGENT_RUNTIME === "maas";
const glimmerWarm = agentsEnabled ? modalPersonaClient().wake().catch((e) => console.warn(`[personas] warm-up: ${e.message}`)) : null;
const host = detectHost();
const runId = `run-vm-exercise-${Date.now().toString(36)}`;
const externalState = process.env.VM_STATE_DIR;
const stateRoot = externalState ?? path.join(process.cwd(), ".disposable");
process.env.VM_STATE_DIR = stateRoot;
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

const spec = {
  version: 1, name: "vm-exercise-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "http", impl: "apache-php" }], resources: { vcpu: 2, memoryMb: 1536, diskGb: 8 } },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: ["app"],
      serviceDecls: [{ kind: "db", impl: "postgres" }], resources: { vcpu: 2, memoryMb: 1536, diskGb: 8 } },
    // Acting from another guest is what makes the source address real and
    // blue's block IP enforceable (T-15).
    { hostId: "atk-01", name: "atk-01", role: "attacker", runtime: "vm", os: "Debian 12", stack: [], services: [],
      serviceDecls: [{ kind: "ssh", impl: "openssh" }], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "web-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [
    { id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 10 },
    { id: "o2", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10 },
  ],
  requiredTelemetry: ["auditd"],
  plantedVulns: [
    { id: "v1", type: "code-flaw", techniqueId: "T1059", targetHostId: "web-01", pinnedVersion: "8.2", proofAtomicGuid: "g1", difficulty: "standard" },
    { id: "v2", type: "weak-cred", techniqueId: "T1078", targetHostId: "db-01", pinnedVersion: "16", proofAtomicGuid: "g2", difficulty: "standard" },
  ],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

let primaryError = null;
try {
  assert.deepEqual(deployability(spec), [], "supported VM spec must deploy");
  const golden = await resolveGoldenImage(host.hostArch);
  console.log("image:", golden.image.name, golden.image.digest);
  const res = await startRunVms(spec, { ...lifecycle, golden }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const state = res.state;
  for (const inst of Object.values(state.instances)) {
    const id = await probeGuestIdentity(inst, { runId }, { attempts: 45, delayMs: 2000, timeoutMs: 15000 });
    console.log(`${inst.hostId}: ssh-ready hostname=${id.hostname}`);
  }

  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  console.log("configure: ansible-playbook over SSH…");
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 15 * 60_000, maxBuffer: 16 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [h, r] of recap) console.log(`${h}: ${r.line}`);
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed: ${stdout.slice(-2500)}`);

  const readiness = await checkSpecReadiness({
    spec, runId,
    sshUserOf: (hostId) => state.instances[hostId]?.ssh?.user ?? "arena",
    exec: async (hostId, command, timeoutMs) => {
      const inst = state.instances[hostId];
      if (!inst) throw new Error(`no VM ${hostId}`);
      return (await execInGuest(inst, command, { timeoutMs })).stdout;
    },
  });
  for (const h of readiness) for (const c of h.checks) console.log(`${h.hostId}: ${c.ok ? "PASS" : "FAIL"} ${c.kind}/${c.probe}`);
  if (readiness.some((h) => !h.ok)) throw new Error(`readiness failed: ${JSON.stringify(readiness)}`);

  const gateStore = new EventStore();
  const gates = vmGateOptions(spec, { runId, store: gateStore });
  for (const hostId of ["web-01", "db-01"]) {
    const c = await sensorCanary(runId, hostId, gates);
    console.log(`${hostId}: canary ${c.pass ? "PASS" : "FAIL"} — ${c.details.join("; ")}`);
    if (!c.pass) throw new Error(`canary failed on ${hostId}`);
  }
  const proof = await proofGate({ runId, spec }, gates);
  console.log(`proof: ${proof.pass ? "PASS" : "FAIL"} — ${proof.details.join("; ")}`);
  if (!proof.pass) throw new Error("proof gate failed");

  const store = new EventStore();
  const pack = await livePack();
  const runRec = { runId, orgId: "smoke-org", deploymentId: "smoke-dep", mode: "blind", specDigest: "smoke", techniquePackVersion: "v1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm" };
  const agents = agentsEnabled;
  if (glimmerWarm) await glimmerWarm;
  console.log(agents ? "exercise: model agents from the attacker guest…" : "exercise: scripted red/blue over guest telemetry…");
  const ex = agents
    ? await runVmAgentExercise({ spec, run: runRec }, {
        store, detections: pack.store, state,
        // Persona agents (P4): default to Muse Glimmer on Modal; an operator
        // override (MODAL_PERSONA_MODEL_ID) wins in modalPersonaClient.
        personas: modalPersonaClient(),
      })
    : await runVmExercise({ spec, run: runRec }, { store, detections: pack.store, state });
  if (agents) {
    for (const s of ex.shiftReport ?? []) console.log(`  persona ${s.personaId} on ${s.workstation}: ${s.mode}, ${s.auth}, ${s.performed} performed, ${s.refused} refused, model ${s.modelId}`);
    if ((ex.shiftReport ?? []).some((s) => s.mode !== "agent")) throw new Error("persona agents must run in agent mode when the agent runtime is on");
    for (const [id, st] of Object.entries(ex.agentStates)) console.log(`  agent ${id}: ${st.steps} steps, in ${st.inputTokens} tok, out ${st.outputTokens} tok, model ${st.modelId}${st.stoppedByCap ? ` (stopped: ${st.stoppedByCap})` : ""}`);
    console.log(`  guardrails: rejected ${ex.guardrails.rejected}, unverified claims ${ex.guardrails.unverifiedClaims}${ex.guardrails.samples.length ? ` — ${ex.guardrails.samples[0]}` : ""}`);
    for (const p of ex.blueProposals) console.log(`  proposal ${p.hostId} ${p.response} ${p.techniqueId}${p.ip ? ` ip=${p.ip}` : ""}: ${p.why.slice(0, 120)}`);
  }
  console.log(`score: ${ex.scorecard.objectivesAchieved}/${ex.scorecard.objectivesTotal} points ${ex.scorecard.pointsEarned}/${ex.scorecard.pointsTotal}`);
  console.log(`alerts: ${ex.alerts.length}, false positives: ${ex.falsePositives}, benign events: ${ex.benignEvents}`);
  for (const d of ex.falsePositiveDetail) console.log(`  FP ${d.ruleId} on ${d.hostId} (${d.kind}): ${d.sample}`);
  for (const a of ex.alerts) console.log(`  alert ${a.hostId} ${a.techniqueId} ${a.ruleId}`);
  // The scripted loop returns one entry per alert; the agent loop enforces at
  // most one response and returns it (or null).
  const enforcements = agents ? (ex.enforcement ? [ex.enforcement] : []) : ex.enforcement;
  for (const e of enforcements) console.log(`  response ${e.response} on ${e.hostId} -> ${e.target ?? "(none)"} enforced=${e.enforced}${e.reason ? ` (${e.reason})` : e.detail ? ` (${e.detail})` : ""}`);
  if (!agents) {
    assert.ok(enforcements.length > 0, "blue proposed at least one response");
    assert.ok(enforcements.some((e) => e.enforced), "at least one response was enforced on the guest, not just recorded");
  }
  // The scripted baseline must clear every objective (it defines solvability).
  // A model run is evidence of the loop, not of the model's skill: report the
  // score and let the guardrail/enforcement assertions do the gating.
  if (!agents && ex.scorecard.objectivesAchieved !== spec.objectives.length) throw new Error(`objectives ${ex.scorecard.objectivesAchieved}/${spec.objectives.length}`);
  if (ex.falsePositives !== 0) throw new Error(`false positives: ${ex.falsePositives}`);

  const exp = exportDataset(ex.run, "train", { store });
  assertExportIntegrity(exp);
  console.log(`dataset: ${exp.meta.contentHash} (${exp.join.steps.length} steps)`);
  console.log("VM EXERCISE SMOKE OK");
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

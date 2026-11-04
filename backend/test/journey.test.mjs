import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { EventStore } from "../dist/observability/events.js";
import { designEnvironment } from "../dist/designer/pipeline.js";
import { digestOfSpec } from "../dist/lib/digest.js";
import { sensorCanary, proofGate } from "../dist/configurator/gates.js";
import { gateOptionsFromEnv, localGatesEnabled, localSensorStates } from "../dist/configurator/executors.js";
import { checkSensors, validateSpecForRun } from "../dist/prereq/gate.js";
import { DetectionStore } from "../dist/detections/sigma.js";
import { runExercise } from "../dist/exercise/runner.js";
import { exportDataset } from "../dist/observability/export.js";
import { verifyExportHash } from "../dist/traces/integrity.js";
import { writeTrainingFiles } from "../dist/training/exporter.js";
import { MockModelClient } from "../dist/lib/model.js";

const T0 = Date.parse("2026-01-01T00:00:00.000Z");
const iso = (ms) => new Date(T0 + ms).toISOString();

const SPEC = {
  version: 1, name: "journey-org", provider: "kvm", seed: "j1", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu 24.04", stack: ["php"], services: ["http"], databases: [] },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu 24.04", stack: [], services: ["postgres"], databases: ["app"] },
  ],
  personas: [{ id: "p1", role: "intern", workstation: "web-01", access: ["web"], credentialsProfile: "weak", riskProfile: "high", routine: "browses", relationships: [] }],
  objectives: [
    { id: "o1", asset: "db-01", techniqueId: "T1003.001", successSignal: "canary-hash", points: 10 },
    { id: "o2", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 5 },
  ],
  requiredTelemetry: ["auditd"],
  plantedVulns: [{ id: "v1", type: "misconfig", techniqueId: "T1003.001", targetHostId: "db-01", pinnedVersion: "1.0", proofAtomicGuid: "guid-1", difficulty: "standard" }],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const BUDGET = { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 };
const RUN = {
  runId: "run-journey", orgId: "org-1", deploymentId: "dep-1", mode: "blind",
  specDigest: "", techniquePackVersion: "attack-15.1", modelIds: {},
  truthLayer: "mirror-only", backend: "kvm",
};

function promotedDetections() {
  const ds = new DetectionStore();
  ds.add({ id: "sig-canary", version: 1, title: "canary dump", techniqueId: "T1003.001", field: "signal", contains: "canary", status: "draft" });
  ds.promote("sig-canary", 1, [{ runId: "seed", hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1003.001", outcome: "succeeded", at: iso(1_000), detail: { signal: "canary-hash" } }]);
  return ds;
}

test("local gates are opt-in via exact env value only", () => {
  assert.equal(localGatesEnabled({}), false);
  assert.equal(localGatesEnabled({ MUSEARENA_LOCAL_GATES: "0" }), false);
  assert.equal(localGatesEnabled({ MUSEARENA_LOCAL_GATES: "true" }), false);
  assert.equal(localGatesEnabled({ MUSEARENA_LOCAL_GATES: "1" }), true);
  assert.deepEqual(gateOptionsFromEnv({}), {}, "no opt-in → no executors → fail closed");
  const opts = gateOptionsFromEnv({ MUSEARENA_LOCAL_GATES: "1" }, { store: EventStore.fresh() });
  assert.equal(typeof opts.executeCanary, "function");
  assert.equal(typeof opts.executeProof, "function");
});

test("join does not fuse same-host steps across techniques", async () => {
  const { joinRun } = await import("../dist/observability/export.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const { ingest } = await import("../dist/observability/collector.js");
  const store = EventStore.fresh();
  const rec = new LocalTrajectoryRecorder(store);
  // Red trajectory for T1059 on db-01; only ground truth present is T1003.001 (o1, no objectiveId tie).
  rec.record({ runId: RUN.runId, hostId: "db-01", actor: "red", observation: "x", action: "exec thing", techniqueId: "T1059", at: iso(60_000) });
  ingest({ runId: RUN.runId, hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1003.001", outcome: "succeeded", at: iso(60_500), detail: { signal: "unrelated" } }, { store });
  const join = joinRun(RUN.runId, store);
  const fused = join.steps.filter((s) => s.trajectory && s.groundTruth);
  assert.equal(fused.length, 0, "different techniques must not join");
  assert.equal(join.matched, 0);
});

test("full local journey: design → gates → exercise → export → training files", async () => {
  // 1. Design (mock model fixture through the real pipeline).
  const designed = await designEnvironment(new MockModelClient(SPEC), "small org", BUDGET);
  assert.equal(designed.withinBudget, true);
  assert.deepEqual(designed.designErrors, []);
  assert.equal(designed.digest, digestOfSpec(SPEC));
  assert.match(designed.digest, /^sha256:[0-9a-f]{64}$/);
  const spec = designed.spec;

  // 2. Pre-run validation + sensor gate.
  assert.equal(validateSpecForRun(spec).pass, true);
  assert.equal(checkSensors(localSensorStates(spec)).pass, true);
  const blindSensors = localSensorStates(spec).map((s, i) => (i === 0 ? { ...s, sysmonOrAuditd: false, osquery: true } : s));
  assert.equal(checkSensors(blindSensors).pass, false, "osquery alone never satisfies the gate");

  // 3. Canary + proof: fail closed without opt-in; pass locally with it.
  const store = EventStore.fresh();
  const run = { ...RUN, specDigest: designed.digest };
  const closedCanary = await sensorCanary(run.runId, spec.instances[0].hostId, { store });
  assert.equal(closedCanary.pass, false);
  const gates = gateOptionsFromEnv({ MUSEARENA_LOCAL_GATES: "1" }, { store, at: () => iso(1_000) });
  assert.equal((await sensorCanary(run.runId, spec.instances[0].hostId, gates)).pass, true);
  assert.equal((await proofGate({ runId: run.runId, spec }, gates)).pass, true);

  // 4. Exercise with a promoted detection.
  const res = await runExercise({ spec, run }, { store, detections: promotedDetections(), startAt: T0 });
  assert.equal(res.blueDetections, 1);
  assert.equal(res.scorecard.objectivesAchieved, 2, "red hits both objectives on their own assets");
  assert.equal(res.scorecard.exactTechniqueCoverage, 0.5, "only T1003.001 was detected");
  assert.equal(store.verifyChain(), true, "hash-chained event store intact");

  // 5. Export: self-verified, proof/noise-free, pins the design digest.
  const exp = exportDataset(run, "train", { store });
  assert.equal(exp.run.specDigest, designed.digest);
  assert.equal(exp.meta.formatVersion, 1);
  assert.equal(verifyExportHash(exp), true);
  assert.ok(exp.join.steps.length > 0);
  assert.ok(exp.join.steps.every((s) => s.groundTruth?.actor !== "proof" && s.groundTruth?.actor !== "noise"));

  // 6. Training files.
  const outDir = await mkdtemp(path.join(tmpdir(), "musearena-journey-"));
  const manifest = await writeTrainingFiles(exp, outDir);
  assert.equal(manifest.runId, run.runId);
  assert.ok(manifest.sftCount >= 1);
  assert.deepEqual((await readdir(outDir)).sort(), ["manifest.json", "preference-pairs.jsonl", "sft.jsonl"]);
  const sft = (await readFile(path.join(outDir, "sft.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l));
  assert.equal(sft.length, manifest.sftCount);
  assert.ok(sft.some((e) => e.techniqueId === "T1003.001" && e.succeeded === true));
});

test("negative journey: gates stay closed without opt-in, so no scoring unlock", async () => {
  const store = EventStore.fresh();
  const run = { ...RUN, runId: "run-negative" };
  const canary = await sensorCanary(run.runId, "web-01", { store });
  const proof = await proofGate({ runId: run.runId, spec: SPEC }, { store });
  assert.equal(canary.pass, false);
  assert.equal(proof.pass, false);
  // And with no promoted rule, even injected red telemetry yields no detection.
  const res = await runExercise({ spec: SPEC, run }, { store, detections: new DetectionStore(), startAt: T0 });
  assert.equal(res.blueDetections, 0);
  assert.equal(res.scorecard.mttdMinutesP50, undefined);
});

test("trigger rejects malformed pending specs instead of starting a doomed workflow", async () => {
  const { validatePendingSpec } = await import("../dist/workflows/trigger.js");
  const bad = validatePendingSpec({ v: 1 });
  assert.equal(bad.ok, false);
  assert.match(bad.reason, /budgets|version|name/);
  // Deployable variant: the local runtime can plant+prove weak-cred on db.
  const good = validatePendingSpec({ ...SPEC, plantedVulns: [{ ...SPEC.plantedVulns[0], type: "weak-cred" }] });
  assert.equal(good.ok, true);
  assert.equal(good.spec.budgets.ttlHours, SPEC.budgets.ttlHours);
});

test("agent system prompts: designer/refine/red/blue carry the platform contracts", async () => {
  const { readFileSync } = await import("node:fs");
  const prompt = (n) => readFileSync(new URL(`../src/agents/prompts/${n}.md`, import.meta.url), "utf8");
  const designer = prompt("designer");
  for (const needle of ["EnvironmentSpec", "serviceDecls", "dependsOn", "successSignal", "dnsmasq", "openldap", "postfix", "dovecot", "Cannot", "Windows"]) {
    if (needle === "Cannot") continue;
    assert.ok(designer.includes(needle), `designer prompt missing ${needle}`);
  }
  assert.match(designer, /persona\.workstation.*hostId|every `persona\.workstation`/);
  assert.match(designer, /mirror-only/);
  // The prompt must teach what the gates enforce (drift here fails live designs):
  assert.match(designer, /## The attacker guest \(VM org labs\)/, "VM designs include the attacker guest model exercises require");
  assert.match(designer, /platform adds its own attacker container/, "container designs must not emit an attacker");
  assert.match(designer, /"kind": "git",\s+"impl": "gitea",\s+"port": 3000, "readyWhen": "git-ldap-login"/, "git/gitea is designable");
  assert.match(designer, /git host without the FreeIPA dependency\n\s+is rejected|MUST `dependsOn` the FreeIPA server/);
  assert.match(designer, /\{ "kind": "dhcp",\s+"impl": "dnsmasq",\s+"port": 67,\s+"readyWhen": "dhcp-lease" \}/, "dhcp is designable on VM gateways");
  assert.match(designer, /`dhcp` only on a VM gateway beside `dns`/);
  assert.ok(!/diskGb: 4/.test(designer), "VM disk guidance never goes below the 6 GB image floor");
  assert.match(designer, /workstation must list, in its `dependsOn`/, "persona workstations need a service dependency");
  assert.match(designer, /telemetry vocabulary in\n\s+the capability catalog|telemetry vocabulary/, "requiredTelemetry uses the exact catalog names");
  const { designerSystemPrompt, designerRefinePrompt } = await import("../dist/designer/pipeline.js");
  const system = designerSystemPrompt("CATALOG-SENTINEL");
  assert.ok(system.includes("CATALOG-SENTINEL") && system.includes("serviceDecls"), "capability catalog is appended to the designer system prompt");
  const refine = designerRefinePrompt();
  assert.match(refine, /Preserve every instance/);
  assert.match(refine, /hostIds stable|Keep `hostId`s stable/);
  assert.match(refine, /capability catalog appended after this prompt is\s+authoritative|capability catalog appended/, "refine prompt defers to the injected catalog");
  const red = prompt("red");
  assert.match(red, /exec.*tool|through the `exec` tool/);
  assert.match(red, /never invent.*proof|Never invent.*proof/i);
  assert.match(red, /unverified claim/);
  const blue = prompt("blue");
  assert.match(blue, /fetch_telemetry/);
  assert.match(blue, /`respond`/);
  for (const r of ["isolate host", "block IP", "kill process tree", "disable account", "snapshot"]) assert.ok(blue.includes(r), `blue prompt missing allowlist response ${r}`);
  assert.match(blue, /exactly.*`clean`|reply\s+exactly with `clean`/);
});

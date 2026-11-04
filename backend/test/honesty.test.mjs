import { test } from "node:test";
import assert from "node:assert/strict";

import { EventStore } from "../dist/observability/events.js";
import { ingest } from "../dist/observability/collector.js";
import { LocalTrajectoryRecorder } from "../dist/observability/trajectory.js";
import { joinRun, exportDataset } from "../dist/observability/export.js";
import { verifyExportHash, assertExportIntegrity, assertNoProofRows, AdjudicationQueue, applyAdjudications, splitByFamily } from "../dist/traces/integrity.js";
import { digestOfSpec, canonicalJson } from "../dist/lib/digest.js";
import { digestOf, validateDesign } from "../dist/designer/pipeline.js";
import { sensorCanary, proofGate, canaryMarker } from "../dist/configurator/gates.js";
import { scoreExercise } from "../dist/exercise/evaluator.js";
import { computeRubric, navigatorLayer } from "../dist/evaluator/rubric.js";
import { DetectionStore, replay } from "../dist/detections/sigma.js";
import { runExercise } from "../dist/exercise/runner.js";
import { sftExamples, preferencePairs } from "../dist/training/pairs.js";
import { TemplateRegistry } from "../dist/templates/registry.js";
import { MockModelClient } from "../dist/lib/model.js";

const T0 = Date.parse("2026-01-01T00:00:00.000Z");
const iso = (ms) => new Date(T0 + ms).toISOString();

function spec(overrides = {}) {
  return {
    version: 1, name: "honesty-org", provider: "kvm", seed: "s1", difficulty: "standard", truthLayer: "mirror-only",
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
    ...overrides,
  };
}

function run(overrides = {}) {
  return {
    runId: "run-1", orgId: "org-1", deploymentId: "dep-1", mode: "blind",
    specDigest: "sha256:x", techniquePackVersion: "attack-15.1", modelIds: {},
    truthLayer: "mirror-only", backend: "kvm", ...overrides,
  };
}

function gt(store, e) { return ingest(e, { store }); }
function traj(store, s) { return new LocalTrajectoryRecorder(store).record(s); }
function step(gtFields, extra = {}) {
  return { at: iso(60_000), hostId: "db-01", matched: true, groundTruth: { runId: "run-1", hostId: "db-01", kind: "process", at: iso(60_000), ...gtFields }, ...extra };
}
function joinOf(steps) {
  return { runId: "run-1", steps, matched: steps.filter((s) => s.matched).length, trajectoryOnly: 0, groundTruthOnly: 0, dropped: 0 };
}

// ---------- digests ----------

test("spec digest is full-length, canonical, and key-order invariant", () => {
  const s = spec();
  const d = digestOfSpec(s);
  assert.match(d, /^sha256:[0-9a-f]{64}$/);
  const reordered = JSON.parse(JSON.stringify(s));
  const keys = Object.keys(reordered).reverse();
  const shuffled = {};
  for (const k of keys) shuffled[k] = reordered[k];
  assert.equal(digestOfSpec(shuffled), d, "key order must not change the digest");
  assert.equal(digestOf(s), d, "designer digestOf must be the canonical digest");
  assert.equal(canonicalJson({ b: 1, a: { d: 4, c: 3 } }), '{"a":{"c":3,"d":4},"b":1}');
});

// ---------- gates: cannot pass themselves ----------

test("canary fails with no executor and with a blind sensor; passes only on observed telemetry", async () => {
  const s = spec();
  const noExec = await sensorCanary("run-1", "db-01", { store: EventStore.fresh() });
  assert.equal(noExec.pass, false);

  const blind = EventStore.fresh();
  const blindRes = await sensorCanary("run-1", "db-01", { store: blind, executeCanary: async () => {} });
  assert.equal(blindRes.pass, false, "executor ran but sensor saw nothing — must fail");

  const seen = EventStore.fresh();
  const okRes = await sensorCanary("run-1", "db-01", {
    store: seen,
    executeCanary: async (runId, hostId, marker) => { gt(seen, { runId, hostId, kind: marker, actor: "platform", at: iso(1_000) }); },
  });
  assert.equal(okRes.pass, true);
  assert.equal(canaryMarker("run-1", "db-01"), "canary-run-1-db-01");
  void s;
});

test("proof gate fails with no executor, fails unobserved, passes on proof telemetry", async () => {
  const s = spec();
  const noExec = await proofGate({ runId: "run-1", spec: s }, { store: EventStore.fresh() });
  assert.equal(noExec.pass, false);

  const blind = EventStore.fresh();
  const blindRes = await proofGate({ runId: "run-1", spec: s }, { store: blind, executeProof: async () => {} });
  assert.equal(blindRes.pass, false);

  const seen = EventStore.fresh();
  const okRes = await proofGate({ runId: "run-1", spec: s }, {
    store: seen,
    executeProof: async (v, runId) => { gt(seen, { runId, hostId: v.targetHostId, kind: "process", actor: "proof", techniqueId: v.techniqueId, stepId: v.proofAtomicGuid, outcome: "succeeded", at: iso(2_000) }); },
  });
  assert.equal(okRes.pass, true);

  const noVulns = await proofGate({ runId: "run-1", spec: spec({ plantedVulns: [] }) }, { store: EventStore.fresh() });
  assert.equal(noVulns.pass, true, "nothing to prove is a pass, with the note recorded");
});

// ---------- scoring: asset/technique/signal bound ----------

test("scoring requires same asset + technique + objective tie; wrong host earns nothing", () => {
  const s = spec();
  const wrongHost = joinOf([step({ actor: "red", techniqueId: "T1003.001", outcome: "succeeded", detail: { objectiveId: "o1", signal: "canary-hash" } }, { hostId: "web-01", groundTruth: { runId: "run-1", hostId: "web-01", kind: "process", at: iso(60_000), actor: "red", techniqueId: "T1003.001", outcome: "succeeded", detail: { objectiveId: "o1" } } })]);
  // rebuild cleanly: ground truth host differs from objective asset
  wrongHost.steps[0].hostId = "web-01";
  wrongHost.steps[0].groundTruth.hostId = "web-01";
  const sc1 = scoreExercise(s, wrongHost);
  assert.equal(sc1.objectivesAchieved, 0);

  const right = joinOf([step({ actor: "red", techniqueId: "T1003.001", outcome: "succeeded", detail: { objectiveId: "o1" } })]);
  const sc2 = scoreExercise(s, right);
  assert.equal(sc2.objectivesAchieved, 1);
  assert.equal(sc2.pointsEarned, 10);

  const wrongSignal = joinOf([step({ actor: "red", techniqueId: "T1003.001", outcome: "succeeded", detail: { signal: "something-else" } })]);
  assert.equal(scoreExercise(s, wrongSignal).objectivesAchieved, 0, "no objectiveId tie and wrong signal — no credit");

  const proofOnly = joinOf([step({ actor: "proof", techniqueId: "T1003.001", outcome: "succeeded", detail: { objectiveId: "o1" } })]);
  assert.equal(scoreExercise(s, proofOnly).objectivesAchieved, 0, "proof traffic never scores red");
});

test("rubric stamps mode/backend/truth and navigator gives per-technique scores", () => {
  const s = spec();
  const detectStep = step({ actor: "blue", techniqueId: "T1003.001", outcome: "detected" }, { at: iso(360_000) });
  detectStep.groundTruth.at = iso(360_000); // detection ground truth lands 5 min after the red event
  const j = joinOf([
    step({ actor: "red", techniqueId: "T1003.001", outcome: "succeeded", detail: { objectiveId: "o1" } }),
    detectStep,
  ]);
  const r = computeRubric(s, j, run());
  assert.deepEqual(r.stampedWith, { mode: "blind", backend: "kvm", truthLayer: "mirror-only" });
  assert.equal(r.mttdMinutesP50, 5);
  const layer = navigatorLayer(s, run(), j);
  const t1 = layer.techniques.find((t) => t.techniqueID === "T1003.001");
  const t2 = layer.techniques.find((t) => t.techniqueID === "T1059");
  assert.equal(t1.score, 100);
  assert.equal(t2.score, 0);
  assert.ok(t1.tactic.length > 0 && t1.enabled === true);
  // Blinded rescoring is deterministic: same recorded join → identical output.
  assert.deepEqual(computeRubric(s, j, run()), r);
  assert.deepEqual(navigatorLayer(s, run(), j), layer);
});

// ---------- join / export integrity ----------

test("join accounts every row; export verifies and detects tampering", () => {
  const store = EventStore.fresh();
  const r = run();
  traj(store, { runId: r.runId, hostId: "db-01", actor: "red", observation: "password: hunter2 in note", action: "dump", techniqueId: "T1003.001", at: iso(60_000) });
  gt(store, { runId: r.runId, hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1003.001", outcome: "succeeded", at: iso(60_500), detail: { objectiveId: "o1" } });
  gt(store, { runId: r.runId, hostId: "db-01", kind: "process", actor: "proof", techniqueId: "T1003.001", outcome: "succeeded", at: iso(30_000), detail: {} });
  gt(store, { runId: r.runId, hostId: "web-01", kind: "logon", actor: "noise", at: iso(40_000), detail: { personaId: "p1" } });

  const join = joinRun(r.runId, store);
  // 1 traj + 3 GT rows; the traj matches the red GT row, so 3 steps account for all 4 rows.
  assert.equal(join.steps.length, 3, "every trajectory + ground-truth row is accounted");
  assert.equal(join.matched, 1);
  assert.equal(join.trajectoryOnly, 0);
  assert.equal(join.groundTruthOnly, 2);

  const exp = exportDataset(r, "train", { store });
  assert.equal(verifyExportHash(exp), true);
  assert.equal(assertNoProofRows(exp), true);
  assert.ok(exp.join.steps.every((s) => s.groundTruth?.actor !== "proof" && s.groundTruth?.actor !== "noise"), "export excludes proof/noise");
  assert.ok(!JSON.stringify(exp).includes("hunter2"), "secrets redacted");
  assert.throws(() => assertExportIntegrity({ ...exp, join: { ...exp.join, steps: [] } }), /hash mismatch/);
  const tampered = JSON.parse(JSON.stringify(exp));
  tampered.join.steps[0].hostId = "evil-01";
  assert.equal(verifyExportHash(tampered), false);
});

test("adjudicated labels supersede auto-labels in exports; family split is deterministic", () => {
  const store = EventStore.fresh();
  const r = run();
  const at = iso(60_000);
  gt(store, { runId: r.runId, hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1059", outcome: "failed", at, detail: {} });
  const exp = exportDataset(r, "train", { store });
  const q = new AdjudicationQueue();
  const d = q.file(r.runId, exp.join.steps[0].at, { techniqueId: "T1059", stepId: "g", actor: "red", outcome: "failed" });
  q.adjudicate(d.id, { techniqueId: "T1003.001", stepId: "g", actor: "red", outcome: "succeeded" });
  const fixed = applyAdjudications(exp, q);
  assert.equal(fixed.join.steps[0].groundTruth.techniqueId, "T1003.001");
  assert.equal(fixed.join.steps[0].groundTruth.outcome, "succeeded");
  assert.equal(verifyExportHash(fixed), true, "re-hashed after adjudication");

  const fam = { r1: "alpha", r2: "alpha", r3: "beta", r4: "beta", r5: "gamma" };
  const a = splitByFamily(["r1", "r2", "r3", "r4", "r5"], (id) => fam[id]);
  const b = splitByFamily(["r5", "r4", "r3", "r2", "r1"], (id) => fam[id]);
  const splitOf = (splits, id) => Object.entries(splits).find(([, ids]) => ids.includes(id))[0];
  for (const id of Object.keys(fam)) assert.equal(splitOf(a, id), splitOf(b, id), "order must not change family split");
  assert.equal(splitOf(a, "r1"), splitOf(a, "r2"), "same family, same split");
});

// ---------- detections ----------

test("promotion requires replay alerts; versions are immutable; drafts never fire live", () => {
  const store = new DetectionStore();
  const rule = { id: "sig-1", version: 1, title: "dump", techniqueId: "T1003.001", field: "signal", contains: "canary", status: "draft" };
  store.add(rule);
  assert.throws(() => store.add({ ...rule, contains: "other" }), /immutable/);
  assert.throws(() => store.promote("sig-1", 1, []), /no alerts/);
  const events = [{ runId: "run-1", hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1003.001", outcome: "succeeded", at: iso(1_000), detail: { signal: "canary-hash" } }];
  assert.deepEqual(store.liveAlerts(events), [], "draft rules never fire");
  store.promote("sig-1", 1, events);
  assert.equal(store.promotionEvidence("sig-1", 1).replayAlerts, 1);
  const alerts = store.liveAlerts(events);
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].ruleId, "sig-1");
  assert.equal(replay({ ...rule, status: "promoted" }, events).length, 1);
});

// ---------- exercise harness ----------

test("exercise: no promoted rule → no detections; promoted rule → detection + asset-bound score", async () => {
  const s = spec();
  const r = run();

  const storeA = EventStore.fresh();
  const noRules = await runExercise({ spec: s, run: r }, { store: storeA, detections: new DetectionStore(), startAt: T0 });
  assert.equal(noRules.blueDetections, 0);
  assert.equal(noRules.scorecard.mttdMinutesP50, undefined, "no fabricated MTTD");

  const storeB = EventStore.fresh();
  const detections = new DetectionStore();
  detections.add({ id: "sig-1", version: 1, title: "canary", techniqueId: "T1003.001", field: "signal", contains: "canary", status: "draft" });
  const seedEvents = [{ runId: "seed", hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1003.001", outcome: "succeeded", at: iso(1_000), detail: { signal: "canary-hash" } }];
  detections.promote("sig-1", 1, seedEvents);
  const withRules = await runExercise({ spec: s, run: r }, { store: storeB, detections, startAt: T0 });
  assert.equal(withRules.blueDetections, 1, "only the canary-matching objective is detected");
  assert.equal(withRules.scorecard.objectivesAchieved, 2, "red succeeds on both objectives; detection is separate");
  assert.equal(withRules.scorecard.exactTechniqueCoverage, 0.5);
  // Red ground truth lands 500ms after its trajectory step; detection 5 min after the step → 4.9917 min.
  assert.ok(Math.abs(withRules.scorecard.mttdMinutesP50 - 4.9917) < 0.001, `MTTD from ground-truth times, got ${withRules.scorecard.mttdMinutesP50}`);
});

// ---------- training pairs ----------

test("SFT labels come from ground truth; preference pairs need distinct success+failure", async () => {
  const s = spec();
  const store = EventStore.fresh();
  const detections = new DetectionStore();
  detections.add({ id: "sig-1", version: 1, title: "canary", techniqueId: "T1003.001", field: "signal", contains: "canary", status: "draft" });
  detections.promote("sig-1", 1, [{ runId: "seed", hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1003.001", outcome: "succeeded", at: iso(1_000), detail: { signal: "canary-hash" } }]);
  await runExercise({ spec: s, run: run() }, { store, detections, startAt: T0 });
  const exp = exportDataset(run(), "train", { store });
  const sft = sftExamples(exp);
  assert.ok(sft.length >= 1);
  assert.ok(sft.every((e) => typeof e.succeeded === "boolean"));
  const okExample = sft.find((e) => e.techniqueId === "T1003.001");
  assert.equal(okExample.succeeded, true);
  // A blue contained step is present in the export join but never an SFT success.
  assert.ok(sft.every((e) => e.completion !== "kill process tree" || e.succeeded === false));

  const crafted = {
    meta: { runId: "run-9", formatVersion: 1, contentHash: "x", split: "train", redactionPolicyVersion: "v1" },
    run: { runId: "run-9", specDigest: "d", techniquePackVersion: "p", truthLayer: "mirror-only", backend: "kvm" },
    join: { runId: "run-9", dropped: 0, matched: 2, trajectoryOnly: 0, groundTruthOnly: 0, steps: [
      { at: iso(1_000), hostId: "h", techniqueId: "T1", matched: true, trajectory: { runId: "run-9", hostId: "h", actor: "red", observation: "o", action: "good", at: iso(1_000) }, groundTruth: { runId: "run-9", hostId: "h", kind: "process", actor: "red", techniqueId: "T1", outcome: "succeeded", at: iso(1_000) } },
      { at: iso(2_000), hostId: "h", techniqueId: "T1", matched: true, trajectory: { runId: "run-9", hostId: "h", actor: "red", observation: "o", action: "bad", at: iso(2_000) }, groundTruth: { runId: "run-9", hostId: "h", kind: "process", actor: "red", techniqueId: "T1", outcome: "failed", at: iso(2_000) } },
      { at: iso(3_000), hostId: "h", techniqueId: "T1", matched: true, trajectory: { runId: "run-9", hostId: "h", actor: "blue", observation: "o", action: "contained-it", at: iso(3_000) }, groundTruth: { runId: "run-9", hostId: "h", kind: "process", actor: "blue", techniqueId: "T1", outcome: "contained", at: iso(3_000) } },
    ] },
  };
  const pairs = preferencePairs(crafted);
  assert.equal(pairs.length, 1);
  assert.equal(pairs[0].chosen, "good");
  assert.equal(pairs[0].rejected, "bad");
});

// ---------- templates + designer validation ----------

test("template registry: latest wins, families filter, digests are canonical", () => {
  const reg = new TemplateRegistry();
  const s = spec();
  const v1 = reg.register("tpl", "phishing", s);
  const v2 = reg.register("tpl", "phishing", { ...s, seed: "s2" });
  assert.equal(v1.version, 1);
  assert.equal(v2.version, 2);
  assert.equal(reg.get("tpl").version, 2);
  assert.equal(reg.get("tpl", 1).digest, v1.digest);
  assert.match(v1.digest, /^sha256:[0-9a-f]{64}$/);
  assert.equal(reg.byFamily("phishing").length, 2);
  assert.equal(reg.byFamily("other").length, 0);

  const bad = spec({ objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1003.001", successSignal: " ", points: 1 }] });
  assert.ok(validateDesign(bad).some((e) => e.includes("successSignal")));
});

test("mock model client parses fixtures through the schema (designer pipeline stays testable)", async () => {
  const mock = new MockModelClient(spec());
  const parsed = await mock.generateObject({ system: "s", prompt: "p", schema: (await import("@musearena/shared")).EnvironmentSpec });
  assert.equal(parsed.name, "honesty-org");
});

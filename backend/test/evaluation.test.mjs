import test from "node:test";
import assert from "node:assert/strict";

import {
  createEvaluation, CreateEvaluation, leaderboard, runEvaluation, wilsonInterval,
} from "../dist/learning/evaluation.js";

const ORG = "org-1";
const CANDIDATE_ID = "33333333-3333-4333-8333-333333333333";
const BASE_ID = "22222222-2222-4222-8222-222222222222";
const AT = "2026-01-01T00:00:00.000Z";
const T0 = Date.parse(AT);
const iso = (ms) => new Date(T0 + ms).toISOString();

function model(id, over = {}) {
  return {
    id, org_id: ORG, name: id === BASE_ID ? "muse-base" : "muse-candidate", version: 1,
    base_model: "muse-spark-1.3", served_model: "muse-spark-1.3", provider: "meta",
    status: "ready", artifact_path: null, artifact_hash: id === BASE_ID ? null : "sha256:candidate",
    metrics: {}, role: ["red", "blue"], training_run_id: null, created_at: AT, ...over,
  };
}

function suiteSpec() {
  return {
    version: 1, name: "heldout", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.2.0.0/16", subnets: [], firewallRules: [] },
    instances: [{ hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: ["db"], databases: ["app"] }],
    personas: [], requiredTelemetry: ["auditd"], plantedVulns: [],
    objectives: [{ id: "o-db", asset: "db-01", techniqueId: "T1110", successSignal: "auth", points: 10 }],
    budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
  };
}

function fakeStore() {
  const evaluations = new Map();
  const audits = [];
  const models = [model(BASE_ID), model(CANDIDATE_ID)];
  return {
    evaluations, audits, models,
    async getModel(orgId, id) { return models.find((m) => m.org_id === orgId && m.id === id) ?? null; },
    async findModelByServed(orgId, servedModel) {
      return models.find((m) => m.org_id === orgId && m.served_model === servedModel && m.id === BASE_ID) ?? null;
    },
    async insertEvaluation(row) { evaluations.set(row.id, { ...row }); return evaluations.get(row.id); },
    async getEvaluation(orgId, id) { const row = evaluations.get(id); return row?.org_id === orgId ? { ...row } : null; },
    async updateEvaluation(orgId, id, patch) {
      const row = evaluations.get(id);
      if (!row || row.org_id !== orgId) return null;
      Object.assign(row, patch);
      return { ...row };
    },
    async listEvaluations(orgId) { return [...evaluations.values()].filter((r) => r.org_id === orgId); },
    async audit(entry) { audits.push(entry); },
  };
}

function join({ achieved, detectedAt = 660_000, confidence = 0.9 }) {
  const steps = [
    {
      at: iso(60_000), hostId: "db-01", techniqueId: "T1110", matched: true,
      groundTruth: {
        runId: "run-eval", hostId: "db-01", kind: "auth", actor: "red", techniqueId: "T1110",
        outcome: achieved ? "succeeded" : "attempted", at: iso(60_000),
        detail: { objectiveId: "o-db", signal: "auth" },
      },
    },
  ];
  if (achieved) {
    steps.push(
      {
        at: iso(detectedAt), hostId: "db-01", techniqueId: "T1110", matched: true,
        groundTruth: {
          runId: "run-eval", hostId: "db-01", kind: "alert", actor: "blue", techniqueId: "T1110",
          outcome: "detected", at: iso(detectedAt), detail: { confidence },
        },
      },
      {
        at: iso(detectedAt + 60_000), hostId: "db-01", techniqueId: "T1110", matched: true,
        groundTruth: {
          runId: "run-eval", hostId: "db-01", kind: "response", actor: "blue", techniqueId: "T1110",
          outcome: "contained", at: iso(detectedAt + 60_000), detail: {},
        },
      },
    );
  }
  return { runId: "run-eval", matched: steps.length, trajectoryOnly: 0, groundTruthOnly: 0, dropped: 0, steps };
}

function trial(achieved, over = {}) {
  return {
    join: join({ achieved }),
    run: {
      runId: "run-eval", orgId: ORG, deploymentId: "dep", mode: "blind", specDigest: "sha256:x",
      techniquePackVersion: "attack-15.1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm",
    },
    usage: { steps: 4, inputTokens: 100, outputTokens: 20, guardrailViolations: 0, unverifiedClaims: 0 },
    citations: { total: 2, correct: 2 },
    ...over,
  };
}

const input = (over = {}) => ({
  orgId: ORG,
  requestedBy: "trainer-1",
  modelId: CANDIDATE_ID,
  role: "red",
  suite: [{ name: "heldout-db", family: "family-test", split: "test", spec: suiteSpec() }],
  config: { trials: 2 },
  ...over,
});

test("evaluations: creation pins a test-split suite by digest and resolves the registered baseline", async () => {
  assert.throws(() => CreateEvaluation.parse({ modelId: CANDIDATE_ID, role: "red", suite: [], config: {} }), /suite/i);
  const store = fakeStore();
  const row = await createEvaluation(input(), store);
  assert.equal(row.status, "queued");
  assert.equal(row.baseline_model_id, BASE_ID, "baseline defaults to the candidate's registered base model");
  assert.equal(row.suite.trials, 2);
  assert.equal(row.suite.items[0].split, "test");
  assert.match(row.suite.items[0].specDigest, /^sha256:/);
  assert.match(row.suite.digest, /^sha256:/);
  await assert.rejects(
    createEvaluation(input({ suite: [{ name: "train", family: "f", split: "train", spec: suiteSpec() }] }), store),
    /test split/i,
  );
});

test("evaluations: candidate-vs-base reports means/spreads and an improvement only beyond combined spread", async () => {
  const store = fakeStore();
  const row = await createEvaluation(input(), store);
  const runner = async ({ model: m }) => trial(m.id === CANDIDATE_ID);
  const done = await runEvaluation({ orgId: ORG, id: row.id, actor: "trainer-1" }, store, runner);
  assert.equal(done.status, "succeeded");
  assert.equal(done.metrics.candidate.objectivesAchieved.mean, 1);
  assert.equal(done.metrics.baseline.objectivesAchieved.mean, 0);
  assert.equal(done.metrics.candidate.objectivesAchieved.spread, 0);
  assert.equal(done.metrics.candidate.mttdMinutesP50.mean, 10);
  assert.equal(done.metrics.candidate.calibration.mean, 0.99);
  assert.equal(done.comparison.verdict, "improved");
  assert.equal(done.comparison.passed, true);
  assert.ok(store.audits.some((a) => a.action === "EVALUATION_SUCCEEDED"));
});

test("evaluations: a delta inside the trial spread is inconclusive, never a pass", async () => {
  const store = fakeStore();
  const row = await createEvaluation(input(), store);
  let candidateCalls = 0;
  const runner = async ({ model: m }) => trial(m.id === CANDIDATE_ID ? (candidateCalls++ === 0) : false);
  const done = await runEvaluation({ orgId: ORG, id: row.id, actor: "trainer-1" }, store, runner);
  assert.equal(done.status, "succeeded");
  assert.equal(done.metrics.candidate.objectivesAchieved.mean, 0.5);
  assert.equal(done.metrics.candidate.objectivesAchieved.spread, 1);
  assert.equal(done.comparison.verdict, "inconclusive");
  assert.equal(done.comparison.passed, false);
});

test("evaluations: no runner fails honestly with no fabricated metrics", async () => {
  const store = fakeStore();
  const row = await createEvaluation(input(), store);
  const done = await runEvaluation({ orgId: ORG, id: row.id, actor: "trainer-1" }, store, null);
  assert.equal(done.status, "failed");
  assert.match(done.error, /no evaluation runner/i);
  assert.deepEqual(done.metrics, {});
  assert.deepEqual(done.comparison, {});
});

test("evaluations: clock-skewed windows are unscorable and excluded from MTTD/calibration", async () => {
  const store = fakeStore();
  const row = await createEvaluation(input({ role: "blue", config: { trials: 1 } }), store);
  const skewed = trial(true);
  skewed.join = join({ achieved: true, detectedAt: 30_000 });
  const runner = async ({ model: m }) => m.id === CANDIDATE_ID ? skewed : trial(false);
  const done = await runEvaluation({ orgId: ORG, id: row.id, actor: "trainer-1" }, store, runner);
  assert.equal(done.metrics.candidate.unscorableWindows.mean, 1);
  assert.equal(done.metrics.candidate.mttdMinutesP50.count, 0);
  assert.equal(done.metrics.candidate.calibration.count, 0);
});

test("evaluations: Wilson intervals and leaderboard never rank across mode/truth-layer groups", () => {
  const [low, high] = wilsonInterval(8, 10);
  assert.ok(low > 0.48 && low < 0.50, `low=${low}`);
  assert.ok(high > 0.93 && high < 0.95, `high=${high}`);
  const row = (id, mean, mode = "blind") => ({
    id, org_id: ORG, model_id: CANDIDATE_ID, baseline_model_id: BASE_ID, role: "red", status: "succeeded",
    suite: { trials: 2, mode, truthLayer: "mirror-only", items: [] },
    metrics: {
      candidate: {
        objectivesAchieved: { mean, min: mean, max: mean, spread: 0, count: 2 },
        objectivesTotal: { mean: 1, min: 1, max: 1, spread: 0, count: 2 },
      },
    },
    comparison: { verdict: "improved", passed: true, primaryMetric: "objectivesAchieved" },
  });
  const board = leaderboard([row("a", 0.5), row("b", 1), row("c", 1, "adaptive")]);
  assert.equal(board.length, 2);
  const blind = board.find((g) => g.mode === "blind");
  assert.deepEqual(blind.entries.map((e) => e.evaluationId), ["b", "a"]);
  assert.ok(blind.entries[0].wilson);
});

import test from "node:test";
import assert from "node:assert/strict";

import {
  pinDeploymentsForRun, promoteModel, rollbackDeployment,
} from "../dist/learning/deployments.js";

const ORG = "org-1";
const BASE_ID = "22222222-2222-4222-8222-222222222222";
const CANDIDATE_ID = "33333333-3333-4333-8333-333333333333";
const CANDIDATE2_ID = "44444444-4444-4444-8444-444444444444";
const EVAL_ID = "55555555-5555-4555-8555-555555555555";
const EVAL2_ID = "66666666-6666-4666-8666-666666666666";
const AT = "2026-01-01T00:00:00.000Z";

function model(id, over = {}) {
  return {
    id, org_id: ORG, name: `model-${id.slice(0, 4)}`, version: 1,
    base_model: "muse-spark-1.3", served_model: "muse-spark-1.3", provider: "meta",
    status: "ready", artifact_path: null, artifact_hash: "sha256:artifact", metrics: {},
    role: ["red", "blue"], training_run_id: null, created_at: AT, ...over,
  };
}

function evaluation(id, modelId, passed = true) {
  return {
    id, org_id: ORG, model_id: modelId, baseline_model_id: BASE_ID, role: "red",
    suite: { digest: "sha256:suite", trials: 3, mode: "blind", truthLayer: "mirror-only", items: [] },
    config: {}, status: "succeeded", metrics: {},
    comparison: { primaryMetric: "objectivesAchieved", verdict: passed ? "improved" : "inconclusive", passed, metrics: {} },
    error: null, requested_by: "trainer-1", started_at: AT, finished_at: AT, created_at: AT, updated_at: AT,
  };
}

function fakeStore() {
  const deployments = new Map();
  const audits = [];
  const models = [model(BASE_ID), model(CANDIDATE_ID), model(CANDIDATE2_ID)];
  const evaluations = [evaluation(EVAL_ID, CANDIDATE_ID), evaluation(EVAL2_ID, CANDIDATE2_ID)];
  return {
    deployments, audits, models, evaluations,
    async getModel(orgId, id) { return models.find((m) => m.org_id === orgId && m.id === id) ?? null; },
    async getEvaluation(orgId, id) { return evaluations.find((e) => e.org_id === orgId && e.id === id) ?? null; },
    async insertDeployment(row) { deployments.set(row.id, { ...row }); return deployments.get(row.id); },
    async getDeployment(orgId, id) { const row = deployments.get(id); return row?.org_id === orgId ? { ...row } : null; },
    async updateDeployment(orgId, id, patch) {
      const row = deployments.get(id);
      if (!row || row.org_id !== orgId) return null;
      Object.assign(row, patch);
      return { ...row };
    },
    async listDeployments(orgId) {
      return [...deployments.values()].filter((r) => r.org_id === orgId)
        .sort((a, b) => b.created_at.localeCompare(a.created_at));
    },
    async audit(entry) { audits.push(entry); },
  };
}

const input = (over = {}) => ({
  orgId: ORG,
  approvedBy: "operator-1",
  modelId: CANDIDATE_ID,
  evaluationId: EVAL_ID,
  role: "red",
  alias: "red-prod",
  environment: "production",
  trafficPct: 100,
  ...over,
});

test("deployments: promotion without a passing evaluation is refused and audited", async () => {
  const store = fakeStore();
  store.evaluations[0] = evaluation(EVAL_ID, CANDIDATE_ID, false);
  await assert.rejects(promoteModel(input(), store), /passing evaluation/i);
  assert.equal(store.deployments.size, 0);
  assert.ok(store.audits.some((a) => a.action === "MODEL_PROMOTION_REFUSED"));
});

test("deployments: exactly one active row per alias/environment and rollback restores the previous target", async () => {
  const store = fakeStore();
  const first = await promoteModel(input(), store);
  assert.equal(first.status, "active");
  const second = await promoteModel(input({ modelId: CANDIDATE2_ID, evaluationId: EVAL2_ID }), store);
  assert.equal(second.status, "active");
  const active = [...store.deployments.values()].filter((d) => d.status === "active");
  assert.equal(active.length, 1);
  assert.equal(active[0].id, second.id);

  const rolled = await rollbackDeployment({ orgId: ORG, id: second.id, actor: "operator-2" }, store);
  assert.equal(rolled.id, first.id);
  assert.equal(rolled.status, "active");
  assert.equal(store.deployments.get(second.id).status, "rolled_back");
  assert.ok(store.audits.some((a) => a.action === "MODEL_DEPLOYMENT_ROLLED_BACK"));
  assert.ok(store.audits.some((a) => a.action === "MODEL_DEPLOYMENT_RESTORED"));
});

test("deployments: exercise-start pinning records alias, model and traffic, with traffic deciding the served model", async () => {
  const store = fakeStore();
  await promoteModel(input({ trafficPct: 25 }), store);
  const hit = await pinDeploymentsForRun({
    orgId: ORG, roles: ["red"], environment: "production",
    fallbackModelIds: { red: "muse-spark-1.3" }, rng: () => 0.1,
  }, store);
  assert.equal(hit.red.alias, "red-prod");
  assert.equal(hit.red.trafficPct, 25);
  assert.equal(hit.red.trafficHit, true);
  assert.equal(hit.red.modelId, "muse-spark-1.3");

  const miss = await pinDeploymentsForRun({
    orgId: ORG, roles: ["red"], environment: "production",
    fallbackModelIds: { red: "muse-spark-1.1" }, rng: () => 0.9,
  }, store);
  assert.equal(miss.red.trafficHit, false);
  assert.equal(miss.red.modelId, "muse-spark-1.1", "a traffic miss serves the fallback model but still records the deployment tuple");
  assert.equal(miss.red.alias, "red-prod");
});

test("deployments: a failed candidate leaves the current production target untouched", async () => {
  const store = fakeStore();
  const first = await promoteModel(input(), store);
  store.evaluations[1] = evaluation(EVAL2_ID, CANDIDATE2_ID, false);
  await assert.rejects(promoteModel(input({ modelId: CANDIDATE2_ID, evaluationId: EVAL2_ID }), store), /passing evaluation/i);
  assert.equal(store.deployments.get(first.id).status, "active");
});

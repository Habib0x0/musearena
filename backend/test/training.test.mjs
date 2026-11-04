import test from "node:test";
import assert from "node:assert/strict";

import {
  approveTrainingRun, cancelTrainingRun, CreateTrainingRun, createTrainingRun,
} from "../dist/learning/training.js";

const ORG = "org-1";
const DATASET_ID = "11111111-1111-4111-8111-111111111111";
const BASE_ID = "22222222-2222-4222-8222-222222222222";
const AT = "2026-01-01T00:00:00.000Z";

function fakeStore() {
  const runs = new Map();
  const models = [];
  const audits = [];
  const dataset = {
    id: DATASET_ID, org_id: ORG, content_hash: "sha256:dataset", storage_path: `datasets/${ORG}/built/abc`,
    roles: ["red"], split: "train", family: "red-family",
  };
  const base = {
    id: BASE_ID, org_id: ORG, name: "muse-base", version: 1,
    base_model: "muse-spark-1.3", served_model: "muse-spark-1.3", provider: "meta",
    status: "available", artifact_path: null, artifact_hash: null, metrics: {}, role: ["red", "blue"],
    training_run_id: null, created_at: AT,
  };
  return {
    runs, models, audits, dataset, base,
    async getDataset(orgId, id) { return orgId === ORG && id === DATASET_ID ? dataset : null; },
    async getModel(orgId, id) { return orgId === ORG && id === BASE_ID ? base : (models.find((m) => m.org_id === orgId && m.id === id) ?? null); },
    async insertRun(row) { runs.set(row.id, { ...row }); return runs.get(row.id); },
    async getRun(orgId, id) { const run = runs.get(id); return run?.org_id === orgId ? { ...run } : null; },
    async updateRun(orgId, id, patch) {
      const run = runs.get(id);
      if (!run || run.org_id !== orgId) return null;
      Object.assign(run, patch);
      return { ...run };
    },
    async nextModelVersion(orgId, name) {
      return Math.max(0, ...models.filter((m) => m.org_id === orgId && m.name === name).map((m) => m.version)) + 1;
    },
    async insertModel(row) { models.push({ ...row }); return row; },
    async audit(entry) { audits.push(entry); },
  };
}

const input = (over = {}) => ({
  orgId: ORG,
  requestedBy: "trainer-1",
  datasetId: DATASET_ID,
  baseModelId: BASE_ID,
  role: "red",
  method: "sft",
  config: { epochs: 1 },
  budgetUsd: 25,
  targetEnvironment: "staging",
  ...over,
});

test("training runs: creation pins dataset/base/role/method/config/budget and refuses a missing budget", async () => {
  assert.throws(() => CreateTrainingRun.parse({ datasetId: DATASET_ID, baseModelId: BASE_ID, role: "red", method: "sft" }), /budget/i);
  const store = fakeStore();
  const run = await createTrainingRun(input(), store);
  assert.equal(run.status, "queued");
  assert.equal(run.dataset_id, DATASET_ID);
  assert.equal(run.base_model_id, BASE_ID);
  assert.equal(run.role, "red");
  assert.equal(run.method, "sft");
  assert.equal(run.requested_by, "trainer-1");
  assert.equal(Number(run.budget_usd), 25);
  assert.equal(run.manifest.dataset.hash, "sha256:dataset");
  assert.equal(run.manifest.baseModel, "muse-spark-1.3");
  assert.equal(store.models.length, 0, "creation alone produces no model");
  await assert.rejects(createTrainingRun(input({ role: "blue" }), store), /role/i, "a red-only dataset cannot train blue");
});

test("training runs: no trainer parks in awaiting_trainer with the manifest, never as success", async () => {
  const store = fakeStore();
  const run = await createTrainingRun(input({ targetEnvironment: "production", targetAlias: "prod-red" }), store);
  const parked = await approveTrainingRun({ orgId: ORG, id: run.id, approvedBy: "operator-1" }, store, null);
  assert.equal(parked.status, "awaiting_trainer");
  assert.equal(parked.approved_by, "operator-1");
  assert.ok(parked.approved_at);
  assert.equal(parked.manifest.runId, run.id);
  assert.equal(store.models.length, 0);
});

test("training runs: a fake trainer success creates exactly one ready model with an artifact hash", async () => {
  const store = fakeStore();
  const run = await createTrainingRun(input({ outputName: "red candidate" }), store);
  const trainer = {
    async train(manifest) {
      assert.equal(manifest.runId, run.id);
      return {
        status: "succeeded", jobId: "job-1", spentUsd: 12.5,
        metrics: { loss: 0.25 }, artifactPath: "org-1/models/output/", artifactHash: "sha256:artifact",
        servedModel: "muse-spark-1.3",
      };
    },
  };
  const done = await approveTrainingRun({ orgId: ORG, id: run.id, approvedBy: "operator-1" }, store, trainer);
  assert.equal(done.status, "succeeded");
  assert.equal(store.models.length, 1);
  assert.equal(store.models[0].status, "ready");
  assert.equal(store.models[0].artifact_hash, "sha256:artifact");
  assert.equal(store.models[0].training_run_id, run.id);
  assert.equal(done.output_model_id, store.models[0].id);
  assert.ok(store.audits.some((a) => a.action === "TRAINING_RUN_SUCCEEDED"));
});

test("training runs: trainer failure and over-budget spend create no ready model", async () => {
  const failedStore = fakeStore();
  const failedRun = await createTrainingRun(input(), failedStore);
  const failed = await approveTrainingRun(
    { orgId: ORG, id: failedRun.id, approvedBy: "op" },
    failedStore,
    { async train() { throw new Error("trainer exploded"); } },
  );
  assert.equal(failed.status, "failed");
  assert.match(failed.error, /exploded/);
  assert.equal(failedStore.models.length, 0);

  const overStore = fakeStore();
  const overRun = await createTrainingRun(input({ budgetUsd: 10 }), overStore);
  const over = await approveTrainingRun(
    { orgId: ORG, id: overRun.id, approvedBy: "op" },
    overStore,
    { async train() { return { status: "succeeded", spentUsd: 10.01, artifactHash: "sha256:x", servedModel: "muse-spark-1.3" }; } },
  );
  assert.equal(over.status, "cancelled");
  assert.equal(Number(over.spent_usd), 10.01);
  assert.equal(overStore.models.length, 0, "an over-budget run never creates a ready model");
  assert.ok(overStore.audits.some((a) => a.action === "TRAINING_RUN_CANCELLED"));
});

test("training runs: cancel is audited and terminal runs cannot be cancelled", async () => {
  const store = fakeStore();
  const run = await createTrainingRun(input(), store);
  const cancelled = await cancelTrainingRun({ orgId: ORG, id: run.id, actor: "operator-1" }, store);
  assert.equal(cancelled.status, "cancelled");
  assert.ok(store.audits.some((a) => a.action === "TRAINING_RUN_CANCELLED"));
  await assert.rejects(cancelTrainingRun({ orgId: ORG, id: run.id, actor: "operator-1" }, store), /terminal|cannot/i);
});

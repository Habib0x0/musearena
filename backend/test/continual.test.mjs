import test from "node:test";
import assert from "node:assert/strict";

import {
  approveProposal, continualSweepConfigFromEnv, createProposalsFromTriggers,
  deriveContinualAggregates, evaluateContinualTriggers, rejectProposal,
  runContinualSweepForOrg,
} from "../dist/learning/continual.js";

const ORG = "org-1";
const DATASET_ID = "11111111-1111-4111-8111-111111111111";
const BASE_ID = "22222222-2222-4222-8222-222222222222";
const AT = "2026-01-01T00:00:00.000Z";

function fakeStores() {
  const proposals = new Map();
  const runs = new Map();
  const audits = [];
  const dataset = {
    id: DATASET_ID, org_id: ORG, content_hash: "sha256:dataset", storage_path: "datasets/org-1/built/abc",
    roles: ["red", "blue"], split: "train", family: "fam",
  };
  const base = {
    id: BASE_ID, org_id: ORG, name: "muse-base", version: 1,
    base_model: "muse-spark-1.3", served_model: "muse-spark-1.3", provider: "meta",
    status: "available", artifact_path: null, artifact_hash: null, metrics: {}, role: ["red", "blue"],
    training_run_id: null, created_at: AT,
  };
  const proposalStore = {
    async insertProposal(row) { proposals.set(row.id, { ...row }); return proposals.get(row.id); },
    async getProposal(orgId, id) { const row = proposals.get(id); return row?.org_id === orgId ? { ...row } : null; },
    async updateProposal(orgId, id, patch) {
      const row = proposals.get(id);
      if (!row || row.org_id !== orgId) return null;
      Object.assign(row, patch);
      return { ...row };
    },
    async listProposals(orgId) { return [...proposals.values()].filter((r) => r.org_id === orgId); },
    async audit(entry) { audits.push(entry); },
  };
  const trainingStore = {
    async getDataset(orgId, id) { return orgId === ORG && id === DATASET_ID ? dataset : null; },
    async getModel(orgId, id) { return orgId === ORG && id === BASE_ID ? base : null; },
    async insertRun(row) { runs.set(row.id, { ...row }); return runs.get(row.id); },
    async getRun(orgId, id) { const row = runs.get(id); return row?.org_id === orgId ? { ...row } : null; },
    async updateRun(orgId, id, patch) {
      const row = runs.get(id);
      if (!row || row.org_id !== orgId) return null;
      Object.assign(row, patch);
      return { ...row };
    },
    async nextModelVersion() { return 1; },
    async insertModel(row) { return row; },
    async audit(entry) { audits.push(entry); },
  };
  return { proposals, runs, audits, proposalStore, trainingStore };
}

test("continual triggers: traces, corrections, regression and schedule each draft a named proposal", () => {
  const drafts = evaluateContinualTriggers({
    labelledTraces: { red: 60, blue: 3 },
    correctionsByTechnique: [{ role: "red", techniqueId: "T1110", count: 12 }],
    regression: [{ role: "blue", metric: "containmentCorrectness", value: 0.4, bar: 0.8, direction: "higher" }],
    schedule: { due: true, role: "red" },
  });
  assert.deepEqual(drafts.map((d) => d.trigger).sort(), ["corrections", "new_traces", "regression", "schedule"]);
  assert.ok(drafts.every((d) => d.role && d.method && d.reason));

  const quiet = evaluateContinualTriggers({ labelledTraces: { red: 1 }, correctionsByTechnique: [], regression: [] });
  assert.deepEqual(quiet, []);
});

test("continual loop: trigger evaluation creates proposals only and dedupes open ones", async () => {
  const { proposals, runs, audits, proposalStore } = fakeStores();
  const created = await createProposalsFromTriggers({
    orgId: ORG,
    actor: "continual-loop",
    aggregates: { labelledTraces: { red: 100 } },
    defaults: { datasetId: DATASET_ID, baseModelId: BASE_ID, method: "sft", budgetUsd: 20 },
  }, proposalStore);
  assert.equal(created.length, 1);
  assert.equal(created[0].status, "proposed");
  assert.equal(created[0].dataset_id, DATASET_ID);
  assert.equal(created[0].base_model_id, BASE_ID);
  assert.equal(runs.size, 0, "a trigger never starts training");
  assert.ok(audits.some((a) => a.action === "TRAINING_PROPOSAL_CREATED"));

  const again = await createProposalsFromTriggers({
    orgId: ORG,
    actor: "continual-loop",
    aggregates: { labelledTraces: { red: 100 } },
    defaults: { datasetId: DATASET_ID, baseModelId: BASE_ID, method: "sft", budgetUsd: 20 },
  }, proposalStore);
  assert.equal(again.length, 0, "an open proposal for the same trigger is not duplicated");
  assert.equal(proposals.size, 1);
});

test("continual loop: approval converts a proposal to a queued training run and never auto-approves training", async () => {
  const stores = fakeStores();
  const [proposal] = await createProposalsFromTriggers({
    orgId: ORG,
    actor: "continual-loop",
    aggregates: { correctionsByTechnique: [{ role: "red", techniqueId: "T1110", count: 25 }] },
    defaults: { datasetId: DATASET_ID, baseModelId: BASE_ID, method: "sft", budgetUsd: 15 },
  }, stores.proposalStore);
  const approved = await approveProposal(
    { orgId: ORG, id: proposal.id, approvedBy: "operator-1" },
    stores.proposalStore,
    stores.trainingStore,
  );
  assert.equal(approved.status, "converted");
  assert.ok(approved.training_run_id);
  const run = stores.runs.get(approved.training_run_id);
  assert.equal(run.status, "queued", "approval creates the run; training approval remains a separate operator step");
  assert.equal(run.dataset_id, DATASET_ID);
  assert.ok(stores.audits.some((a) => a.action === "TRAINING_PROPOSAL_APPROVED"));
  await assert.rejects(
    approveProposal({ orgId: ORG, id: proposal.id, approvedBy: "operator-1" }, stores.proposalStore, stores.trainingStore),
    /converted|already/i,
  );
});

test("continual loop: rejection is terminal and audited", async () => {
  const stores = fakeStores();
  const [proposal] = await createProposalsFromTriggers({
    orgId: ORG,
    actor: "continual-loop",
    aggregates: { schedule: { due: true, role: "blue" } },
    defaults: { datasetId: DATASET_ID, baseModelId: BASE_ID, method: "sft", budgetUsd: 15 },
  }, stores.proposalStore);
  const rejected = await rejectProposal(
    { orgId: ORG, id: proposal.id, actor: "operator-1", reason: "not now" },
    stores.proposalStore,
  );
  assert.equal(rejected.status, "rejected");
  assert.equal(stores.runs.size, 0);
  assert.ok(stores.audits.some((a) => a.action === "TRAINING_PROPOSAL_REJECTED"));
});

test("continual aggregates are derived from persisted rows after each trigger watermark", () => {
  const now = "2026-02-01T00:00:00.000Z";
  const aggregates = deriveContinualAggregates({
    now,
    traces: [
      { actor: "red", outcome: "succeeded", created_at: "2026-01-19T00:00:00.000Z" },
      { actor: "red", outcome: "failed", created_at: "2026-01-21T00:00:00.000Z" },
      { actor: "red", outcome: "succeeded", created_at: "2026-01-22T00:00:00.000Z" },
      { actor: "red", outcome: "succeeded", created_at: "2026-01-23T00:00:00.000Z" },
      { actor: "red", outcome: null, created_at: "2026-01-24T00:00:00.000Z" },
      { actor: "blue", outcome: "contained", created_at: "2026-01-24T00:00:00.000Z" },
      { actor: "blue", outcome: "succeeded", created_at: "2026-01-25T00:00:00.000Z" },
      { actor: "persona", outcome: "succeeded", created_at: "2026-01-25T00:00:00.000Z" },
    ],
    corrections: [
      { actor: "red", technique_id: "T1110", created_at: "2026-01-01T00:00:00.000Z" },
      { actor: "red", technique_id: "T1110", created_at: "2026-01-26T00:00:00.000Z" },
      { actor: "red", technique_id: "T1110", created_at: "2026-01-27T00:00:00.000Z" },
      { actor: "red", technique_id: "T1110", created_at: "2026-01-28T00:00:00.000Z" },
      { actor: "blue", technique_id: "T1059", created_at: "2026-01-28T00:00:00.000Z" },
    ],
    runs: [
      { mode: "scripted", created_at: "2026-02-01T00:00:00.000Z", score: { objectivesAchieved: 0, objectivesTotal: 2, containmentCorrectness: 0, mttdMinutesP50: 99 } },
      { mode: "agents", created_at: "2026-01-31T00:00:00.000Z", score: { objectivesAchieved: 1, objectivesTotal: 2, containmentCorrectness: 0.5, mttdMinutesP50: 10 } },
      { mode: "agents", created_at: "2026-01-30T00:00:00.000Z", score: { objectivesAchieved: 1, objectivesTotal: 2, containmentCorrectness: 0.7, mttdMinutesP50: 12 } },
      { mode: "agents", created_at: "2026-01-29T00:00:00.000Z", score: { objectivesAchieved: 2, objectivesTotal: 2, containmentCorrectness: 1, mttdMinutesP50: 1 } },
    ],
    proposals: [
      { trigger: "new_traces", role: "red", detail: {}, created_at: "2026-01-20T00:00:00.000Z" },
      { trigger: "corrections", role: "red", detail: { techniqueId: "T1110" }, created_at: "2026-01-27T12:00:00.000Z" },
      { trigger: "schedule", role: "red", detail: {}, created_at: "2026-01-20T00:00:00.000Z" },
      { trigger: "schedule", role: "blue", detail: {}, created_at: "2026-01-30T00:00:00.000Z" },
    ],
  }, {
    correctionWindowDays: 30,
    regressionWindowRuns: 2,
    regressionBars: { redObjectivesRatio: 0.8, blueContainment: 0.8, blueMttdMinutesP50: 5 },
    scheduleIntervalDays: 7,
  });

  assert.deepEqual(aggregates.labelledTraces, { red: 3, blue: 2 });
  assert.deepEqual(aggregates.correctionsByTechnique, [
    { role: "red", techniqueId: "T1110", count: 1 },
    { role: "blue", techniqueId: "T1059", count: 1 },
  ]);
  assert.deepEqual(aggregates.regression, [
    { role: "red", metric: "objectivesAchievedRatio", value: 0.5, bar: 0.8, direction: "higher" },
    { role: "blue", metric: "containmentCorrectness", value: 0.6, bar: 0.8, direction: "higher" },
    { role: "blue", metric: "mttdMinutesP50", value: 11, bar: 5, direction: "lower" },
  ]);
  assert.deepEqual(aggregates.schedule, [{ due: true, role: "red" }]);
});

test("continual sweep env config is disabled by default and rejects invalid numbers", () => {
  const off = continualSweepConfigFromEnv({});
  assert.equal(off.enabled, false);
  assert.equal(off.intervalMs, 3_600_000);

  const on = continualSweepConfigFromEnv({
    MUSEARENA_CONTINUAL_SWEEP: "1",
    MUSEARENA_CONTINUAL_SWEEP_INTERVAL_MS: "60000",
    MUSEARENA_CONTINUAL_LABELLED_TRACES: "25",
    MUSEARENA_CONTINUAL_CORRECTIONS: "3",
    MUSEARENA_CONTINUAL_SCHEDULE_DAYS: "14",
    MUSEARENA_CONTINUAL_BUDGET_USD: "12.5",
  });
  assert.equal(on.enabled, true);
  assert.equal(on.intervalMs, 60_000);
  assert.equal(on.sweep.thresholds.labelledTraces, 25);
  assert.equal(on.sweep.thresholds.corrections, 3);
  assert.equal(on.sweep.scheduleIntervalDays, 14);
  assert.equal(on.sweep.budgetUsd, 12.5);
  assert.throws(
    () => continualSweepConfigFromEnv({ MUSEARENA_CONTINUAL_SWEEP_INTERVAL_MS: "soon" }),
    /MUSEARENA_CONTINUAL_SWEEP_INTERVAL_MS/,
  );
});

test("continual sweep derives aggregates, picks role defaults, and only proposes", async () => {
  const stores = fakeStores();
  const redTraces = Array.from({ length: 60 }, (_, i) => ({
    actor: "red", outcome: i % 2 ? "failed" : "succeeded", created_at: "2026-01-15T00:00:00.000Z",
  }));
  const aggregateStore = {
    async listOrgIds() { return [ORG]; },
    async listTraces() { return redTraces; },
    async listCorrections() { return []; },
    async listRuns() { return []; },
    async listDatasets() {
      return [
        { id: "33333333-3333-4333-8333-333333333333", split: "train", roles: [], family: null, content_hash: "sha256:run", storage_path: "datasets/org-1/run/hash", created_at: "2026-01-20T00:00:00.000Z" },
        { id: DATASET_ID, split: "train", roles: ["red"], family: "clinic", content_hash: "sha256:built", storage_path: "datasets/org-1/built/hash", created_at: "2026-01-19T00:00:00.000Z" },
      ];
    },
    async listModels() {
      return [
        { id: "44444444-4444-4444-8444-444444444444", status: "deprecated", role: ["red"], provider: "meta", served_model: "muse-spark-1.3", created_at: "2026-01-20T00:00:00.000Z" },
        { id: BASE_ID, status: "available", role: ["red", "blue"], provider: "meta", served_model: "muse-spark-1.3", created_at: "2026-01-18T00:00:00.000Z" },
        { id: "55555555-5555-4555-8555-555555555555", status: "ready", role: ["red"], provider: "meta", served_model: "muse-spark-1.3", created_at: "2026-01-17T00:00:00.000Z" },
      ];
    },
  };

  const first = await runContinualSweepForOrg(
    { orgId: ORG, actor: "continual-worker", now: "2026-02-01T00:00:00.000Z", config: { thresholds: { labelledTraces: 50 }, budgetUsd: 20 } },
    { aggregates: aggregateStore, proposals: stores.proposalStore },
  );
  assert.equal(first.proposals.length, 1);
  assert.equal(first.proposals[0].dataset_id, DATASET_ID);
  assert.equal(first.proposals[0].base_model_id, "55555555-5555-4555-8555-555555555555", "ready models are preferred as the training base");
  assert.equal(first.skipped.length, 0);
  assert.equal(stores.runs.size, 0, "the scheduled sweep never starts training");

  const second = await runContinualSweepForOrg(
    { orgId: ORG, actor: "continual-worker", now: "2026-02-01T00:00:00.000Z", config: { thresholds: { labelledTraces: 50 }, budgetUsd: 20 } },
    { aggregates: aggregateStore, proposals: stores.proposalStore },
  );
  assert.equal(second.proposals.length, 0, "the watermark/open-proposal dedupe prevents a duplicate sweep proposal");
});

test("continual sweep skips a triggered role when no built dataset or base model is available", async () => {
  const stores = fakeStores();
  const aggregateStore = {
    async listOrgIds() { return [ORG]; },
    async listTraces() {
      return Array.from({ length: 60 }, () => ({ actor: "blue", outcome: "contained", created_at: "2026-01-15T00:00:00.000Z" }));
    },
    async listCorrections() { return []; },
    async listRuns() { return []; },
    async listDatasets() {
      return [{ id: DATASET_ID, split: "train", roles: ["red"], family: "clinic", content_hash: "sha256:built", storage_path: "datasets/org-1/built/hash", created_at: AT }];
    },
    async listModels() {
      return [{ id: BASE_ID, status: "available", role: ["red", "blue"], provider: "meta", served_model: "muse-spark-1.3", created_at: AT }];
    },
  };
  const result = await runContinualSweepForOrg(
    { orgId: ORG, actor: "continual-worker", now: "2026-02-01T00:00:00.000Z", config: { thresholds: { labelledTraces: 50 }, budgetUsd: 20 } },
    { aggregates: aggregateStore, proposals: stores.proposalStore },
  );
  assert.equal(result.proposals.length, 0);
  assert.deepEqual(result.skipped.map((s) => s.role), ["blue"]);
  assert.match(result.skipped[0].reason, /dataset/);
});

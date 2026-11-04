import test from "node:test";
import assert from "node:assert/strict";
import { AdjudicationQueue, applyAdjudications, computeExportHash } from "../dist/traces/integrity.js";
import { queueFromRows } from "../dist/traces/adjudication.js";
import { autoLabelOf, CorrectionInput, AdjudicationInput } from "../dist/api/review.js";

const AT = "2026-01-01T00:00:00.000Z";
const AUTO = { techniqueId: "T1059", stepId: "g1", actor: "red", outcome: "failed" };
const FIXED = { techniqueId: "T1003.001", stepId: "g1", actor: "red", outcome: "succeeded" };

function exportOf() {
  const exp = {
    meta: { runId: "run-1", formatVersion: 1, contentHash: "", split: "train", redactionPolicyVersion: "v1" },
    run: { runId: "run-1", specDigest: "d", techniquePackVersion: "p", truthLayer: "mirror-only", backend: "kvm" },
    join: {
      runId: "run-1", matched: 1, trajectoryOnly: 0, groundTruthOnly: 0, dropped: 0,
      steps: [{
        at: AT, hostId: "db-01", matched: true,
        groundTruth: { runId: "run-1", hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1059", stepId: "g1", outcome: "failed", at: AT },
      }],
    },
  };
  exp.meta.contentHash = computeExportHash(exp);
  return exp;
}

test("adjudication matches Postgres timestamptz formatting, not exact strings", () => {
  const exp = exportOf();
  const queue = new AdjudicationQueue();
  // Supabase returns "+00:00" where the export uses ".000Z" — the same instant.
  const dispute = queue.file("run-1", "2026-01-01T00:00:00+00:00", AUTO);
  queue.adjudicate(dispute.id, FIXED);

  const fixed = applyAdjudications(exp, queue);
  assert.equal(fixed.join.steps[0].groundTruth.techniqueId, "T1003.001");
  assert.equal(fixed.join.steps[0].groundTruth.outcome, "succeeded");
  assert.notEqual(fixed.meta.contentHash, exp.meta.contentHash, "the adjudicated export is re-hashed");
  assert.equal(fixed.meta.contentHash, computeExportHash(fixed));
});

test("a dispute for a different instant leaves the step alone", () => {
  const exp = exportOf();
  const queue = new AdjudicationQueue();
  const dispute = queue.file("run-1", "2026-01-01T00:05:00.000Z", AUTO);
  queue.adjudicate(dispute.id, FIXED);
  const same = applyAdjudications(exp, queue);
  assert.equal(same.join.steps[0].groundTruth.outcome, "failed");
});

test("queueFromRows rebuilds filing and adjudication from stored rows", () => {
  const queue = queueFromRows([
    {
      id: "d1", org_id: "org-1", run_id: "run-1", step_at: "2026-01-01T00:00:00+00:00",
      auto_label: AUTO, adjudicated_label: FIXED, version: 2, status: "adjudicated",
      filed_by: "user-1", adjudicated_by: "user-2",
      created_at: AT, updated_at: AT,
    },
    {
      id: "d2", org_id: "org-1", run_id: "run-1", step_at: "2026-01-01T00:10:00+00:00",
      auto_label: AUTO, adjudicated_label: null, version: 1, status: "pending",
      filed_by: "user-1", adjudicated_by: null,
      created_at: AT, updated_at: AT,
    },
  ]);
  assert.equal(queue.list().length, 2);
  assert.equal(queue.pending().length, 1);
  const first = queue.list()[0];
  assert.deepEqual(queue.effective(first), FIXED);
  assert.deepEqual(queue.effective(queue.list()[1]), AUTO);
});

test("a trace without an Atomic GUID step can still file a dispute under its trace identity", () => {
  const trace = {
    id: "trace-uuid-1", run_id: "run-1", at: AT,
    payload: { groundTruth: { techniqueId: "T1110", actor: "red", outcome: "attempted" } },
  };
  assert.deepEqual(autoLabelOf(trace), {
    techniqueId: "T1110", stepId: "trace-uuid-1", actor: "red", outcome: "attempted",
  });
  const withGuid = { ...trace, payload: { groundTruth: { ...trace.payload.groundTruth, stepId: "g1" } } };
  assert.equal(autoLabelOf(withGuid).stepId, "g1", "an explicit Atomic GUID wins over the trace identity");
});

test("corrections are append-only records with a closed kind set", () => {
  assert.deepEqual(CorrectionInput.parse({ kind: "edit" }).before, {}, "before defaults to empty");
  assert.deepEqual(CorrectionInput.parse({ kind: "reprompt", after: { action: "x" } }).after, { action: "x" });
  assert.throws(() => CorrectionInput.parse({ kind: "delete" }), /invalid/i);
  assert.throws(() => CorrectionInput.parse({ kind: "edit", traceId: "x" }), /unrecognized key/i, "unknown fields are rejected");
});

test("an adjudication must carry a complete label", () => {
  assert.throws(() => AdjudicationInput.parse({ label: { techniqueId: "T1" } }), /invalid/i);
  assert.throws(() => AdjudicationInput.parse({ label: { ...FIXED, approval: "ok" } }), /unrecognized key/i);
  assert.deepEqual(AdjudicationInput.parse({ label: FIXED }).label, FIXED);
});

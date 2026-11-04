import test from "node:test";
import assert from "node:assert/strict";
import { CaptureTrace } from "@musearena/shared";
import { persistRunTraces, traceRowsFor } from "../dist/training/traces.js";
import { captureRow } from "../dist/api/traces.js";

const AT = "2026-01-01T00:00:00.000Z";

function exportOf(steps, split = "train") {
  return {
    meta: { runId: "run-1", formatVersion: 1, contentHash: "sha256:x", split, redactionPolicyVersion: "v1" },
    run: { runId: "run-1", specDigest: "d", techniquePackVersion: "p", truthLayer: "mirror-only", backend: "kvm" },
    join: { runId: "run-1", steps, matched: 1, trajectoryOnly: 0, groundTruthOnly: 0, dropped: 0 },
  };
}

test("trace rows: one row per joined step, indexed, with the structured payload", () => {
  const exp = exportOf([
    {
      at: AT, hostId: "db-01", techniqueId: "T1003.001", matched: true,
      trajectory: {
        runId: "run-1", hostId: "db-01", actor: "red", observation: "dump", action: "pg_dump",
        toolCall: "exec", techniqueId: "T1003.001", at: AT,
        detail: { argv: ["pg_dump", "-f", "/tmp/x"] },
      },
      groundTruth: { runId: "run-1", hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1003.001", outcome: "succeeded", at: AT },
    },
    {
      at: AT, hostId: "web-01", matched: false,
      groundTruth: { runId: "run-1", hostId: "web-01", kind: "alert", actor: "blue", techniqueId: "T1190", outcome: "detected", at: AT },
    },
  ]);

  const rows = traceRowsFor(exp, "org-1", "ds-1");
  assert.equal(rows.length, 2);
  assert.equal(rows[0].step_index, 0);
  assert.equal(rows[1].step_index, 1);
  assert.equal(rows[0].org_id, "org-1");
  assert.equal(rows[0].run_id, "run-1");
  assert.equal(rows[0].dataset_id, "ds-1");
  assert.equal(rows[0].actor, "red");
  assert.equal(rows[0].outcome, "succeeded");
  assert.equal(rows[0].action, "pg_dump");
  assert.equal(rows[0].tool_call, "exec");
  assert.equal(rows[0].split, "train");
  assert.deepEqual(rows[0].payload.trajectory.detail.argv, ["pg_dump", "-f", "/tmp/x"]);

  assert.equal(rows[1].actor, "blue", "ground truth supplies the actor when no trajectory exists");
  assert.equal(rows[1].outcome, "detected");
  assert.equal(rows[1].action, null);
  assert.equal(rows[1].observation, null);
  assert.equal(rows[1].payload.trajectory, null);
});

test("trace rows: the split follows the dataset, not the caller", () => {
  const rows = traceRowsFor(exportOf([], "val"), "org-1", null);
  assert.equal(rows.length, 0);
  const one = traceRowsFor(exportOf([{ at: AT, hostId: "h", matched: false }], "val"), "org-1", null);
  assert.equal(one[0].split, "val");
  assert.equal(one[0].dataset_id, null);
});

test("trace persistence: an uninstalled learning schema degrades to zero; real write errors still fail", async () => {
  const exp = exportOf([{
    at: AT, hostId: "db-01", matched: true,
    trajectory: { runId: "run-1", hostId: "db-01", actor: "red", observation: "ok", action: "login", at: AT },
    groundTruth: { runId: "run-1", hostId: "db-01", kind: "db", actor: "red", outcome: "succeeded", at: AT },
  }]);
  const missingSchema = {
    from: () => ({
      upsert: async () => ({
        error: { code: "PGRST205", message: "Could not find the table 'public.traces' in the schema cache" },
      }),
    }),
  };
  assert.equal(await persistRunTraces(exp, "org-1", "ds-1", missingSchema), 0);

  const broken = {
    from: () => ({ upsert: async () => ({ error: { message: "connection reset" } }) }),
  };
  await assert.rejects(
    () => persistRunTraces(exp, "org-1", "ds-1", broken),
    /trace persistence failed: connection reset/,
  );
});

test("capture contract: strict, actor-required, timestamp-checked, defaults applied", () => {
  const valid = {
    runId: "run-9", stepIndex: 2, at: AT, actor: "blue",
    techniqueId: "T1", action: "isolate host", outcome: "contained", detail: { evidence: ["E1"] },
  };
  const parsed = CaptureTrace.parse(valid);
  assert.equal(parsed.hostId, "", "host defaults to empty");
  assert.equal(parsed.matched, false, "matched defaults to false");

  assert.throws(() => CaptureTrace.parse({ ...valid, orgId: "org-foreign" }), /unrecognized key/i, "unknown fields are rejected");
  assert.throws(() => CaptureTrace.parse({ ...valid, actor: undefined }), /actor/i, "a trace without an actor cannot train");
  assert.throws(() => CaptureTrace.parse({ ...valid, at: "not-a-date" }), /ISO timestamp/i);
  assert.throws(() => CaptureTrace.parse({ ...valid, stepIndex: -1 }));
});

test("capture row: uniform payload, org from the key, ground truth only when an outcome is reported", () => {
  const withOutcome = captureRow(CaptureTrace.parse({
    runId: "run-9", stepIndex: 2, at: AT, hostId: "web-01", actor: "blue",
    techniqueId: "T1", action: "isolate host", outcome: "contained", detail: { evidence: ["E1"] },
  }), "org-9");
  assert.equal(withOutcome.org_id, "org-9");
  assert.equal(withOutcome.run_id, "run-9");
  assert.equal(withOutcome.actor, "blue");
  assert.equal(withOutcome.outcome, "contained");
  assert.equal(withOutcome.split, "train");
  assert.equal(withOutcome.payload.groundTruth.outcome, "contained");
  assert.equal(withOutcome.payload.groundTruth.kind, "capture");
  assert.deepEqual(withOutcome.payload.trajectory.detail.evidence, ["E1"]);

  const withoutOutcome = captureRow(CaptureTrace.parse({
    runId: "run-9", stepIndex: 3, at: AT, actor: "red", action: "curl",
  }), "org-9");
  assert.equal(withoutOutcome.outcome, null);
  assert.equal(withoutOutcome.payload.groundTruth, null);
  assert.equal(withoutOutcome.payload.trajectory.action, "curl");
});

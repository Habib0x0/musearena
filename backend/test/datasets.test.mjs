import test from "node:test";
import assert from "node:assert/strict";
import { applyAdjudication, applyCorrections, roleExamples, snapshotHash } from "../dist/learning/datasets.js";
import { preferencePairs, sftExamples } from "../dist/training/pairs.js";

const AT = "2026-01-01T00:00:00.000Z";

const trace = (over = {}) => ({
  id: "tr-1", org_id: "org-1", run_id: "run-1", dataset_id: null, step_index: 0, at: AT,
  host_id: "db-01", technique_id: "T1003.001", actor: "red",
  action: "pg_dump", observation: "dump the table", reasoning: null, tool_call: "exec",
  outcome: "succeeded", matched: true, split: "train",
  source: "synthetic", framework: null, payload: {},
  ...over,
});

const correction = (over = {}) => ({
  id: "c1", trace_id: "tr-1", kind: "edit", before: { action: "pg_dump" },
  after: { action: "pg_dump --schema-only" }, created_at: "2026-01-01T00:00:01.000Z",
  ...over,
});

test("role files are separate; legacy red files never carry blue rows", () => {
  const rows = [
    trace({ id: "r1", actor: "red", outcome: "succeeded" }),
    trace({ id: "r2", actor: "red", outcome: "failed", action: "cat /etc/passwd", technique_id: "T1003.001" }),
    trace({ id: "b1", actor: "blue", outcome: "contained", action: "block IP", technique_id: "T1190" }),
    trace({ id: "p1", actor: "proof", outcome: "succeeded" }),
    trace({ id: "n1", actor: "noise", outcome: "succeeded" }),
    trace({ id: "x1", actor: "platform", outcome: "succeeded" }),
  ];
  const none = new Map();
  const red = roleExamples(rows, none, "red");
  const blue = roleExamples(rows, none, "blue");
  assert.equal(red.sft.length, 2, "red SFT carries red rows only");
  assert.deepEqual(red.sft.map((e) => e.completion).sort(), ["cat /etc/passwd", "pg_dump"]);
  assert.equal(red.pairs.length, 1, "a red success pairs with the red failure of the same technique");
  assert.equal(blue.sft.length, 1, "blue SFT carries blue rows only");
  assert.equal(blue.sft[0].completion, "block IP");
  assert.equal(blue.sft[0].succeeded, true, "blue success is containment");
  assert.equal(blue.pairs.length, 0);
});

test("a correction changes the exported completion, records its id, and leaves the trace readable", () => {
  const row = trace();
  const eff = applyCorrections(row, [correction()]);
  assert.equal(eff.action, "pg_dump --schema-only");
  assert.deepEqual(eff.appliedCorrections, ["c1"]);
  assert.equal(row.action, "pg_dump", "the stored action is never overwritten");

  const shaped = roleExamples([row], new Map([[row.id, [correction()]]]), "red");
  assert.equal(shaped.sft[0].completion, "pg_dump --schema-only");
  assert.deepEqual(shaped.appliedCorrections, ["c1"]);
});

test("a label correction changes the effective outcome and technique without mutating the trace", () => {
  const row = trace({ outcome: "failed", technique_id: "T1059" });
  const labelCorrection = correction({ kind: "label", after: { outcome: "succeeded", techniqueId: "T1003.001", action: "token=corrected-secret-value" } });
  const eff = applyCorrections(row, [labelCorrection]);
  assert.equal(eff.outcome, "succeeded");
  assert.equal(eff.techniqueId, "T1003.001");
  assert.ok(!String(eff.action).includes("corrected-secret-value"), "corrected actions are deep-redacted before shaping");

  const shaped = roleExamples([row], new Map([[row.id, [labelCorrection]]]), "red");
  assert.equal(shaped.sft[0].succeeded, true);
  assert.equal(shaped.sft[0].techniqueId, "T1003.001");
  assert.equal(row.outcome, "failed", "the stored outcome remains readable");
});

test("the newest correction wins field by field", () => {
  const rows = new Map([["tr-1", [
    correction({ id: "old", created_at: "2026-01-01T00:00:01.000Z", after: { action: "first" } }),
    correction({ id: "new", created_at: "2026-01-01T00:00:02.000Z", after: { action: "second" } }),
  ]]]);
  const shaped = roleExamples([trace()], rows, "red");
  assert.equal(shaped.sft[0].completion, "second");
  assert.deepEqual(shaped.appliedCorrections.sort(), ["new", "old"]);
});

test("with no corrections or adjudications the legacy red files are byte-identical", () => {
  const rows = [
    trace({ id: "r1", actor: "red", outcome: "succeeded", technique_id: "T1003.001" }),
    trace({ id: "r2", actor: "red", outcome: "failed", action: "cat /etc/passwd", technique_id: "T1003.001" }),
  ];
  const legacy = {
    meta: { runId: "run-1", formatVersion: 1, contentHash: "", split: "train", redactionPolicyVersion: "v1" },
    run: { runId: "run-1", specDigest: "x", techniquePackVersion: "attack-15.1", truthLayer: "mirror-only", backend: "kvm" },
    join: {
      runId: "run-1",
      matched: 2, trajectoryOnly: 0, groundTruthOnly: 0, dropped: 0, dropReasons: {},
      steps: rows.map((r) => ({
        at: r.at, hostId: r.host_id, techniqueId: r.technique_id,
        trajectory: { runId: r.run_id, hostId: r.host_id, actor: r.actor, observation: r.observation, action: r.action, toolCall: r.tool_call, techniqueId: r.technique_id, at: r.at },
        groundTruth: { runId: r.run_id, hostId: r.host_id, kind: "objective", actor: r.actor, techniqueId: r.technique_id, outcome: r.outcome, at: r.at },
        matched: true,
      })),
    },
  };
  const shaped = roleExamples(rows, new Map(), "red");
  assert.equal(JSON.stringify(shaped.sft), JSON.stringify(sftExamples(legacy)));
  assert.equal(JSON.stringify(shaped.pairs), JSON.stringify(preferencePairs(legacy)));
});

test("an adjudicated label supersedes the auto-label before shaping", () => {
  const row = trace({ outcome: "failed" });
  const dispute = {
    id: "d1", run_id: "run-1", step_at: AT, status: "adjudicated",
    adjudicated_label: { actor: "red", outcome: "succeeded", techniqueId: "T1003.001" },
  };
  const applied = applyAdjudication(row, [dispute]);
  assert.equal(applied.row.outcome, "succeeded");
  assert.deepEqual(applied.applied, ["d1"]);
  const other = applyAdjudication(row, [{ ...dispute, step_at: "2026-01-01T00:10:00.000Z" }]);
  assert.equal(other.row.outcome, "failed", "a different instant is a different step");
  assert.deepEqual(other.applied, []);
});

test("the snapshot hash ignores its own field and changes with content", () => {
  const make = (completion) => ({
    meta: { formatVersion: 2, contentHash: "", split: "train", redactionPolicyVersion: "v1", catalogVersion: "c", profileVersion: "p", imageVersion: "i", specDigests: [], techniquePackVersions: [], modelIds: {} },
    selection: { filters: {}, runIds: [], counts: { traces: 1, red: 1, blue: 0, excluded: 0, correctionsApplied: 0, adjudicationsApplied: 0 }, corrections: [], adjudications: [] },
    roles: { red: { sft: [{ runId: "run-1", hostId: "h", techniqueId: undefined, prompt: "p", completion, succeeded: true }], pairs: [] }, blue: { sft: [], pairs: [] } },
  });
  const a = make("one");
  const b = make("two");
  const aHash = snapshotHash(a);
  a.meta.contentHash = "sha256:other";
  assert.equal(snapshotHash(a), aHash, "the hash does not hash itself");
  assert.notEqual(snapshotHash(b), aHash);
});

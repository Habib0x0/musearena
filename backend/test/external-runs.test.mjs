import test from "node:test";
import assert from "node:assert/strict";
import { ExternalRunExport, toCaptureTraces } from "../dist/learning/external-runs.js";

const exportFixture = {
  runId: "run-imported-1",
  framework: "caller-system",
  source: "imported",
  steps: [
    {
      at: "2026-01-01T00:00:00.000Z", host: "web-01", actor: "red", technique: "T1190",
      tool: "curl", command: ["curl", "-s", "http://web-01/login"], output: "HTTP/1.1 200 OK",
      outcome: "succeeded", detail: { requestId: "r1" },
    },
    {
      at: "2026-01-01T00:01:00.000Z", host: "db-01", actor: "red", technique: "T1005",
      command: "psql -h db-01 -U app -d app -tAc 'select value from secrets'",
      output: "s3cr3t", outcome: "succeeded",
    },
  ],
};

test("external run: maps an exported agent run to capture bodies", () => {
  const parsed = ExternalRunExport.parse(exportFixture);
  const steps = toCaptureTraces(parsed);
  assert.equal(steps.length, 2);
  assert.equal(steps[0].runId, "run-imported-1");
  assert.equal(steps[0].stepIndex, 0);
  assert.equal(steps[0].source, "imported");
  assert.equal(steps[0].framework, "caller-system");
  assert.equal(steps[0].action, "curl");
  assert.equal(steps[0].toolCall, "curl -s http://web-01/login");
  assert.equal(steps[0].observation, "HTTP/1.1 200 OK");
  assert.equal(steps[0].detail.requestId, "r1");
  assert.equal(steps[0].detail.imported.tool, "curl");
  assert.equal(steps[1].action, "psql");
  assert.match(steps[1].toolCall, /^psql -h db-01/);
});

test("external run: source defaults to imported and field is accepted", () => {
  const parsed = ExternalRunExport.parse({ runId: "r", steps: [{ at: "2026-01-01T00:00:00.000Z", host: "h", actor: "blue", outcome: "contained" }] });
  assert.equal(parsed.source, "imported");
  assert.equal(toCaptureTraces(parsed)[0].source, "imported");
  assert.equal(ExternalRunExport.parse({ ...exportFixture, source: "field" }).source, "field");
});

test("external run: the import contract is strict", () => {
  assert.throws(() => ExternalRunExport.parse({ runId: "r", steps: [] }), /at least 1|too_small/i);
  assert.throws(() => ExternalRunExport.parse({ ...exportFixture, extra: true }), /unrecognized key/i);
  assert.throws(() => ExternalRunExport.parse({ ...exportFixture, source: "synthetic" }), /invalid/i);
  assert.throws(() => ExternalRunExport.parse({ ...exportFixture, steps: [{ at: "not-a-time", host: "h" }] }), /ISO timestamp/i);
  assert.throws(() => ExternalRunExport.parse({ ...exportFixture, steps: [{ at: "2026-01-01T00:00:00.000Z", host: "h", actor: "proof" }] }), /invalid/i);
});

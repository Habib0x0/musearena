import test from "node:test";
import assert from "node:assert/strict";

const { formatDesignSseEvent, createPacedDesignEventSink } = await import("../dist/designer/server.js");
const { orchestrateDesign } = await import("../dist/designer/orchestrator.js");
const { clinicOrgSpec } = await import("../dist/designer/clinic.js");

const budget = { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 };

function parseFrame(chunk) {
  const line = chunk.split("\n").find((l) => l.startsWith("data: "));
  assert.ok(line, `frame has a data line: ${chunk}`);
  return JSON.parse(line.slice("data: ".length));
}

test("SSE frames carry id, event name, and the full event JSON", () => {
  const event = {
    runId: "run-1", seq: 7, at: "2026-11-02T00:00:00.000Z",
    type: "step.started", phase: "model", stepId: "model-attempt-1",
    title: "Generating structured design", detail: "streaming", data: { attempt: 1 },
  };
  const frame = formatDesignSseEvent(event);
  assert.ok(frame.startsWith("id: 7\nevent: step.started\ndata: "));
  assert.ok(frame.endsWith("\n\n"), "frames are separated by a blank line");
  assert.deepEqual(parseFrame(frame), event);
});

test("paced sink preserves order, numbers events, and stops after close", async () => {
  const chunks = [];
  const sink = createPacedDesignEventSink((chunk) => chunks.push(chunk), "run-42", 20);
  for (let i = 0; i < 3; i++) {
    sink.emit({ type: "step.started", phase: "model", stepId: `step-${i}`, title: `step ${i}` });
  }
  await sink.flush();
  const events = chunks.map(parseFrame);
  assert.deepEqual(events.map((e) => e.seq), [1, 2, 3]);
  assert.deepEqual(events.map((e) => e.stepId), ["step-0", "step-1", "step-2"]);
  assert.ok(events.every((e) => e.runId === "run-42" && typeof e.at === "string"));

  sink.close();
  sink.emit({ type: "step.completed", phase: "model", stepId: "late", title: "late" });
  await sink.flush();
  assert.equal(chunks.length, 3, "events after close are dropped, not written");
});

test("a designer run streams the real lifecycle from context to deployability", async () => {
  const spec = clinicOrgSpec();
  const events = [];
  const client = {
    modelId: "stream-mock",
    async generateObject({ schema, onDelta }) {
      onDelta?.({ kind: "reasoning", text: "planning hosts", reasoningChars: 15, contentChars: 0 });
      onDelta?.({ kind: "content", text: '{"name":', reasoningChars: 15, contentChars: 8 });
      return schema.parse(spec);
    },
  };

  const pkg = await orchestrateDesign(client, "clinic", budget, { onEvent: (event) => events.push(event) });
  assert.equal(pkg.spec.instances.length, spec.instances.length);

  const started = events.filter((e) => e.type === "step.started").map((e) => e.stepId);
  assert.equal(started[0], "context");
  assert.ok(started.includes("model-attempt-1"));
  assert.ok(started.includes("normalize"));
  assert.ok(started.includes("validation-1"));
  assert.ok(started.includes("package-topology"));
  assert.ok(started.includes("package-plan"));
  assert.ok(started.includes("package-cost"));
  assert.ok(started.includes("package-deployability"));

  // Every started step reaches a terminal state before the run ends.
  for (const stepId of started) {
    const terminal = events.find((e) => e.stepId === stepId && (e.type === "step.completed" || e.type === "step.failed" || e.type === "step.blocked"));
    assert.ok(terminal, `${stepId} has a terminal event`);
  }

  // Model deltas are forwarded as semantic progress events, not raw chunks of nothing.
  const reasoning = events.filter((e) => e.type === "model.reasoning" && e.stepId === "model-attempt-1");
  const progress = events.filter((e) => e.type === "model.progress" && e.stepId === "model-attempt-1");
  assert.equal(reasoning.map((e) => e.data.text).join(""), "planning hosts");
  assert.equal(progress.map((e) => e.data.text).join(""), '{"name":');

  const deployability = events.at(-1);
  assert.equal(deployability.stepId, "package-deployability");
  assert.equal(deployability.type, pkg.canProvision ? "step.completed" : "step.blocked");
});

test("a rejected model output streams the failure and the bounded repair attempt", async () => {
  const spec = clinicOrgSpec();
  const events = [];
  let attempts = 0;
  const client = {
    modelId: "stream-mock",
    async generateObject({ schema, prompt }) {
      attempts++;
      if (attempts === 1) throw new Error("no JSON object in model response");
      assert.match(prompt, /previous reply was rejected/, "the repair prompt quotes the rejection");
      return schema.parse(spec);
    },
  };

  const pkg = await orchestrateDesign(client, "clinic", budget, { onEvent: (event) => events.push(event) });
  assert.equal(attempts, 2);
  assert.equal(pkg.spec.instances.length, spec.instances.length);

  const failed = events.find((e) => e.type === "step.failed" && e.stepId === "model-attempt-1");
  assert.ok(failed, "attempt 1 failure is streamed");
  assert.match(failed.detail, /no JSON object/);
  const repairStarted = events.findIndex((e) => e.type === "step.started" && e.stepId === "model-attempt-2");
  const repairDone = events.findIndex((e) => e.type === "step.completed" && e.stepId === "model-attempt-2");
  assert.ok(repairStarted > events.indexOf(failed), "repair starts after the failure");
  assert.ok(repairDone > repairStarted, "repair completes before packaging");
  assert.ok(events.some((e) => e.type === "step.completed" && e.stepId === "package-deployability"), "the loop still reaches packaging");
});

test("an aborted run stops before the model is called", async () => {
  let calls = 0;
  const events = [];
  const client = {
    modelId: "stream-mock",
    async generateObject() { calls++; throw new Error("must not be called"); },
  };
  const controller = new AbortController();
  const abortError = new Error("design run cancelled by client");
  abortError.name = "AbortError";
  controller.abort(abortError);

  await assert.rejects(
    orchestrateDesign(client, "clinic", budget, { signal: controller.signal, onEvent: (e) => events.push(e) }),
    (err) => err.name === "AbortError",
  );
  assert.equal(calls, 0, "no model spend after cancellation");
  assert.ok(!events.some((e) => e.stepId === "model-attempt-1"), "no model step is started");
});

test("a throwing observer never changes the design outcome", async () => {
  const spec = clinicOrgSpec();
  const client = { modelId: "stream-mock", async generateObject({ schema }) { return schema.parse(spec); } };
  const pkg = await orchestrateDesign(client, "clinic", budget, { onEvent: () => { throw new Error("observer blew up"); } });
  assert.deepEqual(pkg.spec, spec);
});

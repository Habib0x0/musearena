import test from "node:test";
import assert from "node:assert/strict";

/**
 * Lifecycle invariants. These are the rules that keep a failed run
 * from being reported as a clean teardown:
 * - a failure is never erased by a later write,
 * - a failed row whose cleanup succeeded is not swept again,
 * - a failed row whose cleanup failed IS swept again,
 * - `destroying` is retried (a stuck teardown is a leak, not a state).
 */

test("access_info merges: a later step never erases the failure or the outputs", async () => {
  const { mergeAccessInfo, failureRecord } = await import("../dist/provisioner/deployment-status.js");
  const afterDeploy = mergeAccessInfo({}, { outputs: { "web-01": "vm:hvf:web-01" }, cidr: "10.2.0.0/16" });
  const afterFailure = mergeAccessInfo(afterDeploy, { failure: failureRecord("exercise", "Meta Model API 403") });
  const afterTeardown = mergeAccessInfo(afterFailure, { resourcesDestroyed: true, destroyedAt: "2026-10-30T00:00:00.000Z" });

  assert.equal(afterTeardown.failure.stage, "exercise");
  assert.match(afterTeardown.failure.error, /403/);
  assert.deepEqual(afterTeardown.outputs, { "web-01": "vm:hvf:web-01" });
  assert.equal(afterTeardown.cidr, "10.2.0.0/16");
  assert.equal(afterTeardown.resourcesDestroyed, true);
});

test("failure records name the stage, keep the message, and are bounded", async () => {
  const { failureRecord } = await import("../dist/provisioner/deployment-status.js");
  const f = failureRecord("readiness", "x".repeat(5000), "2026-10-30T00:00:00.000Z");
  assert.equal(f.stage, "readiness");
  assert.equal(f.error.length, 2000);
  assert.equal(f.at, "2026-10-30T00:00:00.000Z");
});

test("guest runs are only swept when their deployment is gone and they are old", async () => {
  const { vmOrphanReason } = await import("../dist/ops/maintenance.js");
  const old = new Date(Date.now() - 60 * 60_000).toISOString();
  const fresh = new Date(Date.now() - 60_000).toISOString();
  const run = (startedAt) => ({ runId: "run-x", instances: { a: { startedAt } } });
  const minAge = 30 * 60_000;
  const now = Date.now();

  assert.equal(vmOrphanReason(run(old), undefined, now, minAge), "no deployment row");
  assert.equal(vmOrphanReason(run(old), { id: "x", org_id: "o", status: "destroyed" }, now, minAge), "deployment destroyed");
  assert.equal(
    vmOrphanReason(run(old), { id: "x", org_id: "o", status: "failed", access_info: { resourcesDestroyed: true } }, now, minAge),
    "deployment failed and cleanup was recorded",
  );
  // A live deployment, or a debug run still in progress, is left alone.
  assert.equal(vmOrphanReason(run(old), { id: "x", org_id: "o", status: "ready" }, now, minAge), null);
  assert.equal(vmOrphanReason(run(old), { id: "x", org_id: "o", status: "failed", access_info: { resourcesDestroyed: false } }, now, minAge), null);
  assert.equal(vmOrphanReason(run(fresh), undefined, now, minAge), null);
});

test("a permanent model API failure is named so Temporal does not retry it", async () => {
  const prev = { key: process.env.META_API_KEY, model: process.env.META_MODEL_ID, fetch: globalThis.fetch };
  process.env.META_API_KEY = "test-key";
  process.env.META_MODEL_ID = "muse-spark-1.3";
  try {
    const { MetaModelClient, PermanentModelError } = await import("../dist/lib/model.js");
    const client = new MetaModelClient();
    globalThis.fetch = async () => new Response('{"error":{"code":"user_blocked"}}', { status: 403 });
    await assert.rejects(
      client.generateTurn({ system: "", transcript: [], tools: [] }),
      (e) => e instanceof PermanentModelError && e.name === "PermanentModelError" && /403/.test(e.message),
    );
    // 5xx stays a plain Error: it is worth retrying.
    globalThis.fetch = async () => new Response("upstream", { status: 503 });
    await assert.rejects(client.generateTurn({ system: "", transcript: [], tools: [] }), (e) => e.name === "Error");
  } finally {
    if (prev.key === undefined) delete process.env.META_API_KEY; else process.env.META_API_KEY = prev.key;
    if (prev.model === undefined) delete process.env.META_MODEL_ID; else process.env.META_MODEL_ID = prev.model;
    globalThis.fetch = prev.fetch;
  }
});

test("cleanup is retried exactly when resources may still exist", async () => {
  const { needsCleanup } = await import("../dist/provisioner/deployment-status.js");
  // Nothing was created / already gone.
  assert.equal(needsCleanup("pending", {}), false);
  assert.equal(needsCleanup("destroyed", {}), false);
  // Failed, cleanup never ran or failed.
  assert.equal(needsCleanup("failed", {}), true);
  assert.equal(needsCleanup("failed", { resourcesDestroyed: false }), true);
  assert.equal(needsCleanup("failed", { resourcesDestroyed: true }), false);
  // A teardown that threw must be retried, not skipped forever.
  assert.equal(needsCleanup("destroying", {}), true);
  // Live or in-flight work still owns resources.
  for (const s of ["provisioning", "configuring", "verifying", "exercising", "ready"]) {
    assert.equal(needsCleanup(s, {}), true, `${s} still needs cleanup`);
  }
});

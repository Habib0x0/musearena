import assert from "node:assert/strict";
import { createClient } from "@supabase/supabase-js";
import { EventStore } from "../dist/observability/events.js";
import { ingest } from "../dist/observability/collector.js";
import { LocalTrajectoryRecorder } from "../dist/observability/trajectory.js";
import { publishRunDataset } from "../dist/observability/publish.js";
import { decodeObject } from "../dist/observability/dataset-object.js";
import { createApiServer } from "../dist/api/server.js";
import { newCaptureKey } from "../dist/api/keys.js";
import { traceRoutes } from "../dist/api/traces.js";
import { reviewRoutes } from "../dist/api/review.js";
import { signalRoutes } from "../dist/api/signals.js";
import { graderRoutes } from "../dist/api/graders.js";
import { modelRoutes } from "../dist/api/models.js";
import { datasetRoutes } from "../dist/api/datasets.js";
import { runRoutes } from "../dist/api/runs.js";
import { baseModelFor, resolveAgentClients, resolveModel } from "../dist/learning/models.js";
import { ModalModelClient } from "../dist/lib/model.js";

/**
 * Live learning-platform smoke (F-4 + F-5) against a local Supabase stack.
 *
 *   supabase start
 *   SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... node scripts/learning-smoke.mjs
 *
 * Drives the real HTTP routes and the real database: publish/trace idempotency,
 * a correction, a dispute, a role refusal, adjudication-driven re-hashing, and a
 * capture key round trip including revocation. Clerk verification is the only
 * substituted part — the local stack has no Clerk, so the session verifier is
 * injected; org/role resolution below it is the production code.
 */
const url = process.env.SUPABASE_URL;
const key = process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SECRET_KEY;
if (!url || !key) {
  console.error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SECRET_KEY) are required");
  process.exit(1);
}
process.env.SUPABASE_SERVICE_ROLE_KEY = key;
// Resolving an agent role builds a Meta client, which refuses to construct
// without a key. This smoke asserts the resolved ID and never sends a turn.
process.env.META_API_KEY ||= "smoke-key-not-used";

const sb = createClient(url, key, { auth: { persistSession: false } });
const checks = [];
const pass = (name) => { checks.push(name); console.log(`✔ ${name}`); };

const { error: bucketError } = await sb.storage.getBucket("datasets");
if (bucketError) {
  const { error } = await sb.storage.createBucket("datasets", { public: false });
  if (error && !/already exists/i.test(error.message)) throw error;
}

// A unique org per run: traces/corrections/disputes are append-only (0011),
// so curation cleans nothing physically — an aborted run's rows simply belong
// to a different org and cannot pollute this run's counts.
const orgId = `org-smoke-${Date.now()}`;
const runId = `run-smoke-${Date.now()}`;
const at = new Date().toISOString();
const store = EventStore.fresh();
new LocalTrajectoryRecorder(store).record({
  runId, hostId: "db-01", actor: "red", observation: "dump the customer table",
  action: "pg_dump", toolCall: "exec", techniqueId: "T1003.001",
  detail: { argv: ["pg_dump", "-f", "/tmp/dump.sql"] }, at,
});
ingest({
  runId, hostId: "db-01", kind: "process", actor: "red", techniqueId: "T1003.001",
  stepId: "g1", outcome: "succeeded", at, detail: { objectiveId: "o1" },
}, { store });

const run = {
  runId, orgId, deploymentId: "dep-smoke", mode: "blind",
  specDigest: "sha256:smoke", techniquePackVersion: "attack-15.1",
  modelIds: {}, truthLayer: "mirror-only", backend: "kvm",
};

const first = await publishRunDataset(run, { store });
assert.equal(first.traceCount, 1);
const afterFirst = await sb.from("traces").select("id, at, outcome").eq("org_id", orgId).eq("run_id", runId);
assert.equal(afterFirst.data.length, 1);
assert.equal(afterFirst.data[0].outcome, "succeeded");
pass("publish writes one trace row per joined step");

const second = await publishRunDataset(run, { store });
const afterSecond = await sb.from("traces").select("id").eq("org_id", orgId).eq("run_id", runId);
assert.equal(afterSecond.data.length, 1, "re-publish must not duplicate rows");
assert.equal(second.contentHash, first.contentHash);
pass("re-publish is idempotent (one row, same hash)");

// The local stack has no Clerk; the verifier is the only substituted part.
const ISSUER = "https://clerk.invalid";
const claimsFor = (token) => {
  const sessions = {
    "reviewer-token": { sub: "smoke-reviewer", iss: ISSUER, exp: 9_999_999_999, o: { id: orgId, rol: "reviewer" } },
    "trainer-token": { sub: "smoke-trainer", iss: ISSUER, exp: 9_999_999_999, o: { id: orgId, rol: "trainer" } },
    "operator-token": { sub: "smoke-operator", iss: ISSUER, exp: 9_999_999_999, o: { id: orgId, rol: "operator" } },
  };
  if (!sessions[token]) throw new Error("bad token");
  return sessions[token];
};

const server = createApiServer({
  issuer: ISSUER,
  verifySession: async (token) => claimsFor(token),
  routes: [...traceRoutes(), ...reviewRoutes(), ...signalRoutes(), ...graderRoutes(), ...modelRoutes(), ...datasetRoutes(), ...runRoutes()],
  allowedOrigins: [],
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const { port } = server.address();
const base = `http://127.0.0.1:${port}`;
const call = (path, token, init = {}) => fetch(`${base}${path}`, {
  ...init,
  headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...(init.headers ?? {}) },
});

const traceId = afterFirst.data[0].id;
try {
  const correction = await call(`/traces/${traceId}/corrections`, "reviewer-token", {
    method: "POST",
    body: JSON.stringify({ kind: "edit", before: { action: "pg_dump" }, after: { action: "pg_dump --schema-only" }, note: "least data" }),
  });
  assert.equal(correction.status, 201);
  const correctionRow = await correction.json();
  const detail = await call(`/traces/${traceId}`, "reviewer-token");
  assert.equal(detail.status, 200);
  const detailBody = await detail.json();
  assert.equal(detailBody.corrections.length, 1);
  assert.equal(detailBody.corrections[0].reviewer, "smoke-reviewer");
  assert.deepEqual(detailBody.corrections[0].after, { action: "pg_dump --schema-only" });
  pass("a correction is recorded with before/after and reviewer");

  const dispute = await call(`/traces/${traceId}/disputes`, "reviewer-token", { method: "POST", body: "{}" });
  assert.equal(dispute.status, 201);
  const disputeRow = await dispute.json();
  assert.equal(disputeRow.status, "pending");
  assert.equal(disputeRow.version, 1);
  pass("a dispute is filed against the trace's ground-truth label");

  const duplicate = await call(`/traces/${traceId}/disputes`, "reviewer-token", { method: "POST", body: "{}" });
  assert.equal(duplicate.status, 409, "the same run step cannot be disputed twice");
  pass("a duplicate dispute is refused (409)");

  const notAllowed = await call(`/disputes/${disputeRow.id}/adjudicate`, "reviewer-token", {
    method: "POST",
    body: JSON.stringify({ label: { techniqueId: "T1003.001", stepId: "g1", actor: "red", outcome: "failed" } }),
  });
  assert.equal(notAllowed.status, 403);
  assert.equal((await notAllowed.json()).required_role, "operator");
  pass("a reviewer cannot adjudicate (403 names the operator role)");

  const adjudicated = await call(`/disputes/${disputeRow.id}/adjudicate`, "operator-token", {
    method: "POST",
    body: JSON.stringify({ label: { techniqueId: "T1003.001", stepId: "g1", actor: "red", outcome: "failed" } }),
  });
  assert.equal(adjudicated.status, 200);
  const adjudicatedRow = await adjudicated.json();
  assert.equal(adjudicatedRow.status, "adjudicated");
  assert.equal(adjudicatedRow.version, 2);
  pass("an operator adjudicates at version 2");

  const third = await publishRunDataset(run, { store });
  assert.notEqual(third.contentHash, first.contentHash, "an adjudication must change the snapshot hash");
  const afterThird = await sb.from("traces").select("outcome").eq("org_id", orgId).eq("run_id", runId);
  assert.equal(afterThird.data[0].outcome, "succeeded", "the raw trace is append-only; adjudication is a build-time overlay");
  pass("adjudication re-hashes the export while the raw trace stays immutable");

  // The stored snapshot itself must carry the adjudicated label.
  const hash = third.contentHash.replace(/^sha256:/, "");
  const { data: blob, error: dlError } = await sb.storage.from("datasets").download(`${orgId}/${runId}/${hash}/export.json.gz`);
  if (dlError || !blob) throw new Error(`stored export unreadable: ${dlError?.message}`);
  const storedExport = JSON.parse(await decodeObject(blob));
  assert.equal(storedExport.join.steps[0].groundTruth.outcome, "failed");
  pass("the stored snapshot contains the adjudicated label");

  const audits = await sb.from("audit_log").select("action").eq("org_id", orgId)
    .in("action", ["CORRECTION_RECORDED", "LABEL_DISPUTE_FILED", "LABEL_ADJUDICATED"]);
  const actions = new Set(audits.data.map((row) => row.action));
  for (const action of ["CORRECTION_RECORDED", "LABEL_DISPUTE_FILED", "LABEL_ADJUDICATED"]) {
    assert.ok(actions.has(action), `${action} audit entry missing`);
  }
  pass("correction, dispute and adjudication are audited");

  const signal = await call("/signals", "trainer-token", {
    method: "POST",
    body: JSON.stringify({ name: "red-actions", kind: "rule", definition: { match: "all", conditions: [{ field: "actor", op: "eq", value: "red" }] } }),
  });
  assert.equal(signal.status, 201);
  const signalRow = await signal.json();
  assert.equal(signalRow.version, 1);

  const runOnce = await call(`/signals/${signalRow.id}/run`, "trainer-token", { method: "POST", body: JSON.stringify({ runId }) });
  assert.equal(runOnce.status, 200);
  const firstRun = await runOnce.json();
  assert.equal(firstRun.hits, 1);
  const runTwice = await call(`/signals/${signalRow.id}/run`, "trainer-token", { method: "POST", body: JSON.stringify({ runId }) });
  const secondRun = await runTwice.json();
  assert.equal(secondRun.hits, 1);
  const hitCount = await sb.from("signal_hits").select("*", { count: "exact", head: true }).eq("org_id", orgId).eq("signal_id", signalRow.id);
  assert.equal(hitCount.count, 1, "re-running an unchanged signal must not duplicate hits");
  const signalsList = await (await call("/signals", "reviewer-token")).json();
  assert.equal(signalsList.signals.find((row) => row.id === signalRow.id).hits, 1);
  pass("a rule signal hits once and re-running it does not duplicate");

  // A model signal names its judge at definition time; every result pins it.
  const noJudge = await call("/signals", "trainer-token", {
    method: "POST", body: JSON.stringify({ name: "judge-dump", kind: "model", definition: { question: "did it dump?" } }),
  });
  assert.equal(noJudge.status, 400, "a model signal must name its judge");
  const judgeSignal = await call("/signals", "trainer-token", {
    method: "POST",
    body: JSON.stringify({ name: "judge-dump", kind: "model", definition: { model: "muse-spark-1.3", question: "Did the red agent read the secrets table?" } }),
  });
  assert.equal(judgeSignal.status, 201);
  const judgeRow = await judgeSignal.json();
  const { runModelSignal } = await import("../dist/learning/signals.js");
  const judge = { modelId: "muse-spark-1.3", generateObject: async () => ({ matched: true, score: 0.9, rationale: "pg_dump of the secrets table" }) };
  const judged = await runModelSignal({ orgId, signalId: judgeRow.id, runId }, { client: judge });
  assert.equal(judged.judgeModel, "muse-spark-1.3");
  const judgeHit = await sb.from("signal_hits").select("label, score").eq("org_id", orgId).eq("signal_id", judgeRow.id).single();
  assert.equal(judgeHit.data.label.model_id, "muse-spark-1.3", "the judge ID is pinned in the result");
  assert.equal(judgeHit.data.label.matched, true);
  assert.equal(judgeHit.data.score, 0.9);
  pass("a model signal pins its judge ID in every result");

  // Continual grading is opted in per signal; the capture route applies it.
  const continual = await call("/signals", "trainer-token", {
    method: "POST",
    body: JSON.stringify({ name: "continual-blue", kind: "rule", continual: true, definition: { match: "all", conditions: [{ field: "actor", op: "eq", value: "blue" }] } }),
  });
  assert.equal(continual.status, 201);
  assert.equal((await continual.json()).continual, true);

  const unpinned = await call("/graders", "trainer-token", {
    method: "POST", body: JSON.stringify({ name: "judge", kind: "model", spec: {} }),
  });
  assert.equal(unpinned.status, 400, "a model grader must name its judge model");
  const grader = await call("/graders", "trainer-token", {
    method: "POST", body: JSON.stringify({ name: "judge", kind: "model", spec: { model: "muse-spark-1.3" } }),
  });
  assert.equal(grader.status, 201);
  const graderV2 = await call("/graders", "trainer-token", {
    method: "POST", body: JSON.stringify({ name: "judge", kind: "model", spec: { model: "muse-spark-1.3" } }),
  });
  assert.equal((await graderV2.json()).version, 2);
  pass("a model grader pins its judge and versions on redefinition");

  const badProvider = await call("/models", "operator-token", {
    method: "POST",
    body: JSON.stringify({ name: "r", baseModel: "muse-spark-1.3", servedModel: "muse-spark-1.3", provider: "other-vendor", role: ["red"] }),
  });
  assert.equal(badProvider.status, 400, "the provider is a closed set");

  const badId = await call("/models", "operator-token", {
    method: "POST",
    body: JSON.stringify({ name: "r", baseModel: "muse-spark-1.3", servedModel: "unapproved-model-id", provider: "meta", role: ["red"] }),
  });
  assert.equal(badId.status, 400, "a non-Meta served model is refused");

  const registered = await call("/models", "operator-token", {
    method: "POST",
    body: JSON.stringify({ name: "red-base", baseModel: "muse-spark-1.3", servedModel: "muse-spark-1.3", provider: "meta", role: ["red"], status: "ready" }),
  });
  assert.equal(registered.status, 201);
  const model = await registered.json();
  assert.equal(model.served_model, "muse-spark-1.3");

  const resolvedRed = await (await call("/models/resolve?role=red", "reviewer-token")).json();
  assert.equal(resolvedRed.source, "registry");
  assert.equal(resolvedRed.modelId, "muse-spark-1.3");
  const resolvedBlue = await (await call("/models/resolve?role=blue", "reviewer-token")).json();
  assert.equal(resolvedBlue.source, "base", "a role without a ready model falls back to its base");
  const byRole = await (await call("/models?role=red", "reviewer-token")).json();
  assert.equal(byRole.models.length, 1);
  pass("the registry resolves a role to a verified model and fails closed on others");

  // F-14: a ready Modal-hosted row resolves to the Modal agent client (tool
  // turns verified on Spark/Glimmer), and the exercise client pair comes from
  // the registry factory rather than a direct constructor.
  const modal = await call("/models", "operator-token", {
    method: "POST",
    body: JSON.stringify({ name: "red-modal", baseModel: "muse-spark-1.3", servedModel: "meta-models/Muse-Spark-Open-816B-A42B", provider: "meta-modal", role: ["red"], status: "ready" }),
  });
  assert.equal(modal.status, 201);
  const modalRow = await modal.json();
  assert.ok(await resolveModel("red", orgId) instanceof ModalModelClient, "a ready Modal row resolves to a Modal agent client");
  await sb.from("models").delete().eq("id", modalRow.id);
  const agentClients = await resolveAgentClients(orgId);
  assert.equal(agentClients.red.modelId, model.served_model, "red resolves from the registry");
  assert.equal(agentClients.blue.modelId, baseModelFor("blue").modelId, "blue falls back to its verified base for the effective surface");
  pass("exercise agent roles build their clients through the registry, including Modal rows");

  const captureKey = newCaptureKey();
  const { error: keyError } = await sb.from("capture_keys").insert({
    org_id: orgId, name: "smoke", key_prefix: captureKey.prefix, key_hash: captureKey.hash,
  });
  if (keyError) throw new Error(`capture key insert failed: ${keyError.message}`);

  const externalRun = `${runId}-ext`;
  const body = {
    runId: externalRun, stepIndex: 0, at, hostId: "web-01", actor: "blue",
    techniqueId: "T1190", action: "isolate host", outcome: "contained",
    source: "field", framework: "field-telemetry",
    detail: { evidence: ["E1"] },
  };
  const post = (raw) => call("/capture/v1/traces", raw, { method: "POST", body: JSON.stringify(body) });

  const accepted = await post(captureKey.raw);
  assert.equal(accepted.status, 202);
  const captured = await sb.from("traces").select("id, actor, outcome, payload").eq("org_id", orgId).eq("run_id", externalRun).single();
  assert.equal(captured.data.actor, "blue");
  assert.equal(captured.data.outcome, "contained");
  assert.deepEqual(captured.data.payload.trajectory.detail.evidence, ["E1"]);
  pass("a capture key ingests an external step for its own org");

  const autoHit = await sb.from("signal_hits").select("signal_id").eq("org_id", orgId).eq("trace_id", captured.data.id);
  assert.equal(autoHit.data.length, 1, "the continual signal graded the new trace without a manual run");
  pass("an enabled continual signal grades a newly captured trace automatically");

  // Import an exported external agent run through the same capture path.
  const { toCaptureTraces } = await import("../dist/learning/external-runs.js");
  const importedRun = `${runId}-imported`;
  const imported = toCaptureTraces({
    runId: importedRun, framework: "caller-system", source: "imported",
    steps: [
      { at, host: "web-01", actor: "red", technique: "T1190", tool: "curl", command: ["curl", "-s", "http://web-01/login"], output: "HTTP/1.1 200 OK", outcome: "succeeded" },
      { at, host: "db-01", actor: "red", technique: "T1005", tool: "psql", command: "psql -h db-01 -U app -d app -tAc 'select value from secrets'", output: "s3cr3t", outcome: "succeeded" },
    ],
  });
  for (const step of imported) {
    const res = await call("/capture/v1/traces", captureKey.raw, { method: "POST", body: JSON.stringify(step) });
    assert.equal(res.status, 202);
  }
  const importedRows = await sb.from("traces").select("source, framework, action").eq("org_id", orgId).eq("run_id", importedRun).order("step_index");
  assert.deepEqual(importedRows.data.map((r) => r.source), ["imported", "imported"]);
  assert.equal(importedRows.data[0].framework, "caller-system");
  pass("an exported external agent run is imported with provenance");

  // F-7: the builder selects from real traces, applies the correction, and
  // writes separate red/blue files with the legacy red-only names intact.
  const buildBody = {
    name: "clinic-v1", family: "clinic-family", split: "train", roles: ["red", "blue"],
    runIds: [runId, externalRun, importedRun],
    sources: ["synthetic", "imported", "field"], minRealShare: 0.5,
  };
  const built = await call("/datasets", "trainer-token", { method: "POST", body: JSON.stringify(buildBody) });
  assert.equal(built.status, 201);
  const builtBody = await built.json();
  assert.equal(builtBody.counts.redSft, 3);
  assert.equal(builtBody.counts.blueSft, 1);
  assert.equal(builtBody.selection.filters.family, "clinic-family");
  assert.deepEqual(builtBody.selection.filters.runIds, [runId, externalRun, importedRun]);
  assert.deepEqual(builtBody.selection.counts.sources, { field: 1, imported: 2, synthetic: 1 });
  assert.equal(builtBody.selection.counts.realShare, 0.75);
  assert.equal(builtBody.selection.counts.realism.share, 1, "every red action uses recognisably real tooling");
  assert.deepEqual([...builtBody.sources].sort(), ["field", "imported", "synthetic"]);
  assert.ok(builtBody.selection.corrections.includes(correctionRow.id), "the applied correction is recorded");
  assert.ok(builtBody.selection.adjudications.includes(disputeRow.id), "the applied adjudication is recorded");
  pass("the builder emits red and blue snapshots and records the selection");

  const prefix = builtBody.storagePath.replace(/^datasets\//, "");
  const read = async (name) => {
    const { data, error } = await sb.storage.from("datasets").download(`${prefix}/${name}.gz`);
    if (error || !data) throw new Error(`download ${name}: ${error?.message}`);
    return decodeObject(data);
  };
  const legacyRed = await read("sft.jsonl");
  const redFile = await read("red-sft.jsonl");
  const blueFile = await read("blue-sft.jsonl");
  assert.equal(legacyRed, redFile, "the legacy red file is exactly the red file");
  assert.match(legacyRed, /pg_dump --schema-only/, "the corrected completion is exported");
  assert.equal(JSON.parse(blueFile.trim()).completion, "isolate host", "blue has its own file");
  const original = await sb.from("traces").select("action").eq("org_id", orgId).eq("run_id", runId).single();
  assert.equal(original.data.action, "pg_dump", "the original action is still readable");
  pass("corrections change the export while the trace keeps its original action");

  const again = await call("/datasets", "trainer-token", { method: "POST", body: JSON.stringify(buildBody) });
  assert.equal(again.status, 201);
  assert.equal((await again.json()).reused, true);
  const same = await sb.from("datasets").select("*", { count: "exact", head: true }).eq("org_id", orgId).eq("content_hash", builtBody.contentHash);
  assert.equal(same.count, 1, "the same content reuses its row");
  pass("re-building the same selection reuses the snapshot");

  const collision = await call("/datasets", "trainer-token", { method: "POST", body: JSON.stringify({ ...buildBody, split: "test" }) });
  assert.equal(collision.status, 409);
  pass("a scenario family cannot straddle train and test");

  const filtered = await call("/datasets", "trainer-token", {
    method: "POST",
    body: JSON.stringify({ name: "filtered", family: "clinic-filtered", split: "train", roles: ["red"], signalId: signalRow.id, correctionKind: "edit" }),
  });
  assert.equal(filtered.status, 201);
  const filteredBody = await filtered.json();
  assert.equal(filteredBody.counts.traces, 1);
  assert.equal(filteredBody.counts.redSft, 1);
  assert.equal(filteredBody.counts.blueSft, 0);
  pass("selection filters by signal hit and correction kind");

  const listed = await (await call("/datasets", "reviewer-token")).json();
  const listedMain = listed.datasets.find((d) => d.contentHash === builtBody.contentHash);
  assert.equal(listedMain.family, "clinic-family");
  assert.equal(listedMain.split, "train");
  assert.equal(listedMain.leakage, "clear");
  assert.deepEqual([...listedMain.roles].sort(), ["blue", "red"]);
  assert.deepEqual([...listedMain.sources].sort(), ["field", "imported", "synthetic"]);
  pass("the dataset list exposes hashes, roles, sources and leakage status");

  const tooSynthetic = await call("/datasets", "trainer-token", {
    method: "POST",
    body: JSON.stringify({ name: "too-synthetic", family: "clinic-too-synthetic", split: "train", roles: ["red"], sources: ["synthetic"], minRealShare: 0.5 }),
  });
  assert.equal(tooSynthetic.status, 422, "a real-share floor refuses a synthetic-only snapshot");
  pass("a minimum real-share gate refuses synthetic-only data");

  const fieldOnly = await call("/datasets", "trainer-token", {
    method: "POST",
    body: JSON.stringify({ name: "field-only", family: "clinic-field", split: "train", roles: ["red", "blue"], sources: ["field"] }),
  });
  assert.equal(fieldOnly.status, 201);
  const fieldBody = await fieldOnly.json();
  assert.deepEqual(fieldBody.sources, ["field"]);
  assert.equal(fieldBody.counts.blueSft, 1);
  assert.equal(fieldBody.counts.redSft, 0);
  pass("a source filter selects only that provenance");

  const foreignTenant = await call("/capture/v1/traces", captureKey.raw, {
    method: "POST", body: JSON.stringify({ ...body, runId: `${externalRun}-x`, orgId: "org-other" }),
  });
  assert.equal(foreignTenant.status, 400, "the strict contract rejects a body tenant field");
  pass("a capture body cannot claim another org");

  await sb.from("capture_keys").update({ revoked_at: new Date().toISOString() }).eq("key_hash", captureKey.hash);
  const denied = await post(captureKey.raw);
  assert.equal(denied.status, 401);
  const audited = await sb.from("audit_log").select("action").eq("org_id", orgId).eq("action", "CAPTURE_KEY_REJECTED");
  assert.ok(audited.data.length >= 1, "a revoked key's use is audited");
  pass("a revoked key is refused and audited");

  // ---- CRUD lifecycle (update/edit/delete closure) ----

  // Datasets: rename, archive, restore. The immutable snapshot keeps its hash.
  const builtDatasetId = fieldBody.datasetId;
  const renamed = await call(`/datasets/${builtDatasetId}`, "trainer-token", {
    method: "PATCH", body: JSON.stringify({ name: "field-renamed" }),
  });
  assert.equal(renamed.status, 200);
  assert.equal((await renamed.json()).name, "field-renamed");
  const hashBefore = await sb.from("datasets").select("content_hash").eq("id", builtDatasetId).single();
  assert.equal(hashBefore.data.content_hash, fieldBody.contentHash, "a rename never moves the content hash");

  const renameRefused = await call(`/datasets/${builtDatasetId}`, "reviewer-token", {
    method: "PATCH", body: JSON.stringify({ name: "nope" }),
  });
  assert.equal(renameRefused.status, 403, "a reviewer cannot edit datasets");
  pass("datasets: rename is a trainer action and never rehashes the snapshot");

  const archived = await call(`/datasets/${builtDatasetId}?action=archive`, "trainer-token", { method: "PATCH", body: "{}" });
  assert.equal(archived.status, 200);
  assert.ok((await archived.json()).archivedAt, "archiving stamps archived_at");
  const activeList = await (await call("/datasets", "reviewer-token")).json();
  assert.ok(!activeList.datasets.some((d) => d.id === builtDatasetId), "an archived snapshot leaves the active list");
  const withArchived = await (await call("/datasets?archived=1", "reviewer-token")).json();
  assert.ok(withArchived.datasets.some((d) => d.id === builtDatasetId && d.archivedAt), "archived=1 still lists it");
  const restored = await call(`/datasets/${builtDatasetId}?action=restore`, "trainer-token", { method: "PATCH", body: "{}" });
  assert.equal(restored.status, 200);
  assert.equal((await restored.json()).archivedAt, null);
  const restoreAgain = await call(`/datasets/${builtDatasetId}?action=restore`, "trainer-token", { method: "PATCH", body: "{}" });
  assert.equal(restoreAgain.status, 409, "restoring a non-archived snapshot is a conflict, not a server error");
  pass("datasets: archive hides from builders, restore brings it back");

  // Models: metadata edit and the deprecate guard.
  const modelList = await (await call("/models", "reviewer-token")).json();
  const smokeModel = modelList.models.find((m) => m.name === "red-base");
  const modelPatched = await call(`/models/${smokeModel.id}`, "operator-token", {
    method: "PATCH", body: JSON.stringify({ metrics: { winRate: 0.61 } }),
  });
  assert.equal(modelPatched.status, 200);
  assert.equal((await modelPatched.json()).metrics.winRate, 0.61);
  const statusRefused = await call(`/models/${smokeModel.id}`, "operator-token", {
    method: "PATCH", body: JSON.stringify({ status: "ready" }),
  });
  assert.equal(statusRefused.status, 409, "readiness is earned by a training run, never set by hand");
  assert.match((await statusRefused.json()).error, /training pipeline/);
  pass("models: metadata edits apply; manual status changes are refused");

  // Signals: toggle in place, delete removes hits.
  const toggleList = await (await call("/signals", "reviewer-token")).json();
  const judgeDump = toggleList.signals.find((s) => s.name === "judge-dump");
  const disabled = await call(`/signals/${judgeDump.id}`, "trainer-token", {
    method: "PATCH", body: JSON.stringify({ enabled: false }),
  });
  assert.equal(disabled.status, 200);
  assert.equal((await disabled.json()).enabled, false);
  const reEnabled = await call(`/signals/${judgeDump.id}`, "trainer-token", {
    method: "PATCH", body: JSON.stringify({ enabled: true }),
  });
  assert.equal((await reEnabled.json()).enabled, true);
  const defEdited = await call(`/signals/${judgeDump.id}`, "trainer-token", {
    method: "PATCH", body: JSON.stringify({ definition: { model: "muse-spark-1.3", question: "Did the agent exfiltrate the table?" } }),
  });
  assert.equal(defEdited.status, 200);
  const editedRow = await defEdited.json();
  assert.equal(editedRow.version, judgeDump.version + 1, "a changed definition mints the next version");
  const supersededRow = await sb.from("signals").select("enabled").eq("id", judgeDump.id).single();
  assert.equal(supersededRow.data.enabled, false, "the superseded version is disabled so continual grading cannot double-apply");
  pass("signals: enable/disable is in place; a changed definition re-versions and supersedes");

  const graderList = await (await call("/graders", "reviewer-token")).json();
  const judgeGrader = graderList.graders.find((g) => g.name === "judge" && g.version === 1);
  const graderDisabled = await call(`/graders/${judgeGrader.id}`, "trainer-token", {
    method: "PATCH", body: JSON.stringify({ enabled: false }),
  });
  assert.equal(graderDisabled.status, 200);
  assert.equal((await graderDisabled.json()).enabled, false);
  const graderGone = await call(`/graders/${judgeGrader.id}`, "trainer-token", { method: "DELETE" });
  assert.equal(graderGone.status, 200);
  const graderAfter = await (await call("/graders", "reviewer-token")).json();
  assert.ok(!graderAfter.graders.some((g) => g.id === judgeGrader.id), "a deleted grader is gone");
  const graderV2Row = graderAfter.graders.find((g) => g.name === "judge" && g.version === 2);
  const graderSpecEdited = await call(`/graders/${graderV2Row.id}`, "trainer-token", {
    method: "PATCH", body: JSON.stringify({ spec: { model: "muse-spark-1.3", rubric: " stricter" } }),
  });
  assert.equal(graderSpecEdited.status, 200);
  const supersededGrader = await sb.from("graders").select("enabled").eq("id", graderV2Row.id).single();
  assert.equal(supersededGrader.data.enabled, false, "the superseded grader version is disabled");
  pass("graders: disable and delete work; a changed spec re-versions and supersedes");

  // Traces: synthetic tombstones, imported evidence refused.
  const traceList = await (await call("/traces?runId=" + runId, "reviewer-token")).json();
  const syntheticTrace = traceList.traces.find((t) => t.id === traceId);
  const traceDeleted = await call(`/traces/${syntheticTrace.id}`, "operator-token", { method: "DELETE" });
  assert.equal(traceDeleted.status, 200);
  const traceRow = await sb.from("traces").select("tombstoned_at, action").eq("id", syntheticTrace.id).single();
  assert.ok(traceRow.data.tombstoned_at, "deletion tombstones rather than removing the chained row");
  assert.equal(traceRow.data.action, "pg_dump", "the raw trace payload is untouched");
  const restoredTrace = await call(`/traces/${syntheticTrace.id}/restore`, "operator-token", { method: "PATCH", body: "{}" });
  assert.equal(restoredTrace.status, 200);
  const traceRow2 = await sb.from("traces").select("tombstoned_at").eq("id", syntheticTrace.id).single();
  assert.equal(traceRow2.data.tombstoned_at, null, "restore clears the tombstone");
  pass("traces: delete tombstones the chained row and restore undoes it");

  const externalTraces = await sb.from("traces").select("id").eq("org_id", orgId).eq("source", "imported").limit(1);
  if (externalTraces.data.length > 0) {
    const refused = await call(`/traces/${externalTraces.data[0].id}`, "operator-token", { method: "DELETE" });
    assert.equal(refused.status, 409, "imported evidence cannot be deleted");
    assert.match((await refused.json()).error, /imported/);
    pass("traces: imported provenance is refused deletion");
  }

  // Runs: delete tombstones traces and removes the runs row; the chain stays verifiable.
  const runDeleted = await call(`/runs/${runId}`, "operator-token", { method: "DELETE" });
  assert.equal(runDeleted.status, 200);
  const tracesAfter = await sb.from("traces").select("id, tombstoned_at").eq("org_id", orgId).eq("run_id", runId);
  assert.equal(tracesAfter.data.filter((t) => t.tombstoned_at).length, tracesAfter.data.length, "run deletion tombstones all of the run's traces");
  const runAudit = await sb.from("audit_log").select("action").eq("org_id", orgId).eq("action", "RUN_DELETED");
  assert.ok(runAudit.data.length >= 1, "run deletion is audited");
  const chain = await sb.rpc("trace_chain_verify", { p_org: orgId, p_run: runId });
  assert.equal(chain.error, null, "the hash chain still verifies after curation");
  assert.equal(chain.data.length, 0, "no broken links after tombstoning");
  pass("runs: delete tombstones the run's traces and the hash chain stays intact");
} finally {
  await new Promise((resolve) => server.close(resolve));
}

// No physical cleanup: each run owns its unique org, and traces, corrections,
// disputes and audit entries are append-only by design. Only mutable registry
// rows that would collide on (org, name) unique constraints are removed — and
// since the org is unique per run, nothing collides.
console.log(JSON.stringify({ ok: true, orgId, runId, checks }, null, 2));

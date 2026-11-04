/**
 * Full workflow run on VMs (T-18 remainder): the clinic org through the real
 * Temporal workflow, not component by component.
 *
 *   node scripts/vm-workflow.mjs
 *
 * Preconditions: platform up (`npm run up -w deployment`), the backend worker
 * running (`node dist/worker.js`), and Supabase creds in ../.env.
 *
 * Inserts an approved environment + pending deployment, lets the worker's
 * trigger claim it, then verifies the whole lifecycle the workflow performs:
 * deploy (Pulumi gate + 6 QEMU guests) → configure over SSH → readiness →
 * canaries/proof → live-vm exercise → dataset in Storage (hash re-verified) →
 * score row → TTL teardown. Exits non-zero on the first broken claim and
 * always tears the run down.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { Client, Connection } from "@temporalio/client";
import { createClient } from "@supabase/supabase-js";
import { clinicOrgSpec, clinicOrgSpecWithAttacker } from "../dist/designer/clinic.js";
import { digestOf } from "../dist/designer/pipeline.js";
import { planDeployment } from "../dist/configurator/plan.js";
import { digestOfSpec } from "../dist/lib/digest.js";

const root = new URL("../../", import.meta.url).pathname;
for (const f of ["deployment/.platform.env", ".env"]) {
  if (!existsSync(root + f)) continue;
  for (const l of readFileSync(root + f, "utf8").split("\n").filter((x) => x.includes("="))) {
    const i = l.indexOf("=");
    process.env[l.slice(0, i).trim()] ??= l.slice(i + 1).trim();
  }
}
// Stack passphrases come from the environment plane (deploy.ts), the same
// source the worker uses. A script-local override creates stacks the worker
// cannot decrypt, which is exactly how a destroyed stack reported a passphrase
// failure after its resources were already gone.

const ORG = "vm-workflow-org";
// --agents runs the model loops, which need the attacker guest and several
// minutes; the TTL timer is already proven on the scripted path.
const AGENTS = process.argv.includes("--agents");
// TTL is a deadline from deployment start (not hold time after scoring), so it
// must exceed the run: the scripted run holds for the remainder and is torn
// down by the workflow's own timer; the agent run is cancelled after checks.
const ttlOverrideHours = Number(process.env.VM_WORKFLOW_TTL_HOURS);
const TTL_HOURS = Number.isFinite(ttlOverrideHours) && ttlOverrideHours > 0
  ? ttlOverrideHours
  : AGENTS ? 0.3 : 0.08;
const readyOverrideMs = Number(process.env.VM_WORKFLOW_READY_TIMEOUT_MS);
const READY_TIMEOUT_MS = Number.isFinite(readyOverrideMs) && readyOverrideMs > 0
  ? readyOverrideMs
  : AGENTS ? 15 * 60_000 : 5 * 60_000;
const TARGET_WORKER_ID = process.env.MUSEARENA_TARGET_WORKER_ID?.trim() || undefined;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// The row now keeps its failure after teardown; report that, not a timeout.
const failureOf = (d) => {
  const f = d.access_info?.failure;
  if (!f && d.status !== "failed") return null;
  return `[${f?.stage ?? d.status}] ${f?.error ?? d.access_info?.error ?? "no failure detail"}`;
};
const buildSpec = () => (AGENTS ? clinicOrgSpecWithAttacker({ ttlHours: TTL_HOURS }) : clinicOrgSpec({ ttlHours: TTL_HOURS }));
const spec = buildSpec();
const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, { auth: { persistSession: false } });

const t0 = Date.now();
const lap = () => `${((Date.now() - t0) / 1000).toFixed(0)}s`;

async function deployment(id) {
  const { data, error } = await sb.from("deployments").select("status, access_info, stack_id").eq("id", id).single();
  if (error) throw new Error(`deployment read failed: ${error.message}`);
  return data;
}

/** Poll until `done` returns a value, or the deadline passes. */
async function until(label, deadlineMs, done) {
  for (let waited = 0; waited < deadlineMs; waited += 2000) {
    const v = await done();
    if (v !== undefined && v !== null) return v;
    await sleep(2000);
  }
  throw new Error(`timeout waiting for ${label}`);
}

let dep = null;
let primaryError = null;
try {
  assert.deepEqual(digestOf(spec), digestOf(buildSpec()), "spec is deterministic");

  const planDigest = digestOfSpec(planDeployment(spec));
  const { data: env, error: envErr } = await sb.from("environments")
    .insert({ org_id: ORG, created_by: "vm-workflow-smoke", spec, spec_digest: digestOf(spec), status: "approved" })
    .select("id").single();
  if (envErr) throw new Error(`environment insert failed: ${envErr.message}`);

  const { data: row, error: depErr } = await sb.from("deployments")
    .insert({ org_id: ORG, environment_id: env.id, stack_id: "pending", status: "pending", access_info: { planDigest, ...(TARGET_WORKER_ID ? { workerId: TARGET_WORKER_ID } : {}) } })
    .select("id").single();
  if (depErr) throw new Error(`deployment insert failed: ${depErr.message}`);
  dep = row.id;
  const workflowRunId = `run-${dep}`;
  console.log(`[${lap()}] deployment ${dep} pending (org ${ORG}, ${spec.instances.length} guests, ttl ${TTL_HOURS}h${TARGET_WORKER_ID ? `, worker ${TARGET_WORKER_ID}` : ""})`);

  // The worker claims it on its 15s poll; provisioning starts after that.
  await until("workflow to claim the deployment", 90_000, async () => {
    const d = await deployment(dep);
    if (d.status === "failed") throw new Error(`rejected before deploy: ${JSON.stringify(d.access_info)}`);
    return d.status !== "pending" ? d.status : null;
  });
  console.log(`[${lap()}] claimed by the workflow`);

  // `ready` is now written only after configure + readiness + gates + scoring.
  const ready = await until("deployment ready", READY_TIMEOUT_MS, async () => {
    const d = await deployment(dep);
    const why = failureOf(d);
    if (why) throw new Error(`run failed: ${why}`);
    return d.status === "ready" ? d : null;
  });
  if (TARGET_WORKER_ID) assert.equal(ready.access_info?.workerId, TARGET_WORKER_ID, `deployment owner is ${TARGET_WORKER_ID}`);
  const outputs = ready.access_info?.outputs ?? {};
  for (const inst of spec.instances) {
    assert.match(outputs[inst.hostId] ?? "", /^vm:/, `${inst.hostId} is a real guest (outputs ${JSON.stringify(outputs)})`);
  }
  console.log(`[${lap()}] ready: ${spec.instances.map((i) => `${i.hostId}=${outputs[i.hostId]}`).join(" ")}`);


  // Exercise publishes the dataset and writes the score row.
  const ds = await until("dataset in Storage", 6 * 60_000, async () => {
    const d = await deployment(dep);
    const why = failureOf(d);
    if (why) throw new Error(`run failed: ${why}`);
    // A retried exercise publishes a second dataset; the newest is the run's.
    const { data } = await sb.from("datasets").select("content_hash, storage_path")
      .like("name", `${workflowRunId}%`).order("created_at", { ascending: false }).limit(1).maybeSingle();
    return data ?? null;
  });
  console.log(`[${lap()}] dataset ${ds.content_hash.slice(0, 23)}…`);

  const { data: run } = await sb.from("runs").select("score, mode, backend").eq("run_id", workflowRunId).single();
  assert.equal(run?.backend, "kvm", `run backend is kvm (got ${run?.backend})`);
  // `runs.mode` is the run mode (blind); the executor is recorded on the audit row.
  const { data: audits } = await sb.from("audit_log").select("detail")
    .eq("org_id", ORG).eq("action", "SCORE_COMPUTED").eq("subject_id", workflowRunId);
  const executorMode = AGENTS ? "agents-maas-vm" : "live-vm";
  assert.ok((audits ?? []).some((a) => a.detail?.mode === executorMode),
    `SCORE_COMPUTED audit shows the ${executorMode} executor (got ${JSON.stringify((audits ?? []).map((a) => a.detail?.mode))})`);
  if (AGENTS) {
    const a = (audits ?? []).find((x) => x.detail?.mode === "agents-maas-vm");
    assert.ok(a.detail.modelIds?.red && a.detail.modelIds?.blue, `model ids recorded (${JSON.stringify(a.detail.modelIds)})`);
    assert.equal(a.detail.transport, "lab-attacker-guest", `transport recorded (${a.detail.transport})`);
    assert.equal(typeof a.detail.guardrails?.rejected, "number", "guardrail counters recorded");
  }
  assert.ok((audits ?? []).some((a) => a.detail?.langfuseEvents > 0),
    `SCORE_COMPUTED audit records Langfuse spans (got ${JSON.stringify((audits ?? []).map((a) => a.detail?.langfuseEvents))})`);
  // A model run is evidence of the loop, not a solvability claim; the scripted
  // baseline proves solvability separately.
  if (!AGENTS) {
    assert.equal(run.score.objectivesAchieved, spec.objectives.length, `objectives ${JSON.stringify(run.score)}`);
    assert.equal(run.score.pointsEarned, spec.objectives.reduce((a, o) => a + o.points, 0));
  }
  assert.equal(run.score.falsePositiveRate, 0, `false positives: ${run.score.falsePositiveRate}`);
  console.log(`[${lap()}] score ${run.score.objectivesAchieved}/${run.score.objectivesTotal} · ${run.score.pointsEarned}/${run.score.pointsTotal} points · executor ${executorMode}`);

  // Verify the stored object, not the in-memory export.
  const { decodeObject, GZ } = await import("../dist/observability/dataset-object.js");
  const { verifyExportHash } = await import("../dist/traces/integrity.js");
  const { data: blob, error: dlErr } = await sb.storage.from("datasets").download(`${ds.storage_path.replace(/^datasets\//, "")}/export.json${GZ}`);
  if (dlErr || !blob) throw new Error(`stored dataset unreadable: ${dlErr?.message}`);
  const exp = JSON.parse(await decodeObject(blob));
  assert.equal(exp.meta.runId, workflowRunId);
  assert.equal(exp.meta.contentHash, ds.content_hash, "stored hash matches the datasets row");
  assert.equal(verifyExportHash(exp), true, "stored export hash verifies");
  console.log(`[${lap()}] stored dataset verified: ${exp.join.steps.length} steps`);

  // Ingestion is asynchronous (worker → ClickHouse): poll briefly, as e2e.mjs does.
  const { langfuseConfig, langfuseTraceSpans } = await import("../dist/observability/langfuse.js");
  const lf = langfuseConfig();
  if (!lf) throw new Error("LANGFUSE_* not set; cannot verify the VM trace");
  let spans = 0;
  for (let i = 0; i < 20 && spans === 0; i++) { spans = await langfuseTraceSpans(lf, workflowRunId); if (!spans) await sleep(2000); }
  assert.ok(spans > 0, "Langfuse holds spans for this run");
  console.log(`[${lap()}] langfuse spans ${spans} for ${workflowRunId}`);

  // Drift observation runs the readiness probes over SSH against the live
  // registry. Status `ready` only means deployed, so observe after the
  // exercise has completed, when every configured service should be up.
  const { observeVmState } = await import("../dist/ops/maintenance.js");
  const { detectDrift } = await import("../dist/ops/drift.js");
  const observed = await observeVmState(spec, workflowRunId);
  const driftedNow = detectDrift(spec, observed).filter((d) => d.drifted);
  // Containment has blast radius: blue may isolate a host other services
  // depend on (directory, gateway), and those dependents then legitimately
  // stop answering. That drift is the exercise working, not a configure
  // regression — but it must be explained by a recorded isolation, never
  // waved through. Unexplained drift still fails the run.
  const isolated = new Set((audits ?? []).flatMap((a) => (a.detail?.enforcement ?? [])
    .filter((e) => e.enforced && e.response === "isolate host").map((e) => e.hostId)));
  const depsOf = new Map(spec.instances.map((i) => [i.hostId, i.dependsOn ?? []]));
  const reachesIsolated = (hostId, seen = new Set()) => {
    if (seen.has(hostId)) return false;
    seen.add(hostId);
    return (depsOf.get(hostId) ?? []).some((d) => isolated.has(d) || reachesIsolated(d, seen));
  };
  const explained = driftedNow.filter((d) => isolated.has(d.hostId) || reachesIsolated(d.hostId));
  const unexplained = driftedNow.filter((d) => !explained.includes(d));
  if (explained.length) {
    console.log(`[${lap()}] drift explained by containment (isolated: ${[...isolated].join(", ")}): ${explained.map((d) => `${d.hostId} missing ${d.missingServices.join("+")}`).join(" ")}`);
  }
  assert.deepEqual(unexplained, [], `configured guests are in sync apart from containment: ${JSON.stringify(unexplained)}`);
  console.log(`[${lap()}] drift in-sync: ${observed.map((o) => `${o.hostId}=${o.services.join("+") || "-"}`).join(" ")}`);

  if (AGENTS) {
    // TTL teardown is covered by the scripted run. Cancel (not terminate):
    // cancellation runs the workflow's non-cancellable teardown; terminate
    // kills the workflow with no cleanup and leaves only the TTL sweeper.
    const client = new Client({ connection: await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? "localhost:7233" }) });
    await client.workflow.getHandle(`deployment-${dep}`).cancel().catch(() => undefined);
    await until("teardown after cancel", 3 * 60_000, async () => (await deployment(dep)).status === "destroyed" ? "destroyed" : null);
    console.log(`[${lap()}] destroyed after cancel (agent run)`);
    const leaked = await new Promise((resolve) => {
      execFile("pgrep", ["-f", `musearena-${workflowRunId}-`], (e, out) => resolve(!e && out.trim().length > 0));
    });
    assert.equal(leaked, false, "no QEMU process survives teardown");
    console.log(`[${lap()}] no leaked QEMU`);
    console.log("VM WORKFLOW OK (agents)");
    throw { handled: true };
  }

  // The workflow's own TTL timer must destroy the guests; the script does not.
  // The timer starts at deployment start, so wait for the remaining TTL (plus
  // teardown time), not a fixed six minutes from the post-ready checks.
  const ttlTeardownWaitMs = Math.max(60_000, t0 + TTL_HOURS * 3_600_000 - Date.now() + 3 * 60_000);
  await until("TTL teardown", ttlTeardownWaitMs, async () => {
    const d = await deployment(dep);
    if (d.status === "failed") throw new Error(`run failed before TTL: ${failureOf(d)}`);
    return d.status === "destroyed" ? "destroyed" : null;
  });
  console.log(`[${lap()}] destroyed by the workflow TTL timer`);

  const leaked = await new Promise((resolve) => {
    execFile("pgrep", ["-f", `musearena-${workflowRunId}-`], (e, out) => resolve(!e && out.trim().length > 0));
  });
  assert.equal(leaked, false, "no QEMU process survives the TTL teardown");
  console.log(`[${lap()}] no leaked QEMU`);
  console.log("VM WORKFLOW OK");
} catch (err) {
  if (!(err && err.handled)) {
    primaryError = err;
    console.error("VM WORKFLOW FAILURE:", err instanceof Error ? err.message : err);
  }
} finally {
  if (dep) {
    const d = await deployment(dep).catch(() => null);
    if (d && d.status !== "destroyed" && d.access_info?.resourcesDestroyed !== true) {
      console.log(`cleanup: deployment is ${d.status}; terminating and tearing down`);
      const runIdForDep = `run-${dep}`;
      try {
        const client = new Client({ connection: await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? "localhost:7233" }) });
        await client.workflow.getHandle(`deployment-${dep}`).terminate("vm-workflow smoke cleanup");
      } catch (e) {
        console.error(`cleanup: workflow terminate failed: ${e instanceof Error ? e.message : e}`);
      }
      const { teardownEnvironment } = await import("../dist/provisioner/deploy.js");
      // Preserve a recorded failure: cleanup removes resources, it does not
      // get to rewrite the run's outcome as a clean teardown.
      const failure = d.access_info?.failure;
      await teardownEnvironment({
        deploymentId: dep, orgId: ORG, spec, runId: runIdForDep,
        stackName: (d.stack_id ?? "").split("/").pop() || `dev-${dep.slice(0, 8)}`,
        ...(failure ? { outcome: { status: "failed", failure } } : {}),
      }).catch((e) => console.error(`cleanup: teardown failed: ${e instanceof Error ? e.message : e}`));
    }
  }
}
if (primaryError) process.exit(1);

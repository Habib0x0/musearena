/**
 * Cold reproduction (T-13 acceptance): take a PREVIOUS deployment's stored
 * EnvironmentSpec (Supabase, by digest) and nothing else, insert a fresh
 * deployment of it, let the worker run the whole lifecycle, then check:
 *   - same spec digest as the source
 *   - exported dataset hash verifies; zero proof/noise rows
 *   - every row accounted: steps = matched + trajectoryOnly + groundTruthOnly,
 *     and dropped == sum(dropReasons) (no unexplained drops)
 *   - same objectives achieved as the source run
 *     node scripts/cold-repro.mjs <source-deployment-id>
 */
import { readFileSync, existsSync } from "node:fs";
import { createClient } from "@supabase/supabase-js";
import { Client, Connection } from "@temporalio/client";
import { digestOfSpec } from "../dist/lib/digest.js";
import { pinForSpec, pinnedDesignDigest } from "../dist/designer/archetypes.js";
import { planDeployment } from "../dist/configurator/plan.js";
import { verifyExportHash, assertNoProofRows } from "../dist/traces/integrity.js";

const root = new URL("../../", import.meta.url).pathname;
for (const f of ["deployment/.platform.env", ".env"]) if (existsSync(root + f)) for (const l of readFileSync(root + f, "utf8").split("\n").filter((x) => x.includes("="))) { const i = l.indexOf("="); process.env[l.slice(0, i).trim()] ??= l.slice(i + 1).trim(); }
if (!process.env.PULUMI_PASSPHRASE && existsSync("/tmp/musearena-smoke-passphrase")) process.env.PULUMI_PASSPHRASE = readFileSync("/tmp/musearena-smoke-passphrase", "utf8").trim();
const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, { auth: { persistSession: false } });
const src = process.argv[2];
if (!src) { console.error("usage: cold-repro.mjs <source-deployment-id>"); process.exit(2); }

const { data: srcDep, error } = await sb.from("deployments").select("id, org_id, access_info, environments(spec, spec_digest)").eq("id", src).single();
if (error) { console.error(error.message); process.exit(1); }
const spec = srcDep.environments.spec;
if (digestOfSpec(spec) !== srcDep.environments.spec_digest) { console.error("stored spec does not match its digest"); process.exit(1); }
const { data: srcRun } = await sb.from("runs").select("score").eq("run_id", `run-${src}`).single();

const planDigest = digestOfSpec(planDeployment(spec));
const { data: env } = await sb.from("environments").insert({ org_id: srcDep.org_id, created_by: "cold-repro", spec, spec_digest: srcDep.environments.spec_digest, status: "approved" }).select("id").single();
const targetWorkerId = process.env.MUSEARENA_TARGET_WORKER_ID?.trim() || srcDep.access_info?.workerId || undefined;
const { data: dep } = await sb.from("deployments").insert({ org_id: srcDep.org_id, environment_id: env.id, stack_id: "pending", status: "pending", access_info: { planDigest, ...(targetWorkerId ? { workerId: targetWorkerId } : {}) } }).select("id").single();
const runId = `run-${dep.id}`;
console.log("source", src, "→ fresh", dep.id);

let ds = null;
for (let i = 0; i < 100 && !ds; i++) { ds = (await sb.from("datasets").select("content_hash, storage_path").like("name", `${runId}%`).maybeSingle()).data; if (!ds) await new Promise((r) => setTimeout(r, 5000)); }
if (!ds) { console.error("TIMEOUT: no dataset for fresh run"); process.exit(1); }
const temporal = new Client({ connection: await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? "localhost:7233" }) });
const h = temporal.workflow.getHandle(`deployment-${dep.id}`);
await h.terminate("cold repro verified; tearing down").catch(() => {});
const { data: newRun } = await sb.from("runs").select("score, spec_digest").eq("run_id", runId).single();
const { decodeObject, GZ } = await import("../dist/observability/dataset-object.js");
const { data: blob } = await sb.storage.from("datasets").download(`${ds.storage_path.replace(/^datasets\//, "")}/export.json${GZ}`);
const exp = JSON.parse(await decodeObject(blob));
const j = exp.join;
const sumReasons = Object.values(j.dropReasons ?? {}).reduce((a, b) => a + b, 0);
const checks = {
  // Runs carry the pinned design digest (spec + producing versions, T-17);
  // the environment row keeps the bare spec digest.
  pinnedDigest: newRun.spec_digest === pinnedDesignDigest(spec, pinForSpec(spec)),
  hashVerifies: verifyExportHash(exp) && exp.meta.contentHash === ds.content_hash,
  noProofRows: assertNoProofRows(exp),
  allRowsAccounted: j.steps.length === j.matched + j.trajectoryOnly + j.groundTruthOnly,
  noUnexplainedDrops: j.dropped === sumReasons,
  sameObjectives: newRun.score.objectivesAchieved === srcRun.score.objectivesAchieved,
};
console.log(JSON.stringify({ join: { steps: j.steps.length, matched: j.matched, trajectoryOnly: j.trajectoryOnly, groundTruthOnly: j.groundTruthOnly, dropped: j.dropped, dropReasons: j.dropReasons }, objectives: `${newRun.score.objectivesAchieved}/${newRun.score.objectivesTotal}`, checks }, null, 1));
// teardown via the real destroy path
const { teardownEnvironment } = await import("../dist/provisioner/deploy.js");
const { data: d2 } = await sb.from("deployments").select("stack_id").eq("id", dep.id).single();
if (d2.stack_id?.startsWith("musearena-env/dev-")) await teardownEnvironment({ deploymentId: dep.id, orgId: srcDep.org_id, stackName: d2.stack_id.split("/").pop(), spec, runId });
const ok = Object.values(checks).every(Boolean);
console.log(ok ? "COLD REPRO OK" : "COLD REPRO FAILED");
process.exit(ok ? 0 : 1);

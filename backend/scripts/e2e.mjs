/**
 * Prompt-to-dataset loop (T-9, local runtime): natural-language prompt ->
 * Meta designer -> approved environment + pending deployment (exactly what
 * the frontend does) -> worker trigger -> CrossGuard -> deploy -> Ansible ->
 * canary/proof gates -> live red/blue -> score -> dataset in Storage ->
 * Langfuse trace -> teardown.
 *     node scripts/e2e.mjs "prompt text"
 */
import { readFileSync, existsSync } from "node:fs";
import { createClient } from "@supabase/supabase-js";
import { Client, Connection } from "@temporalio/client";

const root = new URL("../../", import.meta.url).pathname;
for (const f of ["deployment/.platform.env", ".env"]) if (existsSync(root + f)) for (const l of readFileSync(root + f, "utf8").split("\n").filter((x) => x.includes("="))) { const i = l.indexOf("="); process.env[l.slice(0, i).trim()] ??= l.slice(i + 1).trim(); }
// No script-local Pulumi passphrase: teardown must decrypt with the
// environment plane's persisted passphrase, exactly like the worker.
const { designerModelClient } = await import("../dist/lib/model.js");
const { orchestrateDesign } = await import("../dist/designer/orchestrator.js");
const { langfuseConfig, langfuseTraceSpans } = await import("../dist/observability/langfuse.js");
const { verifyExportHash } = await import("../dist/traces/integrity.js");

const prompt = process.argv[2] ?? "small company intranet: vulnerable PHP web app and a Postgres database with weak credentials, two employees";
const ORG = "e2e-org";
const t0 = Date.now();
const lap = () => `${((Date.now() - t0) / 1000).toFixed(1)}s`;
const designer = designerModelClient();
if (!designer) throw new Error("no designer model configured — set MODAL_PROXY_TOKEN_ID/MODAL_PROXY_TOKEN_SECRET or META_API_KEY");
const pkg = await orchestrateDesign(designer, prompt, { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 });
console.log(`[${lap()}] designed: ${pkg.spec.instances.map((i) => `${i.hostId}/${i.role}`).join(", ")} · vulns ${pkg.spec.plantedVulns.map((v) => `${v.type}@${v.targetHostId}`).join(", ")} · canProvision=${pkg.canProvision}`);
if (!pkg.canProvision) { console.error("blocked:", pkg.blockReasons); process.exit(1); }

const TARGET_WORKER_ID = process.env.MUSEARENA_TARGET_WORKER_ID?.trim() || undefined;
const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, { auth: { persistSession: false } });
const { data: env } = await sb.from("environments").insert({ org_id: ORG, created_by: "e2e", spec: pkg.spec, spec_digest: pkg.digest, status: "approved" }).select("id").single();
const { data: dep } = await sb.from("deployments").insert({ org_id: ORG, environment_id: env.id, stack_id: "pending", status: "pending", access_info: { planDigest: pkg.planDigest, ...(TARGET_WORKER_ID ? { workerId: TARGET_WORKER_ID } : {}) } }).select("id").single();
const runId = `run-${dep.id}`;
console.log(`[${lap()}] deployment ${dep.id} pending`);

let ds = null; let last = "";
for (let i = 0; i < 120 && !ds; i++) {
  const { data: d } = await sb.from("deployments").select("status, access_info").eq("id", dep.id).single();
  if (d.status !== last) { console.log(`[${lap()}] status ${d.status}`); last = d.status; }
  if (d.status === "failed") { console.error("FAILED:", JSON.stringify(d.access_info)); process.exit(1); }
  ds = (await sb.from("datasets").select("content_hash, storage_path").like("name", `${runId}%`).maybeSingle()).data;
  if (!ds) await new Promise((r) => setTimeout(r, 3000));
}
if (!ds) { console.error("TIMEOUT"); process.exit(1); }
const { data: run } = await sb.from("runs").select("score").eq("run_id", runId).single();
const { decodeObject, GZ } = await import("../dist/observability/dataset-object.js");
const { data: blob } = await sb.storage.from("datasets").download(`${ds.storage_path.replace(/^datasets\//, "")}/export.json${GZ}`);
// Langfuse ingestion is asynchronous (worker -> ClickHouse): poll briefly.
let spans = langfuseConfig() ? 0 : -1;
for (let i = 0; i < 20 && spans === 0; i++) { spans = await langfuseTraceSpans(langfuseConfig(), runId); if (!spans) await new Promise((r) => setTimeout(r, 2000)); }
console.log(`[${lap()}] scored ${run.score.objectivesAchieved}/${run.score.objectivesTotal} · containment ${run.score.containmentCorrectness} · FP ${run.score.falsePositiveRate} · dataset ${ds.content_hash.slice(0, 18)}… verifies=${verifyExportHash(JSON.parse(await decodeObject(blob)))} · langfuse spans ${spans}`);

const temporal = new Client({ connection: await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? "localhost:7233" }) });
await temporal.workflow.getHandle(`deployment-${dep.id}`).terminate("e2e verified").catch(() => {});
const { teardownEnvironment } = await import("../dist/provisioner/deploy.js");
const { data: d2 } = await sb.from("deployments").select("stack_id").eq("id", dep.id).single();
await teardownEnvironment({ deploymentId: dep.id, orgId: ORG, stackName: d2.stack_id.split("/").pop(), spec: pkg.spec, runId });
const ok = run.score.objectivesAchieved === run.score.objectivesTotal && spans !== 0;
console.log(`[${lap()}] destroyed · ${ok ? "E2E OK" : "E2E FAILED"}`);
process.exit(ok ? 0 : 1);

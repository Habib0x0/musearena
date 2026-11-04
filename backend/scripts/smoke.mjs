/**
 * Live smoke driver (not a test): drives REAL workflows through the running
 * worker against live Temporal + Supabase.
 *
 *   node scripts/smoke.mjs noop        → orgScopedJob via Temporal
 *   node scripts/smoke.mjs lifecycle   → insert env+deployment rows, the
 *     worker trigger claims them, deploymentWorkflow runs deploy → configure
 *     → proof gates → exercise, a runs row with score lands in Supabase,
 *     then the driver terminates the workflow (TTL is hours) and destroys
 *     the Pulumi stack via the repo's teardown path.
 *
 * Env: reads ../../.env for Supabase. Pulumi passphrase comes from the
 * environment plane (deploy.ts envPassphrase: env override, else the
 * persisted state-root file) — the same source the worker uses. A
 * script-local passphrase creates stacks whose history the worker cannot
 * decrypt (and vice versa), so this driver must never inject one.
 */
import { readFileSync, existsSync } from "node:fs";
import { Client, Connection } from "@temporalio/client";
import { createClient } from "@supabase/supabase-js";
import { digestOfSpec } from "../dist/lib/digest.js";
import { planDeployment } from "../dist/configurator/plan.js";

const root = new URL("../../", import.meta.url).pathname;
// Platform plane settings (deployment/.platform.env) when present, then Supabase (.env).
for (const f of ["deployment/.platform.env", ".env"]) {
  if (!existsSync(root + f)) continue;
  for (const l of readFileSync(root + f, "utf8").split("\n").filter((x) => x.includes("="))) {
    const i = l.indexOf("="); process.env[l.slice(0, i).trim()] ??= l.slice(i + 1).trim();
  }
}

const mode = process.argv[2] ?? "noop";
const TARGET_WORKER_ID = process.env.MUSEARENA_TARGET_WORKER_ID?.trim() || undefined;
const TARGET_TASK_QUEUE = process.env.MUSEARENA_TARGET_WORKER_TASK_QUEUE?.trim() || (TARGET_WORKER_ID ? `musearena-${TARGET_WORKER_ID}` : "musearena");
const AGENT_MODE = process.env.SMOKE_MODE === "agents";
const temporal = new Client({
  connection: await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? "localhost:7233" }),
  namespace: process.env.TEMPORAL_NAMESPACE ?? "default",
});

if (mode === "noop") {
  const res = await temporal.workflow.execute("orgScopedJob", {
    taskQueue: TARGET_TASK_QUEUE,
    workflowId: `smoke-noop-${Date.now()}`,
    args: ["smoke-org"],
  });
  console.log("noop result:", res);
  process.exit(res === "ok:smoke-org" ? 0 : 1);
}

if (mode !== "lifecycle") { console.error("usage: smoke.mjs [noop|lifecycle]"); process.exit(2); }

// ---------- lifecycle ----------
const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, { auth: { persistSession: false } });
const ORG = "smoke-org";

const spec = {
  version: 1, name: "smoke-org", provider: "kvm", seed: "smoke1", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu 24.04", stack: ["php"], services: ["http"], databases: [] },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu 24.04", stack: [], services: ["postgres"], databases: ["app"] },
  ],
  personas: [{ id: "p1", role: "intern", workstation: "web-01", access: ["web"], credentialsProfile: "weak", riskProfile: "high", routine: "browses", relationships: [] }],
  objectives: [
    { id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10 },
    { id: "o2", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 5 },
  ],
  requiredTelemetry: ["auditd"],
  plantedVulns: [
    { id: "v1", type: "weak-cred", techniqueId: "T1078", targetHostId: "db-01", pinnedVersion: "16", proofAtomicGuid: "guid-weakcred", difficulty: "standard" },
    { id: "v2", type: "code-flaw", techniqueId: "T1059", targetHostId: "web-01", pinnedVersion: "8.2", proofAtomicGuid: "guid-cmdinj", difficulty: "standard" },
  ],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const digest = digestOfSpec(spec);
const planDigest = digestOfSpec(planDeployment(spec));
const { data: envRow, error: e1 } = await sb.from("environments")
  .insert({ org_id: ORG, created_by: "smoke", spec, spec_digest: digest, status: "approved" })
  .select("id").single();
if (e1) { console.error("environment insert failed:", e1.message); process.exit(1); }
const { data: depRow, error: e2 } = await sb.from("deployments")
  .insert({ org_id: ORG, environment_id: envRow.id, stack_id: "pending", status: "pending", access_info: { planDigest, ...(TARGET_WORKER_ID ? { workerId: TARGET_WORKER_ID } : {}) } })
  .select("id").single();
if (e2) { console.error("deployment insert failed:", e2.message); process.exit(1); }
const deploymentId = depRow.id;
const runId = `run-${deploymentId}`;
console.log("deployment:", deploymentId, "digest:", digest.slice(0, 20) + "…");
console.log("waiting for worker trigger → workflow → scored run…");

const deadline = Date.now() + 8 * 60_000;
let runRow = null;
let depRowNow = null; // last observed state, for the timeout diagnostic only
while (Date.now() < deadline) {
  // Wait until the exercise ACTIVITY finished (score + dataset), not just the score write.
  const { data: r } = await sb.from("runs").select("*").eq("run_id", runId).maybeSingle();
  const { data: d0 } = await sb.from("datasets").select("id").like("name", `${runId}%`).maybeSingle();
  if (r?.score && d0) { runRow = r; break; }
  const { data: d } = await sb.from("deployments").select("status, stack_id").eq("id", deploymentId).maybeSingle();
  depRowNow = d;
  await new Promise((res) => setTimeout(res, 5_000));
}
if (!runRow) {
  console.error("TIMEOUT waiting for scored run. deployment state:", depRowNow);
  process.exit(1);
}
console.log("run scored:", JSON.stringify(runRow.score));

// ---- environment assertions while it is live (before teardown) ----
const { execSync } = await import("node:child_process");
const { containerName, networkName } = await import("../dist/provisioner/names.js");
const sh = (c) => execSync(c, { encoding: "utf8" }).trim();
const fail = (m) => { console.error("ASSERTION FAILED:", m); process.exitCode = 1; };
const net = networkName(runId);
const netInfo = JSON.parse(sh(`docker network inspect ${net}`))[0];
if (netInfo.Internal !== true) fail(`network ${net} is not internal`);
const names = ["web-01", "db-01", "attacker"].map((h) => containerName(runId, h));
for (const n of names) {
  const c = JSON.parse(sh(`docker inspect ${n}`))[0];
  const nets = Object.keys(c.NetworkSettings.Networks);
  // The attacker may already be cut off the env network by blue's enforced response.
  const okNets = n === names[2] ? nets.length === 0 || (nets.length === 1 && nets[0] === net) : nets.length === 1 && nets[0] === net;
  if (!okNets) fail(`${n} attached to ${nets.join(",")}`);
  const published = Object.values(c.NetworkSettings.Ports ?? {}).filter(Boolean);
  if (published.length) fail(`${n} publishes host ports ${JSON.stringify(published)}`);
}
const pgVersion = sh(`docker exec ${names[1]} psql -U app -d app -tAc "select version()"`);
if (!/PostgreSQL 16/.test(pgVersion)) fail(`db-01 is not Postgres: ${pgVersion}`);
// Attacker reachability is proven by the scored red objectives (it ran before blue cut it off).
const egress = sh(`docker exec ${names[1]} sh -c 'wget -q -T 5 -O /dev/null http://1.1.1.1/ && echo OPEN || echo BLOCKED'`);
if (egress !== "BLOCKED") fail("env has outbound internet egress");
const secret = sh(`docker exec ${names[1]} psql -U app -d app -tAc "select value from secrets where objective_id='o1'"`);
// Agent mode replaces the seeded canary with a random per-run proof before red starts.
if (!secret.startsWith(AGENT_MODE ? "MUSE-PROOF-" : "MUSE-CANARY-")) fail(`objective secret not seeded on db-01: ${secret.slice(0, 20)}`);
const { data: gate } = await sb.from("audit_log").select("detail").eq("action", "PROOF_GATE_DECISION").eq("subject_id", runId).maybeSingle();
if (gate?.detail?.executor !== "docker" || gate?.detail?.pass !== true) fail(`gate not passed by docker executor: ${JSON.stringify(gate?.detail)}`);
console.log("env checks: internal network, no published ports, postgres:", pgVersion.split(" on ")[0], "| egress", egress, "| gate", JSON.stringify(gate?.detail?.proof));
const { data: scoreAudit } = await sb.from("audit_log").select("detail").eq("action", "SCORE_COMPUTED").eq("subject_id", runId).maybeSingle();
const wantMode = AGENT_MODE ? "agents-maas" : "live-docker";
if (scoreAudit?.detail?.mode !== wantMode) fail(`exercise mode: got ${JSON.stringify(scoreAudit?.detail?.mode)} want ${wantMode}`);
if (!AGENT_MODE && !(scoreAudit?.detail?.alerts > 0)) fail("blue raised no alerts from promoted Sigma rules");
if (AGENT_MODE) {
  // Agent alerts depend on blue citing real evidence, so they are measured, not asserted;
  // what must hold is that the audit attributes the run and records the guardrail outcome.
  const d = scoreAudit?.detail ?? {};
  if (!d.modelIds?.red || !d.modelIds?.blue) fail(`score audit lacks per-role model ids: ${JSON.stringify(d.modelIds)}`);
  if (typeof d.guardrails?.rejected !== "number" || typeof d.guardrails?.unverifiedClaims !== "number") fail("score audit lacks guardrail counters");
  // Any alert must rest on an evidence-cited proposal.
  if (d.alerts > 0 && !(d.blueProposals ?? []).every((p) => p.evidence?.length)) fail("an agent alert rests on a proposal without evidence");
}
const attacked = `${runRow.score.objectivesAchieved}/${runRow.score.objectivesTotal}`;
if (!AGENT_MODE && attacked !== "2/2") fail(`scripted run should score 2/2, got ${attacked}`);
const attackerNets = JSON.parse(sh(`docker inspect ${names[2]}`))[0].NetworkSettings.Networks;
if (!AGENT_MODE && Object.keys(attackerNets).length !== 0) fail(`blue's block response not enforced: attacker still on ${Object.keys(attackerNets).join(",")}`);
if (AGENT_MODE) console.log("agent run: objectives " + attacked + "; attacker networks:", Object.keys(attackerNets).join(", ") || "(none)");
console.log("exercise:", JSON.stringify(scoreAudit?.detail), "| attacker networks after blue response:", Object.keys(attackerNets));
const { data: ds } = await sb.from("datasets").select("name, content_hash, storage_path, split, redaction_policy_version").eq("org_id", ORG).like("name", `${runId}%`).maybeSingle();
if (!ds) fail("no dataset row recorded for run");
else {
  const { verifyExportHash, assertNoProofRows } = await import("../dist/traces/integrity.js");
  const { decodeObject, GZ } = await import("../dist/observability/dataset-object.js");
  const key = ds.storage_path.replace(/^datasets\//, "");
  const { data: blob, error: dlErr } = await sb.storage.from("datasets").download(`${key}/export.json${GZ}`);
  if (dlErr) fail(`dataset export not downloadable: ${dlErr.message}`);
  const exp = JSON.parse(await decodeObject(blob));
  if (!verifyExportHash(exp) || exp.meta.contentHash !== ds.content_hash) fail("stored export hash does not verify / match row");
  if (!assertNoProofRows(exp)) fail("stored export contains proof/noise rows");
  const { data: sftBlob } = await sb.storage.from("datasets").download(`${key}/sft.jsonl${GZ}`);
  const sft = (await decodeObject(sftBlob)).trim().split("\n").filter(Boolean).map(JSON.parse);
  if (!AGENT_MODE && !sft.some((e) => e.succeeded)) fail("no succeeded red SFT example from live run");
  const { data: navBlob } = await sb.storage.from("datasets").download(`${key}/navigator-layer.json${GZ}`);
  const nav = navBlob ? JSON.parse(await decodeObject(navBlob)) : null;
  if (!nav?.techniques?.length || !/STIX bundle sha256/.test(nav.description)) fail("navigator layer missing or not STIX-pinned");
  else console.log("navigator:", nav.techniques.map((t) => `${t.techniqueID}/${t.tactic}=${t.score}`).join(" "));
  console.log("dataset:", ds.content_hash.slice(0, 20) + "…", ds.storage_path, "| steps", exp.join.steps.length, "| sft", sft.length, "(succeeded", sft.filter((e) => e.succeeded).length + ")");
}
if (process.env.LANGFUSE_HOST) {
  const { langfuseConfig, langfuseTraceSpans } = await import("../dist/observability/langfuse.js");
  let spans = 0;
  for (let i = 0; i < 20 && spans === 0; i++) { spans = await langfuseTraceSpans(langfuseConfig(), runId); if (!spans) await new Promise((r) => setTimeout(r, 3000)); }
  if (spans === 0) fail("no trajectory spans in Langfuse for run");
  console.log("langfuse: trace", runId, "spans", spans);
}
if (process.exitCode) console.error("continuing to teardown despite failed assertions");

const handle = temporal.workflow.getHandle(`deployment-${deploymentId}`);
const desc = await handle.describe();
console.log("workflow status during TTL wait:", desc.status.name);
await handle.terminate("smoke complete — TTL teardown exercised separately");
console.log("workflow terminated");

// Explicit teardown through the real Pulumi destroy path. Re-read the row:
// the poll snapshot can predate deploy writing stack_id.
const { teardownEnvironment } = await import("../dist/provisioner/deploy.js");
const { data: readyDep } = await sb.from("deployments").select("stack_id").eq("id", deploymentId).maybeSingle();
const stackName = readyDep?.stack_id?.split("/").pop() ?? "";
if (!stackName.startsWith("dev-")) { console.error("refusing teardown: unexpected stack_id", readyDep?.stack_id); process.exit(1); }
await teardownEnvironment({ deploymentId, orgId: ORG, stackName, spec, runId });
const leaked = execSync(`docker ps -aq --filter label=arena.run_id=${runId}`).toString().trim();
if (leaked) { console.error("teardown left containers:", leaked.split("\n").join(", ")); process.exit(1); }
if (sh(`docker network ls -q --filter name=^${net}$`)) { console.error("teardown left network", net); process.exit(1); }
console.log("no containers remain for", runId);
const { data: finalDep } = await sb.from("deployments").select("status").eq("id", deploymentId).maybeSingle();
console.log("deployment status after teardown:", finalDep?.status);
console.log(process.exitCode ? "SMOKE LIFECYCLE FAILED (see assertions)" : "SMOKE LIFECYCLE OK");
process.exit(finalDep?.status === "destroyed" && !process.exitCode ? 0 : 1);

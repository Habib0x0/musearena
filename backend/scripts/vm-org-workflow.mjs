/**
 * T-41: the combined multi-service FreeIPA org (T-39) through the real
 * Temporal workflow, not component by component.
 *
 *   node scripts/vm-org-workflow.mjs
 *
 * Preconditions: platform up (`npm run up -w deployment`), the backend worker
 * running (`node dist/worker.js`), and Supabase creds in ../.env.
 *
 * Same org as vm-org-multi-service-smoke.mjs (Rocky dc-01 FreeIPA + Debian
 * mail-01/db-01/git-01/ws-01 members), with the one addition the workflow
 * contract requires: an objective. A T1110 detection objective on dc-01
 * (repeated failed SSH logins) exercises the scored path without touching
 * any service's directory authentication. The run must carry the org through
 * claim → CrossGuard → Pulumi stack + 5 guests → configure over SSH (FreeIPA
 * install + joins + service keytabs) → readiness (incl. GSSAPI + git-ssh
 * probes) → canaries → live-vm exercise → dataset in Storage → score row →
 * the workflow's own TTL teardown, with no leaked QEMU.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { Client, Connection } from "@temporalio/client";
import { createClient } from "@supabase/supabase-js";
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

const ORG = "vm-org-workflow-org";
// TTL is a deadline from deployment start; it must exceed the FreeIPA
// install + joins + exercise, with the workflow's own timer left to prove
// the teardown. The script waits out the remainder after scoring.
const TTL_HOURS = 0.4;
const TARGET_WORKER_ID = process.env.MUSEARENA_TARGET_WORKER_ID?.trim() || undefined;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const failureOf = (d) => {
  const f = d.access_info?.failure;
  if (!f && d.status !== "failed") return null;
  return `[${f?.stage ?? d.status}] ${f?.error ?? d.access_info?.error ?? "no failure detail"}`;
};

const buildSpec = () => ({
  version: 1, name: "org-multi-service-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "mail-01", name: "mail-01", role: "mail", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "smtp", impl: "postfix", port: 25, readyWhen: "smtp-imap-roundtrip" },
                      { kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 10 } },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: ["app"],
      serviceDecls: [{ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 10 } },
    { hostId: "git-01", name: "git-01", role: "git", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 2048, diskGb: 10 } },
    { hostId: "ws-01", name: "ws-01", role: "workstation", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [], dependsOn: ["dc-01"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "ws-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [{ id: "o1", asset: "dc-01", techniqueId: "T1110", successSignal: "auth-failures", points: 10 }],
  requiredTelemetry: ["auditd"], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: TTL_HOURS },
});
const spec = buildSpec();
const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SECRET_KEY, { auth: { persistSession: false } });

const t0 = Date.now();
const lap = () => `${((Date.now() - t0) / 1000).toFixed(0)}s`;

async function deployment(id) {
  const { data, error } = await sb.from("deployments").select("status, access_info, stack_id").eq("id", id).single();
  if (error) throw new Error(`deployment read failed: ${error.message}`);
  return data;
}

async function until(label, deadlineMs, done) {
  for (let waited = 0; waited < deadlineMs; waited += 5000) {
    const v = await done();
    if (v !== undefined && v !== null) return v;
    await sleep(5000);
  }
  throw new Error(`timeout waiting for ${label}`);
}

let dep = null;
let primaryError = null;
try {
  assert.deepEqual(digestOf(spec), digestOf(buildSpec()), "spec is deterministic");

  const planDigest = digestOfSpec(planDeployment(spec));
  const { data: env, error: envErr } = await sb.from("environments")
    .insert({ org_id: ORG, created_by: "vm-org-workflow", spec, spec_digest: digestOf(spec), status: "approved" })
    .select("id").single();
  if (envErr) throw new Error(`environment insert failed: ${envErr.message}`);

  const { data: row, error: depErr } = await sb.from("deployments")
    .insert({ org_id: ORG, environment_id: env.id, stack_id: "pending", status: "pending", access_info: { planDigest, ...(TARGET_WORKER_ID ? { workerId: TARGET_WORKER_ID } : {}) } })
    .select("id").single();
  if (depErr) throw new Error(`deployment insert failed: ${depErr.message}`);
  dep = row.id;
  const workflowRunId = `run-${dep}`;
  console.log(`[${lap()}] deployment ${dep} pending (org ${ORG}, ${spec.instances.length} guests, ttl ${TTL_HOURS}h)`);

  await until("workflow to claim the deployment", 90_000, async () => {
    const d = await deployment(dep);
    if (d.status === "failed") throw new Error(`rejected before deploy: ${JSON.stringify(d.access_info)}`);
    return d.status !== "pending" ? d.status : null;
  });
  console.log(`[${lap()}] claimed by the workflow`);

  // `ready` is written only after configure + readiness + gates + scoring.
  const ready = await until("deployment ready", 25 * 60_000, async () => {
    const d = await deployment(dep);
    const why = failureOf(d);
    if (why) throw new Error(`run failed: ${why}`);
    return d.status === "ready" ? d : null;
  });
  const outputs = ready.access_info?.outputs ?? {};
  for (const inst of spec.instances) {
    assert.match(outputs[inst.hostId] ?? "", /^vm:/, `${inst.hostId} is a real guest (outputs ${JSON.stringify(outputs)})`);
  }
  console.log(`[${lap()}] ready: ${spec.instances.map((i) => `${i.hostId}=${outputs[i.hostId]}`).join(" ")}`);

  // Readiness is a hard gate on the path to `ready`; its audit row names the
  // per-host checks (ldap-bind, smtp-imap-roundtrip, sql-select,
  // git-ldap-login, gssapi-*, git-ssh).
  const { data: gateAudits } = await sb.from("audit_log").select("detail")
    .eq("org_id", ORG).eq("action", "PROOF_GATE_DECISION").eq("subject_id", workflowRunId);
  const readiness = (gateAudits ?? []).find((a) => a.detail?.gate === "readiness");
  assert.ok(readiness, `readiness gate audited (got ${JSON.stringify((gateAudits ?? []).map((a) => a.detail?.gate))})`);
  assert.equal(readiness.detail.pass, true, `readiness passed: ${JSON.stringify(readiness.detail.hosts)}`);
  const probes = readiness.detail.hosts.flatMap((h) => h.checks.map((c) => `${h.host}/${c.probe}:${c.ok ? "ok" : "FAIL"}`));
  console.log(`[${lap()}] readiness probes: ${probes.join(" ")}`);
  for (const want of ["dc-01/ldap-bind", "mail-01/smtp-imap-roundtrip", "db-01/sql-select", "git-01/git-ldap-login"]) {
    assert.ok(probes.some((p) => p.startsWith(`${want}:ok`)), `${want} passed (got ${probes.join(" ")})`);
  }

  const ds = await until("dataset in Storage", 10 * 60_000, async () => {
    const d = await deployment(dep);
    const why = failureOf(d);
    if (why) throw new Error(`run failed: ${why}`);
    const { data } = await sb.from("datasets").select("content_hash, storage_path")
      .like("name", `${workflowRunId}%`).order("created_at", { ascending: false }).limit(1).maybeSingle();
    return data ?? null;
  });
  console.log(`[${lap()}] dataset ${ds.content_hash.slice(0, 23)}…`);

  const { data: run } = await sb.from("runs").select("score, mode, backend").eq("run_id", workflowRunId).single();
  assert.equal(run?.backend, "kvm", `run backend is kvm (got ${run?.backend})`);
  const { data: audits } = await sb.from("audit_log").select("detail")
    .eq("org_id", ORG).eq("action", "SCORE_COMPUTED").eq("subject_id", workflowRunId);
  assert.ok((audits ?? []).some((a) => a.detail?.mode === "live-vm"),
    `SCORE_COMPUTED audit shows the live-vm executor (got ${JSON.stringify((audits ?? []).map((a) => a.detail?.mode))})`);
  assert.ok((audits ?? []).some((a) => a.detail?.langfuseEvents > 0),
    `SCORE_COMPUTED audit records Langfuse spans (got ${JSON.stringify((audits ?? []).map((a) => a.detail?.langfuseEvents))})`);
  assert.equal(run.score.objectivesAchieved, 1, `objectives ${JSON.stringify(run.score)}`);
  assert.equal(run.score.pointsEarned, 10);
  assert.equal(run.score.falsePositiveRate, 0, `false positives: ${run.score.falsePositiveRate}`);
  console.log(`[${lap()}] score ${run.score.objectivesAchieved}/${run.score.objectivesTotal} · ${run.score.pointsEarned}/${run.score.pointsTotal} points`);

  const { decodeObject, GZ } = await import("../dist/observability/dataset-object.js");
  const { verifyExportHash } = await import("../dist/traces/integrity.js");
  const { data: blob, error: dlErr } = await sb.storage.from("datasets").download(`${ds.storage_path.replace(/^datasets\//, "")}/export.json${GZ}`);
  if (dlErr || !blob) throw new Error(`stored dataset unreadable: ${dlErr?.message}`);
  const exp = JSON.parse(await decodeObject(blob));
  assert.equal(exp.meta.runId, workflowRunId);
  assert.equal(exp.meta.contentHash, ds.content_hash, "stored hash matches the datasets row");
  assert.equal(verifyExportHash(exp), true, "stored export hash verifies");
  console.log(`[${lap()}] stored dataset verified: ${exp.join.steps.length} steps`);

  const { langfuseConfig, langfuseTraceSpans } = await import("../dist/observability/langfuse.js");
  const lf = langfuseConfig();
  if (!lf) throw new Error("LANGFUSE_* not set; cannot verify the VM trace");
  let spans = 0;
  for (let i = 0; i < 20 && spans === 0; i++) { spans = await langfuseTraceSpans(lf, workflowRunId); if (!spans) await sleep(2000); }
  assert.ok(spans > 0, "Langfuse holds spans for this run");
  console.log(`[${lap()}] langfuse spans ${spans} for ${workflowRunId}`);

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

  // The workflow's own TTL timer must destroy the guests; the script does not.
  await until("TTL teardown", 30 * 60_000, async () => {
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
  console.log("VM ORG WORKFLOW OK");
} catch (err) {
  primaryError = err;
  console.error("VM ORG WORKFLOW FAILURE:", err instanceof Error ? err.message : err);
} finally {
  if (dep) {
    const d = await deployment(dep).catch(() => null);
    if (d && d.status !== "destroyed" && d.access_info?.resourcesDestroyed !== true) {
      console.log(`cleanup: deployment is ${d.status}; terminating and tearing down`);
      const runIdForDep = `run-${dep}`;
      try {
        const client = new Client({ connection: await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? "localhost:7233" }) });
        await client.workflow.getHandle(`deployment-${dep}`).terminate("vm-org-workflow cleanup");
      } catch (e) {
        console.error(`cleanup: workflow terminate failed: ${e instanceof Error ? e.message : e}`);
      }
      const { teardownEnvironment } = await import("../dist/provisioner/deploy.js");
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

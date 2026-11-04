import { Client, Connection } from "@temporalio/client";
import { EnvironmentSpec, type EnvironmentSpec as SpecT, type Run } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { checkOrgLimits } from "../api/admin.js";
import { digestOfSpec } from "../lib/digest.js";
import { validateDesign } from "../designer/coherence.js";
import { pinForSpec, pinnedDesignDigest } from "../designer/archetypes.js";
import { deployability } from "../provisioner/capability.js";
import { planDeployment, type DeploymentPlan } from "../configurator/plan.js";
import { failureRecord, markDeployment, type AccessInfo } from "../provisioner/deployment-status.js";
import { hostCapabilities } from "../provisioner/host-capabilities.js";
import {
  claimAccessInfo,
  workerCanRunDeployment,
  workerRoutingConfig,
  type WorkerRoute,
  type WorkerRoutingConfig,
} from "../lib/worker-routing.js";

/**
 * Deployment trigger: the missing link between the UI and the worker.
 * The frontend inserts `environments` + `deployments(status=pending)` rows;
 * this poller claims pending rows and starts one `deploymentWorkflow` each.
 * Claiming is a conditional update (pending → provisioning) so two pollers
 * can never start the same deployment twice. In multi-host mode the poller
 * first checks worker routing/capabilities and leaves another host's row
 * pending; the winning claim stamps the owner and starts the workflow on
 * that owner's task queue.
 */
export interface PendingDeployment {
  deploymentId: string;
  orgId: string;
  spec: SpecT;
  workerId?: string;
  workerRoute?: WorkerRoute;
  taskQueue?: string;
}

/**
 * A pending row's spec must satisfy the shared contract before a workflow is
 * started; otherwise deployActivity would retry a malformed spec forever.
 */
export function validatePendingSpec(spec: unknown): { ok: true; spec: SpecT; plan: DeploymentPlan } | { ok: false; reason: string } {
  const parsed = EnvironmentSpec.safeParse(spec);
  if (parsed.success) {
    // No rewriting here: the stored spec (and its digest) is what runs. The
    // designer already normalizes roles; anything else is rejected with reason.
    const spec = parsed.data;
    const blocked = deployability(spec);
    if (blocked.length) return { ok: false, reason: `not deployable: ${blocked.join("; ")}` };
    // Last gate before deploy: an org that cannot be scored is rejected here,
    // not after six guests are running. This is the same semantic gate the
    // designer ran, so a spec that reached the table by another path (import,
    // template, direct insert) cannot be weaker than a designed one.
    const invalid = validateDesign(spec);
    if (invalid.length) return { ok: false, reason: `invalid design: ${invalid.join("; ")}` };
    // The plan is the bill of materials the configurator will execute. A spec
    // whose topology cannot be planned (bad/too-small CIDR, an unexpandable
    // profile) is refused before provisioning instead of failing mid-run.
    let plan: DeploymentPlan;
    try {
      plan = planDeployment(spec);
    } catch (err) {
      return { ok: false, reason: `cannot be planned: ${err instanceof Error ? err.message : String(err)}` };
    }
    if (plan.gaps.length) return { ok: false, reason: `cannot be planned: ${plan.gaps.join("; ")}` };
    return { ok: true, spec, plan };
  }
  return { ok: false, reason: parsed.error.issues.slice(0, 5).map((i) => `${i.path.join(".") || "(root)"}: ${i.message}`).join("; ") };
}

/** The stored spec is what runs; it must still hash to the approved digest. */
export function validateStoredSpecDigest(spec: SpecT, storedDigest: unknown): { ok: true } | { ok: false; reason: string } {
  if (typeof storedDigest !== "string" || !storedDigest) return { ok: false, reason: "no spec digest on the environment" };
  if (digestOfSpec(spec) !== storedDigest) return { ok: false, reason: "stored spec does not match its digest" };
  return { ok: true };
}

/**
 * The reviewed plan must be the executed plan. `access_info.planDigest` is
 * written when the deployment is created; recomputing the plan from the stored
 * spec and comparing detects a catalog/profile/image change between approval
 * and deploy. A row without a digest never went through an approval step.
 */
export function validateApprovedPlan(plan: DeploymentPlan, approvedDigest: unknown): { ok: true } | { ok: false; reason: string } {
  if (typeof approvedDigest !== "string" || !approvedDigest) {
    return { ok: false, reason: "no approved plan digest on the deployment (create it from the designer and record planDigest)" };
  }
  const now = digestOfSpec(plan);
  if (now !== approvedDigest) {
    return { ok: false, reason: `plan changed since approval (approved ${approvedDigest.slice(0, 19)}…, now ${now.slice(0, 19)}…)` };
  }
  return { ok: true };
}

export async function claimPendingDeployments(
  limit = 10,
  routing: WorkerRoutingConfig = workerRoutingConfig(),
): Promise<PendingDeployment[]> {
  const sb = serviceClient();
  const caps = hostCapabilities();
  // Scan beyond the claim limit so older rows for another host do not starve
  // this worker's eligible rows behind them in one shared pending queue.
  const scanLimit = Math.min(Math.max(limit * 5, 50), 200);
  const { data, error } = await sb
    .from("deployments")
    .select("id, org_id, access_info, environments(spec, spec_digest)")
    .eq("status", "pending")
    .order("created_at", { ascending: true })
    .limit(scanLimit);
  if (error) throw new Error(`pending scan failed: ${error.message}`);
  const claimed: PendingDeployment[] = [];
  for (const row of (data ?? []) as unknown as {
    id: string;
    org_id: string;
    access_info?: AccessInfo | null;
    environments?: { spec: unknown; spec_digest?: string | null } | null;
  }[]) {
    if (claimed.length >= limit) break;
    const raw = row.environments?.spec;
    if (!raw) continue;

    // Route before host-specific validation: a worker that cannot run this
    // deployment must leave it pending for its owner, not fail it.
    const parsedForRoute = EnvironmentSpec.safeParse(raw);
    const eligibility = parsedForRoute.success
      ? workerCanRunDeployment({ spec: parsedForRoute.data, accessInfo: row.access_info, routing, caps })
      : null;
    if (eligibility && !eligibility.eligible) continue;

    const reject = async (detail: string) => {
      // Keep the approved digest in the row: it is the evidence for why the
      // plan was refused (never replace access_info with only the error).
      await sb.from("deployments").update({ status: "failed", access_info: { ...(row.access_info ?? {}), error: detail, failure: failureRecord("trigger", detail) } }).eq("id", row.id).eq("status", "pending");
      console.error(`trigger: rejected deployment ${row.id} (${detail})`);
    };
    const check = validatePendingSpec(raw);
    if (!check.ok) { await reject(`invalid spec: ${check.reason}`); continue; }
    // The stored spec is what runs; it must still be the spec whose digest was
    // approved (a spec update that missed the digest is refused).
    const specDigest = validateStoredSpecDigest(check.spec, row.environments?.spec_digest);
    if (!specDigest.ok) { await reject(specDigest.reason); continue; }
    const approved = validateApprovedPlan(check.plan, row.access_info?.planDigest);
    if (!approved.ok) { await reject(`unapproved plan: ${approved.reason}`); continue; }
    // Org budgets and quotas (admin limits), checked at the one place every
    // run path passes through before resources exist.
    const overLimit = await checkOrgLimits(row.org_id, check.spec, row.id);
    if (overLimit.length) {
      await reject(`organization limit: ${overLimit.join("; ")}`);
      await audit({ orgId: row.org_id, actor: "orchestrator", action: "ADMIN_DEPLOYMENT_REFUSED", subjectType: "deployment", subjectId: row.id, detail: { reasons: overLimit } })
        .catch((e: Error) => console.error(`trigger: audit of refused deployment ${row.id} failed: ${e.message}`));
      continue;
    }

    const route = eligibility?.route ?? workerCanRunDeployment({ spec: check.spec, accessInfo: row.access_info, routing, caps }).route;
    const update: { status: "provisioning"; access_info?: AccessInfo } = { status: "provisioning" };
    if (routing.workerId) update.access_info = claimAccessInfo(row.access_info, routing, route);
    const { data: updated } = await sb.from("deployments").update(update).eq("id", row.id).eq("status", "pending").select("id");
    if (updated && updated.length > 0) {
      claimed.push({
        deploymentId: row.id,
        orgId: row.org_id,
        spec: check.spec,
        ...(routing.workerId ? { workerId: routing.workerId } : {}),
        workerRoute: route,
        taskQueue: routing.taskQueue,
      });
    }
  }
  return claimed;
}

export function runRecordFor(deploymentId: string, orgId: string, spec: EnvironmentSpec): Run {
  return {
    runId: `run-${deploymentId}`,
    orgId,
    deploymentId,
    mode: "blind",
    // T-17: the run record pins the versions that produced the design
    // (archetype recovered by digest equality; model designs pin the
    // executing build's catalog/profile/image versions).
    specDigest: pinnedDesignDigest(spec, pinForSpec(spec)),
    techniquePackVersion: "attack-15.1",
    modelIds: {},
    truthLayer: spec.truthLayer,
    backend: spec.provider,
  };
}

export async function startDeploymentWorkflow(
  client: Client,
  p: PendingDeployment,
  routing: WorkerRoutingConfig = workerRoutingConfig(),
): Promise<string> {
  const run = runRecordFor(p.deploymentId, p.orgId, p.spec);
  const handle = await client.workflow.start("deploymentWorkflow", {
    taskQueue: p.taskQueue ?? routing.taskQueue,
    workflowId: `deployment-${p.deploymentId}`,
    args: [{ orgId: p.orgId, deploymentId: p.deploymentId, runId: run.runId, spec: p.spec, run }],
  });
  return handle.workflowId;
}

/** One trigger pass: claim pending deployments and start their workflows. */
export async function triggerPendingDeployments(
  client?: Client,
  routing: WorkerRoutingConfig = workerRoutingConfig(),
): Promise<string[]> {
  const pending = await claimPendingDeployments(10, routing);
  if (pending.length === 0) return [];
  const temporal = client ?? new Client({ connection: await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? "localhost:7234" }) });
  const started: string[] = [];
  const failures: string[] = [];
  for (const p of pending) {
    try {
      started.push(await startDeploymentWorkflow(temporal, p, routing));
    } catch (err) {
      // The row was already claimed (pending → provisioning). Without this
      // compensation it would stay provisioning forever with no workflow.
      const message = err instanceof Error ? err.message : String(err);
      await markDeployment(p.deploymentId, { status: "failed", accessInfo: { failure: failureRecord("trigger", message) } })
        .catch((e: Error) => console.error(`trigger: could not record start failure for ${p.deploymentId}: ${e.message}`));
      failures.push(`${p.deploymentId}: ${message}`);
    }
  }
  if (failures.length) throw new Error(`workflow start failed: ${failures.join("; ")}`);
  return started;
}

import type { EnvironmentSpec, Run } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import type { DatasetExport } from "./export.js";
import { assertExportIntegrity, assertNoProofRows } from "../traces/integrity.js";
import { needsCleanup, type AccessInfo } from "../provisioner/deployment-status.js";
import { deploymentOwnedByWorker, workerRoutingConfig, type WorkerRoutingConfig } from "../lib/worker-routing.js";

/**
 * Persistence for runs + datasets. The Realtime UI subscribes to the `runs`
 * table, which stayed empty until something wrote rows — these functions are
 * that writer. `runs.score` carries the shared RunScore fields plus the
 * scorecard extras the Overview page reads (mttdMinutesP50, falsePositiveRate).
 */
export async function recordRun(run: Run): Promise<void> {
  const sb = serviceClient();
  const { error } = await sb.from("runs").upsert({
    run_id: run.runId,
    org_id: run.orgId,
    deployment_id: run.deploymentId,
    mode: run.mode,
    spec_digest: run.specDigest,
    technique_pack_version: run.techniquePackVersion,
    truth_layer: run.truthLayer,
    backend: run.backend,
    model_ids: run.modelIds ?? {},
    ...(run.deployments ? { deployments: run.deployments } : {}),
    score: run.score ?? null,
  });
  if (error) throw new Error(`run upsert failed: ${error.message}`);
}

export async function recordRunScore(run: Run, detail: Record<string, unknown> = {}): Promise<void> {
  if (!run.score) throw new Error("recordRunScore requires run.score");
  await recordRun(run);
  await audit({ orgId: run.orgId, actor: "evaluator", action: "SCORE_COMPUTED", subjectType: "run", subjectId: run.runId, detail: { objectives: "scored", ...detail } });
}

export interface RecordDatasetInput {
  orgId: string;
  name: string;
  exp: DatasetExport;
  storagePath: string;
}

/** Dataset rows are written only for hash-verified, proof/noise-free exports. */
export async function recordDataset(input: RecordDatasetInput): Promise<string> {
  assertExportIntegrity(input.exp);
  if (!assertNoProofRows(input.exp)) throw new Error("dataset export contains proof/noise/platform rows — refusing to record");
  const sb = serviceClient();
  const { data, error } = await sb.from("datasets").insert({
    org_id: input.orgId,
    name: input.name,
    content_hash: input.exp.meta.contentHash,
    format_version: input.exp.meta.formatVersion,
    split: input.exp.meta.split,
    redaction_policy_version: input.exp.meta.redactionPolicyVersion,
    storage_path: input.storagePath,
  }).select("id").single();
  if (error) throw new Error(`dataset insert failed: ${error.message}`);
  await audit({ orgId: input.orgId, actor: "trace-pipeline", action: "DATASET_EXPORTED", subjectType: "run", subjectId: input.exp.meta.runId, detail: { hash: input.exp.meta.contentHash } });
  return (data as { id: string }).id;
}

/** Retention (Req §6, T-5/T-10): deployments past their spec TTL that may still own resources. */
export async function ttlExpiredDeployments(
  now = new Date(),
  routing: WorkerRoutingConfig = workerRoutingConfig(),
): Promise<{
  id: string; orgId: string; stackId: string; spec: EnvironmentSpec; status: string; failure?: unknown;
}[]> {
  const sb = serviceClient();
  const { data, error } = await sb
    .from("deployments")
    .select("id, org_id, stack_id, status, access_info, created_at, environments(spec)")
    .neq("status", "destroyed");
  if (error) throw new Error(`ttl scan failed: ${error.message}`);
  const out: { id: string; orgId: string; stackId: string; spec: EnvironmentSpec; status: string; failure?: unknown }[] = [];
  for (const row of (data ?? []) as unknown as { id: string; org_id: string; stack_id: string; status: string; access_info?: AccessInfo | null; created_at: string; environments?: { spec: EnvironmentSpec } | null }[]) {
    const spec = row.environments?.spec;
    // A failed row whose cleanup already succeeded is done; a stuck
    // `destroying` row, or a failed row whose teardown threw, is retried.
    if (!needsCleanup(row.status, row.access_info ?? {})) continue;
    // Pulumi/VM state is host-local: another worker's TTL teardown must run
    // on the owning host, never from whichever maintenance loop wakes first.
    if (!deploymentOwnedByWorker(row.access_info ?? {}, routing)) continue;
    // A row with no valid TTL is skipped here (it never provisioned: the trigger
    // rejects invalid specs) — one bad row must not halt TTL for every other env.
    const ttlHours = spec?.budgets?.ttlHours;
    if (!spec || typeof ttlHours !== "number") continue;
    // A run that is actively working gets a grace window past its deadline:
    // the TTL is a cap on idle lifetime, and killing a scoring run mid-flight
    // would destroy evidence rather than bound cost. The workflow's own timer
    // still tears down as soon as the run finishes.
    const active = ["provisioning", "configuring", "verifying", "exercising"];
    const graceMs = active.includes(row.status) ? 10 * 60_000 : 0;
    const expiresAt = Date.parse(row.created_at) + ttlHours * 3_600_000 + graceMs;
    if (Number.isFinite(expiresAt) && now.getTime() >= expiresAt) {
      out.push({ id: row.id, orgId: row.org_id, stackId: row.stack_id, spec, status: row.status, failure: row.access_info?.failure });
    }
  }
  return out;
}

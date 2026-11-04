import type { DeploymentStatus } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";

/**
 * Deployment lifecycle state.
 *
 * The row is the only durable account of what happened to a deployment, so it
 * must survive teardown: a failed run is recorded as `failed` with the stage
 * and error that caused it, never rewritten to `destroyed` with an empty
 * `access_info` (which is what made a 403 in the exercise leg look like a
 * dataset timeout). `destroyed` means "completed, then torn down"; `failed`
 * means "did not complete". Cleanup success is recorded inside `access_info`
 * so a failed row can still be retried by the TTL sweeper when teardown
 * itself failed.
 */

export type AccessInfo = Record<string, unknown>;

export interface FailureRecord {
  /** Lifecycle step that failed: deploy | configure | readiness | gates | exercise | teardown | trigger. */
  stage: string;
  error: string;
  at: string;
}

export function failureRecord(stage: string, error: string, at = new Date().toISOString()): FailureRecord {
  return { stage, error: error.slice(0, 2000), at };
}

/** Shallow merge: a later step must never erase evidence written by an earlier one. */
export function mergeAccessInfo(current: AccessInfo | null | undefined, patch: AccessInfo): AccessInfo {
  return { ...(current ?? {}), ...patch };
}

/**
 * True when the deployment may still own runtime resources. Used by the TTL
 * sweep, which previously skipped `destroying` rows forever and skipped every
 * row whose `stack_id` was not a real Pulumi stack — both permanent leaks.
 */
export function needsCleanup(status: string, info: AccessInfo | null | undefined = {}): boolean {
  if (status === "destroyed" || status === "pending") return false;
  if (status === "failed") return (info ?? {}).resourcesDestroyed !== true;
  return true;
}

export async function readAccessInfo(deploymentId: string): Promise<AccessInfo> {
  const sb = serviceClient();
  const { data, error } = await sb.from("deployments").select("access_info").eq("id", deploymentId).single();
  if (error) throw new Error(`deployment ${deploymentId} unreadable: ${error.message}`);
  return ((data as { access_info?: AccessInfo } | null)?.access_info ?? {}) as AccessInfo;
}

/** Write a status, stack id and/or merge `access_info`. Never replaces the whole object. */
export async function markDeployment(
  deploymentId: string,
  patch: { status?: DeploymentStatus; accessInfo?: AccessInfo; stackId?: string },
): Promise<AccessInfo> {
  const sb = serviceClient();
  const current = await readAccessInfo(deploymentId);
  const accessInfo = patch.accessInfo ? mergeAccessInfo(current, patch.accessInfo) : current;
  const row: { access_info?: AccessInfo; status?: DeploymentStatus; stack_id?: string } = { access_info: accessInfo };
  if (patch.status) row.status = patch.status;
  if (patch.stackId) row.stack_id = patch.stackId;
  const { error } = await sb.from("deployments").update(row).eq("id", deploymentId);
  if (error) throw new Error(`deployment ${deploymentId} status write failed: ${error.message}`);
  return accessInfo;
}

/** Record a failure without changing a terminal status (used before teardown). */
export async function markFailed(deploymentId: string, stage: string, error: string): Promise<void> {
  await markDeployment(deploymentId, { status: "failed", accessInfo: { failure: failureRecord(stage, error), error: error.slice(0, 400) } });
}

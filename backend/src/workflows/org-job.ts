import { CancellationScope, continueAsNew, isCancellation, log, proxyActivities, sleep, workflowInfo } from "@temporalio/workflow";
import type { EnvironmentSpec, Run } from "@musearena/shared";
import type * as actsType from "../activities/index.js";
import { containerName } from "../provisioner/names.js";

const acts = proxyActivities<typeof actsType>({
  startToCloseTimeout: "30 minutes",
  retry: { maximumAttempts: 2 },
});

// The model API distinguishes access failures (401/403/404) from transient
// ones. Retrying a permanent 403 only delays the teardown and hides the cause.
const exerciseActs = proxyActivities<Pick<typeof actsType, "exerciseActivity">>({
  startToCloseTimeout: "30 minutes",
  retry: { maximumAttempts: 2, nonRetryableErrorTypes: ["PermanentModelError"] },
});

/** Placeholder kept for existing callers. */
export async function orgScopedJob(orgId: string): Promise<string> {
  return acts.noop(orgId);
}

/**
 * Temporal wraps an activity error as "Activity task failed" and keeps the
 * real cause on the failure chain. The row must carry the cause (a 403, a
 * probe failure, a missing binary), not the wrapper.
 */
function failureMessage(err: unknown): string {
  const parts: string[] = [];
  let cur: unknown = err;
  for (let i = 0; i < 6 && cur; i++) {
    const message = (cur as { message?: unknown }).message;
    if (typeof message === "string" && message && !parts.includes(message)) parts.push(message);
    cur = (cur as { cause?: unknown }).cause;
  }
  return (parts.join(": ") || String(err)).slice(0, 2000);
}

/**
 * Deployment lifecycle: provision → configure → proof gates → exercise, then
 * TTL enforcement (Req §2.5): when the spec TTL expires the environment is
 * torn down automatically. Workflow history is the execution audit.
 */
export async function deploymentWorkflow(input: {
  orgId: string; deploymentId: string; runId: string; spec: EnvironmentSpec; run: Run;
}): Promise<string> {
  // `stackId` is only known once deploy succeeds; a failure before that still
  // has to be recorded and must still tear down whatever deploy started.
  let stackId = "";
  let stackName = "";
  const teardown = (outcome?: { status: "destroyed" | "failed"; failure?: { stage: string; error: string; at?: string } }) =>
    acts.teardownActivity({ deploymentId: input.deploymentId, orgId: input.orgId, stackName, spec: input.spec, runId: input.runId, outcome });
  let score: string;
  let stage = "deploy";
  try {
    stackId = await acts.deployActivity({ deploymentId: input.deploymentId, orgId: input.orgId, runId: input.runId, spec: input.spec });
    stackName = stackId.split("/").pop() ?? stackId;
    const targets = input.spec.instances.map((i) => ({ hostId: i.hostId, name: i.name, connectVia: i.runtime === "container" ? containerName(input.runId, i.hostId) : i.hostId }));
    stage = "configure";
    await acts.configureActivity({ deploymentId: input.deploymentId, orgId: input.orgId, runId: input.runId, spec: input.spec, targets });
    stage = "readiness";
    await acts.readinessActivity({ deploymentId: input.deploymentId, orgId: input.orgId, runId: input.runId, spec: input.spec });
    stage = "gates";
    await acts.proofActivity({ deploymentId: input.deploymentId, orgId: input.orgId, runId: input.runId, spec: input.spec });
    stage = "exercise";
    score = await exerciseActs.exerciseActivity({ spec: input.spec, run: input.run });
    stage = "hold";
    // TTL is a deadline from deployment start, not extra hold time after
    // scoring. Without this, maintenance (created_at + ttl) and this sleep
    // race and the environment is torn down twice.
    const ttlMs = input.spec.budgets.ttlHours * 3_600_000;
    const elapsedMs = Date.now() - workflowInfo().startTime.getTime();
    await sleep(Math.max(0, ttlMs - elapsedMs));
  } catch (err) {
    // A deployed env that fails config/gates/exercise is never scorable and
    // must not outlive the failure. The failure is written with the row and
    // is never replaced by `destroyed`. Cancellation (cancel, not terminate)
    // tears down without recording a failure.
    const outcome = isCancellation(err) ? undefined : { status: "failed" as const, failure: { stage, error: failureMessage(err), at: new Date().toISOString() } };
    await CancellationScope.nonCancellable(() => teardown(outcome)).catch((e: Error) => {
      // teardownEnvironment already recorded `failed` + resourcesDestroyed:false,
      // so the TTL sweep retries; the original error stays the run's outcome.
      log.warn(`teardown failed for ${input.deploymentId}: ${e.message}`);
    });
    throw err;
  }
  await teardown();
  return `${stackId}|${score}|ttl-teardown`;
}

export async function teardownWorkflow(input: {
  orgId: string; deploymentId: string; stackName: string; spec: EnvironmentSpec; runId: string;
}): Promise<string> {
  return acts.teardownActivity(input);
}

/**
 * Hourly maintenance (orphan sweeper, TTL backstop, drift). Runs forever as
 * one workflow id; continue-as-new keeps history bounded.
 */
export async function maintenanceWorkflow(iterations = 0): Promise<void> {
  // One bad deployment must not stop TTL, drift and orphan sweeping for every
  // other one: the pass isolates per-deployment errors, and a pass-level throw
  // is contained here instead of killing the loop.
  try {
    await acts.maintenanceActivity();
  } catch (err) {
    log.warn(`maintenance pass failed: ${err instanceof Error ? err.message : String(err)}`);
  }
  await sleep("1h");
  if (iterations >= 23) await continueAsNew<typeof maintenanceWorkflow>(0);
  return maintenanceWorkflow(iterations + 1);
}

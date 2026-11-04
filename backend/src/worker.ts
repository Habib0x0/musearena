// SPDX-License-Identifier: Apache-2.0
import { NativeConnection, Worker } from "@temporalio/worker";
import * as activities from "./activities/index.js";
import { maintenanceWorkflowIdFor, workerRoutingConfig } from "./lib/worker-routing.js";
import { continualSweepConfigFromEnv, runContinualSweep, supabaseContinualSweepStores } from "./learning/continual.js";

async function main() {
  // The managed platform publishes Temporal on 7234 (7233 is left free for a
  // developer's own Temporal). TEMPORAL_ADDRESS still wins when set.
  const temporalAddress = process.env.TEMPORAL_ADDRESS ?? "localhost:7234";
  const connection = await NativeConnection.connect({
    address: temporalAddress,
  });
  const routing = workerRoutingConfig();
  const continual = continualSweepConfigFromEnv();
  const worker = await Worker.create({
    connection,
    namespace: process.env.TEMPORAL_NAMESPACE ?? "default",
    taskQueue: routing.taskQueue,
    workflowsPath: new URL("./workflows/org-job.js", import.meta.url).pathname,
    activities,
  });
  console.log(`musearena worker ${routing.workerId ?? "legacy"} running on queue '${routing.taskQueue}' routes=${routing.routes.join(",")} continual=${continual.enabled ? "on" : "off"}`);
  const { metricsServer } = await import("./observability/metrics.js");
  // Metrics are best-effort: a port still held by an exiting worker must not
  // crash this one (it used to die on EADDRINUSE and leave runs unserved).
  const metrics = metricsServer();
  metrics.on("error", (e: NodeJS.ErrnoException) => console.error(`metrics endpoint unavailable (${e.code ?? e.message}); worker continues without it`));
  // Deployment trigger: turn UI-created pending rows into workflows.
  const { triggerPendingDeployments } = await import("./workflows/trigger.js");
  // Stop claiming the moment shutdown begins: a stopping worker must not
  // claim a row it will never run (it would orphan the deployment and race the
  // next worker into running two exercises at once).
  let accepting = true;
  const poll = async () => {
    if (!accepting) return;
    try {
      const started = await triggerPendingDeployments(undefined, routing);
      if (started.length) console.log(`trigger: started ${started.join(", ")}`);
    } catch (err) {
      console.error("trigger poll failed", err);
    }
  };
  void poll();
  const timer = setInterval(poll, 15_000);

  // Learning proposals are a global, service-role sweep rather than a
  // host-local deployment activity. Keep it opt-in and enable it on exactly
  // one worker; it only creates proposals and never approves training.
  let continualRunning = false;
  const runContinual = async () => {
    if (!accepting || continualRunning) return;
    continualRunning = true;
    try {
      const { results, errors } = await runContinualSweep(
        { actor: "continual-worker", config: continual.sweep },
        supabaseContinualSweepStores(),
      );
      const proposals = results.reduce((n, r) => n + r.proposals.length, 0);
      const skipped = results.reduce((n, r) => n + r.skipped.length, 0);
      console.log(`continual sweep: orgs=${results.length} proposals=${proposals} skipped=${skipped} errors=${errors.length}`);
      for (const err of errors) console.error(`continual sweep org ${err.orgId} failed: ${err.error}`);
    } catch (err) {
      console.error("continual sweep failed (will retry):", err instanceof Error ? err.message : err);
    } finally {
      continualRunning = false;
    }
  };
  let continualTimer: ReturnType<typeof setInterval> | undefined;
  const continualKickoff = continual.enabled
    ? setTimeout(() => {
        void runContinual();
        continualTimer = setInterval(() => void runContinual(), continual.intervalMs);
      }, 30_000)
    : undefined;

  const stopClaiming = () => {
    accepting = false;
    clearInterval(timer);
    if (continualKickoff) clearTimeout(continualKickoff);
    if (continualTimer) clearInterval(continualTimer);
  };
  process.once("SIGINT", stopClaiming);
  process.once("SIGTERM", stopClaiming);
  // Singleton hourly maintenance workflow (fixed id: starting twice is a no-op).
  const { Client, Connection, WorkflowExecutionAlreadyStartedError } = await import("@temporalio/client");
  const client = new Client({ connection: await Connection.connect({ address: temporalAddress }), namespace: process.env.TEMPORAL_NAMESPACE ?? "default" });
  await client.workflow.start("maintenanceWorkflow", { taskQueue: routing.taskQueue, workflowId: maintenanceWorkflowIdFor(routing), args: [0] })
    .then(() => console.log("maintenance workflow started"))
    .catch((e) => { if (!(e instanceof WorkflowExecutionAlreadyStartedError)) console.error("maintenance start failed", e); });
  try {
    await worker.run();
  } finally {
    stopClaiming();
    metrics.close();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });

import { sendJson, type ApiRoute } from "./server.js";
import {
  approveTrainingRun, cancelTrainingRun, CreateTrainingRun, createTrainingRun,
  InvalidTrainingRun, listTrainingRuns, supabaseTrainingStore, trainerFromEnv,
  TrainingRunConflict, TrainingRunNotFound, TRAINING_STATUSES,
  type TrainerAdapter, type TrainingStatus, type TrainingStore,
} from "../learning/training.js";

/**
 * Training-run routes (F-9). Creation/cancellation are trainer actions;
 * approval is the operator gate that may submit external spend. Reads are
 * reviewer. Production-target runs therefore cannot run without an explicit
 * operator approval call that names the approver in the audit chain.
 */
export interface TrainingRouteDeps {
  store?: TrainingStore;
  trainer?: TrainerAdapter | null;
  list?: typeof listTrainingRuns;
}

function fail(ctx: Parameters<ApiRoute["handler"]>[0], err: unknown): boolean {
  if (err instanceof TrainingRunNotFound) { sendJson(ctx.res, 404, { error: err.message }); return true; }
  if (err instanceof TrainingRunConflict) { sendJson(ctx.res, 409, { error: err.message }); return true; }
  if (err instanceof InvalidTrainingRun) { sendJson(ctx.res, 400, { error: err.message }); return true; }
  return false;
}

export function trainingRoutes(deps: TrainingRouteDeps = {}): ApiRoute[] {
  const store = () => deps.store ?? supabaseTrainingStore();
  const list = deps.list ?? listTrainingRuns;

  async function postRun(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const parsed = CreateTrainingRun.safeParse(ctx.body);
    if (!parsed.success) {
      sendJson(ctx.res, 400, {
        error: "invalid training run",
        issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
      });
      return;
    }
    try {
      const run = await createTrainingRun(
        { ...parsed.data, orgId: ctx.session!.orgId, requestedBy: ctx.session!.subject },
        store(),
      );
      sendJson(ctx.res, 201, run);
    } catch (err) {
      if (!fail(ctx, err)) throw err;
    }
  }

  async function getRuns(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const statusRaw = ctx.url.searchParams.get("status");
    const roleRaw = ctx.url.searchParams.get("role");
    if (statusRaw && !(TRAINING_STATUSES as readonly string[]).includes(statusRaw)) {
      sendJson(ctx.res, 400, { error: `status must be one of ${TRAINING_STATUSES.join(", ")}` });
      return;
    }
    if (roleRaw && roleRaw !== "red" && roleRaw !== "blue") {
      sendJson(ctx.res, 400, { error: "role must be red or blue" });
      return;
    }
    const runs = await list(ctx.session!.orgId, {
      ...(statusRaw ? { status: statusRaw as TrainingStatus } : {}),
      ...(roleRaw ? { role: roleRaw as "red" | "blue" } : {}),
    });
    sendJson(ctx.res, 200, { trainingRuns: runs });
  }

  async function approve(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const outputName = ctx.body && typeof ctx.body === "object" && "outputName" in ctx.body &&
      typeof (ctx.body as { outputName?: unknown }).outputName === "string"
      ? (ctx.body as { outputName: string }).outputName
      : undefined;
    try {
      const run = await approveTrainingRun(
        { orgId: ctx.session!.orgId, id: ctx.params.id, approvedBy: ctx.session!.subject, outputName },
        store(),
        deps.trainer === undefined ? trainerFromEnv() : deps.trainer,
      );
      sendJson(ctx.res, 200, run);
    } catch (err) {
      if (!fail(ctx, err)) throw err;
    }
  }

  async function cancel(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    try {
      const run = await cancelTrainingRun(
        { orgId: ctx.session!.orgId, id: ctx.params.id, actor: ctx.session!.subject },
        store(),
      );
      sendJson(ctx.res, 200, run);
    } catch (err) {
      if (!fail(ctx, err)) throw err;
    }
  }

  return [
    { method: "POST", path: "/training-runs", auth: "session", role: "trainer", handler: postRun },
    { method: "GET", path: "/training-runs", auth: "session", role: "reviewer", handler: getRuns },
    { method: "POST", path: "/training-runs/:id/approve", auth: "session", role: "operator", handler: approve },
    { method: "POST", path: "/training-runs/:id/cancel", auth: "session", role: "operator", handler: cancel },
  ];
}

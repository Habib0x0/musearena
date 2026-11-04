import { sendJson, type ApiRoute } from "./server.js";
import {
  createEvaluation, CreateEvaluation, EvaluationConflict, EvaluationNotFound,
  InvalidEvaluation, leaderboard, runEvaluation, supabaseEvaluationStore,
  type EvaluationStore, type EvaluationTrialRunner,
} from "../learning/evaluation.js";

/**
 * Evaluation routes (F-10). Creation pins the held-out suite; running is a
 * separate trainer action so a queued evaluation is visible before compute is
 * spent. With no production trial runner wired, a run fails honestly instead
 * of inventing metrics.
 */
export interface EvaluationRouteDeps {
  store?: EvaluationStore;
  runner?: EvaluationTrialRunner | null;
}

function fail(ctx: Parameters<ApiRoute["handler"]>[0], err: unknown): boolean {
  if (err instanceof EvaluationNotFound) { sendJson(ctx.res, 404, { error: err.message }); return true; }
  if (err instanceof EvaluationConflict) { sendJson(ctx.res, 409, { error: err.message }); return true; }
  if (err instanceof InvalidEvaluation) { sendJson(ctx.res, 400, { error: err.message }); return true; }
  return false;
}

export function evaluationRoutes(deps: EvaluationRouteDeps = {}): ApiRoute[] {
  const store = () => deps.store ?? supabaseEvaluationStore();

  async function postEvaluation(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const parsed = CreateEvaluation.safeParse(ctx.body);
    if (!parsed.success) {
      sendJson(ctx.res, 400, {
        error: "invalid evaluation",
        issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
      });
      return;
    }
    try {
      const row = await createEvaluation(
        { ...parsed.data, orgId: ctx.session!.orgId, requestedBy: ctx.session!.subject },
        store(),
      );
      sendJson(ctx.res, 201, row);
    } catch (err) {
      if (!fail(ctx, err)) throw err;
    }
  }

  async function getEvaluations(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const rows = await store().listEvaluations(ctx.session!.orgId);
    sendJson(ctx.res, 200, { evaluations: rows });
  }

  async function run(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    try {
      const row = await runEvaluation(
        { orgId: ctx.session!.orgId, id: ctx.params.id, actor: ctx.session!.subject },
        store(),
        deps.runner ?? null,
      );
      sendJson(ctx.res, 200, row);
    } catch (err) {
      if (!fail(ctx, err)) throw err;
    }
  }

  async function board(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const rows = await store().listEvaluations(ctx.session!.orgId);
    sendJson(ctx.res, 200, { leaderboard: leaderboard(rows) });
  }

  return [
    { method: "POST", path: "/evaluations", auth: "session", role: "trainer", handler: postEvaluation },
    { method: "GET", path: "/evaluations", auth: "session", role: "reviewer", handler: getEvaluations },
    { method: "GET", path: "/evaluations/leaderboard", auth: "session", role: "reviewer", handler: board },
    { method: "POST", path: "/evaluations/:id/run", auth: "session", role: "trainer", handler: run },
  ];
}

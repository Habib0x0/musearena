import { z } from "zod";
import { sendJson, type ApiRoute } from "./server.js";
import {
  approveProposal, createProposalsFromTriggers, EvaluateTriggersInput,
  InvalidProposal, ProposalConflict, ProposalNotFound, rejectProposal,
  supabaseProposalStore, type ProposalStore,
} from "../learning/continual.js";
import { supabaseTrainingStore, type TrainingStore } from "../learning/training.js";

/**
 * Continual-loop proposal routes (F-12). Evaluating triggers only creates
 * proposals; converting one needs an operator and still leaves the training
 * run queued for its own approval step.
 */
const ApproveBody = z.object({
  datasetId: z.string().uuid().optional(),
  baseModelId: z.string().uuid().optional(),
  budgetUsd: z.number().positive().optional(),
}).strict();
const RejectBody = z.object({ reason: z.string().max(2000).optional() }).strict();

function fail(ctx: Parameters<ApiRoute["handler"]>[0], err: unknown): boolean {
  if (err instanceof ProposalNotFound) { sendJson(ctx.res, 404, { error: err.message }); return true; }
  if (err instanceof ProposalConflict) { sendJson(ctx.res, 409, { error: err.message }); return true; }
  if (err instanceof InvalidProposal) { sendJson(ctx.res, 400, { error: err.message }); return true; }
  return false;
}

export function continualRoutes(deps: { proposals?: ProposalStore; training?: TrainingStore } = {}): ApiRoute[] {
  const proposals = () => deps.proposals ?? supabaseProposalStore();
  const training = () => deps.training ?? supabaseTrainingStore();

  async function evaluate(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const parsed = EvaluateTriggersInput.safeParse(ctx.body);
    if (!parsed.success) {
      sendJson(ctx.res, 400, {
        error: "invalid trigger evaluation",
        issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
      });
      return;
    }
    try {
      const created = await createProposalsFromTriggers(
        { ...parsed.data, orgId: ctx.session!.orgId, actor: ctx.session!.subject },
        proposals(),
      );
      sendJson(ctx.res, 201, { proposals: created });
    } catch (err) {
      if (!fail(ctx, err)) throw err;
    }
  }

  async function list(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const rows = await proposals().listProposals(ctx.session!.orgId);
    sendJson(ctx.res, 200, { proposals: rows });
  }

  async function approve(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const parsed = ApproveBody.safeParse(ctx.body ?? {});
    if (!parsed.success) {
      sendJson(ctx.res, 400, { error: "invalid proposal approval", issues: parsed.error.issues.map((i) => i.message) });
      return;
    }
    try {
      const row = await approveProposal(
        { orgId: ctx.session!.orgId, id: ctx.params.id, approvedBy: ctx.session!.subject, ...parsed.data },
        proposals(),
        training(),
      );
      sendJson(ctx.res, 200, row);
    } catch (err) {
      if (!fail(ctx, err)) throw err;
    }
  }

  async function reject(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const parsed = RejectBody.safeParse(ctx.body ?? {});
    if (!parsed.success) {
      sendJson(ctx.res, 400, { error: "invalid proposal rejection", issues: parsed.error.issues.map((i) => i.message) });
      return;
    }
    try {
      const row = await rejectProposal(
        { orgId: ctx.session!.orgId, id: ctx.params.id, actor: ctx.session!.subject, reason: parsed.data.reason },
        proposals(),
      );
      sendJson(ctx.res, 200, row);
    } catch (err) {
      if (!fail(ctx, err)) throw err;
    }
  }

  return [
    { method: "GET", path: "/training-proposals", auth: "session", role: "reviewer", handler: list },
    { method: "POST", path: "/training-proposals/evaluate", auth: "session", role: "trainer", handler: evaluate },
    { method: "POST", path: "/training-proposals/:id/approve", auth: "session", role: "operator", handler: approve },
    { method: "POST", path: "/training-proposals/:id/reject", auth: "session", role: "operator", handler: reject },
  ];
}

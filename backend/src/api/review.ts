import { z } from "zod";
import { Label } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import {
  adjudicateLabel, DuplicateDispute, DisputeNotFound, fileLabelDispute, listLabelDisputes,
} from "../traces/adjudication.js";
import { sendJson, type ApiRoute } from "./server.js";

/**
 * Review surface (F-5): corrections on a trace and versioned label disputes.
 * Every handler resolves the trace inside the caller's org first; the service
 * role never touches a row the caller could not see.
 */
export const CorrectionInput = z.object({
  kind: z.enum(["approve", "reject", "edit", "reprompt", "label"]),
  before: z.record(z.unknown()).default({}),
  after: z.record(z.unknown()).default({}),
  note: z.string().max(2000).optional(),
}).strict();

export const AdjudicationInput = z.object({ label: Label.strict() }).strict();

interface TraceRowLite { id: string; run_id: string; at: string; payload: Record<string, unknown> | null }

async function traceFor(orgId: string, id: string): Promise<TraceRowLite | null> {
  const { data, error } = await serviceClient()
    .from("traces")
    .select("id, run_id, at, payload")
    .eq("org_id", orgId)
    .eq("id", id)
    .maybeSingle();
  if (error) throw new Error(`trace lookup failed: ${error.message}`);
  return (data as TraceRowLite | null) ?? null;
}

/**
 * The disputable auto-label for a trace. Most ground-truth rows carry no
 * Atomic GUID `stepId` (only proof/objective rows mint one); the trace row's
 * own identity is the stable step identity then, so filing a dispute never
 * needs a manual SQL insert just to invent one.
 */
export function autoLabelOf(trace: TraceRowLite): Label | null {
  const groundTruth = (trace.payload?.groundTruth ?? null) as Record<string, unknown> | null;
  if (!groundTruth) return null;
  const parsed = Label.safeParse({
    techniqueId: groundTruth.techniqueId,
    stepId: typeof groundTruth.stepId === "string" && groundTruth.stepId.length > 0 ? groundTruth.stepId : trace.id,
    actor: groundTruth.actor,
    outcome: groundTruth.outcome,
  });
  return parsed.success ? parsed.data : null;
}

async function listTraces(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  let query = serviceClient()
    .from("traces")
    .select("id, run_id, step_index, at, host_id, technique_id, actor, action, observation, outcome, matched, split, source, tombstoned_at, created_at")
    .eq("org_id", orgId)
    .order("created_at", { ascending: false })
    .limit(100);
  const actor = ctx.url.searchParams.get("actor");
  const outcome = ctx.url.searchParams.get("outcome");
  const techniqueId = ctx.url.searchParams.get("techniqueId");
  const runId = ctx.url.searchParams.get("runId");
  if (actor) query = query.eq("actor", actor);
  if (outcome) query = query.eq("outcome", outcome);
  if (techniqueId) query = query.eq("technique_id", techniqueId);
  if (runId) query = query.eq("run_id", runId);
  const { data, error } = await query;
  if (error) throw new Error(`traces unreadable: ${error.message}`);
  sendJson(ctx.res, 200, { traces: data ?? [] });
}

async function getTrace(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  const trace = await traceFor(orgId, ctx.params.id);
  if (!trace) {
    sendJson(ctx.res, 404, { error: "trace not found" });
    return;
  }
  const sb = serviceClient();
  const [corrections, disputes] = await Promise.all([
    sb.from("corrections").select("*").eq("org_id", orgId).eq("trace_id", trace.id).order("created_at", { ascending: false }),
    sb.from("label_disputes").select("*").eq("org_id", orgId).eq("run_id", trace.run_id).order("created_at", { ascending: false }),
  ]);
  if (corrections.error) throw new Error(`corrections unreadable: ${corrections.error.message}`);
  if (disputes.error) throw new Error(`disputes unreadable: ${disputes.error.message}`);
  sendJson(ctx.res, 200, { trace, corrections: corrections.data ?? [], disputes: disputes.data ?? [] });
}

async function addCorrection(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  const parsed = CorrectionInput.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid correction", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    return;
  }
  const trace = await traceFor(orgId, ctx.params.id);
  if (!trace) {
    sendJson(ctx.res, 404, { error: "trace not found" });
    return;
  }
  const { data, error } = await serviceClient().from("corrections").insert({
    org_id: orgId,
    trace_id: trace.id,
    reviewer: ctx.session!.subject,
    kind: parsed.data.kind,
    before: parsed.data.before,
    after: parsed.data.after,
    note: parsed.data.note ?? null,
  }).select("id, created_at").single();
  if (error) throw new Error(`correction insert failed: ${error.message}`);
  await audit({
    orgId, actor: ctx.session!.subject, action: "CORRECTION_RECORDED",
    subjectType: "trace", subjectId: trace.id,
    detail: { kind: parsed.data.kind, correctionId: data.id },
  });
  sendJson(ctx.res, 201, { id: data.id, kind: parsed.data.kind });
}

async function openDispute(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  const trace = await traceFor(orgId, ctx.params.id);
  if (!trace) {
    sendJson(ctx.res, 404, { error: "trace not found" });
    return;
  }
  const auto = autoLabelOf(trace);
  if (!auto) {
    sendJson(ctx.res, 409, { error: "trace has no complete ground-truth label to dispute" });
    return;
  }
  try {
    const dispute = await fileLabelDispute({
      orgId, runId: trace.run_id, stepAt: trace.at, auto, filedBy: ctx.session!.subject,
    });
    sendJson(ctx.res, 201, dispute);
  } catch (err) {
    if (err instanceof DuplicateDispute) {
      sendJson(ctx.res, 409, { error: err.message });
      return;
    }
    throw err;
  }
}

async function listDisputes(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const status = ctx.url.searchParams.get("status");
  if (status && status !== "pending" && status !== "adjudicated") {
    sendJson(ctx.res, 400, { error: "status must be pending or adjudicated" });
    return;
  }
  const disputes = await listLabelDisputes(ctx.session!.orgId, {
    runId: ctx.url.searchParams.get("runId") ?? undefined,
    status: (status as "pending" | "adjudicated" | null) ?? undefined,
  });
  sendJson(ctx.res, 200, { disputes });
}

async function adjudicate(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = AdjudicationInput.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid adjudication", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    return;
  }
  try {
    const dispute = await adjudicateLabel({
      orgId: ctx.session!.orgId,
      disputeId: ctx.params.id,
      label: parsed.data.label,
      reviewer: ctx.session!.subject,
    });
    sendJson(ctx.res, 200, dispute);
  } catch (err) {
    if (err instanceof DisputeNotFound) {
      sendJson(ctx.res, 404, { error: "dispute not found" });
      return;
    }
    throw err;
  }
}

export function reviewRoutes(): ApiRoute[] {
  return [
    { method: "GET", path: "/traces", auth: "session", role: "reviewer", handler: listTraces },
    { method: "GET", path: "/traces/:id", auth: "session", role: "reviewer", handler: getTrace },
    { method: "POST", path: "/traces/:id/corrections", auth: "session", role: "reviewer", handler: addCorrection },
    { method: "POST", path: "/traces/:id/disputes", auth: "session", role: "reviewer", handler: openDispute },
    { method: "GET", path: "/disputes", auth: "session", role: "reviewer", handler: listDisputes },
    { method: "POST", path: "/disputes/:id/adjudicate", auth: "session", role: "operator", handler: adjudicate },
  ];
}

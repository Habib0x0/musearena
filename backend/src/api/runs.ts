import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { sendJson, type ApiRoute } from "./server.js";

/**
 * Run and trace curation (CRUD closure).
 *
 * Traces are hash-chained and append-only (0011): curation tombstones rather
 * than deletes. A tombstoned trace is excluded from dataset builds and signal
 * runs but stays stored, readable and chained; tombstoning is reversible.
 *
 * Deleting a run tombstones its traces and removes its `runs` row (the runs
 * table has no such trigger). This works for capture-only runs — an external
 * harness's run with no platform `runs` row — keyed by `run_id` text.
 */

interface TraceLight { id: string; source: string; tombstoned_at: string | null }

async function tombstoneTraces(orgId: string, runId: string, actor: string, reason: string): Promise<number> {
  const sb = serviceClient();
  const { data: traces, error: traceError } = await sb.from("traces")
    .select("id, source, tombstoned_at").eq("org_id", orgId).eq("run_id", runId);
  if (traceError) throw new Error(`traces unreadable: ${traceError.message}`);
  const rows = (traces ?? []) as TraceLight[];
  const live = rows.filter((row) => !row.tombstoned_at);
  if (live.length === 0) return 0;
  const { error } = await sb.from("traces")
    .update({ tombstoned_at: new Date().toISOString(), tombstone_reason: reason })
    .eq("org_id", orgId).eq("run_id", runId).is("tombstoned_at", null);
  if (error) throw new Error(`trace tombstone failed: ${error.message}`);
  await audit({
    orgId, actor, action: "TRACE_DELETED", subjectType: "run", subjectId: runId,
    detail: { tombstoned: live.length, reason },
  });
  return live.length;
}

async function deleteRunRoute(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  const runId = ctx.params.id;
  const sb = serviceClient();
  const { count } = await sb.from("traces")
    .select("id", { count: "exact", head: true })
    .eq("org_id", orgId).eq("run_id", runId);
  const tombstoned = await tombstoneTraces(orgId, runId, ctx.session!.subject, `run deleted by ${ctx.session!.subject}`);
  // The runs row itself is deletable (no append-only trigger); traces,
  // corrections and disputes stay as the append-only history of the run.
  const { error: runError } = await sb.from("runs").delete().eq("org_id", orgId).eq("run_id", runId);
  if (runError) throw new Error(`runs delete failed: ${runError.message}`);
  await audit({
    orgId, actor: ctx.session!.subject, action: "RUN_DELETED", subjectType: "run", subjectId: runId,
    detail: { traces: tombstoned, totalTraces: count ?? 0 },
  });
  sendJson(ctx.res, 200, { ok: true, runId, tombstoned });
}

async function deleteTraceRoute(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  const sb = serviceClient();
  const { data, error } = await sb.from("traces")
    .select("id, run_id, source, tombstoned_at").eq("org_id", orgId).eq("id", ctx.params.id).maybeSingle();
  if (error) throw new Error(`trace lookup failed: ${error.message}`);
  const trace = data as { id: string; run_id: string; source: string; tombstoned_at: string | null } | null;
  if (!trace) {
    sendJson(ctx.res, 404, { error: "trace not found" });
    return;
  }
  if (trace.tombstoned_at) {
    sendJson(ctx.res, 200, { ok: true, id: trace.id, already: true });
    return;
  }
  if (trace.source !== "synthetic") {
    sendJson(ctx.res, 409, { error: `trace ${trace.id} is ${trace.source} evidence and cannot be deleted` });
    return;
  }
  const { error: updateError } = await sb.from("traces")
    .update({ tombstoned_at: new Date().toISOString(), tombstone_reason: `deleted by ${ctx.session!.subject}` })
    .eq("org_id", orgId).eq("id", trace.id);
  if (updateError) throw new Error(`trace tombstone failed: ${updateError.message}`);
  await audit({
    orgId, actor: ctx.session!.subject, action: "TRACE_DELETED", subjectType: "trace", subjectId: trace.id,
    detail: { runId: trace.run_id },
  });
  sendJson(ctx.res, 200, { ok: true, id: trace.id });
}

/** Restore a tombstoned trace (undo). */
async function restoreTraceRoute(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  const sb = serviceClient();
  const { data, error } = await sb.from("traces")
    .select("id, tombstoned_at").eq("org_id", orgId).eq("id", ctx.params.id).maybeSingle();
  if (error) throw new Error(`trace lookup failed: ${error.message}`);
  const trace = data as { id: string; tombstoned_at: string | null } | null;
  if (!trace) {
    sendJson(ctx.res, 404, { error: "trace not found" });
    return;
  }
  if (!trace.tombstoned_at) {
    sendJson(ctx.res, 200, { ok: true, id: trace.id, already: true });
    return;
  }
  const { error: updateError } = await sb.from("traces")
    .update({ tombstoned_at: null, tombstone_reason: null })
    .eq("org_id", orgId).eq("id", trace.id);
  if (updateError) throw new Error(`trace restore failed: ${updateError.message}`);
  await audit({
    orgId, actor: ctx.session!.subject, action: "TRACE_RESTORED", subjectType: "trace", subjectId: trace.id,
    detail: { restored: true },
  });
  sendJson(ctx.res, 200, { ok: true, id: trace.id, restored: true });
}

export function runRoutes(): ApiRoute[] {
  return [
    { method: "DELETE", path: "/runs/:id", auth: "session", role: "operator", handler: deleteRunRoute },
    { method: "DELETE", path: "/traces/:id", auth: "session", role: "operator", handler: deleteTraceRoute },
    { method: "PATCH", path: "/traces/:id/restore", auth: "session", role: "operator", handler: restoreTraceRoute },
  ];
}

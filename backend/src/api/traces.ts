import { z } from "zod";
import { CaptureTrace, type CaptureTrace as CaptureTraceT } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { newCaptureKey } from "./keys.js";
import { sendJson, type ApiRoute } from "./server.js";
import type { TraceRow } from "../training/traces.js";
import { applyContinualGraders } from "../learning/signals.js";
import { redactDeep } from "../observability/export.js";
import { canonicalJson } from "../lib/digest.js";

/**
 * Trace capture and capture-key routes (F-4).
 *
 * The capture endpoint shares the trace-row shape with an internal exercise
 * trace, so a dataset built later cannot tell an external harness's step from
 * a platform one. The org is always the key's org — never a body field.
 */

/** Shape one captured step into the row an internal publish would write. */
export function captureRow(body: CaptureTraceT, orgId: string): TraceRow {
  const at = new Date(body.at).toISOString();
  const actor = body.actor;
  const groundTruth = body.outcome
    ? {
        runId: body.runId,
        hostId: body.hostId,
        kind: "capture",
        actor,
        techniqueId: body.techniqueId,
        outcome: body.outcome,
        at,
      }
    : null;
  return redactDeep({
    org_id: orgId,
    run_id: body.runId,
    dataset_id: null,
    step_index: body.stepIndex,
    at,
    host_id: body.hostId,
    technique_id: body.techniqueId ?? null,
    actor,
    action: body.action ?? null,
    observation: body.observation ?? null,
    reasoning: body.reasoning ?? null,
    tool_call: body.toolCall ?? null,
    outcome: body.outcome ?? null,
    matched: body.matched,
    split: body.split,
    source: body.source,
    framework: body.framework ?? null,
    payload: {
      trajectory: {
        runId: body.runId,
        hostId: body.hostId || undefined,
        actor,
        observation: body.observation ?? "",
        reasoning: body.reasoning,
        toolCall: body.toolCall,
        action: body.action,
        techniqueId: body.techniqueId,
        at,
        ...(body.detail ? { detail: body.detail } : {}),
      },
      groundTruth,
      matched: body.matched,
    },
  });
}

const KeyName = z.object({ name: z.string().trim().min(1).max(80) }).strict();

async function captureTrace(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = CaptureTrace.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, {
      error: "invalid trace",
      issues: parsed.error.issues.map((issue) => ({ path: issue.path.join("."), message: issue.message })),
    });
    return;
  }
  const row = captureRow(parsed.data, ctx.orgId as string);
  // External capture is append-only: an identical retry is idempotent, but a
  // capture key can never rewrite a training trace that is already stored.
  const inserted = await serviceClient()
    .from("traces")
    .insert(row)
    .select("id")
    .single();
  let traceId = inserted.data?.id as string | undefined;
  if (inserted.error) {
    if (inserted.error.code !== "23505") throw new Error(`trace capture failed: ${inserted.error.message}`);
    const existing = await serviceClient()
      .from("traces")
      .select("id, at, host_id, technique_id, actor, action, observation, reasoning, tool_call, outcome, matched, split, payload")
      .eq("org_id", row.org_id)
      .eq("run_id", row.run_id)
      .eq("step_index", row.step_index)
      .maybeSingle();
    if (existing.error) throw new Error(`trace capture conflict check failed: ${existing.error.message}`);
    const current = existing.data as (TraceRow & { id: string }) | null;
    const comparable = (r: TraceRow) => canonicalJson({
      at: r.at, host_id: r.host_id, technique_id: r.technique_id, actor: r.actor, action: r.action,
      observation: r.observation, reasoning: r.reasoning, tool_call: r.tool_call, outcome: r.outcome,
      matched: r.matched, split: r.split, payload: r.payload,
    });
    if (!current || comparable(current) !== comparable(row)) {
      sendJson(ctx.res, 409, { error: "trace step already exists with different content" });
      return;
    }
    traceId = current.id;
  }
  // A newly arrived trace gets the org's enabled continual graders (F-6).
  await applyContinualGraders({ orgId: row.org_id, traceIds: [traceId as string] });
  sendJson(ctx.res, 202, { ok: true, runId: row.run_id, stepIndex: row.step_index });
}

async function issueKey(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = KeyName.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid key request", issues: parsed.error.issues.map((issue) => issue.message) });
    return;
  }
  const key = newCaptureKey();
  const { data, error } = await serviceClient()
    .from("capture_keys")
    .insert({ org_id: ctx.session!.orgId, name: parsed.data.name, key_prefix: key.prefix, key_hash: key.hash })
    .select("id")
    .single();
  if (error) throw new Error(`capture key insert failed: ${error.message}`);
  await audit({
    orgId: ctx.session!.orgId, actor: ctx.session!.subject, action: "CAPTURE_KEY_ISSUED",
    subjectType: "capture_key", subjectId: data.id as string, detail: { prefix: key.prefix, name: parsed.data.name },
  });
  // The raw key is returned once and never stored.
  sendJson(ctx.res, 201, { id: data.id, key: key.raw, prefix: key.prefix });
}

async function revokeKey(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  const { data, error } = await serviceClient()
    .from("capture_keys")
    .update({ revoked_at: new Date().toISOString() })
    .eq("org_id", orgId)
    .eq("id", ctx.params.id)
    .select("id")
    .maybeSingle();
  if (error) throw new Error(`capture key revoke failed: ${error.message}`);
  if (!data) {
    sendJson(ctx.res, 404, { error: "capture key not found" });
    return;
  }
  await audit({
    orgId, actor: ctx.session!.subject, action: "CAPTURE_KEY_REVOKED",
    subjectType: "capture_key", subjectId: ctx.params.id,
  });
  sendJson(ctx.res, 200, { ok: true, id: ctx.params.id });
}

async function listKeys(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const { data, error } = await serviceClient()
    .from("capture_keys")
    .select("id, name, key_prefix, last_used_at, revoked_at, created_at")
    .eq("org_id", ctx.session!.orgId)
    .order("created_at", { ascending: false });
  if (error) throw new Error(`capture keys unreadable: ${error.message}`);
  sendJson(ctx.res, 200, { keys: data ?? [] });
}

export function traceRoutes(): ApiRoute[] {
  return [
    { method: "POST", path: "/capture/v1/traces", auth: "capture", handler: captureTrace },
    { method: "POST", path: "/capture/v1/keys", auth: "session", role: "operator", handler: issueKey },
    { method: "GET", path: "/capture/v1/keys", auth: "session", role: "reviewer", handler: listKeys },
    { method: "POST", path: "/capture/v1/keys/:id/revoke", auth: "session", role: "operator", handler: revokeKey },
  ];
}

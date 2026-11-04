import { z } from "zod";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { sendJson, type ApiRoute } from "./server.js";

/**
 * Grader definitions (F-6, design §3.8). A model grader names its judge model
 * at definition time (`spec.model`), so every result can pin the exact judge —
 * a grader cannot later fall back to "whatever model is configured".
 */
const CreateGrader = z.object({
  name: z.string().trim().min(1).max(80),
  kind: z.enum(["rubric", "deterministic", "model"]),
  spec: z.record(z.unknown()),
  enabled: z.boolean().optional(),
}).strict();

const UpdateGrader = z.object({
  spec: z.record(z.unknown()).optional(),
  enabled: z.boolean().optional(),
}).strict();

export interface GraderRow {
  id: string;
  org_id: string;
  name: string;
  kind: "rubric" | "deterministic" | "model";
  spec: Record<string, unknown>;
  version: number;
  enabled: boolean;
  created_at: string;
}

async function graderFor(orgId: string, id: string): Promise<GraderRow | null> {
  const { data, error } = await serviceClient()
    .from("graders").select("*").eq("org_id", orgId).eq("id", id).maybeSingle();
  if (error) throw new Error(`grader lookup failed: ${error.message}`);
  return (data as GraderRow | null) ?? null;
}

async function getGraders(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const { data, error } = await serviceClient()
    .from("graders")
    .select("*")
    .eq("org_id", ctx.session!.orgId)
    .order("created_at", { ascending: false });
  if (error) throw new Error(`graders unreadable: ${error.message}`);
  sendJson(ctx.res, 200, { graders: data ?? [] });
}

async function postGrader(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = CreateGrader.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid grader", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    return;
  }
  if (parsed.data.kind === "model" && typeof parsed.data.spec.model !== "string") {
    sendJson(ctx.res, 400, { error: "a model grader must name its judge in spec.model" });
    return;
  }
  const sb = serviceClient();
  const { data: latest, error: readError } = await sb.from("graders")
    .select("version").eq("org_id", ctx.session!.orgId).eq("name", parsed.data.name)
    .order("version", { ascending: false }).limit(1).maybeSingle();
  if (readError) throw new Error(`grader version lookup failed: ${readError.message}`);
  const version = ((latest?.version as number | undefined) ?? 0) + 1;
  const { data, error } = await sb.from("graders").insert({
    org_id: ctx.session!.orgId,
    name: parsed.data.name,
    kind: parsed.data.kind,
    spec: parsed.data.spec,
    version,
    enabled: parsed.data.enabled ?? true,
  }).select("*").single();
  if (error) throw new Error(`grader insert failed: ${error.message}`);
  sendJson(ctx.res, 201, data);
}

/**
 * Edit a grader. A changed spec mints the next version of the same name (the
 * judge of a model grader stays pinned in that spec); flag-only edits update
 * the current row in place.
 */
async function patchGrader(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = UpdateGrader.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid grader update", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    return;
  }
  const grader = await graderFor(ctx.session!.orgId, ctx.params.id);
  if (!grader) {
    sendJson(ctx.res, 404, { error: "grader not found" });
    return;
  }
  const specChanged = parsed.data.spec !== undefined &&
    JSON.stringify(parsed.data.spec) !== JSON.stringify(grader.spec);
  if (parsed.data.spec !== undefined && specChanged && grader.kind === "model" &&
      typeof parsed.data.spec.model !== "string") {
    sendJson(ctx.res, 400, { error: "a model grader must name its judge in spec.model" });
    return;
  }
  await audit({
    orgId: ctx.session!.orgId, actor: ctx.session!.subject, action: "GRADER_UPDATED",
    subjectType: "grader", subjectId: grader.id,
    detail: { specChanged, ...(parsed.data.enabled !== undefined ? { enabled: parsed.data.enabled } : {}) },
  });
  if (specChanged) {
    // The new version supersedes: the old row is disabled so continual
    // grading applies the new spec only, never both.
    const { error: supersedeError } = await serviceClient().from("graders")
      .update({ enabled: false }).eq("org_id", ctx.session!.orgId).eq("id", grader.id);
    if (supersedeError) throw new Error(`grader supersede failed: ${supersedeError.message}`);
    const sb = serviceClient();
    const { data: latest, error: readError } = await sb.from("graders")
      .select("version").eq("org_id", ctx.session!.orgId).eq("name", grader.name)
      .order("version", { ascending: false }).limit(1).maybeSingle();
    if (readError) throw new Error(`grader version lookup failed: ${readError.message}`);
    const version = ((latest?.version as number | undefined) ?? 0) + 1;
    const { data, error } = await sb.from("graders").insert({
      org_id: ctx.session!.orgId,
      name: grader.name,
      kind: grader.kind,
      spec: parsed.data.spec,
      version,
      enabled: parsed.data.enabled ?? grader.enabled,
    }).select("*").single();
    if (error) throw new Error(`grader insert failed: ${error.message}`);
    sendJson(ctx.res, 200, data);
    return;
  }
  const fields: Record<string, unknown> = {};
  if (parsed.data.enabled !== undefined && parsed.data.enabled !== grader.enabled) fields.enabled = parsed.data.enabled;
  if (Object.keys(fields).length === 0) {
    sendJson(ctx.res, 200, grader);
    return;
  }
  const { data, error } = await serviceClient().from("graders")
    .update(fields).eq("org_id", ctx.session!.orgId).eq("id", grader.id)
    .select("*").single();
  if (error) throw new Error(`grader update failed: ${error.message}`);
  sendJson(ctx.res, 200, data);
}

async function deleteGrader(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const grader = await graderFor(ctx.session!.orgId, ctx.params.id);
  if (!grader) {
    sendJson(ctx.res, 404, { error: "grader not found" });
    return;
  }
  const { error } = await serviceClient().from("graders")
    .delete().eq("org_id", ctx.session!.orgId).eq("id", grader.id);
  if (error) throw new Error(`grader delete failed: ${error.message}`);
  await audit({
    orgId: ctx.session!.orgId, actor: ctx.session!.subject, action: "GRADER_DELETED",
    subjectType: "grader", subjectId: grader.id, detail: { name: grader.name, version: grader.version },
  });
  sendJson(ctx.res, 200, { ok: true, id: grader.id });
}

export function graderRoutes(): ApiRoute[] {
  return [
    { method: "GET", path: "/graders", auth: "session", role: "reviewer", handler: getGraders },
    { method: "POST", path: "/graders", auth: "session", role: "trainer", handler: postGrader },
    { method: "PATCH", path: "/graders/:id", auth: "session", role: "trainer", handler: patchGrader },
    { method: "DELETE", path: "/graders/:id", auth: "session", role: "trainer", handler: deleteGrader },
  ];
}

import type { EnvironmentSpec } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";
import { audit, verifyAuditChain } from "../lib/audit.js";
import { ApiError } from "./auth.js";
import { sendJson, type ApiContext, type ApiRoute } from "./server.js";
import {
  auditCsv, fromClerkRole, LIVE_STATUSES, limitViolations, monthStart, NO_LIMITS, parseLimitsPatch,
  toClerkRole, tokensByModel, usageFor, CLERK_ROLES,
  type AuditRowLite, type DeploymentLite, type OrgLimits, type AdminRole,
} from "../admin/core.js";
import { estimateCostPerHour } from "../designer/cost.js";
import { MODAL_API_BASE, MODAL_GLIMMER_API_BASE, META_API_BASE } from "../lib/model.js";

/**
 * Admin routes: audit log, fleet control, limits, usage, members and
 * integrations. Reads need the reviewer role; anything that changes state
 * needs operator and writes an audit entry. Rows are always scoped to the
 * caller's org from the verified session, never from the request.
 */

const AUDIT_COLS = "id, actor, action, subject_type, subject_id, detail, entry_hash, prev_hash, created_at";

async function auditList(ctx: ApiContext): Promise<void> {
  const orgId = ctx.session!.orgId;
  const limit = Math.min(Math.max(Number(ctx.url.searchParams.get("limit") ?? 100) || 100, 1), 500);
  const before = Number(ctx.url.searchParams.get("before"));
  const action = ctx.url.searchParams.get("action");
  let q = serviceClient().from("audit_log").select(AUDIT_COLS).eq("org_id", orgId).order("id", { ascending: false }).limit(limit);
  if (Number.isFinite(before) && before > 0) q = q.lt("id", before);
  if (action) q = q.eq("action", action);
  const { data, error } = await q;
  if (error) throw new Error(`audit_log unreadable: ${error.message}`);
  sendJson(ctx.res, 200, { entries: data ?? [] });
}

async function auditVerify(ctx: ApiContext): Promise<void> {
  const broken = await verifyAuditChain(ctx.session!.orgId);
  sendJson(ctx.res, 200, { valid: broken === null, broken, checkedAt: new Date().toISOString() });
}

async function auditExport(ctx: ApiContext): Promise<void> {
  const orgId = ctx.session!.orgId;
  const rows: AuditRowLite[] = [];
  // Page through the whole chain in id order; the export is the full record.
  for (let after = 0; ; ) {
    const { data, error } = await serviceClient().from("audit_log").select(AUDIT_COLS)
      .eq("org_id", orgId).gt("id", after).order("id", { ascending: true }).limit(1000);
    if (error) throw new Error(`audit_log unreadable: ${error.message}`);
    const page = (data ?? []) as AuditRowLite[];
    rows.push(...page);
    if (page.length < 1000) break;
    after = page.at(-1)!.id;
  }
  ctx.res.writeHead(200, {
    "Content-Type": "text/csv; charset=utf-8",
    "Content-Disposition": `attachment; filename="musearena-audit-${new Date().toISOString().slice(0, 10)}.csv"`,
  }).end(auditCsv(rows));
}

type DeploymentRow = { id: string; status: string; created_at: string; stack_id: string; access_info: Record<string, unknown> | null; environments: { spec: EnvironmentSpec } | null };

async function orgDeployments(orgId: string, sinceIso?: string): Promise<DeploymentRow[]> {
  let q = serviceClient().from("deployments").select("id, status, created_at, stack_id, access_info, environments(spec)").eq("org_id", orgId).order("created_at", { ascending: false });
  if (sinceIso) q = q.or(`created_at.gte.${sinceIso},status.in.(${LIVE_STATUSES.join(",")})`);
  const { data, error } = await q.limit(1000);
  if (error) throw new Error(`deployments unreadable: ${error.message}`);
  return (data ?? []) as unknown as DeploymentRow[];
}

const lite = (d: DeploymentRow): DeploymentLite => ({ id: d.id, status: d.status, created_at: d.created_at, access_info: d.access_info, spec: d.environments?.spec ?? null });

async function fleet(ctx: ApiContext): Promise<void> {
  const rows = await orgDeployments(ctx.session!.orgId);
  const now = Date.now();
  const labs = rows.filter((d) => LIVE_STATUSES.includes(d.status)).map((d) => {
    const spec = d.environments?.spec;
    const ttl = spec?.budgets?.ttlHours ?? null;
    return {
      id: d.id, status: d.status, createdAt: d.created_at, name: spec?.name ?? "—",
      vms: spec ? spec.instances.filter((i) => i.runtime === "vm").length : 0,
      dollarsPerHour: spec ? estimateCostPerHour(spec) : null,
      expiresAt: ttl ? new Date(Date.parse(d.created_at) + ttl * 3_600_000).toISOString() : null,
      ageMinutes: Math.round((now - Date.parse(d.created_at)) / 60_000),
      worker: (d.access_info?.workerId as string | undefined) ?? null,
      platform: (d.access_info?.platform as Record<string, string> | undefined) ?? spec?.platform ?? null,
    };
  });
  const recent = rows.filter((d) => !LIVE_STATUSES.includes(d.status)).slice(0, 20).map((d) => ({
    id: d.id, status: d.status, createdAt: d.created_at, name: d.environments?.spec?.name ?? "—",
    failure: (d.access_info?.failure as { stage?: string; error?: string } | undefined) ?? null,
  }));
  sendJson(ctx.res, 200, { labs, recent });
}

/** Seam for tests: cancel the deployment workflow so it tears down through its own path. */
export type WorkflowCanceller = (workflowId: string) => Promise<void>;
let cancelWorkflow: WorkflowCanceller = async (workflowId) => {
  const { Client, Connection } = await import("@temporalio/client");
  const connection = await Connection.connect({ address: process.env.TEMPORAL_ADDRESS ?? "localhost:7234" });
  try {
    const client = new Client({ connection, namespace: process.env.TEMPORAL_NAMESPACE ?? "default" });
    await client.workflow.getHandle(workflowId).cancel();
  } finally {
    await connection.close();
  }
};
export function setWorkflowCanceller(fn: WorkflowCanceller): void { cancelWorkflow = fn; }
/** The live workflow canceller, for other route modules (environment delete). */
export function workflowCanceller(): WorkflowCanceller { return cancelWorkflow; }

async function stopLab(ctx: ApiContext): Promise<void> {
  const orgId = ctx.session!.orgId;
  const id = ctx.params.id;
  const sb = serviceClient();
  const { data, error } = await sb.from("deployments").select("id, status, access_info").eq("id", id).eq("org_id", orgId).maybeSingle();
  if (error) throw new Error(`deployment unreadable: ${error.message}`);
  if (!data) throw new ApiError(404, "no such lab in this organization");
  const row = data as { status: string; access_info: Record<string, unknown> | null };
  if (!LIVE_STATUSES.includes(row.status)) throw new ApiError(409, `lab is already ${row.status}`);
  const stoppedAt = new Date().toISOString();
  let how: string;
  if (row.status === "pending") {
    // Not claimed by a worker: no resources exist. The guard on status makes
    // this lose cleanly to a worker that claims it in the same instant.
    const { data: upd, error: e } = await sb.from("deployments")
      .update({ status: "failed", access_info: { ...(row.access_info ?? {}), stoppedAt, stoppedBy: ctx.session!.subject, resourcesDestroyed: true, failure: { stage: "admin", error: "stopped by an operator before it started", at: stoppedAt } } })
      .eq("id", id).eq("status", "pending").select("id");
    if (e) throw new Error(`stop failed: ${e.message}`);
    if (!upd?.length) throw new ApiError(409, "a worker claimed this lab just now; stop it again");
    how = "cancelled before provisioning";
  } else {
    // A claimed lab is torn down by its own workflow (cancellation runs the
    // same teardown path as TTL), so resources and the row stay consistent.
    try {
      await cancelWorkflow(`deployment-${id}`);
    } catch (err) {
      throw new ApiError(502, `could not reach the workflow service to stop this lab: ${err instanceof Error ? err.message : String(err)}`);
    }
    how = "teardown requested from its workflow";
  }
  await audit({ orgId, actor: ctx.session!.subject, action: "ADMIN_LAB_STOPPED", subjectType: "deployment", subjectId: id, detail: { previousStatus: row.status, how } });
  sendJson(ctx.res, 200, { id, stopped: true, how });
}

const MISSING_TABLE = /does not exist|schema cache|Could not find/i;

async function readLimits(orgId: string): Promise<OrgLimits> {
  const { data, error } = await serviceClient().from("org_limits").select("*").eq("org_id", orgId).maybeSingle();
  if (error && MISSING_TABLE.test(error.message)) throw new ApiError(503, "limits are not available yet: apply migration 0019_org_limits.sql to the database");
  if (error) throw new Error(`org_limits unreadable: ${error.message}`);
  return data ? { ...NO_LIMITS, ...(data as Partial<OrgLimits>) } : NO_LIMITS;
}

async function getLimits(ctx: ApiContext): Promise<void> {
  sendJson(ctx.res, 200, { limits: await readLimits(ctx.session!.orgId) });
}

async function putLimits(ctx: ApiContext): Promise<void> {
  const orgId = ctx.session!.orgId;
  let patch: Partial<OrgLimits>;
  try { patch = parseLimitsPatch(ctx.body); } catch (err) { throw new ApiError(400, (err as Error).message); }
  const before = await readLimits(orgId);
  const next = { ...before, ...patch };
  const { error } = await serviceClient().from("org_limits").upsert({ org_id: orgId, ...next, updated_by: ctx.session!.subject, updated_at: new Date().toISOString() });
  if (error) throw new Error(`org_limits write failed: ${error.message}`);
  await audit({ orgId, actor: ctx.session!.subject, action: "ADMIN_LIMITS_UPDATED", subjectType: "org", subjectId: orgId, detail: { before, after: next } });
  sendJson(ctx.res, 200, { limits: next });
}

/** Limits check the worker runs before it claims a pending deployment. */
export async function checkOrgLimits(orgId: string, spec: EnvironmentSpec, candidateId: string): Promise<string[]> {
  const limits = await readLimits(orgId).catch((err: Error) => {
    // A missing table (migration not applied yet) means no limits configured.
    if (err instanceof ApiError && err.status === 503) return NO_LIMITS;
    throw err;
  });
  if (limits === NO_LIMITS) return [];
  const now = new Date();
  const rows = await orgDeployments(orgId, monthStart(now).toISOString());
  const live = rows.filter((d) => d.id !== candidateId && LIVE_STATUSES.includes(d.status) && d.status !== "pending").length;
  const spent = usageFor(rows.filter((d) => d.id !== candidateId).map(lite), monthStart(now), now, now).estimatedUsd;
  return limitViolations(limits, spec, live, spent);
}

async function usage(ctx: ApiContext): Promise<void> {
  const orgId = ctx.session!.orgId;
  const now = new Date();
  const days = Math.min(Math.max(Number(ctx.url.searchParams.get("days") ?? 30) || 30, 1), 366);
  const since = new Date(now.getTime() - days * 86_400_000);
  const from = since < monthStart(now) ? since : monthStart(now);
  const rows = (await orgDeployments(orgId, from.toISOString())).map(lite);
  const daily: { day: string; vmHours: number; estimatedUsd: number; labs: number }[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const start = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - i));
    const end = new Date(start.getTime() + 86_400_000);
    const u = usageFor(rows, start, end, now);
    daily.push({ day: start.toISOString().slice(0, 10), vmHours: u.vmHours, estimatedUsd: u.estimatedUsd, labs: u.labs });
  }
  const { data: scored, error } = await serviceClient().from("audit_log").select("detail")
    .eq("org_id", orgId).eq("action", "SCORE_COMPUTED").gte("created_at", since.toISOString()).limit(2000);
  if (error) throw new Error(`audit_log unreadable: ${error.message}`);
  const limits = await readLimits(orgId).catch(() => NO_LIMITS);
  sendJson(ctx.res, 200, {
    period: usageFor(rows, since, now, now),
    monthToDate: usageFor(rows, monthStart(now), now, now),
    monthlyBudgetUsd: limits.monthly_budget_usd,
    daily,
    tokensByModel: tokensByModel((scored ?? []) as { detail: Record<string, unknown> | null }[]),
    note: "Spend is an estimate from the platform cost table (VM role rates + 20% buffer), not a provider invoice. Token counts come from agent runs.",
  });
}

// ---- Members (Clerk organization memberships) ----

async function clerk(path: string, init: RequestInit = {}): Promise<unknown> {
  const key = process.env.CLERK_SECRET_KEY;
  if (!key) throw new ApiError(503, "member management needs CLERK_SECRET_KEY on the API host");
  const res = await fetch(`https://api.clerk.com/v1${path}`, {
    ...init, headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json", ...(init.headers ?? {}) },
  });
  const body = await res.json().catch(() => null) as { errors?: { message?: string; long_message?: string }[] } | null;
  if (!res.ok) throw new ApiError(res.status === 404 ? 404 : 502, `Clerk ${res.status}: ${body?.errors?.[0]?.long_message ?? body?.errors?.[0]?.message ?? "request failed"}`);
  return body;
}

async function members(ctx: ApiContext): Promise<void> {
  const orgId = ctx.session!.orgId;
  const [m, inv] = await Promise.all([
    clerk(`/organizations/${encodeURIComponent(orgId)}/memberships?limit=100`) as Promise<{ data: { role: string; public_user_data?: { user_id?: string; identifier?: string; first_name?: string | null; last_name?: string | null }; created_at?: number }[] }>,
    clerk(`/organizations/${encodeURIComponent(orgId)}/invitations?status=pending&limit=100`) as Promise<{ data: { id: string; email_address: string; role: string; created_at?: number }[] }>,
  ]);
  sendJson(ctx.res, 200, {
    members: m.data.map((x) => ({
      userId: x.public_user_data?.user_id ?? "", email: x.public_user_data?.identifier ?? "",
      name: [x.public_user_data?.first_name, x.public_user_data?.last_name].filter(Boolean).join(" "),
      role: fromClerkRole(x.role) ?? x.role, joinedAt: x.created_at ? new Date(x.created_at).toISOString() : null,
    })),
    invitations: inv.data.map((x) => ({ id: x.id, email: x.email_address, role: fromClerkRole(x.role) ?? x.role })),
    roles: CLERK_ROLES,
  });
}

const parseRole = (v: unknown): AdminRole => {
  if (typeof v !== "string" || !(CLERK_ROLES as readonly string[]).includes(v)) throw new ApiError(400, `role must be one of ${CLERK_ROLES.join(", ")}`);
  return v as AdminRole;
};

async function invite(ctx: ApiContext): Promise<void> {
  const orgId = ctx.session!.orgId;
  const b = (ctx.body ?? {}) as { email?: unknown; role?: unknown };
  if (typeof b.email !== "string" || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(b.email)) throw new ApiError(400, "a valid email is required");
  const role = parseRole(b.role);
  await clerk(`/organizations/${encodeURIComponent(orgId)}/invitations`, { method: "POST", body: JSON.stringify({ email_address: b.email, role: toClerkRole(role), inviter_user_id: ctx.session!.subject }) });
  await audit({ orgId, actor: ctx.session!.subject, action: "ADMIN_MEMBER_INVITED", subjectType: "member", subjectId: b.email, detail: { role } });
  sendJson(ctx.res, 201, { invited: b.email, role });
}

async function setRole(ctx: ApiContext): Promise<void> {
  const orgId = ctx.session!.orgId;
  const userId = ctx.params.userId;
  const role = parseRole((ctx.body as { role?: unknown } | undefined)?.role);
  if (userId === ctx.session!.subject && role !== "operator") throw new ApiError(409, "you cannot remove your own operator role; ask another operator");
  await clerk(`/organizations/${encodeURIComponent(orgId)}/memberships/${encodeURIComponent(userId)}`, { method: "PATCH", body: JSON.stringify({ role: toClerkRole(role) }) });
  await audit({ orgId, actor: ctx.session!.subject, action: "ADMIN_MEMBER_ROLE_CHANGED", subjectType: "member", subjectId: userId, detail: { role } });
  sendJson(ctx.res, 200, { userId, role });
}

async function removeMember(ctx: ApiContext): Promise<void> {
  const orgId = ctx.session!.orgId;
  const userId = ctx.params.userId;
  if (userId === ctx.session!.subject) throw new ApiError(409, "you cannot remove yourself; ask another operator");
  await clerk(`/organizations/${encodeURIComponent(orgId)}/memberships/${encodeURIComponent(userId)}`, { method: "DELETE" });
  await audit({ orgId, actor: ctx.session!.subject, action: "ADMIN_MEMBER_REMOVED", subjectType: "member", subjectId: userId });
  sendJson(ctx.res, 200, { removed: userId });
}

// ---- Integrations ----

const set = (...keys: string[]) => keys.every((k) => Boolean(process.env[k]));

/** Which model and service integrations this host has. Never returns a secret, only whether it is set. */
export function integrationStatus(): { name: string; kind: string; configured: boolean; endpoint: string | null; detail: string }[] {
  return [
    { name: "Muse Spark Open (Modal)", kind: "model", configured: set("MODAL_PROXY_TOKEN_ID", "MODAL_PROXY_TOKEN_SECRET"), endpoint: process.env.MODAL_BASE_URL || MODAL_API_BASE, detail: "red, blue, designer" },
    { name: "Muse Glimmer 30B (Modal)", kind: "model", configured: set("MODAL_PROXY_TOKEN_ID", "MODAL_PROXY_TOKEN_SECRET") || set("MODAL_GLIMMER_PROXY_TOKEN_ID", "MODAL_GLIMMER_PROXY_TOKEN_SECRET"), endpoint: process.env.MODAL_GLIMMER_BASE_URL || process.env.MODAL_PERSONA_BASE_URL || MODAL_GLIMMER_API_BASE, detail: "employee agents; scales to zero" },
    { name: "Meta Model API", kind: "model", configured: set("META_API_KEY"), endpoint: process.env.META_BASE_URL || META_API_BASE, detail: "muse-spark-1.x, muse-wonder-1.0" },
    { name: "Supabase", kind: "data", configured: set("SUPABASE_URL") && (set("SUPABASE_SECRET_KEY") || set("SUPABASE_SERVICE_ROLE_KEY")), endpoint: process.env.SUPABASE_URL ?? null, detail: "rows, audit log, datasets" },
    { name: "Temporal", kind: "workflow", configured: true, endpoint: process.env.TEMPORAL_ADDRESS ?? "localhost:7234", detail: "deployment workflows; fleet stop" },
    { name: "Clerk", kind: "identity", configured: set("CLERK_SECRET_KEY"), endpoint: "https://api.clerk.com", detail: "sign-in; member management needs the secret key" },
    { name: "Langfuse", kind: "observability", configured: set("LANGFUSE_HOST", "LANGFUSE_PUBLIC_KEY", "LANGFUSE_SECRET_KEY"), endpoint: process.env.LANGFUSE_HOST ?? null, detail: "optional agent trace export" },
    { name: "Model trainer", kind: "training", configured: set("META_TRAINER_URL"), endpoint: process.env.META_TRAINER_URL || null, detail: "training runs wait for this" },
  ];
}

async function probe(url: string, headers: Record<string, string>): Promise<{ ok: boolean; status: number | null; ms: number; detail?: string }> {
  const t0 = Date.now();
  try {
    const r = await fetch(url, { headers, signal: AbortSignal.timeout(8000) });
    return { ok: r.ok, status: r.status, ms: Date.now() - t0 };
  } catch (err) {
    return { ok: false, status: null, ms: Date.now() - t0, detail: err instanceof Error ? err.message : String(err) };
  }
}

async function integrations(ctx: ApiContext): Promise<void> {
  const list = integrationStatus();
  const checks: Record<string, unknown> = {};
  if (ctx.url.searchParams.get("probe") === "1") {
    const modal = `Bearer ${process.env.MODAL_PROXY_TOKEN_ID}.${process.env.MODAL_PROXY_TOKEN_SECRET}`;
    if (list[0].configured) checks[list[0].name] = await probe(`${list[0].endpoint}/models`, { Authorization: modal });
    if (list[2].configured) checks[list[2].name] = await probe(`${list[2].endpoint}/models`, { Authorization: `Bearer ${process.env.META_API_KEY}` });
    // Glimmer is not probed: any request wakes a GPU container for minutes.
  }
  sendJson(ctx.res, 200, { integrations: list, checks, rotation: "Secrets live in the API host's environment, not in the database. Rotate a key at its provider, update the host environment, then restart the API and worker." });
}

export function adminRoutes(): ApiRoute[] {
  return [
    { method: "GET", path: "/admin/audit", auth: "session", role: "reviewer", handler: auditList },
    { method: "GET", path: "/admin/audit/verify", auth: "session", role: "reviewer", handler: auditVerify },
    { method: "GET", path: "/admin/audit/export", auth: "session", role: "operator", handler: auditExport },
    { method: "GET", path: "/admin/fleet", auth: "session", role: "reviewer", handler: fleet },
    { method: "POST", path: "/admin/fleet/:id/stop", auth: "session", role: "operator", handler: stopLab },
    { method: "GET", path: "/admin/limits", auth: "session", role: "reviewer", handler: getLimits },
    { method: "PUT", path: "/admin/limits", auth: "session", role: "operator", handler: putLimits },
    { method: "GET", path: "/admin/usage", auth: "session", role: "reviewer", handler: usage },
    { method: "GET", path: "/admin/members", auth: "session", role: "operator", handler: members },
    { method: "POST", path: "/admin/members/invite", auth: "session", role: "operator", handler: invite },
    { method: "PATCH", path: "/admin/members/:userId", auth: "session", role: "operator", handler: setRole },
    { method: "DELETE", path: "/admin/members/:userId", auth: "session", role: "operator", handler: removeMember },
    { method: "GET", path: "/admin/integrations", auth: "session", role: "operator", handler: integrations },
  ];
}

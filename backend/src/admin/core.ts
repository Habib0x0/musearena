import type { EnvironmentSpec } from "@musearena/shared";
import { estimateCostPerHour } from "../designer/cost.js";

/**
 * Pure admin logic (audit CSV, usage, limits). The API module reads rows and
 * calls these, so every rule here is unit-tested without a database.
 */

export interface AuditRowLite {
  id: number; actor: string; action: string; subject_type: string; subject_id: string;
  detail: Record<string, unknown> | null; entry_hash: string; prev_hash: string | null; created_at: string;
}

const csvCell = (v: unknown): string => {
  const s = v === null || v === undefined ? "" : typeof v === "string" ? v : JSON.stringify(v);
  // Quote every cell; a leading = + - @ is neutralised so a spreadsheet never evaluates it.
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return `"${safe.replace(/"/g, '""')}"`;
};

export function auditCsv(rows: AuditRowLite[]): string {
  const head = ["id", "created_at", "actor", "action", "subject_type", "subject_id", "detail", "prev_hash", "entry_hash"];
  const body = rows.map((r) => [r.id, r.created_at, r.actor, r.action, r.subject_type, r.subject_id, r.detail ?? {}, r.prev_hash, r.entry_hash].map(csvCell).join(","));
  return [head.join(","), ...body].join("\n") + "\n";
}

export interface DeploymentLite {
  id: string; status: string; created_at: string;
  access_info?: Record<string, unknown> | null;
  spec?: EnvironmentSpec | null;
}

/** Labs that may still hold resources or work (not finished, not refused). */
export const LIVE_STATUSES = ["pending", "provisioning", "configuring", "verifying", "exercising", "ready", "destroying"];

const endOf = (d: DeploymentLite, now: Date): number => {
  const info = d.access_info ?? {};
  const ended = (info.destroyedAt ?? info.stoppedAt) as string | undefined;
  if (ended && Number.isFinite(Date.parse(ended))) return Date.parse(ended);
  return LIVE_STATUSES.includes(d.status) ? now.getTime() : Date.parse(d.created_at);
};

export interface UsagePeriod {
  from: string; to: string;
  labs: number; vmHours: number; estimatedUsd: number;
}

/**
 * VM-hours and estimated spend inside [from, to): each lab contributes the
 * overlap of its lifetime with the window, times its VM count and its
 * estimated $/hour. Estimates use the platform's own cost table.
 */
export function usageFor(deployments: DeploymentLite[], from: Date, to: Date, now = new Date()): UsagePeriod {
  let labs = 0, vmHours = 0, usd = 0;
  for (const d of deployments) {
    if (!d.spec) continue;
    const start = Math.max(Date.parse(d.created_at), from.getTime());
    const end = Math.min(endOf(d, now), to.getTime());
    if (!(end > start)) continue;
    const hours = (end - start) / 3_600_000;
    const vms = d.spec.instances.filter((i) => i.runtime === "vm").length;
    labs += 1;
    vmHours += hours * vms;
    usd += hours * estimateCostPerHour(d.spec);
  }
  return { from: from.toISOString(), to: to.toISOString(), labs, vmHours: round2(vmHours), estimatedUsd: round2(usd) };
}

const round2 = (n: number) => Math.round(n * 100) / 100;

export const monthStart = (now: Date) => new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));

/** Model tokens per model from SCORE_COMPUTED audit rows that carry agent states. */
export function tokensByModel(rows: { detail: Record<string, unknown> | null }[]): Record<string, { input: number; output: number; runs: number }> {
  const out: Record<string, { input: number; output: number; runs: number }> = {};
  for (const r of rows) {
    const states = (r.detail?.agentStates ?? null) as Record<string, { inputTokens?: number; outputTokens?: number; modelId?: string }> | null;
    if (!states) continue;
    const seen = new Set<string>();
    for (const s of Object.values(states)) {
      const id = s.modelId ?? "unknown";
      const m = (out[id] ??= { input: 0, output: 0, runs: 0 });
      m.input += s.inputTokens ?? 0;
      m.output += s.outputTokens ?? 0;
      if (!seen.has(id)) { m.runs += 1; seen.add(id); }
    }
  }
  return out;
}

export interface OrgLimits {
  max_concurrent_labs: number | null;
  max_vms_per_lab: number | null;
  max_dollars_per_hour: number | null;
  monthly_budget_usd: number | null;
  max_ttl_hours: number | null;
  paused: boolean;
}

export const NO_LIMITS: OrgLimits = {
  max_concurrent_labs: null, max_vms_per_lab: null, max_dollars_per_hour: null,
  monthly_budget_usd: null, max_ttl_hours: null, paused: false,
};

/**
 * Every limit a new lab would break, named. Empty means it may start.
 * `liveLabs` excludes the candidate itself.
 */
export function limitViolations(limits: OrgLimits, spec: EnvironmentSpec, liveLabs: number, monthSpendUsd: number): string[] {
  const out: string[] = [];
  const num = (v: unknown) => (v === null || v === undefined ? null : Number(v));
  if (limits.paused) out.push("organization is paused by an operator (emergency stop)");
  const conc = num(limits.max_concurrent_labs);
  if (conc !== null && liveLabs >= conc) out.push(`concurrent labs: ${liveLabs} running, limit ${conc}`);
  const vms = spec.instances.filter((i) => i.runtime === "vm").length;
  const maxVms = num(limits.max_vms_per_lab);
  if (maxVms !== null && vms > maxVms) out.push(`VMs per lab: ${vms}, limit ${maxVms}`);
  const perHour = estimateCostPerHour(spec);
  const maxHour = num(limits.max_dollars_per_hour);
  if (maxHour !== null && perHour > maxHour) out.push(`estimated $${perHour}/hr, limit $${maxHour}/hr`);
  const maxTtl = num(limits.max_ttl_hours);
  if (maxTtl !== null && spec.budgets.ttlHours > maxTtl) out.push(`TTL ${spec.budgets.ttlHours}h, limit ${maxTtl}h`);
  const budget = num(limits.monthly_budget_usd);
  const projected = round2(monthSpendUsd + perHour * spec.budgets.ttlHours);
  if (budget !== null && projected > budget) out.push(`monthly budget: $${round2(monthSpendUsd)} spent + $${round2(perHour * spec.budgets.ttlHours)} for this lab > $${budget}`);
  return out;
}

const LIMIT_KEYS = ["max_concurrent_labs", "max_vms_per_lab", "max_dollars_per_hour", "monthly_budget_usd", "max_ttl_hours"] as const;

/** Validate an operator's limits update; null clears a limit. */
export function parseLimitsPatch(body: unknown): Partial<OrgLimits> {
  if (!body || typeof body !== "object" || Array.isArray(body)) throw new Error("body must be an object");
  const src = body as Record<string, unknown>;
  const out: Partial<OrgLimits> = {};
  for (const [k, v] of Object.entries(src)) {
    if (k === "paused") {
      if (typeof v !== "boolean") throw new Error("paused must be true or false");
      out.paused = v;
    } else if ((LIMIT_KEYS as readonly string[]).includes(k)) {
      if (v === null) { (out as Record<string, unknown>)[k] = null; continue; }
      if (typeof v !== "number" || !Number.isFinite(v) || v < 0) throw new Error(`${k} must be a non-negative number or null`);
      if (k === "max_ttl_hours" && v === 0) throw new Error("max_ttl_hours must be greater than 0");
      if ((k === "max_concurrent_labs" || k === "max_vms_per_lab") && !Number.isInteger(v)) throw new Error(`${k} must be a whole number`);
      (out as Record<string, unknown>)[k] = v;
    } else {
      throw new Error(`unknown field ${k}`);
    }
  }
  return out;
}

/** Clerk org role key for a MuseArena role, and back. */
export const CLERK_ROLES = ["reviewer", "trainer", "operator"] as const;
export type AdminRole = (typeof CLERK_ROLES)[number];
export const toClerkRole = (role: AdminRole) => `org:${role}`;
export function fromClerkRole(role: string): AdminRole | null {
  const r = role.replace(/^org:/, "");
  return (CLERK_ROLES as readonly string[]).includes(r) ? (r as AdminRole) : null;
}

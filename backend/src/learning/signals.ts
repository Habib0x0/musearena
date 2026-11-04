import { z } from "zod";
import { serviceClient } from "../lib/supabase.js";
import type { ModelClient } from "../lib/model.js";
import type { TraceRow } from "../training/traces.js";
import { resolveModel } from "./models.js";

/**
 * Signals and continual grading (F-6, design §3.3 + §12.18).
 *
 * A rule signal is a closed predicate over trace columns — never an expression
 * language, so a stored signal cannot become a query. A model signal names its
 * judge at definition time and pins that judge's ID into every result. A hit is
 * unique per `(signal, trace)`: re-running an unchanged signal cannot duplicate
 * it. A signal marked `continual` is applied when new traces arrive.
 */
export const RULE_FIELDS = ["actor", "techniqueId", "outcome", "hostId", "action", "observation", "matched"] as const;
export const RULE_OPS = ["eq", "ne", "in", "prefix", "exists"] as const;

const Condition = z.object({
  field: z.enum(RULE_FIELDS),
  op: z.enum(RULE_OPS),
  value: z.union([z.string(), z.number(), z.boolean(), z.array(z.string())]).optional(),
}).strict();

export const RuleDefinition = z.object({
  match: z.enum(["all", "any"]).default("all"),
  conditions: z.array(Condition).min(1),
}).strict();
export type RuleDefinition = z.infer<typeof RuleDefinition>;

/** A model judge is pinned at definition time, never chosen at run time. */
export const ModelDefinition = z.object({
  model: z.string().min(1),
  question: z.string().trim().min(1).max(2000),
}).strict();
export type ModelDefinition = z.infer<typeof ModelDefinition>;

const JudgeVerdict = z.object({
  matched: z.boolean(),
  score: z.number().min(0).max(1),
  rationale: z.string().max(1000),
});

export type SignalKind = "rule" | "model" | "human";

export interface SignalRow {
  id: string;
  org_id: string;
  name: string;
  kind: SignalKind;
  definition: Record<string, unknown>;
  version: number;
  enabled: boolean;
  continual: boolean;
  created_at: string;
}

export class SignalNotFound extends Error {}
export class UnsupportedSignalKind extends Error {}
export class SignalDisabled extends Error {}

function fieldOf(trace: TraceRow, field: (typeof RULE_FIELDS)[number]): unknown {
  switch (field) {
    case "actor": return trace.actor;
    case "techniqueId": return trace.technique_id;
    case "outcome": return trace.outcome;
    case "hostId": return trace.host_id;
    case "action": return trace.action;
    case "observation": return trace.observation;
    case "matched": return trace.matched;
  }
}

function conditionMatches(condition: z.infer<typeof Condition>, trace: TraceRow): boolean {
  const actual = fieldOf(trace, condition.field);
  switch (condition.op) {
    case "exists":
      return condition.value === false ? actual === null || actual === undefined : actual !== null && actual !== undefined;
    case "eq": return actual === condition.value;
    case "ne": return actual !== condition.value;
    case "in": return Array.isArray(condition.value) && condition.value.includes(String(actual));
    case "prefix": return typeof actual === "string" && typeof condition.value === "string" && actual.startsWith(condition.value);
  }
}

export function ruleMatches(definition: RuleDefinition, trace: TraceRow): boolean {
  const results = definition.conditions.map((condition) => conditionMatches(condition, trace));
  return definition.match === "all" ? results.every(Boolean) : results.some(Boolean);
}

export async function listSignals(orgId: string): Promise<SignalRow[]> {
  const { data, error } = await serviceClient()
    .from("signals")
    .select("*")
    .eq("org_id", orgId)
    .order("created_at", { ascending: false });
  if (error) throw new Error(`signals unreadable: ${error.message}`);
  return (data ?? []) as SignalRow[];
}

/** A new definition of an existing name becomes the next version. */
export async function createSignal(input: {
  orgId: string; name: string; kind: SignalKind; definition: Record<string, unknown>; enabled?: boolean; continual?: boolean;
}): Promise<SignalRow> {
  if (input.kind === "rule") RuleDefinition.parse(input.definition);
  if (input.kind === "model") ModelDefinition.parse(input.definition);
  const sb = serviceClient();
  const { data: latest, error: readError } = await sb.from("signals")
    .select("version").eq("org_id", input.orgId).eq("name", input.name)
    .order("version", { ascending: false }).limit(1).maybeSingle();
  if (readError) throw new Error(`signal version lookup failed: ${readError.message}`);
  const version = ((latest?.version as number | undefined) ?? 0) + 1;
  const { data, error } = await sb.from("signals").insert({
    org_id: input.orgId,
    name: input.name,
    kind: input.kind,
    definition: input.definition,
    version,
    enabled: input.enabled ?? true,
    continual: input.continual ?? false,
  }).select("*").single();
  if (error) throw new Error(`signal insert failed: ${error.message}`);
  return data as SignalRow;
}

export interface SignalRunResult { scanned: number; hits: number; signalId: string; version: number }
export interface ModelSignalRunResult extends SignalRunResult { graded: number; judgeModel: string }

/**
 * Edit a signal's definition or flags. A changed definition mints the next
 * version row under the same name and supersedes the old one (it is disabled,
 * so continual grading and runs use the new definition only); unchanged
 * definitions only carry the flag update forward.
 */
export async function updateSignal(input: {
  orgId: string; signalId: string; definition?: Record<string, unknown>; enabled?: boolean; continual?: boolean;
}): Promise<SignalRow> {
  const signal = await loadSignal(input.orgId, input.signalId);
  const definitionChanged = input.definition !== undefined &&
    JSON.stringify(input.definition) !== JSON.stringify(signal.definition);
  if (input.definition !== undefined) {
    if (signal.kind === "rule") RuleDefinition.parse(input.definition);
    if (signal.kind === "model") ModelDefinition.parse(input.definition);
  }
  if (!definitionChanged) {
    const flags: Record<string, boolean> = {};
    if (input.enabled !== undefined && input.enabled !== signal.enabled) flags.enabled = input.enabled;
    if (input.continual !== undefined && input.continual !== signal.continual) flags.continual = input.continual;
    if (Object.keys(flags).length === 0) return signal;
    const { data, error } = await serviceClient().from("signals")
      .update(flags).eq("org_id", input.orgId).eq("id", input.signalId)
      .select("*").single();
    if (error) throw new Error(`signal update failed: ${error.message}`);
    return data as SignalRow;
  }
  // The new version supersedes: the old row is disabled so continual grading
  // and manual runs cannot apply both definitions to the same traces.
  const { error: supersedeError } = await serviceClient().from("signals")
    .update({ enabled: false }).eq("org_id", input.orgId).eq("id", input.signalId);
  if (supersedeError) throw new Error(`signal supersede failed: ${supersedeError.message}`);
  return createSignal({
    orgId: input.orgId,
    name: signal.name,
    kind: signal.kind,
    definition: input.definition as Record<string, unknown>,
    enabled: input.enabled ?? signal.enabled,
    continual: input.continual ?? signal.continual,
  });
}

/** Delete a signal and its hits. Recorded grading history is removable only with the signal. */
export async function deleteSignal(orgId: string, signalId: string): Promise<void> {
  await loadSignal(orgId, signalId);
  const { error } = await serviceClient().from("signals")
    .delete().eq("org_id", orgId).eq("id", signalId);
  if (error) throw new Error(`signal delete failed: ${error.message}`);
}

interface SignalScope { orgId: string; runId?: string; traceIds?: string[]; limit?: number }

async function loadSignal(orgId: string, signalId: string): Promise<SignalRow> {
  const { data, error } = await serviceClient()
    .from("signals").select("*").eq("org_id", orgId).eq("id", signalId).maybeSingle();
  if (error) throw new Error(`signal unreadable: ${error.message}`);
  if (!data) throw new SignalNotFound(`unknown signal ${signalId}`);
  return data as SignalRow;
}

function assertRunnable(signal: SignalRow): void {
  if (!signal.enabled) throw new SignalDisabled(`signal ${signal.id} is disabled`);
}

async function tracesInScope(input: SignalScope): Promise<TraceRow[]> {
  if (input.traceIds && input.traceIds.length === 0) return [];
  // Tombstoned traces are curated out: signals grade live evidence only.
  let query = serviceClient().from("traces").select("*").eq("org_id", input.orgId).is("tombstoned_at", null).limit(input.limit ?? 1000);
  if (input.runId) query = query.eq("run_id", input.runId);
  if (input.traceIds) query = query.in("id", input.traceIds);
  const { data, error } = await query;
  if (error) throw new Error(`traces unreadable: ${error.message}`);
  // Graders judge agent trajectory steps, not ground-truth-only mirror rows.
  return ((data ?? []) as TraceRow[]).filter((row) => {
    const payload = row.payload as { trajectory?: unknown } | null;
    return payload?.trajectory !== null && payload?.trajectory !== undefined;
  });
}

async function executeRuleSignal(signal: SignalRow, input: SignalScope): Promise<SignalRunResult> {
  assertRunnable(signal);
  if (signal.kind !== "rule") throw new UnsupportedSignalKind(`signal ${signal.id} is ${signal.kind}, not rule`);
  const definition = RuleDefinition.parse(signal.definition);
  const traces = await tracesInScope(input);
  const matched = traces.filter((trace) => ruleMatches(definition, trace));
  if (matched.length) {
    const hits = matched.map((trace) => ({
      org_id: input.orgId,
      signal_id: signal.id,
      trace_id: (trace as TraceRow & { id: string }).id,
      label: { matcher: definition.match, conditions: definition.conditions.length },
      score: 1,
    }));
    const { error } = await serviceClient().from("signal_hits").upsert(hits, { onConflict: "signal_id,trace_id" });
    if (error) throw new Error(`signal hits failed: ${error.message}`);
  }
  return { scanned: traces.length, hits: matched.length, signalId: signal.id, version: signal.version };
}

function tracePrompt(question: string, trace: TraceRow): string {
  const facts = {
    actor: trace.actor,
    hostId: trace.host_id,
    techniqueId: trace.technique_id,
    action: trace.action,
    observation: trace.observation,
    outcome: trace.outcome,
    matched: trace.matched,
  };
  return `Question: ${question}\n\nTrace (the ground-truth fields are authoritative):\n${JSON.stringify(facts, null, 2)}`;
}

async function executeModelSignal(
  signal: SignalRow,
  input: SignalScope,
  deps: { client?: ModelClient } = {},
): Promise<ModelSignalRunResult> {
  assertRunnable(signal);
  if (signal.kind !== "model") throw new UnsupportedSignalKind(`signal ${signal.id} is ${signal.kind}, not model`);
  const definition = ModelDefinition.parse(signal.definition);
  const client = deps.client ?? await resolveModel("judge", input.orgId, definition.model);
  const traces = await tracesInScope(input);
  const hits: Record<string, unknown>[] = [];
  let matchedCount = 0;
  for (const trace of traces) {
    const verdict = await client.generateObject<z.infer<typeof JudgeVerdict>>({
      system: "You are an impartial trace grader. Judge the trace against the question using the ground-truth fields as authoritative. Answer with the requested JSON only.",
      prompt: tracePrompt(definition.question, trace),
      schema: JudgeVerdict,
      maxTokens: 300,
    });
    if (!verdict.matched) continue;
    matchedCount++;
    hits.push({
      org_id: input.orgId,
      signal_id: signal.id,
      trace_id: (trace as TraceRow & { id: string }).id,
      label: {
        model_id: client.modelId,
        question: definition.question,
        matched: verdict.matched,
        rationale: verdict.rationale,
      },
      score: verdict.score,
    });
  }
  if (hits.length) {
    const { error } = await serviceClient().from("signal_hits").upsert(hits, { onConflict: "signal_id,trace_id" });
    if (error) throw new Error(`signal hits failed: ${error.message}`);
  }
  return { scanned: traces.length, hits: matchedCount, graded: traces.length, judgeModel: client.modelId, signalId: signal.id, version: signal.version };
}

export async function runRuleSignal(input: { orgId: string; signalId: string; runId?: string; traceIds?: string[]; limit?: number }): Promise<SignalRunResult> {
  return executeRuleSignal(await loadSignal(input.orgId, input.signalId), input);
}

export async function runModelSignal(
  input: { orgId: string; signalId: string; runId?: string; traceIds?: string[]; limit?: number },
  deps: { client?: ModelClient } = {},
): Promise<ModelSignalRunResult> {
  return executeModelSignal(await loadSignal(input.orgId, input.signalId), input, deps);
}

/** Manual or worker-driven run: the signal's kind decides the evaluator. */
export async function runSignal(
  input: { orgId: string; signalId: string; runId?: string; traceIds?: string[]; limit?: number },
  deps: { client?: ModelClient } = {},
): Promise<SignalRunResult | ModelSignalRunResult> {
  const signal = await loadSignal(input.orgId, input.signalId);
  if (signal.kind === "rule") return executeRuleSignal(signal, input);
  if (signal.kind === "model") return executeModelSignal(signal, input, deps);
  throw new UnsupportedSignalKind(`signal ${signal.id} is ${signal.kind}, not executable`);
}

export interface ContinualRunResult { signals: number; hits: number; graded: number }

/**
 * Apply every enabled continual signal to the traces named by the scope. The
 * scope is required: no scope never means "grade the whole org" (that would
 * spend judge calls on history the operator did not ask for).
 */
export async function applyContinualGraders(
  input: { orgId: string; runId?: string; traceIds?: string[] },
  deps: { client?: ModelClient } = {},
): Promise<ContinualRunResult> {
  if (!input.runId && !input.traceIds?.length) return { signals: 0, hits: 0, graded: 0 };
  const { data, error } = await serviceClient()
    .from("signals")
    .select("*")
    .eq("org_id", input.orgId)
    .eq("enabled", true)
    .eq("continual", true);
  if (error) throw new Error(`continual signals unreadable: ${error.message}`);
  const result: ContinualRunResult = { signals: 0, hits: 0, graded: 0 };
  for (const signal of (data ?? []) as SignalRow[]) {
    if (signal.kind === "human") continue;
    result.signals++;
    if (signal.kind === "rule") {
      result.hits += (await executeRuleSignal(signal, input)).hits;
    } else {
      const run = await executeModelSignal(signal, input, deps);
      result.hits += run.hits;
      result.graded += run.graded;
    }
  }
  return result;
}

/** Hit counts per signal, for the Signals screen. */
export async function signalHitCounts(orgId: string): Promise<Record<string, number>> {
  const { data, error } = await serviceClient().from("signal_hits").select("signal_id, label").eq("org_id", orgId);
  if (error) throw new Error(`signal hits unreadable: ${error.message}`);
  const counts: Record<string, number> = {};
  for (const row of data ?? []) {
    const hit = row as { signal_id: string; label?: { matched?: unknown } | null };
    if (hit.label?.matched === false) continue; // legacy graded-but-unmatched rows are not hits
    counts[hit.signal_id] = (counts[hit.signal_id] ?? 0) + 1;
  }
  return counts;
}

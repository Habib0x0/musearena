import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { EnvironmentSpec, Run } from "@musearena/shared";
import { audit, type AuditAction } from "../lib/audit.js";
import { canonicalJson, digestOfSpec, sha256Hex } from "../lib/digest.js";
import { serviceClient } from "../lib/supabase.js";
import { scoreExercise } from "../exercise/evaluator.js";
import { computeRubric } from "../evaluator/rubric.js";
import type { JoinReport } from "../observability/export.js";
import type { ModelRow } from "./models.js";

/**
 * Held-out evaluation control plane (F-10, design §3.7/§5/§7).
 *
 * The suite is pinned by digest at creation and may only contain test-split
 * families. Trials are executed by an injected runner (the worker's exercise
 * runner in production wiring); with no runner an evaluation fails honestly
 * instead of fabricating metrics. Candidate-vs-baseline is a paired delta on
 * the same suite: a mean improvement inside the combined trial spread is
 * `inconclusive`, never a pass.
 */
export const EVALUATION_STATUSES = ["queued", "running", "succeeded", "failed"] as const;
export type EvaluationStatus = (typeof EVALUATION_STATUSES)[number];

const SuiteItem = z.object({
  name: z.string().trim().min(1).max(120),
  family: z.string().trim().min(1).max(120),
  split: z.enum(["train", "val", "test"]),
  spec: z.record(z.unknown()),
}).strict();

export const CreateEvaluation = z.object({
  modelId: z.string().uuid(),
  baselineModelId: z.string().uuid().optional(),
  role: z.enum(["red", "blue"]),
  suite: z.array(SuiteItem).min(1, "a held-out suite with at least one spec is required"),
  config: z.object({ trials: z.number().int().min(1).max(20).default(3) }).passthrough().default({ trials: 3 }),
  mode: z.enum(["blind", "adaptive"]).default("blind"),
  truthLayer: z.enum(["mirror-only", "guest-agent"]).default("mirror-only"),
}).strict();
export type CreateEvaluation = z.infer<typeof CreateEvaluation>;

export class EvaluationNotFound extends Error {}
export class InvalidEvaluation extends Error {}
export class EvaluationConflict extends Error {}

export interface PinnedSuiteItem {
  name: string;
  family: string;
  split: "test";
  specDigest: string;
  spec: Record<string, unknown>;
}

export interface EvaluationSuite {
  digest: string;
  trials: number;
  mode: "blind" | "adaptive";
  truthLayer: "mirror-only" | "guest-agent";
  items: PinnedSuiteItem[];
}

export interface MetricAggregate {
  mean: number | undefined;
  min: number | undefined;
  max: number | undefined;
  spread: number;
  count: number;
}

export type MetricPanel = Record<string, MetricAggregate>;

export interface EvaluationComparison {
  primaryMetric?: string;
  verdict?: "improved" | "inconclusive" | "regressed";
  passed?: boolean;
  metrics?: Record<string, { delta: number; combinedSpread: number; direction: "higher" | "lower" }>;
}

export interface EvaluationRow {
  id: string;
  org_id: string;
  model_id: string;
  baseline_model_id: string;
  role: "red" | "blue";
  suite: EvaluationSuite;
  config: Record<string, unknown>;
  status: EvaluationStatus;
  metrics: { candidate?: MetricPanel; baseline?: MetricPanel } & Record<string, unknown>;
  comparison: EvaluationComparison;
  error: string | null;
  requested_by: string;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface EvaluationTrial {
  join: JoinReport;
  run: Run;
  usage?: {
    steps?: number;
    inputTokens?: number;
    outputTokens?: number;
    guardrailViolations?: number;
    unverifiedClaims?: number;
  };
  citations?: { total: number; correct: number };
}

export interface EvaluationTrialInput {
  orgId: string;
  evaluation: EvaluationRow;
  model: ModelRow;
  role: "red" | "blue";
  suiteItem: PinnedSuiteItem;
  trialIndex: number;
}

export type EvaluationTrialRunner = (input: EvaluationTrialInput) => Promise<EvaluationTrial>;

export interface EvaluationAuditEntry {
  orgId: string;
  actor: string;
  action: string;
  subjectId: string;
  detail: Record<string, unknown>;
}

export interface EvaluationStore {
  getModel(orgId: string, id: string): Promise<ModelRow | null>;
  findModelByServed(orgId: string, servedModel: string): Promise<ModelRow | null>;
  insertEvaluation(row: EvaluationRow): Promise<EvaluationRow>;
  getEvaluation(orgId: string, id: string): Promise<EvaluationRow | null>;
  updateEvaluation(orgId: string, id: string, patch: Partial<EvaluationRow>): Promise<EvaluationRow | null>;
  listEvaluations(orgId: string): Promise<EvaluationRow[]>;
  audit(entry: EvaluationAuditEntry): Promise<void>;
}

const nowIso = () => new Date().toISOString();

export function wilsonInterval(successes: number, total: number, zScore = 1.96): [number, number] {
  if (total <= 0) return [0, 0];
  const p = Math.min(1, Math.max(0, successes / total));
  const z2 = zScore * zScore;
  const denominator = 1 + z2 / total;
  const center = (p + z2 / (2 * total)) / denominator;
  const margin = (zScore * Math.sqrt((p * (1 - p) + z2 / (4 * total)) / total)) / denominator;
  return [Math.max(0, center - margin), Math.min(1, center + margin)];
}

export function aggregateMetricValues(values: Array<number | undefined>): MetricAggregate {
  const clean = values.filter((v): v is number => typeof v === "number" && Number.isFinite(v));
  if (!clean.length) return { mean: undefined, min: undefined, max: undefined, spread: 0, count: 0 };
  const min = Math.min(...clean);
  const max = Math.max(...clean);
  return {
    mean: clean.reduce((sum, v) => sum + v, 0) / clean.length,
    min, max, spread: max - min, count: clean.length,
  };
}

function pinSuite(parsed: CreateEvaluation): EvaluationSuite {
  for (const item of parsed.suite) {
    if (item.split !== "test") {
      throw new InvalidEvaluation(`suite item ${item.name} is in the ${item.split} split; held-out evaluation requires the test split`);
    }
  }
  const items = parsed.suite.map((item) => ({
    name: item.name,
    family: item.family,
    split: "test" as const,
    specDigest: digestOfSpec(item.spec),
    spec: item.spec,
  }));
  return {
    digest: "sha256:" + sha256Hex(canonicalJson(items.map((i) => ({ name: i.name, family: i.family, specDigest: i.specDigest })))),
    trials: parsed.config.trials,
    mode: parsed.mode,
    truthLayer: parsed.truthLayer,
    items,
  };
}

export async function createEvaluation(
  input: CreateEvaluation & { orgId: string; requestedBy: string },
  store: EvaluationStore,
): Promise<EvaluationRow> {
  const { orgId: _orgId, requestedBy: _requestedBy, ...body } = input;
  const parsed = CreateEvaluation.parse(body);
  const candidate = await store.getModel(input.orgId, parsed.modelId);
  if (!candidate) throw new InvalidEvaluation(`candidate model ${parsed.modelId} not found`);
  if (candidate.role.length > 0 && !candidate.role.includes(parsed.role)) {
    throw new InvalidEvaluation(`candidate model ${candidate.name} does not claim the ${parsed.role} role`);
  }
  const baseline = parsed.baselineModelId
    ? await store.getModel(input.orgId, parsed.baselineModelId)
    : await store.findModelByServed(input.orgId, candidate.base_model);
  if (!baseline || baseline.id === candidate.id) {
    throw new InvalidEvaluation("baseline must be the registered untrained base model for this role; register it before evaluating");
  }
  if (baseline.role.length > 0 && !baseline.role.includes(parsed.role)) {
    throw new InvalidEvaluation(`baseline model ${baseline.name} does not claim the ${parsed.role} role`);
  }
  const at = nowIso();
  const row: EvaluationRow = {
    id: randomUUID(), org_id: input.orgId, model_id: candidate.id, baseline_model_id: baseline.id,
    role: parsed.role, suite: pinSuite(parsed), config: parsed.config as Record<string, unknown>,
    status: "queued", metrics: {}, comparison: {}, error: null, requested_by: input.requestedBy,
    started_at: null, finished_at: null, created_at: at, updated_at: at,
  };
  const created = await store.insertEvaluation(row);
  await store.audit({
    orgId: input.orgId, actor: input.requestedBy, action: "EVALUATION_CREATED", subjectId: created.id,
    detail: { role: created.role, modelId: candidate.id, baselineModelId: baseline.id, suiteDigest: created.suite.digest, trials: created.suite.trials },
  });
  return created;
}

const METRIC_KEYS = [
  "objectivesAchieved", "objectivesTotal", "points", "exactTechniqueCoverage",
  "stepsPerObjective", "tokensPerObjective", "guardrailViolations", "unverifiedClaims",
  "mttdMinutesP50", "mttdMinutesP90", "containmentCorrectness", "falsePositiveRate",
  "evidenceCitationCorrectness", "calibration", "calibrationEce", "brierScore", "unscorableWindows",
] as const;

function calibrationFor(spec: EnvironmentSpec, join: JoinReport): { brier?: number; ece?: number; unscorable: number } {
  const steps = [...join.steps].sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  const unscorableKeys = new Set<string>();
  let unscorable = 0;
  for (const objective of spec.objectives) {
    const red = steps.find((s) => s.groundTruth?.actor === "red" && s.groundTruth.techniqueId === objective.techniqueId && (s.groundTruth.hostId ?? s.hostId) === objective.asset);
    const det = steps.find((s) => s.groundTruth?.actor === "blue" && s.groundTruth.outcome === "detected" && s.groundTruth.techniqueId === objective.techniqueId && (s.groundTruth.hostId ?? s.hostId) === objective.asset);
    if (red && det) {
      const redAt = Date.parse(red.groundTruth!.at);
      const detAt = Date.parse(det.groundTruth!.at);
      if (!Number.isFinite(redAt) || !Number.isFinite(detAt) || detAt < redAt) {
        unscorable += 1;
        unscorableKeys.add(`${objective.asset}|${objective.techniqueId}`);
      }
    }
  }
  const rows: Array<{ confidence: number; label: number }> = [];
  for (const step of steps) {
    const gt = step.groundTruth;
    if (!gt || gt.actor !== "blue" || gt.outcome !== "detected" || !gt.techniqueId) continue;
    const host = gt.hostId ?? step.hostId;
    if (unscorableKeys.has(`${host}|${gt.techniqueId}`)) continue;
    const raw = gt.detail?.confidence;
    if (typeof raw !== "number" || !Number.isFinite(raw)) continue;
    const confidence = raw > 1 ? raw / 100 : raw;
    if (confidence < 0 || confidence > 1) continue;
    const label = steps.some((s) => s.groundTruth?.actor === "red" && s.groundTruth.techniqueId === gt.techniqueId && (s.groundTruth.hostId ?? s.hostId) === host) ? 1 : 0;
    rows.push({ confidence, label });
  }
  if (!rows.length) return { unscorable };
  const brier = rows.reduce((sum, r) => sum + (r.confidence - r.label) ** 2, 0) / rows.length;
  let ece = 0;
  for (let bin = 0; bin < 10; bin++) {
    const inBin = rows.filter((r) => Math.min(9, Math.floor(r.confidence * 10)) === bin);
    if (!inBin.length) continue;
    const avg = inBin.reduce((s, r) => s + r.confidence, 0) / inBin.length;
    const acc = inBin.reduce((s, r) => s + r.label, 0) / inBin.length;
    ece += (inBin.length / rows.length) * Math.abs(avg - acc);
  }
  return { brier, ece, unscorable };
}

function trialMetrics(spec: EnvironmentSpec, trial: EvaluationTrial): Record<string, number | undefined> {
  const score = scoreExercise(spec, trial.join);
  const rubric = computeRubric(spec, trial.join, trial.run);
  const calibration = calibrationFor(spec, trial.join);
  const objectives = Math.max(1, spec.objectives.length);
  const usage = trial.usage ?? {};
  return {
    objectivesAchieved: score.objectivesAchieved,
    objectivesTotal: spec.objectives.length,
    points: score.pointsEarned,
    exactTechniqueCoverage: score.exactTechniqueCoverage,
    stepsPerObjective: usage.steps === undefined ? undefined : usage.steps / objectives,
    tokensPerObjective: usage.inputTokens === undefined && usage.outputTokens === undefined
      ? undefined
      : ((usage.inputTokens ?? 0) + (usage.outputTokens ?? 0)) / objectives,
    guardrailViolations: usage.guardrailViolations,
    unverifiedClaims: usage.unverifiedClaims,
    mttdMinutesP50: calibration.unscorable > 0 ? rubric.mttdMinutesP50 : rubric.mttdMinutesP50,
    mttdMinutesP90: rubric.mttdMinutesP90,
    containmentCorrectness: rubric.containmentCorrectness,
    falsePositiveRate: rubric.falsePositiveRate,
    evidenceCitationCorrectness: trial.citations && trial.citations.total > 0
      ? trial.citations.correct / trial.citations.total
      : undefined,
    calibration: calibration.brier === undefined ? undefined : 1 - calibration.brier,
    calibrationEce: calibration.ece,
    brierScore: calibration.brier,
    unscorableWindows: calibration.unscorable,
  };
}

function aggregatePanel(trials: Array<Record<string, number | undefined>>): MetricPanel {
  return Object.fromEntries(METRIC_KEYS.map((key) => [key, aggregateMetricValues(trials.map((t) => t[key]))]));
}

const LOWER_BETTER = new Set([
  "stepsPerObjective", "tokensPerObjective", "guardrailViolations", "unverifiedClaims",
  "mttdMinutesP50", "mttdMinutesP90", "falsePositiveRate", "calibrationEce", "brierScore", "unscorableWindows",
]);

function comparePanels(role: "red" | "blue", candidate: MetricPanel, baseline: MetricPanel): EvaluationComparison {
  const metrics: NonNullable<EvaluationComparison["metrics"]> = {};
  for (const key of METRIC_KEYS) {
    const c = candidate[key];
    const b = baseline[key];
    if (!c || !b || c.mean === undefined || b.mean === undefined) continue;
    metrics[key] = {
      delta: c.mean - b.mean,
      combinedSpread: c.spread + b.spread,
      direction: LOWER_BETTER.has(key) ? "lower" : "higher",
    };
  }
  const primaryMetric = role === "red" ? "objectivesAchieved" : "containmentCorrectness";
  const primary = metrics[primaryMetric];
  if (!primary) return { primaryMetric, verdict: "inconclusive", passed: false, metrics };
  const improvement = primary.direction === "higher" ? primary.delta : -primary.delta;
  const verdict = improvement > primary.combinedSpread ? "improved"
    : improvement < -primary.combinedSpread ? "regressed"
    : "inconclusive";
  return { primaryMetric, verdict, passed: verdict === "improved", metrics };
}

async function mustGetEvaluation(store: EvaluationStore, orgId: string, id: string): Promise<EvaluationRow> {
  const row = await store.getEvaluation(orgId, id);
  if (!row) throw new EvaluationNotFound(`evaluation ${id} not found`);
  return row;
}

async function finishEvaluation(
  store: EvaluationStore, row: EvaluationRow, actor: string,
  patch: Partial<EvaluationRow>, action: string,
): Promise<EvaluationRow> {
  const updated = await store.updateEvaluation(row.org_id, row.id, {
    ...patch, finished_at: nowIso(), updated_at: nowIso(),
  });
  if (!updated) throw new EvaluationNotFound(`evaluation ${row.id} not found`);
  await store.audit({
    orgId: row.org_id, actor, action, subjectId: row.id,
    detail: {
      status: updated.status, role: updated.role,
      verdict: updated.comparison.verdict ?? null,
      ...(updated.error ? { error: updated.error } : {}),
    },
  });
  return updated;
}

export async function runEvaluation(
  input: { orgId: string; id: string; actor: string },
  store: EvaluationStore,
  runner: EvaluationTrialRunner | null,
): Promise<EvaluationRow> {
  const row = await mustGetEvaluation(store, input.orgId, input.id);
  if (row.status === "succeeded" || row.status === "failed" || row.status === "running") {
    throw new EvaluationConflict(`evaluation ${row.id} is already ${row.status}`);
  }
  const started = await store.updateEvaluation(row.org_id, row.id, {
    status: "running", started_at: nowIso(), error: null, updated_at: nowIso(),
  });
  if (!started) throw new EvaluationNotFound(`evaluation ${row.id} not found`);
  if (!runner) {
    return finishEvaluation(store, started, input.actor, {
      status: "failed", metrics: {}, comparison: {},
      error: "no evaluation runner configured; refusing to fabricate metrics",
    }, "EVALUATION_FAILED");
  }
  const candidate = await store.getModel(row.org_id, row.model_id);
  const baseline = await store.getModel(row.org_id, row.baseline_model_id);
  if (!candidate || !baseline) {
    return finishEvaluation(store, started, input.actor, {
      status: "failed", metrics: {}, comparison: {},
      error: "candidate or baseline model disappeared before evaluation",
    }, "EVALUATION_FAILED");
  }
  try {
    const panels: { candidate: Array<Record<string, number | undefined>>; baseline: Array<Record<string, number | undefined>> } = {
      candidate: [], baseline: [],
    };
    for (const [side, model] of [["candidate", candidate], ["baseline", baseline]] as const) {
      for (const suiteItem of started.suite.items) {
        const spec = suiteItem.spec as unknown as EnvironmentSpec;
        if (digestOfSpec(suiteItem.spec) !== suiteItem.specDigest) {
          throw new InvalidEvaluation(`suite item ${suiteItem.name} digest mismatch; evaluation refused before spending compute`);
        }
        for (let trialIndex = 0; trialIndex < started.suite.trials; trialIndex++) {
          const trial = await runner({
            orgId: row.org_id, evaluation: started, model, role: row.role, suiteItem, trialIndex,
          });
          if (trial.run.mode !== started.suite.mode || trial.run.truthLayer !== started.suite.truthLayer) {
            throw new InvalidEvaluation(
              `trial mode/truthLayer ${trial.run.mode}/${trial.run.truthLayer} does not match suite ${started.suite.mode}/${started.suite.truthLayer}`,
            );
          }
          panels[side].push(trialMetrics(spec, trial));
        }
      }
    }
    const candidatePanel = aggregatePanel(panels.candidate);
    const baselinePanel = aggregatePanel(panels.baseline);
    return finishEvaluation(store, started, input.actor, {
      status: "succeeded",
      metrics: { candidate: candidatePanel, baseline: baselinePanel },
      comparison: comparePanels(row.role, candidatePanel, baselinePanel),
      error: null,
    }, "EVALUATION_SUCCEEDED");
  } catch (err) {
    return finishEvaluation(store, started, input.actor, {
      status: "failed", metrics: {}, comparison: {},
      error: err instanceof Error ? err.message : String(err),
    }, "EVALUATION_FAILED");
  }
}

export interface LeaderboardEntry {
  evaluationId: string;
  modelId: string;
  primaryMetric: string;
  mean: number;
  spread: number;
  wilson: [number, number] | null;
  passed: boolean;
}

export interface LeaderboardGroup {
  role: string;
  mode: string;
  truthLayer: string;
  entries: LeaderboardEntry[];
}

export function leaderboard(evaluations: EvaluationRow[]): LeaderboardGroup[] {
  const groups = new Map<string, LeaderboardGroup>();
  for (const row of evaluations) {
    if (row.status !== "succeeded") continue;
    const primaryMetric = row.comparison.primaryMetric ?? (row.role === "red" ? "objectivesAchieved" : "containmentCorrectness");
    const panel = row.metrics.candidate;
    const primary = panel?.[primaryMetric];
    if (!primary || primary.mean === undefined) continue;
    const key = `${row.role}|${row.suite.mode}|${row.suite.truthLayer}`;
    const group = groups.get(key) ?? {
      role: row.role, mode: row.suite.mode, truthLayer: row.suite.truthLayer, entries: [],
    };
    const achieved = panel.objectivesAchieved;
    const total = panel.objectivesTotal;
    const wilson = achieved?.mean !== undefined && total?.mean
      ? wilsonInterval(achieved.mean * achieved.count, total.mean * total.count)
      : null;
    group.entries.push({
      evaluationId: row.id, modelId: row.model_id, primaryMetric,
      mean: primary.mean, spread: primary.spread, wilson,
      passed: row.comparison.passed === true,
    });
    groups.set(key, group);
  }
  for (const group of groups.values()) {
    group.entries.sort((a, b) => {
      const lower = LOWER_BETTER.has(a.primaryMetric);
      return lower ? a.mean - b.mean : b.mean - a.mean;
    });
  }
  return [...groups.values()];
}

export async function listEvaluations(orgId: string): Promise<EvaluationRow[]> {
  const { data, error } = await serviceClient().from("evaluations").select("*")
    .eq("org_id", orgId).order("created_at", { ascending: false });
  if (error) throw new Error(`evaluations unreadable: ${error.message}`);
  return (data ?? []) as EvaluationRow[];
}

export function supabaseEvaluationStore(): EvaluationStore {
  const sb = () => serviceClient();
  return {
    async getModel(orgId, id) {
      const { data, error } = await sb().from("models").select("*")
        .eq("org_id", orgId).eq("id", id).maybeSingle();
      if (error) throw new Error(`model unreadable: ${error.message}`);
      return (data as ModelRow | null) ?? null;
    },
    async findModelByServed(orgId, servedModel) {
      const { data, error } = await sb().from("models").select("*")
        .eq("org_id", orgId).eq("served_model", servedModel)
        .order("created_at", { ascending: true }).limit(1).maybeSingle();
      if (error) throw new Error(`baseline lookup failed: ${error.message}`);
      return (data as ModelRow | null) ?? null;
    },
    async insertEvaluation(row) {
      const { data, error } = await sb().from("evaluations").insert(row).select("*").single();
      if (error) throw new Error(`evaluation insert failed: ${error.message}`);
      return data as EvaluationRow;
    },
    async getEvaluation(orgId, id) {
      const { data, error } = await sb().from("evaluations").select("*")
        .eq("org_id", orgId).eq("id", id).maybeSingle();
      if (error) throw new Error(`evaluation unreadable: ${error.message}`);
      return (data as EvaluationRow | null) ?? null;
    },
    async updateEvaluation(orgId, id, patch) {
      const { data, error } = await sb().from("evaluations").update(patch)
        .eq("org_id", orgId).eq("id", id).select("*").maybeSingle();
      if (error) throw new Error(`evaluation update failed: ${error.message}`);
      return (data as EvaluationRow | null) ?? null;
    },
    async listEvaluations(orgId) {
      return listEvaluations(orgId);
    },
    async audit(entry) {
      await audit({
        orgId: entry.orgId, actor: entry.actor, action: entry.action as AuditAction,
        subjectType: "evaluation", subjectId: entry.subjectId, detail: entry.detail,
      });
    },
  };
}

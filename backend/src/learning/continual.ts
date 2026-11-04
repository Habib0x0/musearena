import { randomUUID } from "node:crypto";
import { z } from "zod";
import { audit, type AuditAction } from "../lib/audit.js";
import { serviceClient } from "../lib/supabase.js";
import { assertApprovedModel } from "./models.js";
import {
  createTrainingRun, TRAINING_METHODS,
  type TrainingMethod, type TrainingStore,
} from "./training.js";

/**
 * Continual-improvement proposals (F-12, design §8).
 *
 * Triggers only *propose*. A proposal names role, dataset, base model and
 * method; an operator approval converts it into a queued training run (which
 * still needs its own training approval before any spend). Nothing in this
 * module starts training, deployment, or a model change by itself.
 */
export const PROPOSAL_TRIGGERS = ["new_traces", "corrections", "regression", "schedule"] as const;
export type ProposalTrigger = (typeof PROPOSAL_TRIGGERS)[number];
export const PROPOSAL_STATUSES = ["proposed", "converted", "rejected"] as const;
export type ProposalStatus = (typeof PROPOSAL_STATUSES)[number];

export class ProposalNotFound extends Error {}
export class InvalidProposal extends Error {}
export class ProposalConflict extends Error {}

export interface ContinualAggregates {
  labelledTraces?: Partial<Record<"red" | "blue", number>>;
  correctionsByTechnique?: Array<{ role: "red" | "blue"; techniqueId: string; count: number }>;
  regression?: Array<{
    role: "red" | "blue"; metric: string; value: number; bar: number; direction: "higher" | "lower";
  }>;
  schedule?: { due: boolean; role: "red" | "blue" } | Array<{ due: boolean; role: "red" | "blue" }>;
}

export interface ContinualThresholds {
  labelledTraces?: number;
  corrections?: number;
}

export interface ProposalDraft {
  trigger: ProposalTrigger;
  role: "red" | "blue";
  method: TrainingMethod;
  techniqueId?: string;
  reason: string;
  detail: Record<string, unknown>;
}

export interface TrainingProposalRow {
  id: string;
  org_id: string;
  trigger: ProposalTrigger;
  role: "red" | "blue";
  dataset_id: string | null;
  dataset_selection: Record<string, unknown>;
  base_model_id: string | null;
  method: TrainingMethod;
  config: Record<string, unknown>;
  budget_usd: number | string | null;
  status: ProposalStatus;
  reason: string;
  detail: Record<string, unknown>;
  training_run_id: string | null;
  created_by: string;
  decided_by: string | null;
  decided_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface ProposalAuditEntry {
  orgId: string;
  actor: string;
  action: string;
  subjectId: string;
  detail: Record<string, unknown>;
}

export interface ProposalStore {
  insertProposal(row: TrainingProposalRow): Promise<TrainingProposalRow>;
  getProposal(orgId: string, id: string): Promise<TrainingProposalRow | null>;
  updateProposal(orgId: string, id: string, patch: Partial<TrainingProposalRow>): Promise<TrainingProposalRow | null>;
  listProposals(orgId: string): Promise<TrainingProposalRow[]>;
  audit(entry: ProposalAuditEntry): Promise<void>;
}

const nowIso = () => new Date().toISOString();

export const EvaluateTriggersInput = z.object({
  aggregates: z.object({
    labelledTraces: z.object({
      red: z.number().nonnegative().optional(),
      blue: z.number().nonnegative().optional(),
    }).strict().optional(),
    correctionsByTechnique: z.array(z.object({
      role: z.enum(["red", "blue"]), techniqueId: z.string().min(1), count: z.number().nonnegative(),
    }).strict()).optional(),
    regression: z.array(z.object({
      role: z.enum(["red", "blue"]), metric: z.string().min(1),
      value: z.number(), bar: z.number(), direction: z.enum(["higher", "lower"]),
    }).strict()).optional(),
    schedule: z.union([
      z.object({ due: z.boolean(), role: z.enum(["red", "blue"]) }).strict(),
      z.array(z.object({ due: z.boolean(), role: z.enum(["red", "blue"]) }).strict()),
    ]).optional(),
  }).strict(),
  thresholds: z.object({
    labelledTraces: z.number().positive().optional(),
    corrections: z.number().positive().optional(),
  }).strict().optional(),
  defaults: z.object({
    datasetId: z.string().uuid(),
    baseModelId: z.string().uuid(),
    method: z.enum(TRAINING_METHODS).default("sft"),
    config: z.record(z.unknown()).default({}),
    budgetUsd: z.number().positive().optional(),
    datasetSelection: z.record(z.unknown()).default({}),
  }).strict(),
}).strict();
export type EvaluateTriggersInput = z.infer<typeof EvaluateTriggersInput>;

export function evaluateContinualTriggers(
  aggregates: ContinualAggregates,
  thresholds: ContinualThresholds = {},
): ProposalDraft[] {
  const labelledBar = thresholds.labelledTraces ?? 50;
  const correctionBar = thresholds.corrections ?? 10;
  const drafts: ProposalDraft[] = [];
  const seen = new Set<string>();
  const add = (draft: ProposalDraft) => {
    const key = `${draft.trigger}|${draft.role}|${draft.techniqueId ?? ""}`;
    if (seen.has(key)) return;
    seen.add(key);
    drafts.push(draft);
  };
  for (const role of ["red", "blue"] as const) {
    const count = aggregates.labelledTraces?.[role] ?? 0;
    if (count >= labelledBar) {
      add({
        trigger: "new_traces", role, method: "sft",
        reason: `${count} new labelled ${role} traces reached the ${labelledBar} threshold`,
        detail: { count, threshold: labelledBar },
      });
    }
  }
  for (const row of aggregates.correctionsByTechnique ?? []) {
    if (row.count >= correctionBar) {
      add({
        trigger: "corrections", role: row.role, method: "sft", techniqueId: row.techniqueId,
        reason: `${row.count} corrections on ${row.techniqueId} reached the ${correctionBar} threshold`,
        detail: { count: row.count, threshold: correctionBar, techniqueId: row.techniqueId },
      });
    }
  }
  for (const row of aggregates.regression ?? []) {
    const regressed = row.direction === "higher" ? row.value < row.bar : row.value > row.bar;
    if (regressed) {
      add({
        trigger: "regression", role: row.role, method: "sft",
        reason: `${row.metric} regressed (${row.value} vs bar ${row.bar}, ${row.direction} is better)`,
        detail: { metric: row.metric, value: row.value, bar: row.bar, direction: row.direction },
      });
    }
  }
  const schedules = Array.isArray(aggregates.schedule)
    ? aggregates.schedule
    : aggregates.schedule ? [aggregates.schedule] : [];
  for (const schedule of schedules) {
    if (!schedule.due) continue;
    add({
      trigger: "schedule", role: schedule.role, method: "sft",
      reason: "scheduled continual-training cadence is due",
      detail: {},
    });
  }
  return drafts;
}

export interface ContinualTraceAggregateRow {
  actor?: string | null;
  outcome?: string | null;
  created_at: string;
}

export interface ContinualCorrectionAggregateRow {
  actor?: string | null;
  technique_id?: string | null;
  created_at: string;
}

export interface ContinualRunAggregateRow {
  mode?: string | null;
  created_at: string;
  score?: Record<string, unknown> | null;
}

export interface ContinualProposalWatermark {
  trigger: ProposalTrigger;
  role: "red" | "blue";
  detail: Record<string, unknown>;
  created_at: string;
}

export interface ContinualAggregateConfig {
  correctionWindowDays?: number;
  regressionWindowRuns?: number;
  regressionMinRuns?: number;
  regressionBars?: {
    redObjectivesRatio?: number;
    blueContainment?: number;
    blueMttdMinutesP50?: number;
  };
  scheduleIntervalDays?: number;
}

const DAY_MS = 86_400_000;
const parseTime = (value: string | Date | undefined): number | null => {
  const ms = value instanceof Date ? value.getTime() : typeof value === "string" ? Date.parse(value) : Number.NaN;
  return Number.isFinite(ms) ? ms : null;
};
const isRole = (value: unknown): value is "red" | "blue" => value === "red" || value === "blue";
const latestProposalTime = (
  proposals: ContinualProposalWatermark[],
  matches: (row: ContinualProposalWatermark) => boolean,
): number | null => proposals.reduce<number | null>((latest, row) => {
  if (!matches(row)) return latest;
  const at = parseTime(row.created_at);
  return at !== null && (latest === null || at > latest) ? at : latest;
}, null);

/**
 * Derive trigger aggregates from persisted learning rows. Each trigger counts
 * only evidence after its last proposal for the same role/subject, so a
 * scheduled sweep does not endlessly repropose the same traces or corrections
 * after one is converted or rejected.
 */
export function deriveContinualAggregates(input: {
  now?: string | Date;
  traces: ContinualTraceAggregateRow[];
  corrections: ContinualCorrectionAggregateRow[];
  runs: ContinualRunAggregateRow[];
  proposals: ContinualProposalWatermark[];
}, config: ContinualAggregateConfig = {}): ContinualAggregates {
  const nowMs = parseTime(input.now) ?? Date.now();
  const correctionWindowDays = config.correctionWindowDays && config.correctionWindowDays > 0 ? config.correctionWindowDays : 30;
  const labelledTraces: Record<"red" | "blue", number> = { red: 0, blue: 0 };
  for (const role of ["red", "blue"] as const) {
    const since = latestProposalTime(input.proposals, (p) => p.trigger === "new_traces" && p.role === role);
    labelledTraces[role] = input.traces.filter((row) => {
      const at = parseTime(row.created_at);
      return row.actor === role && Boolean(row.outcome) && at !== null && at <= nowMs && (since === null || at > since);
    }).length;
  }

  const correctionCounts = new Map<string, { role: "red" | "blue"; techniqueId: string; count: number }>();
  const windowStart = nowMs - correctionWindowDays * DAY_MS;
  for (const row of input.corrections) {
    if (!isRole(row.actor) || !row.technique_id) continue;
    const at = parseTime(row.created_at);
    if (at === null || at > nowMs || at < windowStart) continue;
    const since = latestProposalTime(
      input.proposals,
      (p) => p.trigger === "corrections" && p.role === row.actor && p.detail.techniqueId === row.technique_id,
    );
    if (since !== null && at <= since) continue;
    const key = `${row.actor}|${row.technique_id}`;
    const current = correctionCounts.get(key) ?? { role: row.actor, techniqueId: row.technique_id, count: 0 };
    current.count += 1;
    correctionCounts.set(key, current);
  }
  const roleOrder = { red: 0, blue: 1 } as const;
  const correctionsByTechnique = [...correctionCounts.values()]
    .sort((a, b) => roleOrder[a.role] - roleOrder[b.role] || a.techniqueId.localeCompare(b.techniqueId));

  const regressionWindowRuns = config.regressionWindowRuns && config.regressionWindowRuns > 0 ? Math.floor(config.regressionWindowRuns) : 5;
  const regressionMinRuns = config.regressionMinRuns && config.regressionMinRuns > 0 ? Math.floor(config.regressionMinRuns) : 2;
  const bars = {
    redObjectivesRatio: config.regressionBars?.redObjectivesRatio ?? 0.8,
    blueContainment: config.regressionBars?.blueContainment ?? 0.8,
    blueMttdMinutesP50: config.regressionBars?.blueMttdMinutesP50,
  };
  const finiteScore = (row: ContinualRunAggregateRow, key: string): number | null => {
    const value = row.score?.[key];
    return typeof value === "number" && Number.isFinite(value) ? value : null;
  };
  const recentRuns = (metric: string, role: "red" | "blue") => {
    const since = latestProposalTime(
      input.proposals,
      (p) => p.trigger === "regression" && p.role === role && p.detail.metric === metric,
    );
    return input.runs
      // Scripted runs are a deterministic harness, never model performance:
      // regression is computed only from model-agent runs.
      .filter((row) => row.mode === "agents")
      .map((row) => ({ row, at: parseTime(row.created_at) }))
      .filter((x): x is { row: ContinualRunAggregateRow; at: number } => x.at !== null && x.at <= nowMs && (since === null || x.at > since))
      .sort((a, b) => b.at - a.at)
      .slice(0, regressionWindowRuns)
      .map((x) => x.row);
  };
  const regression: NonNullable<ContinualAggregates["regression"]> = [];
  const redRuns = recentRuns("objectivesAchievedRatio", "red")
    .map((row) => ({ achieved: finiteScore(row, "objectivesAchieved"), total: finiteScore(row, "objectivesTotal") }))
    .filter((x): x is { achieved: number; total: number } => x.achieved !== null && x.total !== null && x.total > 0);
  if (redRuns.length >= regressionMinRuns) {
    regression.push({
      role: "red", metric: "objectivesAchievedRatio",
      value: redRuns.reduce((sum, x) => sum + x.achieved, 0) / redRuns.reduce((sum, x) => sum + x.total, 0),
      bar: bars.redObjectivesRatio, direction: "higher",
    });
  }
  const blueMetric = (metric: "containmentCorrectness" | "mttdMinutesP50", bar: number, direction: "higher" | "lower") => {
    const values = recentRuns(metric, "blue").map((row) => finiteScore(row, metric)).filter((v): v is number => v !== null);
    if (values.length >= regressionMinRuns) {
      regression.push({ role: "blue", metric, value: values.reduce((a, b) => a + b, 0) / values.length, bar, direction });
    }
  };
  blueMetric("containmentCorrectness", bars.blueContainment, "higher");
  if (bars.blueMttdMinutesP50 !== undefined) blueMetric("mttdMinutesP50", bars.blueMttdMinutesP50, "lower");

  const schedule: Array<{ due: true; role: "red" | "blue" }> = [];
  if (config.scheduleIntervalDays && config.scheduleIntervalDays > 0) {
    for (const role of ["red", "blue"] as const) {
      const latest = latestProposalTime(input.proposals, (p) => p.trigger === "schedule" && p.role === role);
      if (latest === null || nowMs - latest >= config.scheduleIntervalDays * DAY_MS) schedule.push({ due: true, role });
    }
  }

  return {
    labelledTraces,
    ...(correctionsByTechnique.length ? { correctionsByTechnique } : {}),
    ...(regression.length ? { regression } : {}),
    ...(schedule.length ? { schedule } : {}),
  };
}

const draftKey = (trigger: string, role: string, detail: Record<string, unknown>) =>
  `${trigger}|${role}|${typeof detail.techniqueId === "string" ? detail.techniqueId : ""}`;

export async function createProposalsFromTriggers(
  input: EvaluateTriggersInput & { orgId: string; actor: string },
  store: ProposalStore,
): Promise<TrainingProposalRow[]> {
  const { orgId: _orgId, actor: _actor, ...body } = input;
  const parsed = EvaluateTriggersInput.parse(body);
  const drafts = evaluateContinualTriggers(parsed.aggregates, parsed.thresholds ?? {});
  const open = new Set(
    (await store.listProposals(input.orgId))
      .filter((row) => row.status === "proposed")
      .map((row) => draftKey(row.trigger, row.role, row.detail)),
  );
  const created: TrainingProposalRow[] = [];
  for (const draft of drafts) {
    if (open.has(draftKey(draft.trigger, draft.role, draft.detail))) continue;
    const at = nowIso();
    const row = await store.insertProposal({
      id: randomUUID(), org_id: input.orgId, trigger: draft.trigger, role: draft.role,
      dataset_id: parsed.defaults.datasetId, dataset_selection: parsed.defaults.datasetSelection,
      base_model_id: parsed.defaults.baseModelId,
      method: parsed.defaults.method ?? draft.method, config: parsed.defaults.config,
      budget_usd: parsed.defaults.budgetUsd ?? null, status: "proposed",
      reason: draft.reason, detail: draft.detail, training_run_id: null,
      created_by: input.actor, decided_by: null, decided_at: null,
      created_at: at, updated_at: at,
    });
    created.push(row);
    await store.audit({
      orgId: input.orgId, actor: input.actor, action: "TRAINING_PROPOSAL_CREATED", subjectId: row.id,
      detail: { trigger: row.trigger, role: row.role, reason: row.reason },
    });
  }
  return created;
}

async function mustGetProposal(store: ProposalStore, orgId: string, id: string): Promise<TrainingProposalRow> {
  const row = await store.getProposal(orgId, id);
  if (!row) throw new ProposalNotFound(`training proposal ${id} not found`);
  return row;
}

export async function approveProposal(
  input: {
    orgId: string; id: string; approvedBy: string;
    datasetId?: string; baseModelId?: string; budgetUsd?: number;
  },
  proposals: ProposalStore,
  training: TrainingStore,
): Promise<TrainingProposalRow> {
  const proposal = await mustGetProposal(proposals, input.orgId, input.id);
  if (proposal.status !== "proposed") {
    throw new ProposalConflict(`training proposal ${proposal.id} is already ${proposal.status}`);
  }
  const datasetId = input.datasetId ?? proposal.dataset_id;
  const baseModelId = input.baseModelId ?? proposal.base_model_id;
  const budgetUsd = input.budgetUsd ?? (proposal.budget_usd === null ? undefined : Number(proposal.budget_usd));
  if (!datasetId || !baseModelId) {
    throw new InvalidProposal("proposal does not name a dataset and base model; supply them at approval");
  }
  if (!budgetUsd || !(budgetUsd > 0)) {
    throw new InvalidProposal("approving a proposal requires a positive training budget");
  }
  const run = await createTrainingRun({
    orgId: input.orgId, requestedBy: input.approvedBy, datasetId, baseModelId,
    role: proposal.role, method: proposal.method,
    config: { ...proposal.config, proposalId: proposal.id, trigger: proposal.trigger },
    budgetUsd,
  }, training);
  const converted = await proposals.updateProposal(input.orgId, proposal.id, {
    status: "converted", training_run_id: run.id,
    decided_by: input.approvedBy, decided_at: nowIso(), updated_at: nowIso(),
  });
  if (!converted) throw new ProposalNotFound(`training proposal ${proposal.id} not found`);
  await proposals.audit({
    orgId: input.orgId, actor: input.approvedBy, action: "TRAINING_PROPOSAL_APPROVED", subjectId: proposal.id,
    detail: { trainingRunId: run.id, role: proposal.role, trigger: proposal.trigger },
  });
  return converted;
}

export async function rejectProposal(
  input: { orgId: string; id: string; actor: string; reason?: string },
  store: ProposalStore,
): Promise<TrainingProposalRow> {
  const proposal = await mustGetProposal(store, input.orgId, input.id);
  if (proposal.status !== "proposed") {
    throw new ProposalConflict(`training proposal ${proposal.id} is already ${proposal.status}`);
  }
  const rejected = await store.updateProposal(input.orgId, proposal.id, {
    status: "rejected", decided_by: input.actor, decided_at: nowIso(), updated_at: nowIso(),
    detail: { ...proposal.detail, rejectionReason: input.reason ?? null },
  });
  if (!rejected) throw new ProposalNotFound(`training proposal ${proposal.id} not found`);
  await store.audit({
    orgId: input.orgId, actor: input.actor, action: "TRAINING_PROPOSAL_REJECTED", subjectId: proposal.id,
    detail: { role: proposal.role, trigger: proposal.trigger, reason: input.reason ?? null },
  });
  return rejected;
}

export async function listProposals(orgId: string): Promise<TrainingProposalRow[]> {
  const { data, error } = await serviceClient().from("training_proposals").select("*")
    .eq("org_id", orgId).order("created_at", { ascending: false });
  if (error) throw new Error(`training proposals unreadable: ${error.message}`);
  return (data ?? []) as TrainingProposalRow[];
}

export function supabaseProposalStore(): ProposalStore {
  const sb = () => serviceClient();
  return {
    async insertProposal(row) {
      const { data, error } = await sb().from("training_proposals").insert(row).select("*").single();
      if (error) throw new Error(`training proposal insert failed: ${error.message}`);
      return data as TrainingProposalRow;
    },
    async getProposal(orgId, id) {
      const { data, error } = await sb().from("training_proposals").select("*")
        .eq("org_id", orgId).eq("id", id).maybeSingle();
      if (error) throw new Error(`training proposal unreadable: ${error.message}`);
      return (data as TrainingProposalRow | null) ?? null;
    },
    async updateProposal(orgId, id, patch) {
      const { data, error } = await sb().from("training_proposals").update(patch)
        .eq("org_id", orgId).eq("id", id).select("*").maybeSingle();
      if (error) throw new Error(`training proposal update failed: ${error.message}`);
      return (data as TrainingProposalRow | null) ?? null;
    },
    async listProposals(orgId) {
      return listProposals(orgId);
    },
    async audit(entry) {
      await audit({
        orgId: entry.orgId, actor: entry.actor, action: entry.action as AuditAction,
        subjectType: "training_proposal", subjectId: entry.subjectId, detail: entry.detail,
      });
    },
  };
}

export interface ContinualDatasetDefault {
  id: string;
  split: string;
  roles: string[] | null;
  family: string | null;
  content_hash: string;
  storage_path: string;
  created_at: string;
}

export interface ContinualModelDefault {
  id: string;
  status: string;
  role: string[];
  provider: string;
  served_model: string;
  created_at: string;
}

export interface ContinualAggregateStore {
  listOrgIds(): Promise<string[]>;
  listTraces(orgId: string): Promise<ContinualTraceAggregateRow[]>;
  listCorrections(orgId: string): Promise<ContinualCorrectionAggregateRow[]>;
  listRuns(orgId: string): Promise<ContinualRunAggregateRow[]>;
  listDatasets(orgId: string): Promise<ContinualDatasetDefault[]>;
  listModels(orgId: string, role: "red" | "blue"): Promise<ContinualModelDefault[]>;
}

export interface ContinualSweepConfig extends ContinualAggregateConfig {
  thresholds?: ContinualThresholds;
  budgetUsd?: number;
  method?: TrainingMethod;
  config?: Record<string, unknown>;
  datasetSelection?: Record<string, unknown>;
}

export interface ContinualSweepSkipped { role: "red" | "blue"; reason: string }
export interface ContinualSweepOrgResult {
  orgId: string;
  aggregates: ContinualAggregates;
  proposals: TrainingProposalRow[];
  skipped: ContinualSweepSkipped[];
}

const byCreatedDesc = (a: { created_at: string }, b: { created_at: string }) =>
  (parseTime(b.created_at) ?? 0) - (parseTime(a.created_at) ?? 0);

export function selectContinualDataset(
  datasets: ContinualDatasetDefault[], role: "red" | "blue",
): ContinualDatasetDefault | null {
  return [...datasets]
    .filter((d) => d.split === "train" && Boolean(d.family) && Boolean(d.content_hash) && Boolean(d.storage_path) && (d.roles ?? []).includes(role))
    .sort(byCreatedDesc)[0] ?? null;
}

export function selectContinualBaseModel(
  models: ContinualModelDefault[], role: "red" | "blue",
): ContinualModelDefault | null {
  const rank = (status: string) => status === "ready" ? 0 : status === "available" ? 1 : 2;
  return [...models]
    .filter((m) => (m.status === "ready" || m.status === "available") && m.role.includes(role))
    .filter((m) => {
      if (m.provider !== "meta" && m.provider !== "meta-modal") return false;
      try { assertApprovedModel(m.provider, m.served_model); return true; } catch { return false; }
    })
    .sort((a, b) => rank(a.status) - rank(b.status) || byCreatedDesc(a, b))[0] ?? null;
}

function aggregatesForRole(all: ContinualAggregates, role: "red" | "blue"): ContinualAggregates {
  const schedules = Array.isArray(all.schedule) ? all.schedule : all.schedule ? [all.schedule] : [];
  return {
    labelledTraces: { [role]: all.labelledTraces?.[role] ?? 0 },
    correctionsByTechnique: (all.correctionsByTechnique ?? []).filter((r) => r.role === role),
    regression: (all.regression ?? []).filter((r) => r.role === role),
    schedule: schedules.filter((s) => s.role === role),
  };
}

export async function runContinualSweepForOrg(
  input: { orgId: string; actor?: string; now?: string | Date; config?: ContinualSweepConfig },
  deps: { aggregates: ContinualAggregateStore; proposals: ProposalStore },
): Promise<ContinualSweepOrgResult> {
  const config = input.config ?? {};
  const [traces, corrections, runs, proposals] = await Promise.all([
    deps.aggregates.listTraces(input.orgId),
    deps.aggregates.listCorrections(input.orgId),
    deps.aggregates.listRuns(input.orgId),
    deps.proposals.listProposals(input.orgId),
  ]);
  const aggregates = deriveContinualAggregates({ now: input.now, traces, corrections, runs, proposals }, config);
  const drafts = evaluateContinualTriggers(aggregates, config.thresholds ?? {});
  const roles = [...new Set(drafts.map((d) => d.role))];
  const created: TrainingProposalRow[] = [];
  const skipped: ContinualSweepSkipped[] = [];

  for (const role of roles) {
    const [datasets, models] = await Promise.all([
      deps.aggregates.listDatasets(input.orgId),
      deps.aggregates.listModels(input.orgId, role),
    ]);
    const dataset = selectContinualDataset(datasets, role);
    if (!dataset) { skipped.push({ role, reason: `no built train dataset for ${role}` }); continue; }
    const baseModel = selectContinualBaseModel(models, role);
    if (!baseModel) { skipped.push({ role, reason: `no approved available/ready base model for ${role}` }); continue; }
    created.push(...await createProposalsFromTriggers({
      orgId: input.orgId,
      actor: input.actor ?? "continual-worker",
      aggregates: aggregatesForRole(aggregates, role),
      thresholds: config.thresholds,
      defaults: {
        datasetId: dataset.id,
        baseModelId: baseModel.id,
        method: config.method ?? "sft",
        config: config.config ?? {},
        ...(config.budgetUsd !== undefined ? { budgetUsd: config.budgetUsd } : {}),
        datasetSelection: config.datasetSelection ?? {},
      },
    }, deps.proposals));
  }
  return { orgId: input.orgId, aggregates, proposals: created, skipped };
}

export async function runContinualSweep(
  input: { actor?: string; now?: string | Date; config?: ContinualSweepConfig } = {},
  deps: { aggregates: ContinualAggregateStore; proposals: ProposalStore },
): Promise<{ results: ContinualSweepOrgResult[]; errors: Array<{ orgId: string; error: string }> }> {
  const results: ContinualSweepOrgResult[] = [];
  const errors: Array<{ orgId: string; error: string }> = [];
  for (const orgId of await deps.aggregates.listOrgIds()) {
    try {
      results.push(await runContinualSweepForOrg({ ...input, orgId }, deps));
    } catch (err) {
      errors.push({ orgId, error: err instanceof Error ? err.message : String(err) });
    }
  }
  return { results, errors };
}

export function supabaseContinualAggregateStore(): ContinualAggregateStore {
  const sb = () => serviceClient();
  const select = async <T>(label: string, query: PromiseLike<{ data: T[] | null; error: { message: string } | null }>): Promise<T[]> => {
    const { data, error } = await query;
    if (error) throw new Error(`${label} unreadable: ${error.message}`);
    return data ?? [];
  };
  return {
    async listOrgIds() {
      const ids = new Set<string>();
      for (const table of ["traces", "datasets", "models", "training_proposals"] as const) {
        const rows = await select<{ org_id: string }>(table, sb().from(table).select("org_id").limit(5000));
        for (const row of rows) if (row.org_id) ids.add(row.org_id);
      }
      return [...ids].sort();
    },
    async listTraces(orgId) {
      return select<ContinualTraceAggregateRow>("traces", sb().from("traces")
        .select("actor, outcome, created_at").eq("org_id", orgId)
        .order("created_at", { ascending: false }).limit(5000));
    },
    async listCorrections(orgId) {
      const corrections = await select<{ trace_id: string; created_at: string }>("corrections", sb().from("corrections")
        .select("trace_id, created_at").eq("org_id", orgId)
        .order("created_at", { ascending: false }).limit(5000));
      const byTrace = new Map<string, { actor: string | null; technique_id: string | null }>();
      const ids = [...new Set(corrections.map((c) => c.trace_id))];
      for (let i = 0; i < ids.length; i += 500) {
        const chunk = ids.slice(i, i + 500);
        if (!chunk.length) continue;
        const traces = await select<{ id: string; actor: string | null; technique_id: string | null }>("correction traces", sb().from("traces")
          .select("id, actor, technique_id").eq("org_id", orgId).in("id", chunk));
        for (const trace of traces) byTrace.set(trace.id, { actor: trace.actor, technique_id: trace.technique_id });
      }
      return corrections.map((c) => ({
        actor: byTrace.get(c.trace_id)?.actor ?? null,
        technique_id: byTrace.get(c.trace_id)?.technique_id ?? null,
        created_at: c.created_at,
      }));
    },
    async listRuns(orgId) {
      return select<ContinualRunAggregateRow>("runs", sb().from("runs")
        .select("mode, score, created_at").eq("org_id", orgId).eq("mode", "agents")
        .order("created_at", { ascending: false }).limit(1000));
    },
    async listDatasets(orgId) {
      return select<ContinualDatasetDefault>("datasets", sb().from("datasets")
        .select("id, split, roles, family, content_hash, storage_path, created_at").eq("org_id", orgId)
        .order("created_at", { ascending: false }).limit(500));
    },
    async listModels(orgId, role) {
      return select<ContinualModelDefault>("models", sb().from("models")
        .select("id, status, role, provider, served_model, created_at").eq("org_id", orgId).contains("role", [role])
        .order("created_at", { ascending: false }).limit(100));
    },
  };
}

export interface ContinualSweepRuntimeConfig {
  enabled: boolean;
  intervalMs: number;
  sweep: ContinualSweepConfig;
}

const envPositiveNumber = (
  env: NodeJS.ProcessEnv, name: string, fallback: number | undefined, opts: { integer?: boolean } = {},
): number | undefined => {
  const raw = env[name]?.trim();
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isFinite(value) || value <= 0 || (opts.integer && !Number.isInteger(value))) {
    throw new Error(`${name} must be a positive ${opts.integer ? "integer" : "number"}`);
  }
  return value;
};

export function continualSweepConfigFromEnv(env: NodeJS.ProcessEnv = process.env): ContinualSweepRuntimeConfig {
  const methodRaw = env.MUSEARENA_CONTINUAL_METHOD?.trim();
  if (methodRaw && !TRAINING_METHODS.includes(methodRaw as TrainingMethod)) {
    throw new Error(`MUSEARENA_CONTINUAL_METHOD must be one of ${TRAINING_METHODS.join(", ")}`);
  }
  const thresholds: ContinualThresholds = {};
  const labelledTraces = envPositiveNumber(env, "MUSEARENA_CONTINUAL_LABELLED_TRACES", undefined, { integer: true });
  const corrections = envPositiveNumber(env, "MUSEARENA_CONTINUAL_CORRECTIONS", undefined, { integer: true });
  if (labelledTraces !== undefined) thresholds.labelledTraces = labelledTraces;
  if (corrections !== undefined) thresholds.corrections = corrections;
  const blueMttd = envPositiveNumber(env, "MUSEARENA_CONTINUAL_BLUE_MTTD_BAR_MINUTES", undefined);
  const budgetUsd = envPositiveNumber(env, "MUSEARENA_CONTINUAL_BUDGET_USD", undefined);
  const scheduleIntervalDays = envPositiveNumber(env, "MUSEARENA_CONTINUAL_SCHEDULE_DAYS", undefined);

  return {
    enabled: /^(1|true|yes|on)$/i.test(env.MUSEARENA_CONTINUAL_SWEEP?.trim() ?? ""),
    intervalMs: envPositiveNumber(env, "MUSEARENA_CONTINUAL_SWEEP_INTERVAL_MS", 3_600_000, { integer: true })!,
    sweep: {
      thresholds,
      correctionWindowDays: envPositiveNumber(env, "MUSEARENA_CONTINUAL_CORRECTION_WINDOW_DAYS", 30),
      regressionWindowRuns: envPositiveNumber(env, "MUSEARENA_CONTINUAL_REGRESSION_RUNS", 5, { integer: true }),
      regressionBars: {
        redObjectivesRatio: envPositiveNumber(env, "MUSEARENA_CONTINUAL_RED_OBJECTIVES_BAR", 0.8),
        blueContainment: envPositiveNumber(env, "MUSEARENA_CONTINUAL_BLUE_CONTAINMENT_BAR", 0.8),
        ...(blueMttd !== undefined ? { blueMttdMinutesP50: blueMttd } : {}),
      },
      ...(scheduleIntervalDays !== undefined ? { scheduleIntervalDays } : {}),
      ...(budgetUsd !== undefined ? { budgetUsd } : {}),
      ...(methodRaw ? { method: methodRaw as TrainingMethod } : {}),
    },
  };
}

export function supabaseContinualSweepStores(): { aggregates: ContinualAggregateStore; proposals: ProposalStore } {
  return { aggregates: supabaseContinualAggregateStore(), proposals: supabaseProposalStore() };
}

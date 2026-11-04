import { randomUUID } from "node:crypto";
import { z } from "zod";
import { audit, type AuditAction } from "../lib/audit.js";
import { serviceClient } from "../lib/supabase.js";
import { assertApprovedModel, type ModelRow } from "./models.js";

/**
 * Training-run control plane (F-9, design §3.6/§5/§6).
 *
 * The platform owns pinning, approval, budget, and the state machine; an
 * external Meta trainer adapter owns gradient work. With no adapter a run
 * parks in `awaiting_trainer` carrying its manifest — it never pretends to
 * have trained. Only a succeeded, within-budget trainer result with an
 * approved served model ID and an artifact hash creates a `ready` model.
 */
export const TRAINING_METHODS = ["sft", "dpo", "lora", "grpo"] as const;
export type TrainingMethod = (typeof TRAINING_METHODS)[number];
export const TRAINING_STATUSES = ["queued", "running", "succeeded", "failed", "cancelled", "awaiting_trainer"] as const;
export type TrainingStatus = (typeof TRAINING_STATUSES)[number];

export const CreateTrainingRun = z.object({
  datasetId: z.string().uuid(),
  baseModelId: z.string().uuid(),
  role: z.enum(["red", "blue"]),
  method: z.enum(TRAINING_METHODS),
  config: z.record(z.unknown()).default({}),
  budgetUsd: z.number({ required_error: "budgetUsd (budget) is required" }).positive(),
  outputName: z.string().trim().min(1).max(80).optional(),
  targetAlias: z.string().trim().min(1).max(80).optional(),
  targetEnvironment: z.enum(["staging", "production"]).optional(),
}).strict();
export type CreateTrainingRun = z.infer<typeof CreateTrainingRun>;

export class TrainingRunNotFound extends Error {}
export class InvalidTrainingRun extends Error {}
export class TrainingRunConflict extends Error {}

export interface DatasetPin {
  id: string;
  org_id: string;
  content_hash: string;
  storage_path: string;
  roles?: string[] | null;
  split?: string | null;
  family?: string | null;
}

export interface TrainingManifest {
  runId: string;
  orgId: string;
  role: "red" | "blue";
  method: TrainingMethod;
  baseModelId: string;
  baseModel: string;
  provider: "meta" | "meta-modal";
  dataset: { id: string; hash: string; storagePath: string; split: string | null; family: string | null };
  config: Record<string, unknown>;
  budgetUsd: number;
  requestedBy: string;
  targetAlias: string | null;
  targetEnvironment: "staging" | "production" | null;
}

export interface TrainingRunRow {
  id: string;
  org_id: string;
  dataset_id: string;
  base_model_id: string;
  output_model_id: string | null;
  role: "red" | "blue";
  method: TrainingMethod;
  config: Record<string, unknown>;
  manifest: TrainingManifest;
  status: TrainingStatus;
  metrics: Record<string, unknown>;
  error: string | null;
  budget_usd: number | string;
  spent_usd: number | string;
  requested_by: string;
  target_alias: string | null;
  target_environment: "staging" | "production" | null;
  trainer_job_id: string | null;
  approved_by: string | null;
  approved_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface TrainerResult {
  status?: "succeeded" | "failed" | "running";
  jobId?: string;
  spentUsd?: number;
  metrics?: Record<string, unknown>;
  artifactPath?: string;
  artifactHash?: string;
  servedModel?: string;
  error?: string;
}

export interface TrainerAdapter {
  train(manifest: TrainingManifest): Promise<TrainerResult>;
}

export interface TrainingAuditEntry {
  orgId: string;
  actor: string;
  action: string;
  subjectId: string;
  detail: Record<string, unknown>;
}

export interface TrainingStore {
  getDataset(orgId: string, id: string): Promise<DatasetPin | null>;
  getModel(orgId: string, id: string): Promise<ModelRow | null>;
  insertRun(row: TrainingRunRow): Promise<TrainingRunRow>;
  getRun(orgId: string, id: string): Promise<TrainingRunRow | null>;
  updateRun(orgId: string, id: string, patch: Partial<TrainingRunRow>): Promise<TrainingRunRow | null>;
  nextModelVersion(orgId: string, name: string): Promise<number>;
  insertModel(row: ModelRow): Promise<ModelRow>;
  audit(entry: TrainingAuditEntry): Promise<void>;
}

const nowIso = () => new Date().toISOString();
const money = (value: number | string) => Number(value);
const TERMINAL: TrainingStatus[] = ["succeeded", "failed", "cancelled"];

function outputModelName(input: CreateTrainingRun, base: ModelRow): string {
  const raw = input.outputName ?? `${base.name}-${input.role}-${input.method}`;
  return raw.replace(/\s+/g, "-").toLowerCase().slice(0, 80);
}

export async function createTrainingRun(
  input: CreateTrainingRun & { orgId: string; requestedBy: string },
  store: TrainingStore,
): Promise<TrainingRunRow> {
  const { orgId: _orgId, requestedBy: _requestedBy, ...body } = input;
  const parsed = CreateTrainingRun.parse(body);
  const dataset = await store.getDataset(input.orgId, parsed.datasetId);
  if (!dataset) throw new InvalidTrainingRun(`dataset ${parsed.datasetId} not found`);
  if (!dataset.content_hash || !dataset.storage_path) {
    throw new InvalidTrainingRun(`dataset ${dataset.id} has no pinned snapshot hash/path to train from`);
  }
  if (dataset.roles && dataset.roles.length > 0 && !dataset.roles.includes(parsed.role)) {
    throw new InvalidTrainingRun(`dataset ${dataset.id} has no ${parsed.role} role file (roles: ${dataset.roles.join(", ")})`);
  }
  const base = await store.getModel(input.orgId, parsed.baseModelId);
  if (!base) throw new InvalidTrainingRun(`base model ${parsed.baseModelId} not found in the registry`);
  if (!(["available", "ready"] as string[]).includes(base.status)) {
    throw new InvalidTrainingRun(`base model ${base.name} is ${base.status}, not available/ready`);
  }
  if (base.role.length > 0 && !base.role.includes(parsed.role)) {
    throw new InvalidTrainingRun(`base model ${base.name} does not claim the ${parsed.role} role`);
  }
  assertApprovedModel(base.provider, base.served_model);

  const id = randomUUID();
  const at = nowIso();
  const manifest: TrainingManifest = {
    runId: id,
    orgId: input.orgId,
    role: parsed.role,
    method: parsed.method,
    baseModelId: base.id,
    baseModel: base.served_model,
    provider: base.provider,
    dataset: {
      id: dataset.id, hash: dataset.content_hash, storagePath: dataset.storage_path,
      split: dataset.split ?? null, family: dataset.family ?? null,
    },
    config: parsed.config,
    budgetUsd: parsed.budgetUsd,
    requestedBy: input.requestedBy,
    targetAlias: parsed.targetAlias ?? null,
    targetEnvironment: parsed.targetEnvironment ?? null,
  };
  const row: TrainingRunRow = {
    id, org_id: input.orgId, dataset_id: dataset.id, base_model_id: base.id, output_model_id: null,
    role: parsed.role, method: parsed.method, config: parsed.config, manifest,
    status: "queued", metrics: {}, error: null, budget_usd: parsed.budgetUsd, spent_usd: 0,
    requested_by: input.requestedBy, target_alias: parsed.targetAlias ?? null,
    target_environment: parsed.targetEnvironment ?? null, trainer_job_id: null,
    approved_by: null, approved_at: null, started_at: null, finished_at: null,
    created_at: at, updated_at: at,
  };
  const created = await store.insertRun(row);
  await store.audit({
    orgId: input.orgId, actor: input.requestedBy, action: "TRAINING_RUN_CREATED", subjectId: created.id,
    detail: { role: created.role, method: created.method, budgetUsd: money(created.budget_usd), datasetId: dataset.id, baseModelId: base.id },
  });
  return created;
}

async function mustGetRun(store: TrainingStore, orgId: string, id: string): Promise<TrainingRunRow> {
  const run = await store.getRun(orgId, id);
  if (!run) throw new TrainingRunNotFound(`training run ${id} not found`);
  return run;
}

async function finishRun(
  store: TrainingStore, run: TrainingRunRow, actor: string,
  patch: Partial<TrainingRunRow>, action: string,
): Promise<TrainingRunRow> {
  const updated = await store.updateRun(run.org_id, run.id, { ...patch, finished_at: nowIso(), updated_at: nowIso() });
  if (!updated) throw new TrainingRunNotFound(`training run ${run.id} not found`);
  await store.audit({
    orgId: run.org_id, actor, action, subjectId: run.id,
    detail: { status: updated.status, spentUsd: money(updated.spent_usd), budgetUsd: money(updated.budget_usd), ...(updated.error ? { error: updated.error } : {}) },
  });
  return updated;
}

export async function approveTrainingRun(
  input: { orgId: string; id: string; approvedBy: string; outputName?: string },
  store: TrainingStore,
  trainer: TrainerAdapter | null,
): Promise<TrainingRunRow> {
  const run = await mustGetRun(store, input.orgId, input.id);
  if (TERMINAL.includes(run.status) || run.status === "running") {
    throw new TrainingRunConflict(`training run ${run.id} is already ${run.status}`);
  }
  const approvedAt = nowIso();
  if (!trainer) {
    const parked = await store.updateRun(run.org_id, run.id, {
      status: "awaiting_trainer", approved_by: input.approvedBy, approved_at: approvedAt, updated_at: approvedAt,
    });
    if (!parked) throw new TrainingRunNotFound(`training run ${run.id} not found`);
    await store.audit({
      orgId: run.org_id, actor: input.approvedBy, action: "TRAINING_RUN_AWAITING_TRAINER", subjectId: run.id,
      detail: { role: run.role, method: run.method, budgetUsd: money(run.budget_usd) },
    });
    return parked;
  }

  const running = await store.updateRun(run.org_id, run.id, {
    status: "running", approved_by: input.approvedBy, approved_at: approvedAt,
    started_at: approvedAt, error: null, updated_at: approvedAt,
  });
  if (!running) throw new TrainingRunNotFound(`training run ${run.id} not found`);
  await store.audit({
    orgId: run.org_id, actor: input.approvedBy, action: "TRAINING_RUN_APPROVED", subjectId: run.id,
    detail: { role: run.role, method: run.method, budgetUsd: money(run.budget_usd) },
  });

  let result: TrainerResult;
  try {
    result = await trainer.train(running.manifest);
  } catch (err) {
    return finishRun(store, running, input.approvedBy, {
      status: "failed", error: err instanceof Error ? err.message : String(err),
    }, "TRAINING_RUN_FAILED");
  }
  const spent = result.spentUsd ?? 0;
  const budget = money(running.budget_usd);
  const jobPatch = result.jobId ? { trainer_job_id: result.jobId } : {};
  if (spent > budget) {
    return finishRun(store, running, input.approvedBy, {
      status: "cancelled", spent_usd: spent, ...jobPatch,
      error: `trainer spend $${spent} exceeded budget $${budget}`,
      metrics: result.metrics ?? running.metrics,
    }, "TRAINING_RUN_CANCELLED");
  }
  if (result.status === "running") {
    const still = await store.updateRun(run.org_id, run.id, {
      spent_usd: spent, ...jobPatch, metrics: result.metrics ?? running.metrics, updated_at: nowIso(),
    });
    if (!still) throw new TrainingRunNotFound(`training run ${run.id} not found`);
    return still;
  }
  if (result.status === "failed") {
    return finishRun(store, running, input.approvedBy, {
      status: "failed", spent_usd: spent, ...jobPatch,
      error: result.error ?? "trainer reported failure", metrics: result.metrics ?? running.metrics,
    }, "TRAINING_RUN_FAILED");
  }
  if (!result.artifactHash || !result.servedModel) {
    return finishRun(store, running, input.approvedBy, {
      status: "failed", spent_usd: spent, ...jobPatch,
      error: "trainer succeeded without an artifact hash and served model id", metrics: result.metrics ?? running.metrics,
    }, "TRAINING_RUN_FAILED");
  }

  const base = await store.getModel(run.org_id, run.base_model_id);
  if (!base) {
    return finishRun(store, running, input.approvedBy, {
      status: "failed", spent_usd: spent, ...jobPatch, error: "base model disappeared during training",
    }, "TRAINING_RUN_FAILED");
  }
  try {
    assertApprovedModel(base.provider, result.servedModel);
  } catch (err) {
    return finishRun(store, running, input.approvedBy, {
      status: "failed", spent_usd: spent, ...jobPatch,
      error: err instanceof Error ? err.message : String(err), metrics: result.metrics ?? running.metrics,
    }, "TRAINING_RUN_FAILED");
  }
  const name = outputModelName(
    { role: run.role, method: run.method, outputName: input.outputName } as CreateTrainingRun,
    base,
  );
  const modelId = randomUUID();
  const model = await store.insertModel({
    id: modelId, org_id: run.org_id, name,
    version: await store.nextModelVersion(run.org_id, name),
    base_model: base.served_model, served_model: result.servedModel, provider: base.provider,
    status: "ready",
    artifact_path: result.artifactPath ?? `${run.org_id}/models/${modelId}/`,
    artifact_hash: result.artifactHash,
    metrics: { ...(result.metrics ?? {}), artifactHash: result.artifactHash, trainingRunId: run.id },
    role: [run.role], training_run_id: run.id, created_at: nowIso(),
  });
  return finishRun(store, running, input.approvedBy, {
    status: "succeeded", spent_usd: spent, ...jobPatch,
    output_model_id: model.id, metrics: result.metrics ?? running.metrics, error: null,
  }, "TRAINING_RUN_SUCCEEDED");
}

export async function cancelTrainingRun(
  input: { orgId: string; id: string; actor: string },
  store: TrainingStore,
): Promise<TrainingRunRow> {
  const run = await mustGetRun(store, input.orgId, input.id);
  if (TERMINAL.includes(run.status)) {
    throw new TrainingRunConflict(`training run ${run.id} is terminal (${run.status}) and cannot be cancelled`);
  }
  return finishRun(store, run, input.actor, { status: "cancelled" }, "TRAINING_RUN_CANCELLED");
}

export async function listTrainingRuns(
  orgId: string,
  filters: { status?: TrainingStatus; role?: "red" | "blue" } = {},
): Promise<TrainingRunRow[]> {
  let query = serviceClient().from("training_runs").select("*").eq("org_id", orgId)
    .order("created_at", { ascending: false });
  if (filters.status) query = query.eq("status", filters.status);
  if (filters.role) query = query.eq("role", filters.role);
  const { data, error } = await query;
  if (error) throw new Error(`training runs unreadable: ${error.message}`);
  return (data ?? []) as TrainingRunRow[];
}

export function supabaseTrainingStore(): TrainingStore {
  const sb = () => serviceClient();
  return {
    async getDataset(orgId, id) {
      const { data, error } = await sb().from("datasets")
        .select("id, org_id, content_hash, storage_path, roles, split, family")
        .eq("org_id", orgId).eq("id", id).maybeSingle();
      if (error) throw new Error(`dataset unreadable: ${error.message}`);
      return (data as DatasetPin | null) ?? null;
    },
    async getModel(orgId, id) {
      const { data, error } = await sb().from("models").select("*")
        .eq("org_id", orgId).eq("id", id).maybeSingle();
      if (error) throw new Error(`model unreadable: ${error.message}`);
      return (data as ModelRow | null) ?? null;
    },
    async insertRun(row) {
      const { data, error } = await sb().from("training_runs").insert(row).select("*").single();
      if (error) throw new Error(`training run insert failed: ${error.message}`);
      return data as TrainingRunRow;
    },
    async getRun(orgId, id) {
      const { data, error } = await sb().from("training_runs").select("*")
        .eq("org_id", orgId).eq("id", id).maybeSingle();
      if (error) throw new Error(`training run unreadable: ${error.message}`);
      return (data as TrainingRunRow | null) ?? null;
    },
    async updateRun(orgId, id, patch) {
      const { data, error } = await sb().from("training_runs").update(patch)
        .eq("org_id", orgId).eq("id", id).select("*").maybeSingle();
      if (error) throw new Error(`training run update failed: ${error.message}`);
      return (data as TrainingRunRow | null) ?? null;
    },
    async nextModelVersion(orgId, name) {
      const { data, error } = await sb().from("models").select("version")
        .eq("org_id", orgId).eq("name", name).order("version", { ascending: false }).limit(1).maybeSingle();
      if (error) throw new Error(`model version lookup failed: ${error.message}`);
      return ((data?.version as number | undefined) ?? 0) + 1;
    },
    async insertModel(row) {
      const { data, error } = await sb().from("models").insert(row).select("*").single();
      if (error) throw new Error(`trained model insert failed: ${error.message}`);
      return data as ModelRow;
    },
    async audit(entry) {
      await audit({
        orgId: entry.orgId, actor: entry.actor, action: entry.action as AuditAction,
        subjectType: "training_run", subjectId: entry.subjectId, detail: entry.detail,
      });
    },
  };
}

/**
 * Meta trainer adapter (design §6). The job body carries the small pinned
 * contract only — never dataset file contents. A response with just a job id
 * leaves the run `running`; a response carrying an artifact hash and served
 * model completes it. Anything else is a trainer failure, never a fake success.
 */
export function httpTrainer(baseUrl: string, fetchImpl: typeof fetch = fetch): TrainerAdapter {
  const root = baseUrl.replace(/\/$/, "");
  const str = (value: unknown) => typeof value === "string" && value.length > 0 ? value : undefined;
  const num = (value: unknown) => typeof value === "number" && Number.isFinite(value) ? value : undefined;
  return {
    async train(manifest) {
      const response = await fetchImpl(`${root}/v1/jobs`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          job_type: manifest.method,
          base_model: manifest.baseModel,
          dataset_snapshot: manifest.dataset.storagePath,
          config: manifest.config,
          budget_usd: manifest.budgetUsd,
          org_id: manifest.orgId,
          run_id: manifest.runId,
        }),
      });
      if (!response.ok) throw new Error(`trainer refused the job (${response.status})`);
      const body = await response.json() as Record<string, unknown>;
      const jobId = str(body.job_id) ?? str(body.jobId) ?? str(body.id);
      const artifactHash = str(body.artifact_hash) ?? str(body.artifactHash);
      const servedModel = str(body.served_model) ?? str(body.servedModel);
      const status = body.status === "failed" ? "failed"
        : artifactHash && servedModel ? "succeeded"
        : "running";
      return {
        status, jobId,
        spentUsd: num(body.spent_usd) ?? num(body.spentUsd),
        metrics: (body.metrics as Record<string, unknown> | undefined) ?? {},
        artifactPath: str(body.artifact_path) ?? str(body.artifactPath),
        artifactHash, servedModel,
        error: str(body.error),
      };
    },
  };
}

export function trainerFromEnv(env: NodeJS.ProcessEnv = process.env): TrainerAdapter | null {
  const url = env.META_TRAINER_URL?.trim();
  return url ? httpTrainer(url) : null;
}

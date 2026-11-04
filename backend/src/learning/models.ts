import { z } from "zod";
import type { ModelSurface } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import {
  AGENT_MODELS, canonicalModalModelId, effectiveAgentSurface, isModalGlimmerModel,
  isModalModelId, MetaModelClient, ModalModelClient, modalModelIdForRole, modelForRole,
  type AgentClient, type ModelRole,
} from "../lib/model.js";

/**
 * Model registry and per-role resolution (F-8 / F-14, design §3.5, §12.9, §12.19).
 *
 * A role resolves to the newest `ready` model that claims it, else to the
 * verified base model for the effective surface. Every ID is checked against
 * that surface's allowlist before it can become a client, so a registry row
 * (or an env override) cannot point an agent at a non-Meta surface.
 */
export const REGISTRY_ROLES = ["red", "blue", "persona", "judge"] as const;
export type RegistryRole = (typeof REGISTRY_ROLES)[number];

export const MODEL_STATUSES = ["available", "training", "ready", "failed", "deprecated"] as const;

export const RegisterModel = z.object({
  name: z.string().trim().min(1).max(80),
  baseModel: z.string().min(1),
  servedModel: z.string().min(1),
  provider: z.enum(["meta", "meta-modal"]),
  role: z.array(z.enum(REGISTRY_ROLES)).min(1),
  status: z.enum(MODEL_STATUSES).default("available"),
  artifactPath: z.string().optional(),
  artifactHash: z.string().optional(),
  metrics: z.record(z.unknown()).default({}),
}).strict();
export type RegisterModel = z.infer<typeof RegisterModel>;

export interface ModelRow {
  id: string;
  org_id: string;
  name: string;
  version: number;
  base_model: string;
  served_model: string;
  provider: "meta" | "meta-modal";
  status: (typeof MODEL_STATUSES)[number];
  artifact_path: string | null;
  artifact_hash: string | null;
  metrics: Record<string, unknown>;
  role: RegistryRole[];
  training_run_id: string | null;
  created_at: string;
}

export class UnapprovedModel extends Error {}

/** Fail closed: only verified Meta IDs, Modal Muse Spark Open, or Muse Glimmer. */
export function assertApprovedModel(provider: "meta" | "meta-modal", servedModel: string): void {
  if (provider === "meta") {
    if (!(AGENT_MODELS as readonly string[]).includes(servedModel)) {
      throw new UnapprovedModel(`${servedModel} is not a verified Meta tool-use model (allowed: ${AGENT_MODELS.join(", ")})`);
    }
    return;
  }
  if (!servedModel.startsWith("meta-models/Muse-Spark-Open") && !isModalGlimmerModel(servedModel)) {
    throw new UnapprovedModel(`${servedModel} is not a Meta Modal Muse Spark Open or Muse Glimmer model`);
  }
}

export interface BaseModel {
  provider: "meta" | "meta-modal";
  modelId: string;
}

/**
 * The unverified-registry fallback for a role on one surface. With no explicit
 * surface, configured Modal tokens choose Modal (Spark for primary roles,
 * Glimmer for personas); explicit Meta always keeps the Meta base model.
 */
export function baseModelFor(
  role: RegistryRole,
  env: NodeJS.ProcessEnv = process.env,
  surface?: ModelSurface,
): BaseModel {
  const effectiveSurface = surface ?? effectiveAgentSurface(undefined, env);
  if (effectiveSurface === "meta-modal") {
    const modelId = canonicalModalModelId(modalModelIdForRole(role as ModelRole, env), env);
    assertApprovedModel("meta-modal", modelId);
    return { provider: "meta-modal", modelId };
  }
  return { provider: "meta", modelId: modelForRole(role as ModelRole, env) };
}

export async function registerModel(input: RegisterModel & { orgId: string }): Promise<ModelRow> {
  assertApprovedModel(input.provider, input.servedModel);
  const sb = serviceClient();
  const { data: latest, error: readError } = await sb.from("models")
    .select("version").eq("org_id", input.orgId).eq("name", input.name)
    .order("version", { ascending: false }).limit(1).maybeSingle();
  if (readError) throw new Error(`model version lookup failed: ${readError.message}`);
  const version = ((latest?.version as number | undefined) ?? 0) + 1;
  const { data, error } = await sb.from("models").insert({
    org_id: input.orgId,
    name: input.name,
    version,
    base_model: input.baseModel,
    served_model: input.servedModel,
    provider: input.provider,
    status: input.status,
    artifact_path: input.artifactPath ?? null,
    artifact_hash: input.artifactHash ?? null,
    metrics: input.metrics,
    role: input.role,
  }).select("*").single();
  if (error) throw new Error(`model insert failed: ${error.message}`);
  return data as ModelRow;
}

export async function listModels(orgId: string, role?: RegistryRole): Promise<ModelRow[]> {
  let query = serviceClient().from("models").select("*").eq("org_id", orgId).order("created_at", { ascending: false });
  if (role) query = query.contains("role", [role]);
  const { data, error } = await query;
  if (error) throw new Error(`models unreadable: ${error.message}`);
  return (data ?? []) as ModelRow[];
}

export class ModelNotFound extends Error {}
/** A model an active deployment still serves cannot be deprecated. */
export class ModelInUse extends Error {}
/** The training pipeline owns readiness; a manual edit may only deprecate. */
export class StatusNotEditable extends Error {}

const EDITABLE_STATUSES = ["deprecated"] as const;

export const UpdateModel = z.object({
  name: z.string().trim().min(1).max(80).optional(),
  role: z.array(z.enum(REGISTRY_ROLES)).min(1).optional(),
  metrics: z.record(z.unknown()).optional(),
  status: z.enum(MODEL_STATUSES).optional(),
}).strict();
export type UpdateModel = z.infer<typeof UpdateModel>;

/**
 * Edit a registry row's metadata. Deprecation is the only status change allowed
 * here — `ready`/`training` are earned by a training run's artifact hash, and
 * an active deployment blocks deprecating the model it serves.
 */
export async function updateModel(orgId: string, id: string, patch: UpdateModel, actor: string): Promise<ModelRow> {
  const sb = serviceClient();
  const { data: current, error: readError } = await sb.from("models")
    .select("*").eq("org_id", orgId).eq("id", id).maybeSingle();
  if (readError) throw new Error(`model lookup failed: ${readError.message}`);
  if (!current) throw new ModelNotFound(`model ${id} not found`);

  if (patch.status !== undefined) {
    if (!(EDITABLE_STATUSES as readonly string[]).includes(patch.status)) {
      throw new StatusNotEditable(`status ${patch.status} is set by the training pipeline; a manual edit may only deprecate`);
    }
    if (current.status !== "deprecated") {
      const { count, error: depError } = await sb.from("model_deployments")
        .select("id", { count: "exact", head: true })
        .eq("org_id", orgId).eq("model_id", id).eq("status", "active");
      if (depError) throw new Error(`deployment lookup failed: ${depError.message}`);
      if ((count ?? 0) > 0) throw new ModelInUse(`model ${id} is served by an active deployment; roll it back first`);
    }
  }

  const fields: Record<string, unknown> = {};
  if (patch.name !== undefined) fields.name = patch.name;
  if (patch.role !== undefined) fields.role = patch.role;
  if (patch.metrics !== undefined) fields.metrics = patch.metrics;
  if (patch.status !== undefined) fields.status = patch.status;
  if (Object.keys(fields).length === 0) return current as ModelRow;

  const { data, error } = await sb.from("models")
    .update(fields).eq("org_id", orgId).eq("id", id)
    .select("*").single();
  if (error) throw new Error(`model update failed: ${error.message}`);
  await audit({
    orgId, actor, action: "MODEL_UPDATED", subjectType: "model", subjectId: id,
    detail: { fields: Object.keys(fields), ...(patch.status ? { status: patch.status } : {}) },
  });
  return data as ModelRow;
}

export interface ResolvedModel {
  modelId: string;
  provider: "meta" | "meta-modal";
  source: "registry" | "base";
  model?: ModelRow;
}

export interface ResolveModelOptions {
  surface?: ModelSurface;
  env?: NodeJS.ProcessEnv;
}

/**
 * The model a role should use: its newest `ready` registry model on the
 * selected surface, else that surface's verified base model. A registry row
 * is re-checked here, not trusted.
 */
export async function resolveServedModel(orgId: string, role: RegistryRole, options: ResolveModelOptions = {}): Promise<ResolvedModel> {
  const env = options.env ?? process.env;
  let query = serviceClient().from("models")
    .select("*").eq("org_id", orgId).eq("status", "ready").contains("role", [role]);
  if (options.surface) query = query.eq("provider", options.surface);
  const { data, error } = await query.order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (error) throw new Error(`model resolution failed: ${error.message}`);
  if (data) {
    const model = data as ModelRow;
    assertApprovedModel(model.provider, model.served_model);
    return { modelId: model.served_model, provider: model.provider, source: "registry", model };
  }
  const base = baseModelFor(role, env, options.surface);
  return { ...base, source: "base" };
}

/**
 * A tool-use client pinned to the resolved ID: the Meta API for Meta IDs and
 * the correct Modal Spark/Glimmer endpoint for Modal IDs (tool turns verified
 * live on both deployments).
 *
 * A grader definition may name its judge explicitly; that ID is still checked
 * against the allowlist of its surface, so "pinned at definition time" cannot
 * smuggle in a non-Meta model. An explicit surface is likewise never crossed.
 */
export async function resolveModel(
  role: RegistryRole,
  orgId: string,
  pinnedModelId?: string,
  options: ResolveModelOptions = {},
): Promise<AgentClient> {
  const env = options.env ?? process.env;
  if (pinnedModelId) {
    const provider = isModalModelId(pinnedModelId) ? "meta-modal" : "meta";
    assertApprovedModel(provider, pinnedModelId);
    if (options.surface && provider !== options.surface) {
      throw new UnapprovedModel(`model ${pinnedModelId} is on the ${provider} surface, not the explicit ${options.surface} surface`);
    }
    return provider === "meta-modal"
      ? new ModalModelClient({ modelId: pinnedModelId, env, role })
      : new MetaModelClient({ modelId: pinnedModelId });
  }
  const resolved = await resolveServedModel(orgId, role, options);
  return resolved.provider === "meta-modal"
    ? new ModalModelClient({ modelId: resolved.modelId, env, role })
    : new MetaModelClient({ modelId: resolved.modelId });
}

export interface AgentClients { red: AgentClient; blue: AgentClient }

/**
 * The red/blue pair for one exercise. Production passes no overrides, so both
 * roles resolve through the registry factory above; injected clients (tests,
 * replay harnesses) bypass the database but are still the caller's explicit
 * choice, never a hidden default.
 */
export async function resolveAgentClients(
  orgId: string,
  overrides: Partial<AgentClients> = {},
  options: ResolveModelOptions = {},
): Promise<AgentClients> {
  return {
    red: overrides.red ?? await resolveModel("red", orgId, undefined, options),
    blue: overrides.blue ?? await resolveModel("blue", orgId, undefined, options),
  };
}

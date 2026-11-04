import { randomUUID } from "node:crypto";
import { z } from "zod";
import type { DeploymentPin } from "@musearena/shared";
import { audit, type AuditAction } from "../lib/audit.js";
import { serviceClient } from "../lib/supabase.js";
import { assertApprovedModel, type ModelRow, type RegistryRole } from "./models.js";
import type { EvaluationRow } from "./evaluation.js";

/**
 * Model deployments and promotion gate (F-11, design §3.9/§5).
 *
 * Promotion requires a passing evaluation for the same model and role, an
 * approver, and a target alias — a refusal is audited and leaves the current
 * production target untouched. Exactly one deployment is active per
 * (org, alias, environment); rollback restores the previous target row.
 */
export const DEPLOYMENT_STATUSES = ["pending", "active", "rolled_back", "retired"] as const;
export type DeploymentStatus = (typeof DEPLOYMENT_STATUSES)[number];

export const PromoteModel = z.object({
  modelId: z.string().uuid(),
  evaluationId: z.string().uuid(),
  role: z.enum(["red", "blue"]),
  alias: z.string().trim().min(1).max(80),
  environment: z.enum(["staging", "production"]),
  trafficPct: z.number().int().min(0).max(100).default(100),
}).strict();
export type PromoteModel = z.infer<typeof PromoteModel>;

export class DeploymentNotFound extends Error {}
export class PromotionRefused extends Error {}
export class DeploymentConflict extends Error {}

export interface ModelDeploymentRow {
  id: string;
  org_id: string;
  model_id: string;
  evaluation_id: string | null;
  role: RegistryRole;
  alias: string;
  environment: "staging" | "production";
  status: DeploymentStatus;
  traffic_pct: number;
  approved_by: string | null;
  approved_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface DeploymentAuditEntry {
  orgId: string;
  actor: string;
  action: string;
  subjectId: string;
  detail: Record<string, unknown>;
}

export interface DeploymentStore {
  getModel(orgId: string, id: string): Promise<ModelRow | null>;
  getEvaluation(orgId: string, id: string): Promise<EvaluationRow | null>;
  insertDeployment(row: ModelDeploymentRow): Promise<ModelDeploymentRow>;
  getDeployment(orgId: string, id: string): Promise<ModelDeploymentRow | null>;
  updateDeployment(orgId: string, id: string, patch: Partial<ModelDeploymentRow>): Promise<ModelDeploymentRow | null>;
  listDeployments(orgId: string): Promise<ModelDeploymentRow[]>;
  audit(entry: DeploymentAuditEntry): Promise<void>;
}

const nowIso = () => new Date().toISOString();

async function refuse(
  store: DeploymentStore, orgId: string, actor: string, modelId: string, reason: string,
): Promise<never> {
  await store.audit({
    orgId, actor, action: "MODEL_PROMOTION_REFUSED", subjectId: modelId,
    detail: { reason },
  });
  throw new PromotionRefused(reason);
}

export async function promoteModel(
  input: PromoteModel & { orgId: string; approvedBy: string },
  store: DeploymentStore,
): Promise<ModelDeploymentRow> {
  const { orgId: _orgId, approvedBy: _approvedBy, ...body } = input;
  const parsed = PromoteModel.parse(body);
  const model = await store.getModel(input.orgId, parsed.modelId);
  if (!model) return refuse(store, input.orgId, input.approvedBy, parsed.modelId, `model ${parsed.modelId} not found`);
  if (model.status !== "ready") {
    return refuse(store, input.orgId, input.approvedBy, model.id, `model ${model.name} is ${model.status}, not ready`);
  }
  if (model.role.length > 0 && !model.role.includes(parsed.role)) {
    return refuse(store, input.orgId, input.approvedBy, model.id, `model ${model.name} does not claim the ${parsed.role} role`);
  }
  try {
    assertApprovedModel(model.provider, model.served_model);
  } catch (err) {
    return refuse(store, input.orgId, input.approvedBy, model.id, err instanceof Error ? err.message : String(err));
  }
  const evaluation = await store.getEvaluation(input.orgId, parsed.evaluationId);
  if (!evaluation || evaluation.model_id !== model.id || evaluation.role !== parsed.role ||
      evaluation.status !== "succeeded" || evaluation.comparison.passed !== true) {
    return refuse(
      store, input.orgId, input.approvedBy, model.id,
      `promotion requires a passing evaluation for model ${model.name} in role ${parsed.role}`,
    );
  }

  // Supersede the current active target first; the partial unique index is
  // the database backstop for concurrent promotions.
  const existing = await store.listDeployments(input.orgId);
  for (const row of existing) {
    if (row.alias === parsed.alias && row.environment === parsed.environment && row.status === "active") {
      await store.updateDeployment(input.orgId, row.id, { status: "retired", updated_at: nowIso() });
    }
  }
  const at = nowIso();
  const created = await store.insertDeployment({
    id: randomUUID(), org_id: input.orgId, model_id: model.id, evaluation_id: evaluation.id,
    role: parsed.role, alias: parsed.alias, environment: parsed.environment, status: "active",
    traffic_pct: parsed.trafficPct, approved_by: input.approvedBy, approved_at: at,
    created_at: at, updated_at: at,
  });
  await store.audit({
    orgId: input.orgId, actor: input.approvedBy, action: "MODEL_PROMOTED", subjectId: created.id,
    detail: {
      modelId: model.id, servedModel: model.served_model, evaluationId: evaluation.id,
      role: parsed.role, alias: parsed.alias, environment: parsed.environment, trafficPct: parsed.trafficPct,
    },
  });
  return created;
}

export async function rollbackDeployment(
  input: { orgId: string; id: string; actor: string },
  store: DeploymentStore,
): Promise<ModelDeploymentRow> {
  const current = await store.getDeployment(input.orgId, input.id);
  if (!current) throw new DeploymentNotFound(`deployment ${input.id} not found`);
  if (current.status !== "active") {
    throw new DeploymentConflict(`deployment ${current.id} is ${current.status}, not active`);
  }
  const candidates = (await store.listDeployments(input.orgId))
    .filter((row) => row.id !== current.id && row.alias === current.alias &&
      row.environment === current.environment && (row.status === "retired" || row.status === "rolled_back") &&
      row.created_at <= current.created_at)
    .sort((a, b) => b.created_at.localeCompare(a.created_at) || b.id.localeCompare(a.id));
  const previous = candidates[0];
  if (!previous) throw new DeploymentConflict(`no previous deployment target for alias ${current.alias}`);
  const rolled = await store.updateDeployment(input.orgId, current.id, { status: "rolled_back", updated_at: nowIso() });
  if (!rolled) throw new DeploymentNotFound(`deployment ${current.id} not found`);
  const restored = await store.updateDeployment(input.orgId, previous.id, {
    status: "active", approved_by: input.actor, approved_at: nowIso(), updated_at: nowIso(),
  });
  if (!restored) throw new DeploymentNotFound(`deployment ${previous.id} not found`);
  await store.audit({
    orgId: input.orgId, actor: input.actor, action: "MODEL_DEPLOYMENT_ROLLED_BACK", subjectId: current.id,
    detail: { alias: current.alias, environment: current.environment, modelId: current.model_id },
  });
  await store.audit({
    orgId: input.orgId, actor: input.actor, action: "MODEL_DEPLOYMENT_RESTORED", subjectId: restored.id,
    detail: { alias: restored.alias, environment: restored.environment, modelId: restored.model_id },
  });
  return restored;
}

/**
 * Resolve active deployments at exercise start. The returned tuple is pinned
 * into the run record; a traffic miss serves the caller's fallback model but
 * still records which alias/percentage decided it. Evaluations never call
 * this — they always use 100% of the candidate.
 */
export async function pinDeploymentsForRun(
  input: {
    orgId: string;
    roles: Array<"red" | "blue">;
    environment?: "staging" | "production";
    fallbackModelIds: Partial<Record<"red" | "blue", string>>;
    rng?: () => number;
  },
  store: DeploymentStore,
): Promise<Record<string, DeploymentPin>> {
  const environment = input.environment ?? "production";
  const rng = input.rng ?? Math.random;
  const deployments = await store.listDeployments(input.orgId);
  const pins: Record<string, DeploymentPin> = {};
  for (const role of input.roles) {
    const active = deployments.filter((d) => d.role === role && d.environment === environment && d.status === "active");
    if (active.length > 1) {
      throw new DeploymentConflict(`multiple active deployments claim role ${role} in ${environment}; refusing to guess`);
    }
    const deployment = active[0];
    if (!deployment) continue;
    const model = await store.getModel(input.orgId, deployment.model_id);
    if (!model) throw new DeploymentConflict(`active deployment ${deployment.id} points at a missing model`);
    const trafficHit = rng() * 100 < deployment.traffic_pct;
    pins[role] = {
      alias: deployment.alias,
      modelId: trafficHit ? model.served_model : input.fallbackModelIds[role] ?? model.served_model,
      trafficPct: deployment.traffic_pct,
      deploymentId: deployment.id,
      trafficHit,
    };
  }
  return pins;
}

export async function listDeployments(orgId: string): Promise<ModelDeploymentRow[]> {
  const { data, error } = await serviceClient().from("model_deployments").select("*")
    .eq("org_id", orgId).order("created_at", { ascending: false });
  if (error) throw new Error(`model deployments unreadable: ${error.message}`);
  return (data ?? []) as ModelDeploymentRow[];
}

export function supabaseDeploymentStore(): DeploymentStore {
  const sb = () => serviceClient();
  return {
    async getModel(orgId, id) {
      const { data, error } = await sb().from("models").select("*")
        .eq("org_id", orgId).eq("id", id).maybeSingle();
      if (error) throw new Error(`model unreadable: ${error.message}`);
      return (data as ModelRow | null) ?? null;
    },
    async getEvaluation(orgId, id) {
      const { data, error } = await sb().from("evaluations").select("*")
        .eq("org_id", orgId).eq("id", id).maybeSingle();
      if (error) throw new Error(`evaluation unreadable: ${error.message}`);
      return (data as EvaluationRow | null) ?? null;
    },
    async insertDeployment(row) {
      const { data, error } = await sb().from("model_deployments").insert(row).select("*").single();
      if (error) throw new Error(`model deployment insert failed: ${error.message}`);
      return data as ModelDeploymentRow;
    },
    async getDeployment(orgId, id) {
      const { data, error } = await sb().from("model_deployments").select("*")
        .eq("org_id", orgId).eq("id", id).maybeSingle();
      if (error) throw new Error(`model deployment unreadable: ${error.message}`);
      return (data as ModelDeploymentRow | null) ?? null;
    },
    async updateDeployment(orgId, id, patch) {
      const { data, error } = await sb().from("model_deployments").update(patch)
        .eq("org_id", orgId).eq("id", id).select("*").maybeSingle();
      if (error) throw new Error(`model deployment update failed: ${error.message}`);
      return (data as ModelDeploymentRow | null) ?? null;
    },
    async listDeployments(orgId) {
      return listDeployments(orgId);
    },
    async audit(entry) {
      await audit({
        orgId: entry.orgId, actor: entry.actor, action: entry.action as AuditAction,
        subjectType: "model_deployment", subjectId: entry.subjectId, detail: entry.detail,
      });
    },
  };
}

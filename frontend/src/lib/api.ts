import { EnvironmentSpec, type Budget, type Deployment, type DeploymentStatus, type Persona, type PlatformSelection, type Run } from "@musearena/shared";
import { sessionToken, supabase } from "./supabase";

// Real data layer: Supabase tables (RLS-scoped by the Clerk JWT) + the live
// designer endpoint. No mock data — empty results render as empty states.

export interface TopologyNode {
  hostId: string; name: string; role: string; runtime: string; os: string;
  services: string[]; subnet: string; vulnCount: number;
}
export interface TopologySubnet { name: string; cidr: string; zone: string; nodes: TopologyNode[] }
export interface TopologyMap { cidr: string; domain: string; subnets: TopologySubnet[]; firewallRules: string[] }

export interface PlanHost {
  hostId: string; role: string; runtime: string; os: string;
  resources: { vcpu: number; memoryMb: number; diskGb: number };
  subnet?: string; address?: string;
  packages: string[]; units: string[]; clientTools: string[]; dependsOn: string[];
  config: { path: string; purpose: string }[];
  seeds: { target: string; purpose: string }[];
  readiness: { probe: string; kind: string; expect?: string }[];
  tasks: string[];
}
export interface PlanEdge { from: string; to: string; protocol: string; port: number; address?: string; purpose: string }
export interface PlanLabProbe { from: string; to: string; probe: string; kind: string; expect?: string }
export interface PlanStep { hostId: string; phase: string; task: string }
export interface DeploymentPlan {
  versions: { catalog: string; profile: string; image: string };
  topology: { cidr: string; domain: string; subnets: EnvironmentSpec["topology"]["subnets"]; addresses: Record<string, string> };
  hosts: PlanHost[];
  edges: PlanEdge[];
  labProbes: PlanLabProbe[];
  steps: PlanStep[];
  totals: { instances: number; vcpu: number; memoryMb: number; diskGb: number; dollarsPerHour: number };
  gaps: string[];
}

export interface DesignPackage {
  spec: EnvironmentSpec;
  digest: string;
  withinBudget: boolean;
  violations: string[];
  designErrors: string[];
  topology: TopologyMap;
  plan: DeploymentPlan;
  /** Content digest of `plan`; the trigger refuses a plan that changed since approval. */
  planDigest: string;
  cost: { perHour: number; ttlTotal: number };
  canProvision: boolean;
  blockReasons: string[];
}

export interface DatasetRow {
  id: string; orgId: string; runId: string; name: string; contentHash: string; formatVersion: number;
  split: string; redactionPolicyVersion: string; storagePath: string; createdAt: string;
  /** Provenance carried by the snapshot: synthetic, imported and/or field rows. */
  sources: string[];
  selection?: {
    counts?: { sources?: Record<string, number>; realShare?: number; realism?: { share?: number } };
  };
}

export interface AuditEntry {
  id: number; actor: string; action: string; subjectType: string; subjectId: string;
  detail: Record<string, unknown>; createdAt: string;
}

export interface TrajectoryStepView {
  runId: string; stepIndex: number; actor: string; action: string; observation: string;
  reasoning?: string; detail?: Record<string, unknown>; hostId?: string; techniqueId?: string;
  at: string; tokenUsage?: { inputTokens: number; outputTokens: number };
}

export interface GroundTruthView {
  runId: string; hostId: string; kind: string; actor: string; outcome: string;
  techniqueId?: string; at: string; detail?: Record<string, unknown>;
}

export interface JoinedStepView {
  at: string; hostId: string; techniqueId?: string;
  trajectory?: TrajectoryStepView; groundTruth?: GroundTruthView; matched: boolean;
}

export interface DatasetExportView {
  meta: { runId: string; formatVersion: number; contentHash: string; split: string; redactionPolicyVersion: string };
  run: { runId: string; specDigest: string; techniquePackVersion: string; truthLayer: string; backend: string };
  join: {
    runId: string; steps: JoinedStepView[]; matched: number; trajectoryOnly: number;
    groundTruthOnly: number; dropped: number; dropReasons?: Record<string, number>;
  };
}

export type DesignerRunEventType =
  | "run.started" | "run.completed" | "run.failed" | "run.cancelled"
  | "step.started" | "step.completed" | "step.failed" | "step.blocked"
  | "model.progress" | "model.reasoning" | "artifact.ready";

export interface DesignerRunEvent {
  type: DesignerRunEventType;
  runId: string;
  seq: number;
  at: string;
  phase: string;
  stepId: string;
  title: string;
  detail?: string;
  data?: Record<string, unknown>;
}

export interface DesignStreamOptions {
  onEvent?: (event: DesignerRunEvent) => void;
  signal?: AbortSignal;
  platform?: PlatformSelection;
}

/** The designer refused to substitute a platform; the operator must choose. */
export class PlatformUnavailableError extends Error {
  readonly field: string;
  readonly requested: PlatformSelection;
  readonly alternatives: PlatformSelection[];
  constructor(message: string, field: string, requested: PlatformSelection, alternatives: PlatformSelection[]) {
    super(message);
    this.name = "PlatformUnavailableError";
    this.field = field;
    this.requested = requested;
    this.alternatives = alternatives;
  }
}

const DESIGN_API = (import.meta as { env?: Record<string, string> }).env?.VITE_DESIGN_API_URL;

async function liveDesignStream(payload: Record<string, unknown>, opts: DesignStreamOptions = {}): Promise<DesignPackage> {
  if (!DESIGN_API) throw new Error("Designer endpoint not configured (VITE_DESIGN_API_URL). Start backend/src/designer/server.ts.");
  const token = await sessionToken();
  if (!token) throw new Error("Not signed in: the designer requires a Clerk session.");

  let res: Response;
  try {
    res = await fetch(`${DESIGN_API}/design/stream`, {
      method: "POST",
      signal: opts.signal,
      headers: {
        "Content-Type": "application/json",
        Accept: "text/event-stream",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify(payload),
    });
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") throw err;
    throw new Error(`Designer endpoint unreachable at ${DESIGN_API}. Start it with: node backend/dist/designer/server.js`);
  }
  if (!res.ok) {
    const text = await res.text();
    if (res.status === 409) {
      try {
        const body = JSON.parse(text) as { error?: string; code?: string; field?: string; requested?: PlatformSelection; alternatives?: PlatformSelection[] };
        if (body.code === "platform_unavailable" && body.requested) {
          throw new PlatformUnavailableError(body.error ?? "Selected platform is unavailable", body.field ?? "platform", body.requested, body.alternatives ?? []);
        }
      } catch (err) {
        if (err instanceof PlatformUnavailableError) throw err;
      }
    }
    throw new Error(`Designer endpoint failed (${res.status}): ${text.slice(0, 300)}`);
  }

  const contentType = res.headers.get("content-type") ?? "";
  if (!contentType.includes("text/event-stream") || !res.body) {
    // Compatibility with a non-streaming deployment of the same handler.
    return (await res.json()) as DesignPackage;
  }

  let artifact: DesignPackage | null = null;
  let failure: string | null = null;
  const decoder = new TextDecoder();
  const reader = res.body.getReader();
  let buffer = "";

  const handleBlock = (block: string) => {
    const data = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith("data:"))
      .map((line) => line.slice(5).trimStart())
      .join("\n");
    if (!data) return;
    const event = JSON.parse(data) as DesignerRunEvent;
    try { opts.onEvent?.(event); } catch { /* rendering an event must not break the stream */ }
    if (event.type === "artifact.ready") {
      const candidate = event.data?.package;
      if (candidate && typeof candidate === "object") artifact = candidate as DesignPackage;
    }
    if (event.type === "run.failed") failure = event.detail ?? "Designer run failed";
    if (event.type === "run.cancelled") failure = "Designer run cancelled";
  };

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, "\n");
      let boundary = buffer.indexOf("\n\n");
      while (boundary >= 0) {
        handleBlock(buffer.slice(0, boundary));
        buffer = buffer.slice(boundary + 2);
        boundary = buffer.indexOf("\n\n");
      }
    }
    buffer += decoder.decode();
    if (buffer.trim()) handleBlock(buffer);
  } catch (err) {
    if (err instanceof Error && err.name === "AbortError") throw err;
    throw err;
  } finally {
    try { reader.releaseLock(); } catch { /* already closed */ }
  }

  if (!artifact) throw new Error(failure ?? "Designer stream ended before an artifact was produced");
  return artifact;
}

interface DeploymentRow {
  id: string; org_id: string; stack_id: string; status: string;
  access_info: Record<string, string>; cost_estimate_per_hour: number | null;
  drift_status: string | null; created_at: string;
  environments?: { spec_digest: string; spec: EnvironmentSpec } | null;
}

function toDeployment(r: DeploymentRow): Deployment {
  return {
    id: r.id, orgId: r.org_id, specDigest: r.environments?.spec_digest ?? "",
    stackId: r.stack_id, status: r.status as DeploymentStatus,
    accessInfo: r.access_info ?? {},
    costEstimatePerHour: r.cost_estimate_per_hour ?? undefined,
    driftStatus: r.drift_status ?? undefined, createdAt: r.created_at,
  };
}

export const api = {
  async deployments(): Promise<Deployment[]> {
    const { data, error } = await supabase().from("deployments").select("*, environments(spec_digest, spec)").order("created_at", { ascending: false });
    if (error) throw new Error(error.message);
    return (data as DeploymentRow[]).map(toDeployment);
  },

  async deployment(id: string): Promise<{ deployment: Deployment; spec?: EnvironmentSpec } | undefined> {
    const { data, error } = await supabase().from("deployments").select("*, environments(spec_digest, spec)").eq("id", id).maybeSingle();
    if (error) throw new Error(error.message);
    if (!data) return undefined;
    const row = data as DeploymentRow;
    return { deployment: toDeployment(row), spec: row.environments?.spec };
  },

  async runs(): Promise<Run[]> {
    const { data, error } = await supabase().from("runs").select("*").order("created_at", { ascending: false });
    if (error) throw new Error(error.message);
    return (data as Record<string, unknown>[]).map((r) => {
      const rawModelIds = r.model_ids;
      const modelIds = rawModelIds && typeof rawModelIds === "object" && !Array.isArray(rawModelIds)
        ? Object.fromEntries(Object.entries(rawModelIds as Record<string, unknown>).filter(([, value]) => typeof value === "string"))
        : {};
      return {
        runId: r.run_id as string, orgId: r.org_id as string, deploymentId: r.deployment_id as string,
        mode: r.mode as Run["mode"], specDigest: r.spec_digest as string,
        techniquePackVersion: r.technique_pack_version as string, modelIds: modelIds as Record<string, string>,
        truthLayer: r.truth_layer as Run["truthLayer"], backend: r.backend as Run["backend"],
        score: (r.score as Run["score"]) ?? undefined,
      };
    });
  },

  async personas(): Promise<Persona[]> {
    const { data, error } = await supabase().from("environments").select("spec").order("created_at", { ascending: false }).limit(20);
    if (error) throw new Error(error.message);
    const seen = new Map<string, Persona>();
    for (const row of data as { spec: EnvironmentSpec }[]) {
      for (const p of row.spec.personas ?? []) if (!seen.has(p.id)) seen.set(p.id, p);
    }
    return [...seen.values()];
  },

  /**
   * Personas grouped by the environment that generated them. A persona exists
   * only inside its environment's spec; this keeps that ownership visible
   * instead of merging every workspace into one flat cast.
   */
  async personasByEnvironment(): Promise<{ environmentId: string; specName: string; createdAt: string; personas: Persona[] }[]> {
    const { data, error } = await supabase()
      .from("environments")
      .select("id, spec, created_at")
      .order("created_at", { ascending: false })
      .limit(20);
    if (error) throw new Error(error.message);
    return (data as { id: string; spec: EnvironmentSpec; created_at: string }[])
      .map((row) => ({
        environmentId: row.id,
        specName: row.spec?.name ?? "",
        createdAt: row.created_at,
        personas: row.spec?.personas ?? [],
      }))
      .filter((group) => group.personas.length > 0);
  },

  async submitDesign(prompt: string, budget: Budget, opts?: DesignStreamOptions): Promise<DesignPackage> {
    return liveDesignStream({ prompt, budget, platform: opts?.platform }, opts);
  },

  async refineDesign(current: EnvironmentSpec, instruction: string, budget: Budget, opts?: DesignStreamOptions): Promise<DesignPackage> {
    return liveDesignStream({ current, instruction, budget, platform: opts?.platform ?? current.platform }, opts);
  },

  /** Validate an imported spec with the same server-side gates as a design. */
  async validateDesign(spec: EnvironmentSpec, budget: Budget, opts?: DesignStreamOptions): Promise<DesignPackage> {
    return liveDesignStream({ spec, budget, platform: opts?.platform ?? spec.platform }, opts);
  },

  /** Persist an approved design as environment + pending deployment (workers provision it). */
  async createDeployment(spec: EnvironmentSpec, digest: string, planDigest: string, orgId: string): Promise<{ deploymentId: string }> {
    const sb = supabase();
    const { data: env, error: e1 } = await sb.from("environments").insert({ org_id: orgId, created_by: "designer", spec, spec_digest: digest, status: "approved" }).select("id").single();
    if (e1) throw new Error(e1.message);
    // The approved plan digest travels with the row; the worker recomputes the
    // plan and refuses to provision if the catalog/profile/image moved.
    const { data: dep, error: e2 } = await sb.from("deployments").insert({ org_id: orgId, environment_id: (env as { id: string }).id, stack_id: "pending", status: "pending", access_info: { planDigest, ...(spec.platform ? { platform: spec.platform } : {}) } }).select("id").single();
    if (e2) throw new Error(e2.message);
    return { deploymentId: (dep as { id: string }).id };
  },

  async templates(): Promise<{ id: string; name: string; family: string; version: number; spec: EnvironmentSpec; digest: string; shared: boolean; shareToken: string | null; createdAt: string }[]> {
    const { data, error } = await supabase().from("templates").select("*").order("created_at", { ascending: false });
    if (error) throw new Error(error.message);
    return (data as Record<string, unknown>[]).map((r) => ({
      id: r.id as string, name: r.name as string, family: r.family as string, version: r.version as number,
      spec: EnvironmentSpec.parse(r.spec), digest: r.digest as string, shared: r.shared as boolean,
      shareToken: (r.share_token as string) ?? null, createdAt: r.created_at as string,
    }));
  },

  async saveTemplate(specInput: EnvironmentSpec, digest: string, orgId: string): Promise<void> {
    const spec = EnvironmentSpec.parse(specInput);
    const sb = supabase();
    let lastError: { code?: unknown; message?: unknown } | null = null;
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const { data: latest, error: latestError } = await sb.from("templates")
        .select("version")
        .eq("org_id", orgId)
        .eq("name", spec.name)
        .order("version", { ascending: false })
        .limit(1)
        .maybeSingle();
      if (latestError) throw new Error(latestError.message);
      const version = ((latest as { version?: number } | null)?.version ?? 0) + 1;
      const { error } = await sb.from("templates")
        .insert({ org_id: orgId, name: spec.name, family: spec.provider, version, spec, digest });
      if (!error) return;
      lastError = error;
      const conflict = error.code === "23505" || /duplicate key|unique constraint/i.test(error.message ?? "");
      if (!conflict || attempt === 2) break;
    }
    throw new Error(String(lastError?.message ?? "template save failed"));
  },

  async shareTemplate(id: string, token: string): Promise<void> {
    const { error } = await supabase().from("templates").update({ shared: true, share_token: token }).eq("id", id);
    if (error) throw new Error(error.message);
  },

  async sharedTemplate(token: string): Promise<EnvironmentSpec | null> {
    const { data, error } = await supabase().from("templates").select("spec").eq("share_token", token).eq("shared", true).maybeSingle();
    if (error) throw new Error(error.message);
    return data ? EnvironmentSpec.parse((data as { spec: unknown }).spec) : null;
  },

  async deleteTemplate(id: string): Promise<void> {
    const { error } = await supabase().from("templates").delete().eq("id", id);
    if (error) throw new Error(error.message);
  },

  async datasets(): Promise<DatasetRow[]> {
    const { data, error } = await supabase().from("datasets").select("*").order("created_at", { ascending: false });
    if (error) throw new Error(error.message);
    return (data as Record<string, unknown>[]).map((r) => {
      const storagePath = r.storage_path as string;
      const segments = storagePath.replace(/^datasets\//, "").split("/");
      return {
        id: r.id as string, orgId: (r.org_id as string) ?? segments[0] ?? "", runId: segments[1] === "built" ? "" : segments[1] ?? "",
        name: r.name as string, contentHash: r.content_hash as string,
        formatVersion: r.format_version as number, split: r.split as string,
        redactionPolicyVersion: r.redaction_policy_version as string,
        storagePath, createdAt: r.created_at as string,
        sources: (r.sources as string[] | null) ?? [],
        selection: (r.selection as DatasetRow["selection"]) ?? undefined,
      };
    });
  },

  /** Score/audit detail for one run (exercise mode, models, enforcement). */
  async runAudit(runId: string): Promise<AuditEntry[]> {
    const { data, error } = await supabase().from("audit_log").select("id, actor, action, subject_type, subject_id, detail, created_at").eq("subject_id", runId).order("id", { ascending: true });
    if (error) throw new Error(error.message);
    return (data as Record<string, unknown>[]).map((r) => ({
      id: r.id as number, actor: r.actor as string, action: r.action as string,
      subjectType: r.subject_type as string, subjectId: r.subject_id as string,
      detail: (r.detail as Record<string, unknown>) ?? {}, createdAt: r.created_at as string,
    }));
  },

  /**
   * Download and decode the immutable joined export behind a dataset row.
   * This is the executed trajectory/ground truth the score was computed from;
   * callers must not synthesize a trajectory when this read fails.
   */
  async datasetExport(dataset: DatasetRow): Promise<DatasetExportView> {
    const objectPath = `${dataset.storagePath.replace(/^datasets\//, "")}/export.json.gz`;
    const { data, error } = await supabase().storage.from("datasets").download(objectPath);
    if (error) throw new Error(`dataset export unavailable: ${error.message}`);
    if (!data) throw new Error("dataset export unavailable: empty object");
    const DS = (globalThis as { DecompressionStream?: typeof DecompressionStream }).DecompressionStream;
    if (!DS) throw new Error("dataset export unavailable: this browser cannot decode gzip exports");
    const parsed = await new Response(data.stream().pipeThrough(new DS("gzip"))).json() as Partial<DatasetExportView> & { roles?: unknown };
    if (!parsed.meta?.runId || !parsed.join || !Array.isArray(parsed.join.steps)) {
      throw new Error(parsed.roles
        ? "dataset export unavailable: built training snapshots are not joined run exports"
        : "dataset export unavailable: object is not a joined run export");
    }
    return parsed as DatasetExportView;
  },
};

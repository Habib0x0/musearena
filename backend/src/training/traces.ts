import { redactDeep, type DatasetExport } from "../observability/export.js";
import { serviceClient } from "../lib/supabase.js";

/**
 * Queryable trace rows (design §3.1, F-4).
 *
 * The dataset export is an immutable artifact; `traces` is the working record
 * reviewers act on and the dataset builder selects from. One row per joined
 * step, carrying the actor, the ground-truth outcome and the full structured
 * payload, so red and blue can be filtered without re-parsing a dataset.
 */
export const TRACE_SOURCES = ["synthetic", "imported", "field"] as const;
/** synthetic = platform exercise; imported = exported external agent run; field = real observation. */
export type TraceSource = (typeof TRACE_SOURCES)[number];

export interface TraceRow {
  /** Present on stored rows; omitted from the insert shape. */
  id?: string;
  org_id: string;
  run_id: string;
  dataset_id: string | null;
  step_index: number;
  at: string;
  host_id: string;
  technique_id: string | null;
  actor: string | null;
  action: string | null;
  observation: string | null;
  reasoning: string | null;
  tool_call: string | null;
  outcome: string | null;
  matched: boolean;
  split: "train" | "val" | "test";
  source: TraceSource;
  framework: string | null;
  payload: Record<string, unknown>;
}

export function traceRowsFor(exp: DatasetExport, orgId: string, datasetId: string | null): TraceRow[] {
  return exp.join.steps.map((step, index) => redactDeep((() => {
    const at = new Date(step.at);
    return {
      org_id: orgId,
      run_id: exp.meta.runId,
      dataset_id: datasetId,
      step_index: index,
      at: Number.isFinite(at.getTime()) ? at.toISOString() : new Date().toISOString(),
      host_id: step.hostId ?? "",
      technique_id: step.groundTruth?.techniqueId ?? step.trajectory?.techniqueId ?? null,
      actor: step.groundTruth?.actor ?? step.trajectory?.actor ?? null,
      action: step.trajectory?.action ?? null,
      observation: step.trajectory?.observation ?? null,
      reasoning: step.trajectory?.reasoning ?? null,
      tool_call: step.trajectory?.toolCall ?? null,
      outcome: step.groundTruth?.outcome ?? null,
      matched: step.matched,
      split: exp.meta.split,
      source: "synthetic" as TraceSource,
      framework: null,
      payload: {
        trajectory: step.trajectory ?? null,
        groundTruth: step.groundTruth ?? null,
        matched: step.matched,
      },
    };
  })()));
}

export interface TraceWriteError {
  code?: string;
  message: string;
}

export interface TraceStore {
  from(table: "traces"): {
    upsert(rows: TraceRow[], opts: { onConflict: string; ignoreDuplicates?: boolean }): Promise<{ error: TraceWriteError | null }>;
  };
}

/** True only for the additive learning tables not being installed yet. */
export function isMissingLearningSchemaError(error: unknown): boolean {
  const record = error && typeof error === "object" ? error as { code?: unknown; message?: unknown } : undefined;
  const code = typeof record?.code === "string" ? record.code : "";
  const message = error instanceof Error
    ? error.message
    : typeof record?.message === "string" ? record.message : typeof error === "string" ? error : "";
  return code === "PGRST205" || code === "42P01"
    || /could not find the table|relation .* does not exist|schema cache/i.test(message);
}

/**
 * Idempotent per `(org, run, step)`: the first published raw row wins and a
 * re-publish inserts only missing steps. The trace is append-only (0011), so a
 * later label change is an adjudication overlay at build time, never a rewrite
 * of the stored trajectory. Actual write errors fail closed. The additive
 * learning schema is rollout-gated: if its tables are not installed, the
 * immutable dataset export remains the source of truth, a loud warning is
 * emitted, and zero queryable rows are reported instead of bricking the core
 * exercise/score path on an unapplied migration.
 */
export async function persistRunTraces(
  exp: DatasetExport,
  orgId: string,
  datasetId: string | null,
  store?: TraceStore,
): Promise<number> {
  const rows = traceRowsFor(exp, orgId, datasetId);
  if (!rows.length) return 0;
  const client = store ?? serviceClient() as unknown as TraceStore;
  const { error } = await client
    .from("traces")
    .upsert(rows, { onConflict: "org_id,run_id,step_index", ignoreDuplicates: true });
  if (error) {
    if (isMissingLearningSchemaError(error)) {
      console.warn(`[traces] learning schema is not installed; published dataset export without trace rows (${error.message})`);
      return 0;
    }
    throw new Error(`trace persistence failed: ${error.message}`);
  }
  return rows.length;
}

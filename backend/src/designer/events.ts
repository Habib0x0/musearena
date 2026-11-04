import type { PlatformSelection } from "@musearena/shared";

/**
 * Observable lifecycle for one designer run.
 *
 * The pipeline emits semantic events at the points where work actually
 * happens: context assembly, each model attempt, streamed reasoning/output
 * progress, normalization, validation gates, bounded repairs, and packaging.
 * Transports (the HTTP SSE endpoint, tests, scripts) decide how to render
 * them; the pipeline itself stays transport-neutral.
 */
export type DesignEventType =
  | "run.started"
  | "run.completed"
  | "run.failed"
  | "run.cancelled"
  | "step.started"
  | "step.completed"
  | "step.failed"
  | "step.blocked"
  | "model.progress"
  | "model.reasoning"
  | "artifact.ready";

export interface DesignEventInput {
  type: DesignEventType;
  phase: string;
  stepId: string;
  title: string;
  detail?: string;
  data?: Record<string, unknown>;
}

export interface DesignRunEvent extends DesignEventInput {
  runId: string;
  seq: number;
  at: string;
}

export type DesignEventSink = (event: DesignEventInput) => void;

export interface DesignRunOptions {
  signal?: AbortSignal;
  onEvent?: DesignEventSink;
  /** Operator-pinned runtime/model/exercise platform for this run. */
  platform?: PlatformSelection;
}

/** Emit without letting an observer/transport failure change the design outcome. */
export function emitDesignEvent(opts: DesignRunOptions | undefined, event: DesignEventInput): void {
  try {
    opts?.onEvent?.(event);
  } catch {
    // Rendering progress is best-effort; the design computation is authoritative.
  }
}

export function throwIfDesignAborted(signal?: AbortSignal): void {
  if (!signal?.aborted) return;
  throw signal.reason instanceof Error ? signal.reason : new Error("design run cancelled");
}

export function isDesignAbort(err: unknown, signal?: AbortSignal): boolean {
  return Boolean(signal?.aborted) || (err instanceof Error && err.name === "AbortError");
}

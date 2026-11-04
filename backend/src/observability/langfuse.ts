import { randomUUID } from "node:crypto";
import type { TrajectoryStep } from "./events.js";
import type { TrajectoryRecorder } from "./trajectory.js";

/**
 * Langfuse trajectory sink (Req §4.1): one trace per run_id, one span per
 * agent step (observation → action, reasoning/tool in metadata). Uses the
 * public ingestion API directly (no SDK dependency). Steps are buffered and
 * sent on flush(); a failed flush throws so the run cannot claim recorded
 * trajectories that never arrived.
 */
export interface LangfuseConfig { host: string; publicKey: string; secretKey: string }

export function langfuseConfig(env: NodeJS.ProcessEnv = process.env): LangfuseConfig | null {
  const host = env.LANGFUSE_HOST, publicKey = env.LANGFUSE_PUBLIC_KEY, secretKey = env.LANGFUSE_SECRET_KEY;
  return host && publicKey && secretKey ? { host: host.replace(/\/$/, ""), publicKey, secretKey } : null;
}

const auth = (c: LangfuseConfig) => `Basic ${Buffer.from(`${c.publicKey}:${c.secretKey}`).toString("base64")}`;

export class LangfuseSink {
  private batch: Record<string, unknown>[] = [];
  private traces = new Set<string>();
  constructor(private cfg: LangfuseConfig, private meta: Record<string, unknown> = {}) {}

  add(step: TrajectoryStep): void {
    const now = new Date().toISOString();
    if (!this.traces.has(step.runId)) {
      this.traces.add(step.runId);
      this.batch.push({ id: randomUUID(), type: "trace-create", timestamp: now, body: { id: step.runId, name: "musearena-run", sessionId: step.runId, metadata: this.meta, tags: ["musearena"] } });
    }
    this.batch.push({
      id: randomUUID(), type: "span-create", timestamp: now,
      body: {
        id: randomUUID(), traceId: step.runId, name: `${step.actor}:${step.toolCall ?? "step"}`,
        startTime: step.at, endTime: step.at,
        input: step.observation, output: step.action ?? null,
        metadata: { actor: step.actor, hostId: step.hostId, techniqueId: step.techniqueId, reasoning: step.reasoning, toolCall: step.toolCall },
      },
    });
  }

  async flush(): Promise<number> {
    if (!this.batch.length) return 0;
    const sent = this.batch;
    this.batch = [];
    const res = await fetch(`${this.cfg.host}/api/public/ingestion`, {
      method: "POST", headers: { Authorization: auth(this.cfg), "Content-Type": "application/json" }, body: JSON.stringify({ batch: sent }),
    });
    const body = (await res.json().catch(() => ({}))) as { errors?: { id: string; status: number; message?: string }[] };
    if (!res.ok || (body.errors ?? []).length) throw new Error(`Langfuse ingestion failed (${res.status}): ${JSON.stringify(body.errors ?? body).slice(0, 300)}`);
    return sent.length;
  }
}

/** Records locally (join/export) AND to Langfuse. */
export class TeeRecorder implements TrajectoryRecorder {
  constructor(private local: TrajectoryRecorder, private sink: LangfuseSink | null) {}
  record(step: TrajectoryStep): TrajectoryStep {
    const s = this.local.record(step);
    this.sink?.add(s);
    return s;
  }
}

/** Count spans Langfuse holds for a trace (verification). */
export async function langfuseTraceSpans(cfg: LangfuseConfig, traceId: string): Promise<number> {
  const res = await fetch(`${cfg.host}/api/public/traces/${encodeURIComponent(traceId)}`, { headers: { Authorization: auth(cfg) } });
  if (res.status === 404) return 0;
  if (!res.ok) throw new Error(`Langfuse trace fetch ${res.status}`);
  const t = (await res.json()) as { observations?: unknown[] };
  return t.observations?.length ?? 0;
}

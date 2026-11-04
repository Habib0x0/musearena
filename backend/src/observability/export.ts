import type { Run, TraceMeta } from "@musearena/shared";
import { computeExportHash, assertExportIntegrity, assertNoProofRows } from "../traces/integrity-crypto.js";
import { localStore, EventStore, type GroundTruthEvent, type TrajectoryStep } from "./events.js";

export { exportPayload, computeExportHash } from "../traces/integrity-crypto.js";

export interface JoinedStep {
  at: string;
  hostId: string;
  techniqueId?: string;
  trajectory?: TrajectoryStep;
  groundTruth?: GroundTruthEvent;
  matched: boolean;
}

export interface JoinReport {
  runId: string;
  steps: JoinedStep[];
  matched: number;
  trajectoryOnly: number;
  groundTruthOnly: number;
  dropped: number; // explicit accounting — silent drops forbidden (§9)
  /** Every dropped row, by reason. sum(dropReasons) === dropped, always. */
  dropReasons?: Record<string, number>;
}

const SKEW_MS = 5 * 60 * 1000; // declared clock-skew tolerance

/**
 * Join trajectory ↔ ground truth (Req §4.3, §9). A trajectory step matches a
 * ground-truth event only when host matches AND (technique matches OR the
 * ground-truth objectiveId is one this trajectory attempted) AND the event is
 * within the declared skew. Host-only matching can fuse unrelated rows and
 * misattribute outcomes, so it is deliberately not enough.
 */
export function joinRun(runId: string, store: EventStore = localStore): JoinReport {
  const traj = store.trajectory(runId);
  const gt = store.groundTruth(runId);
  const usedGt = new Set<number>();
  const steps: JoinedStep[] = [];

  const compatible = (t: TrajectoryStep, g: GroundTruthEvent): boolean => {
    if (t.hostId && g.hostId !== t.hostId) return false;
    if (t.techniqueId && g.techniqueId) return t.techniqueId === g.techniqueId;
    const objectiveId = g.detail?.objectiveId;
    if (typeof objectiveId === "string" && t.action) return t.action.includes(objectiveId) || objectiveId === t.techniqueId;
    return t.techniqueId === g.techniqueId;
  };

  for (const t of traj) {
    const tMs = Date.parse(t.at);
    let best = -1; let bestDelta = Infinity;
    gt.forEach((g, i) => {
      if (usedGt.has(i) || !compatible(t, g)) return;
      const d = Math.abs(Date.parse(g.at) - tMs);
      if (d <= SKEW_MS && d < bestDelta) { best = i; bestDelta = d; }
    });
    if (best >= 0) { usedGt.add(best); steps.push({ at: gt[best].at > t.at ? gt[best].at : t.at, hostId: t.hostId ?? gt[best].hostId, techniqueId: t.techniqueId ?? gt[best].techniqueId, trajectory: t, groundTruth: gt[best], matched: true }); }
    else steps.push({ at: t.at, hostId: t.hostId ?? "", techniqueId: t.techniqueId, trajectory: t, matched: false });
  }
  gt.forEach((g, i) => { if (!usedGt.has(i)) steps.push({ at: g.at, hostId: g.hostId, techniqueId: g.techniqueId, groundTruth: g, matched: false }); });
  steps.sort((a, b) => a.at.localeCompare(b.at));

  const matched = steps.filter((s) => s.matched).length;
  return {
    runId, steps, matched,
    trajectoryOnly: steps.filter((s) => s.trajectory && !s.groundTruth).length,
    groundTruthOnly: steps.filter((s) => s.groundTruth && !s.trajectory).length,
    dropped: 0, // every row is accounted in steps; nothing is silently dropped
    dropReasons: {},
  };
}

export interface DatasetExport {
  meta: TraceMeta;
  run: { runId: string; specDigest: string; techniquePackVersion: string; truthLayer: string; backend: string };
  join: JoinReport;
}

const SECRET_ASSIGN_RE = /([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|credential|private[_-]?key|access[_-]?key|auth|cookie|session|honeytoken)[A-Za-z0-9_.-]*)\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;}\]]+)/gi;
const URI_PASSWORD_RE = /(\b[a-z][a-z0-9+.-]*:\/\/[^/\s:@]+:)([^@\s/]+)(@)/gi;
const BEARER_RE = /\bBearer\s+[A-Za-z0-9._~+\/-]+=*/gi;
const KNOWN_SECRET_RE = /\b(?:sk-(?:live|test|proj)-[A-Za-z0-9_-]+|ghp_[A-Za-z0-9_]+|github_pat_[A-Za-z0-9_]+|xox[baprs]-[A-Za-z0-9-]+|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|MUSE-PROOF-[0-9a-f]+)\b/gi;

function keySegments(key: string): string[] {
  return key.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(/[^A-Za-z0-9]+/).map((s) => s.toLowerCase()).filter(Boolean);
}

function isSensitiveKey(key: string): boolean {
  if (/token(usage|count|budget|limit)/i.test(key)) return false;
  const lower = key.toLowerCase();
  if (/password|passwd|secret|credential|honeytoken|apikey|api[-_]?key|private[-_]?key|access[-_]?key/.test(lower)) return true;
  return keySegments(key).some((s) => ["pwd", "token", "auth", "cookie", "session", "proof"].includes(s));
}

/** The one redaction rule; the dataset builder reuses it so files never diverge. */
export function redactText(value: string | null | undefined): string | null {
  if (value === null || value === undefined) return null;
  return value
    .replace(SECRET_ASSIGN_RE, "$1: [redacted]")
    .replace(URI_PASSWORD_RE, "$1[redacted]$3")
    .replace(BEARER_RE, "Bearer [redacted]")
    .replace(KNOWN_SECRET_RE, "[redacted]");
}

/**
 * Deep, fail-closed redaction for persisted trace/export payloads. Sensitive
 * field names redact the whole value; every remaining string is scanned for
 * credential assignments, bearer/API-key shapes, URI passwords and planted
 * proof values. Unknown object shapes are traversed, never passed through.
 */
export function redactDeep<T>(value: T, key?: string): T {
  if (key && isSensitiveKey(key)) {
    if (Array.isArray(value)) return value.map(() => "[redacted]") as T;
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, redactDeep(v, key)])) as T;
    }
    return "[redacted]" as T;
  }
  if (typeof value === "string") return redactText(value) as T;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v)) as T;
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, redactDeep(v, k)])) as T;
  }
  return value;
}

/** Training-safe copy (Req §11, T-13): proof/noise/platform rows are excluded, never exported as agent data. */
export function excludeProofRows(join: JoinReport): JoinReport {
  const excluded = new Set(["proof", "noise", "platform"]);
  const steps = join.steps.filter((s) => !excluded.has(s.groundTruth?.actor ?? ""));
  const removed = join.steps.length - steps.length;
  const dropReasons = { ...(join.dropReasons ?? {}) };
  for (const s of join.steps) {
    const a = s.groundTruth?.actor;
    if (a && excluded.has(a)) dropReasons[`excluded:${a}`] = (dropReasons[`excluded:${a}`] ?? 0) + 1;
  }
  return {
    ...join,
    dropReasons,
    steps,
    matched: steps.filter((s) => s.matched).length,
    trajectoryOnly: steps.filter((s) => s.trajectory && !s.groundTruth).length,
    groundTruthOnly: steps.filter((s) => s.groundTruth && !s.trajectory).length,
    dropped: join.dropped + removed,
  };
}

/**
 * Versioned dataset export (Req §4.4, §11.3): pins env + technique versions,
 * content-hashed, redacted, proof/noise-free, and self-verifying — the export
 * refuses to hand back a payload whose own hash does not check out.
 */
export function exportDataset(run: Run, split: TraceMeta["split"] = "train", opts: { store?: EventStore } = {}): DatasetExport {
  const base = joinRun(run.runId, opts.store ?? localStore);
  const join = excludeProofRows(base);
  const redacted = redactDeep(join);
  const exp: DatasetExport = {
    meta: { runId: run.runId, formatVersion: 1, contentHash: "", split, redactionPolicyVersion: "v1" },
    run: { runId: run.runId, specDigest: run.specDigest, techniquePackVersion: run.techniquePackVersion, truthLayer: run.truthLayer, backend: run.backend },
    join: redacted,
  };
  exp.meta.contentHash = computeExportHash(exp);
  assertExportIntegrity(exp);
  if (!assertNoProofRows(exp)) throw new Error("dataset export contains proof/noise/platform rows");
  return exp;
}

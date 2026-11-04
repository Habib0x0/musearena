import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { EnvironmentSpec, Run } from "@musearena/shared";
import { ingest } from "../observability/collector.js";
import { EventStore, localStore, type GroundTruthEvent } from "../observability/events.js";
import { LocalTrajectoryRecorder } from "../observability/trajectory.js";
import { incr } from "../observability/metrics.js";
import { LangfuseSink, TeeRecorder, langfuseConfig, type LangfuseConfig } from "../observability/langfuse.js";
import { collectTelemetry, windowStart } from "../observability/docker-telemetry.js";
import { joinRun } from "../observability/export.js";
import { DetectionStore, replay, type Alert, type SigmaRule } from "../detections/sigma.js";
import { canaryValue } from "../configurator/ansible.js";
import { ATTACKER_HOST_ID, containerName } from "../provisioner/names.js";
import { WEAK_DB_PASSWORD, WEAK_DB_USER } from "../provisioner/roles.js";
import { scoreExercise, type Scorecard } from "./evaluator.js";

const run = promisify(execFile);

/**
 * LIVE exercise on the Docker runtime (Req §5).
 *
 * Red acts for real from the attacker container across the env network, one
 * Atomic-style step per objective. Red's outcome is NOT self-reported: the
 * objective counts only if the objective's canary value actually came back
 * (canary-hash) or the injected command actually ran (exec-marker) — and the
 * collector independently records what the target saw.
 *
 * Blue sees only collected telemetry (never red's trajectory or ground-truth
 * labels) and detects exclusively via PROMOTED Sigma rules. On an alert it
 * takes one allowlisted response that is actually enforced (block the
 * attacker's network on the env), recorded with rule id+version.
 *
 * Persona noise is real traffic from the target hosts themselves so blue's FP
 * rate is measured against benign activity in the same telemetry stream.
 */
export interface LiveExerciseOptions {
  store?: EventStore;
  detections: DetectionStore;
  docker?: string;
  /** Enforce blue's response (disconnect attacker). Default true. */
  enforceResponse?: boolean;
  /** Langfuse sink; default from env, null disables. */
  langfuse?: LangfuseConfig | null;
  /** Benign-only control run (Req T-14): personas act, red does not. Measures the FP baseline. */
  control?: boolean;
  /** Persona activity rounds (more rounds → tighter FP estimate). Default 1. */
  noiseRounds?: number;
}

export interface LiveExerciseResult {
  run: Run; scorecard: Scorecard; redSteps: number; alerts: Alert[]; falsePositives: number; benignEvents: number;
  /** What each false positive fired on — the input blue needs to tune rules. */
  falsePositiveDetail: { ruleId: string; hostId: string; kind: string; sample: string }[];
  /** Events sent to Langfuse (0 when not configured). */
  langfuseEvents: number;
}

async function attackerExec(docker: string, runId: string, cmd: string[], env: string[] = []): Promise<string> {
  const args = ["exec", ...env.flatMap((e) => ["-e", e]), containerName(runId, ATTACKER_HOST_ID), ...cmd];
  const { stdout } = await run(docker, args, { timeout: 30_000 }).catch((e: { stdout?: string }) => ({ stdout: e.stdout ?? "" }));
  return stdout;
}

async function targetExec(docker: string, runId: string, hostId: string, cmd: string[]): Promise<void> {
  await run(docker, ["exec", containerName(runId, hostId), ...cmd], { timeout: 30_000 }).catch(() => undefined);
}

/** Benign persona activity generated ON the hosts (local traffic → collector labels it platform/benign). */
async function personaNoise(docker: string, spec: EnvironmentSpec, runId: string): Promise<void> {
  for (const p of spec.personas) {
    const inst = spec.instances.find((i) => i.hostId === p.workstation);
    if (inst?.role === "web") await targetExec(docker, runId, inst.hostId, ["curl", "-s", "-o", "/dev/null", "http://127.0.0.1/"]);
    for (const db of spec.instances.filter((i) => i.role === "db")) {
      await targetExec(docker, runId, db.hostId, ["psql", "-U", WEAK_DB_USER, "-d", "app", "-tAc", "SELECT count(*) FROM employees"]);
    }
  }
}

interface RedStep { objectiveId: string; hostId: string; techniqueId: string; action: string; succeeded: boolean; evidence: string }

async function redAct(docker: string, spec: EnvironmentSpec, runId: string, o: EnvironmentSpec["objectives"][number]): Promise<RedStep> {
  const target = spec.instances.find((i) => i.hostId === o.asset);
  const base = { objectiveId: o.id, hostId: o.asset, techniqueId: o.techniqueId };
  if (target?.role === "db") {
    // Valid Accounts: try the leaked/weak app credential, read the objective's secret.
    const out = await attackerExec(docker, runId,
      ["psql", "-h", o.asset, "-U", WEAK_DB_USER, "-d", "app", "-tAc", `SELECT value FROM secrets WHERE objective_id='${o.id.replace(/'/g, "''")}'`],
      [`PGPASSWORD=${WEAK_DB_PASSWORD}`, "PGCONNECT_TIMEOUT=5"]);
    const want = canaryValue(runId, o.id);
    return { ...base, action: "psql login with weak app credential; read secrets", succeeded: out.trim() === want, evidence: out.trim().slice(0, 120) };
  }
  if (target?.role === "web") {
    // Command and Scripting Interpreter via injectable diag endpoint.
    const marker = `RED-${o.id}-${runId.replace(/^run-/, "").slice(0, 8)}`.replace(/[^A-Za-z0-9-]/g, "");
    const out = await attackerExec(docker, runId, ["wget", "-q", "-T", "20", "-O", "-", `http://${o.asset}/diag.php?host=${encodeURIComponent(`x;echo ${marker}`)}`]);
    return { ...base, action: "command injection via /diag.php", succeeded: out.includes(marker), evidence: out.includes(marker) ? marker : out.slice(0, 120) };
  }
  return { ...base, action: "no live technique for this asset role", succeeded: false, evidence: "" };
}

/** Blue's only enforced response here: cut the attacker off the env network (allowlist: "block IP"). */
async function blockAttacker(docker: string, runId: string): Promise<boolean> {
  const net = `ma-${runId.replace(/^run-/, "").slice(0, 8)}-net`;
  const r = await run(docker, ["network", "disconnect", "-f", net, containerName(runId, ATTACKER_HOST_ID)]).then(() => true, () => false);
  return r;
}

export async function runLiveExercise(input: { spec: EnvironmentSpec; run: Run }, opts: LiveExerciseOptions): Promise<LiveExerciseResult> {
  const { spec, run: runRec } = input;
  const store = opts.store ?? localStore;
  const docker = opts.docker ?? "docker";
  const runId = runRec.runId;
  const lf = opts.langfuse === undefined ? langfuseConfig() : opts.langfuse;
  const sink = lf ? new LangfuseSink(lf, { orgId: runRec.orgId, specDigest: runRec.specDigest, mode: runRec.mode, backend: runRec.backend }) : null;
  const recorder = new TeeRecorder(new LocalTrajectoryRecorder(store), sink);
  // Window starts after the last setup/gate line, on the targets' own clock.
  const startedAt = await windowStart(spec, runId, docker);
  const since = new Date(startedAt - 5000).toISOString();

  for (let i = 0; i < (opts.noiseRounds ?? 1); i++) await personaNoise(docker, spec, runId);

  const steps: RedStep[] = [];
  for (const o of opts.control ? [] : spec.objectives) {
    const s = await redAct(docker, spec, runId, o);
    steps.push(s);
    recorder.record({ runId, hostId: s.hostId, actor: "red", observation: s.evidence || "(no output)", reasoning: `attempt ${s.techniqueId} against ${s.hostId}`, toolCall: "attacker-exec", action: `${s.action} [${s.objectiveId}]`, techniqueId: s.techniqueId, at: new Date().toISOString() });
  }

  // Out-of-band collection after red acts (logs flush asynchronously).
  await new Promise((r) => setTimeout(r, 1500));
  const telemetry = (await collectTelemetry(spec, runId, { docker, since, localActor: "noise" })).filter((e) => Date.parse(e.at) > startedAt);
  for (const e of telemetry) ingest(e, { store });

  // Red outcomes: verified (canary returned / marker executed) AND observed by the collector on that host.
  for (const s of steps) {
    const observed = telemetry.some((e) => e.hostId === s.hostId && e.actor === "red");
    const objective = spec.objectives.find((o) => o.id === s.objectiveId)!;
    ingest({
      runId, hostId: s.hostId, kind: "objective", actor: "red", techniqueId: s.techniqueId,
      outcome: s.succeeded && observed ? "succeeded" : "failed",
      at: telemetry.filter((e) => e.hostId === s.hostId && e.actor === "red").at(-1)?.at ?? new Date().toISOString(),
      detail: { objectiveId: s.objectiveId, signal: objective.successSignal, verified: s.succeeded, observed },
    }, { store });
  }

  // Blue: promoted Sigma rules over collected telemetry only.
  // Rules evaluate the whole stream (blue cannot see labels); the labels are
  // used only afterwards, by the scorer, to split true from false positives.
  const alerts = opts.detections.liveAlerts(telemetry);
  const benign = telemetry.filter((e) => e.actor !== "red");
  const fpAlerts = opts.detections.liveAlerts(benign);
  const truePositive = opts.detections.liveAlerts(telemetry.filter((e) => e.actor === "red"));
  const firstByTech = new Map<string, Alert>();
  for (const a of truePositive.sort((x, y) => Date.parse(x.at) - Date.parse(y.at))) if (!firstByTech.has(`${a.hostId}|${a.techniqueId}`)) firstByTech.set(`${a.hostId}|${a.techniqueId}`, a);

  let blocked = false;
  for (const a of firstByTech.values()) {
    const detectAt = new Date().toISOString();
    ingest({ runId, hostId: a.hostId, kind: "alert", actor: "blue", techniqueId: a.techniqueId, outcome: "detected", at: detectAt, detail: { signal: "sigma-match", ruleId: a.ruleId, ruleVersion: a.ruleVersion, confidence: a.confidence, eventAt: a.at } }, { store });
    recorder.record({ runId, hostId: a.hostId, actor: "blue", observation: `alert ${a.ruleId}@${a.ruleVersion} (${a.techniqueId}) conf ${a.confidence}`, action: "block IP", techniqueId: a.techniqueId, at: detectAt });
    if (!blocked && opts.enforceResponse !== false) blocked = await blockAttacker(docker, runId);
    if (blocked) ingest({ runId, hostId: a.hostId, kind: "response", actor: "blue", techniqueId: a.techniqueId, outcome: "contained", at: new Date().toISOString(), detail: { response: "block IP", enforced: true, ruleId: a.ruleId, ruleVersion: a.ruleVersion } }, { store });
  }

  // Trace export is optional observability: a rejected export is logged and
  // counted as zero, never allowed to fail an already-scored run.
  const langfuseSpans = sink ? await sink.flush().catch((e: Error) => { console.warn(`langfuse export skipped: ${e.message.slice(0, 160)}`); return 0; }) : 0;
  incr("arena_exercises_total", { backend: runRec.backend });
  incr("arena_telemetry_events_total", {}, telemetry.length);
  incr("arena_alerts_total", {}, alerts.length);
  incr("arena_false_positives_total", {}, fpAlerts.length);
  const join = joinRun(runId, store);
  const scorecard = scoreExercise(spec, join);
  incr("arena_objectives_achieved_total", {}, scorecard.objectivesAchieved);
  const falsePositiveRate = benign.length ? fpAlerts.length / benign.length : 0;
  const score = { ...scorecard, falsePositiveRate };
  const falsePositiveDetail = fpAlerts.map((a) => {
    const e = benign.find((x) => x.hostId === a.hostId && x.at === a.at);
    return { ruleId: a.ruleId, hostId: a.hostId, kind: e?.kind ?? "?", sample: JSON.stringify(e?.detail ?? {}).slice(0, 160) };
  });
  return { run: { ...runRec, score }, scorecard: score, redSteps: steps.length, alerts, falsePositives: fpAlerts.length, benignEvents: benign.length, falsePositiveDetail, langfuseEvents: langfuseSpans };
}

/** Promote every rule in the pack against replayed telemetry; rules with no replay hits stay draft. */
export function promoteAgainst(rules: SigmaRule[], replayEvents: GroundTruthEvent[], store = new DetectionStore()): { store: DetectionStore; promoted: string[]; draft: string[] } {
  const promoted: string[] = []; const draft: string[] = [];
  for (const r of rules) {
    store.add(r);
    if (replay(r, replayEvents).length > 0) { store.promote(r.id, r.version, replayEvents); promoted.push(r.id); } else draft.push(r.id);
  }
  return { store, promoted, draft };
}

/**
 * Detection pack for live runs: SigmaHQ YAML in backend/detections, promoted
 * against the checked-in calibration replay (detections/replay/*.jsonl,
 * telemetry recorded from earlier runs). The run being scored is never used
 * for its own promotion.
 */
export async function livePack(dir?: string): Promise<{ store: DetectionStore; promoted: string[]; draft: string[] }> {
  const { loadSigmaDir } = await import("../detections/sigma.js");
  const { readdir, readFile } = await import("node:fs/promises");
  const path = await import("node:path");
  const root = dir ?? path.join(path.dirname(new URL(import.meta.url).pathname), "../../detections");
  const rules = await loadSigmaDir(root);
  const replayDir = path.join(root, "replay");
  const files = (await readdir(replayDir).catch(() => [] as string[])).filter((f) => f.endsWith(".jsonl"));
  const events: GroundTruthEvent[] = [];
  for (const f of files) {
    for (const line of (await readFile(path.join(replayDir, f), "utf8")).split("\n")) if (line.trim()) events.push(JSON.parse(line) as GroundTruthEvent);
  }
  return promoteAgainst(rules, events);
}

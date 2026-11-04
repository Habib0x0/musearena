import type { EnvironmentSpec, Run } from "@musearena/shared";
import { ingest } from "../observability/collector.js";
import { EventStore, localStore } from "../observability/events.js";
import { LocalTrajectoryRecorder } from "../observability/trajectory.js";
import { joinRun } from "../observability/export.js";
import { DetectionStore } from "../detections/sigma.js";
import { generateNoise } from "../prereq/gate.js";
import { scoreExercise, type Scorecard } from "./evaluator.js";

export type BlueResponse = "isolate host" | "block IP" | "kill process tree" | "disable account" | "snapshot";
const RESPONSE_ALLOWLIST: BlueResponse[] = ["isolate host", "block IP", "kill process tree", "disable account", "snapshot"];

export interface ExerciseResult {
  run: Run;
  scorecard: Scorecard;
  redSteps: number;
  blueDetections: number;
}

export interface ExerciseOptions {
  store?: EventStore;
  detections?: DetectionStore;
  startAt?: number;
  includeNoise?: boolean;
}

/**
 * Deterministic LOCAL exercise harness (not model-driven red/blue agents).
 * Red emits one ground-truth attempt per objective on the objective's asset.
 * Blue detects ONLY through promoted Sigma rules replayed over red telemetry —
 * no promoted rule, no detection, no fabricated MTTD. Persona noise is
 * ingested as ground truth for FP measurement and is excluded from scoring.
 */
export async function runExercise(input: { spec: EnvironmentSpec; run: Run }, opts: ExerciseOptions = {}): Promise<ExerciseResult> {
  const { spec, run } = input;
  const store = opts.store ?? localStore;
  const recorder = new LocalTrajectoryRecorder(store);
  const detections = opts.detections ?? new DetectionStore();
  const t0 = opts.startAt ?? Date.now();
  const iso = (ms: number) => new Date(t0 + ms).toISOString();
  let clock = 0;
  let redSteps = 0;
  let blueDetections = 0;

  if (opts.includeNoise !== false) {
    for (const n of generateNoise(spec, run.runId, t0)) {
      ingest({ runId: n.runId, hostId: n.hostId, kind: n.kind, actor: "noise", at: n.at, detail: { personaId: n.personaId } }, { store });
    }
  }

  for (const obj of spec.objectives) {
    const hostId = obj.asset;
    const vuln = spec.plantedVulns.find((v) => v.techniqueId === obj.techniqueId && v.targetHostId === hostId)
      ?? spec.plantedVulns.find((v) => v.techniqueId === obj.techniqueId);
    clock += 60_000;
    recorder.record({ runId: run.runId, hostId, actor: "red", observation: `foothold near ${hostId}`, reasoning: `attempt ${obj.techniqueId} against ${obj.asset}`, toolCall: "atomic", action: `atomic ${vuln?.proofAtomicGuid ?? obj.id}`, techniqueId: obj.techniqueId, at: iso(clock) });
    const redEvent = ingest({ runId: run.runId, hostId, kind: "process", actor: "red", techniqueId: obj.techniqueId, stepId: vuln?.proofAtomicGuid, outcome: "succeeded", at: iso(clock + 500), detail: { signal: obj.successSignal, objectiveId: obj.id } }, { store });
    redSteps++;

    // Blue: promoted detections only. The alert, not this harness, decides detection.
    const alerts = detections.liveAlerts([redEvent]);
    if (alerts.length === 0) continue;
    clock += 5 * 60_000; // detection latency in this deterministic harness
    blueDetections++;
    const alert = alerts[0];
    ingest({ runId: run.runId, hostId, kind: "process", actor: "blue", techniqueId: obj.techniqueId, outcome: "detected", at: iso(clock), detail: { signal: "sigma-match", ruleId: alert.ruleId, ruleVersion: alert.ruleVersion } }, { store });
    const response: BlueResponse = RESPONSE_ALLOWLIST[blueDetections % RESPONSE_ALLOWLIST.length];
    clock += 2 * 60_000;
    recorder.record({ runId: run.runId, hostId, actor: "blue", observation: `alert ${alert.ruleId}@${alert.ruleVersion} for ${obj.techniqueId}`, action: response, techniqueId: obj.techniqueId, at: iso(clock) });
    ingest({ runId: run.runId, hostId, kind: "process", actor: "blue", techniqueId: obj.techniqueId, outcome: "contained", at: iso(clock + 500), detail: { response, ruleId: alert.ruleId, ruleVersion: alert.ruleVersion } }, { store });
  }

  const join = joinRun(run.runId, store);
  const scorecard = scoreExercise(spec, join);
  return { run: { ...run, score: scorecard }, scorecard, redSteps, blueDetections };
}

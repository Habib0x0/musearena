import { readFileSync } from "node:fs";
import type { EnvironmentSpec, Run } from "@musearena/shared";
import type { JoinReport } from "../observability/export.js";
import { scoreExercise } from "../exercise/evaluator.js";

export interface RubricScore {
  analyticCoverage: number;
  exactTechniqueCoverage: number;
  visibilityCoverage: number;
  mttdMinutesP50?: number;
  mttdMinutesP90?: number;
  containmentCorrectness?: number;
  falsePositiveRate?: number;
  calibration?: number;
  brierScore?: number;
  expectedCalibrationError?: number;
  unscorableWindows: number;
  stampedWith: { mode: string; backend: string; truthLayer: string };
  qualityBars: { analytic: boolean; visibility: boolean; mttd: boolean; containment: boolean; fp: boolean };
}

function percentile(xs: number[], p: number): number | undefined {
  if (!xs.length) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.floor((p / 100) * s.length))];
}

/**
 * Lock-in rubric (Req §7, T-11): proof/noise/platform rows are excluded from
 * red/blue scoring; scores are stamped with mode/backend/truth layer and are
 * never ranked across stamps. Pure function of (spec, join, run) — blinded
 * rescoring of a recorded run reproduces identical scores.
 */
/** Only red/blue ground-truth (or trajectory-only) rows are scorable; proof/noise/platform never are. */
export function isScorableStep(s: JoinReport["steps"][number]): boolean {
  const a = s.groundTruth?.actor ?? s.trajectory?.actor;
  return a === undefined || a === "red" || a === "blue";
}

export function computeRubric(spec: EnvironmentSpec, join: JoinReport, run: Run): RubricScore {
  const scored = { ...join, steps: join.steps.filter(isScorableStep) };
  const base = scoreExercise(spec, scored);

  const hostOf = (s: JoinReport["steps"][number]) => s.groundTruth?.hostId ?? s.hostId;
  const objectiveMatches = (objectiveId: unknown, expected?: string) =>
    typeof objectiveId !== "string" || objectiveId.length === 0 || objectiveId === expected;
  const deltas: number[] = [];
  let unscorableWindows = 0;
  for (const objective of spec.objectives) {
    // Deltas are measured between ground-truth event times, scoped to the
    // objective's own asset and technique.
    const red = scored.steps.find((s) => s.groundTruth?.actor === "red" && s.groundTruth.techniqueId === objective.techniqueId && hostOf(s) === objective.asset && objectiveMatches(s.groundTruth.detail?.objectiveId, objective.id) && Number.isFinite(Date.parse(s.groundTruth.at)));
    const det = scored.steps.find((s) => s.groundTruth?.actor === "blue" && s.groundTruth.outcome === "detected" && s.groundTruth.techniqueId === objective.techniqueId && hostOf(s) === objective.asset && objectiveMatches(s.groundTruth.detail?.objectiveId, objective.id) && Number.isFinite(Date.parse(s.groundTruth.at)));
    if (red && det) {
      const d = (Date.parse(det.groundTruth!.at) - Date.parse(red.groundTruth!.at)) / 60000;
      if (Number.isFinite(d) && d >= 0) deltas.push(d);
      else unscorableWindows += 1;
    }
  }
  // FP rate: blue detections with no red ground truth on the same host/technique.
  const blueDetections = scored.steps.filter((s) => s.groundTruth?.actor === "blue" && s.groundTruth.outcome === "detected");
  const detectionIsTrue = (d: JoinReport["steps"][number]) => scored.steps.some((s) =>
    s.groundTruth?.actor === "red" && s.groundTruth.techniqueId === d.groundTruth?.techniqueId && hostOf(s) === hostOf(d) &&
    objectiveMatches(s.groundTruth.detail?.objectiveId, typeof d.groundTruth?.detail?.objectiveId === "string" ? d.groundTruth.detail.objectiveId : undefined));
  const fps = blueDetections.filter((d) => !detectionIsTrue(d));
  const fpRate = blueDetections.length ? fps.length / blueDetections.length : 0;
  const calibrated = blueDetections.flatMap((d) => {
    const raw = d.groundTruth?.detail?.confidence;
    if (typeof raw !== "number" || !Number.isFinite(raw)) return [];
    const confidence = raw > 1 ? raw / 100 : raw;
    return confidence >= 0 && confidence <= 1 ? [{ confidence, label: detectionIsTrue(d) ? 1 : 0 }] : [];
  });
  const brierScore = calibrated.length
    ? calibrated.reduce((sum, x) => sum + (x.confidence - x.label) ** 2, 0) / calibrated.length
    : undefined;
  let expectedCalibrationError: number | undefined;
  if (calibrated.length) {
    expectedCalibrationError = 0;
    for (let bin = 0; bin < 10; bin++) {
      const rows = calibrated.filter((x) => Math.min(9, Math.floor(x.confidence * 10)) === bin);
      if (!rows.length) continue;
      const avgConfidence = rows.reduce((sum, x) => sum + x.confidence, 0) / rows.length;
      const positiveRate = rows.reduce((sum, x) => sum + x.label, 0) / rows.length;
      expectedCalibrationError += (rows.length / calibrated.length) * Math.abs(avgConfidence - positiveRate);
    }
  }
  const mttdP50 = percentile(deltas, 50);

  return {
    analyticCoverage: base.analyticCoverage,
    exactTechniqueCoverage: base.exactTechniqueCoverage,
    visibilityCoverage: base.visibilityCoverage,
    mttdMinutesP50: mttdP50,
    mttdMinutesP90: percentile(deltas, 90),
    containmentCorrectness: base.containmentCorrectness,
    falsePositiveRate: fpRate,
    calibration: brierScore === undefined ? undefined : 1 - brierScore,
    brierScore,
    expectedCalibrationError,
    unscorableWindows,
    stampedWith: { mode: run.mode, backend: run.backend, truthLayer: run.truthLayer },
    qualityBars: {
      analytic: base.analyticCoverage >= 0.7 && base.exactTechniqueCoverage >= 0.4,
      visibility: base.visibilityCoverage >= 0.9,
      mttd: mttdP50 !== undefined && mttdP50 <= 15,
      containment: (base.containmentCorrectness ?? 0) >= 0.8,
      fp: fpRate <= 0.1,
    },
  };
}

export interface NavigatorLayer {
  name: string; versions: { attack: string; navigator: string; layer: string };
  domain: "enterprise-attack";
  description: string;
  techniques: { techniqueID: string; tactic: string; score: number; color: string; comment: string; enabled: boolean }[];
}

export interface AttackIndex { attackVersion: string; bundleSha256: string; techniques: Record<string, { name: string; tactics: string[] }> }

const indexCache = new Map<string, AttackIndex>();

/**
 * Pinned ATT&CK technique index built from the official STIX bundle
 * (scripts/build-attack-index.mjs). Pack versions look like "attack-15.1".
 * An unknown pack version or technique is an error — never a guessed tactic.
 */
export function attackIndex(packVersion: string): AttackIndex {
  const ver = packVersion.replace(/^attack-/, "");
  const hit = indexCache.get(ver);
  if (hit) return hit;
  const file = new URL(`../../attack/enterprise-attack-${ver}.index.json`, import.meta.url);
  let idx: AttackIndex;
  try { idx = JSON.parse(readFileSync(file, "utf8")) as AttackIndex; }
  catch { throw new Error(`ATT&CK pack ${packVersion} is not pinned (missing ${file.pathname})`); }
  indexCache.set(ver, idx);
  return idx;
}

/** ATT&CK tactics for a technique in the pinned pack (all of them; Navigator renders one cell per tactic). */
export function tacticsForTechnique(techniqueId: string, packVersion = "attack-15.1"): string[] {
  const t = attackIndex(packVersion).techniques[techniqueId.toUpperCase()];
  if (!t) throw new Error(`technique ${techniqueId} not in ATT&CK ${packVersion}`);
  return t.tactics;
}

/**
 * ATT&CK Navigator layer from the pinned pack version (no live STIX fetch).
 * Each technique carries its OWN derived score and tactic — the share of that
 * technique's objectives red achieved — never the global coverage pasted
 * uniformly across techniques.
 */
export function navigatorLayer(spec: EnvironmentSpec, run: Run, join: JoinReport): NavigatorLayer {
  const idx = attackIndex(run.techniquePackVersion);
  const techniques = spec.objectives.flatMap((o) => {
    const achieved = join.steps.some((s) =>
      s.groundTruth?.actor === "red" && s.groundTruth.outcome === "succeeded" &&
      s.hostId === o.asset && s.groundTruth.techniqueId === o.techniqueId &&
      (s.groundTruth.detail?.objectiveId === o.id || s.groundTruth.detail?.signal === o.successSignal));
    const score = achieved ? 100 : 0;
    return tacticsForTechnique(o.techniqueId, run.techniquePackVersion).map((tactic) => ({
      techniqueID: o.techniqueId,
      tactic,
      score,
      color: score > 0 ? "#f6d365" : "",
      comment: `${idx.techniques[o.techniqueId.toUpperCase()].name} · objective ${o.id} ${achieved ? "achieved" : "not achieved"} · stamped ${run.mode}/${run.backend}/${run.truthLayer}`,
      enabled: true,
    }));
  });
  return {
    name: `run-${run.runId}`,
    versions: { attack: run.techniquePackVersion.replace(/^attack-/, ""), navigator: "5.1.0", layer: "4.5" },
    domain: "enterprise-attack",
    description: `ATT&CK ${idx.attackVersion} (STIX bundle sha256 ${idx.bundleSha256})`,
    techniques,
  };
}

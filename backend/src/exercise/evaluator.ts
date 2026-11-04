import type { EnvironmentSpec, RunScore } from "@musearena/shared";
import type { JoinReport } from "../observability/export.js";

export interface Scorecard extends RunScore {
  objectivesAchieved: number;
  objectivesTotal: number;
  pointsEarned: number;
  pointsTotal: number;
  mttrMinutesP50?: number;
}

function median(xs: number[]): number | undefined {
  if (!xs.length) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

/** Internal rows excluded from red/blue scoring (§7.2), even if a caller passes them in. */
const EXCLUDED_ACTORS = new Set(["proof", "noise", "platform", "persona"]);

/** True when an ISO timestamp is a comparable instant. */
function validTime(at: string): boolean {
  return Number.isFinite(Date.parse(at));
}

/**
 * Evaluator (Req §5.4): scores from the joined trace only. Proof/noise/platform
 * rows never count toward red/blue scores (§7.2). Objectives are matched per
 * objective — same asset AND technique AND an objectiveId tie or an exact
 * success-signal hit — so a red success on a different host or objective can
 * never satisfy this objective. Invalid timestamps are never trusted for MTTD.
 */
export function scoreExercise(spec: EnvironmentSpec, join: JoinReport): Scorecard {
  const steps = join.steps.filter((s) => {
    const a = s.groundTruth?.actor ?? s.trajectory?.actor;
    return !a || !EXCLUDED_ACTORS.has(a);
  });
  const redSuccess = steps.filter((s) => s.groundTruth?.actor === "red" && s.groundTruth.outcome === "succeeded");
  const objectiveHit = (o: EnvironmentSpec["objectives"][number], s: (typeof redSuccess)[number]): boolean => {
    if (!s.groundTruth || s.hostId !== o.asset || s.groundTruth.techniqueId !== o.techniqueId) return false;
    const objectiveId = s.groundTruth.detail?.objectiveId;
    if (typeof objectiveId === "string" && objectiveId.length > 0) return objectiveId === o.id;
    return s.groundTruth.detail?.signal === o.successSignal;
  };
  const achieved = spec.objectives.filter((o) => redSuccess.some((s) => objectiveHit(o, s)));
  const pointsTotal = spec.objectives.reduce((a, o) => a + o.points, 0);
  const pointsEarned = achieved.reduce((a, o) => a + o.points, 0);

  // MTTD is per objective: first red attempt on that asset/technique to the
  // first blue detection on the same asset/technique. A same-technique event
  // on another host can never create a delta or exact-technique credit.
  const objectiveEvent = (
    o: EnvironmentSpec["objectives"][number],
    s: (typeof steps)[number],
    actor: "red" | "blue",
    outcome?: string,
  ): boolean => {
    const gt = s.groundTruth;
    if (!gt || gt.actor !== actor || gt.techniqueId !== o.techniqueId || !validTime(gt.at)) return false;
    if ((gt.hostId ?? s.hostId) !== o.asset) return false;
    if (outcome && gt.outcome !== outcome) return false;
    const objectiveId = gt.detail?.objectiveId;
    return typeof objectiveId !== "string" || objectiveId.length === 0 || objectiveId === o.id;
  };
  const detectDeltas: number[] = [];
  const respondDeltas: number[] = [];
  for (const objective of achieved) {
    // Deltas are measured between ground-truth event times, not joined-step times.
    const firstRed = steps.find((s) => objectiveEvent(objective, s, "red"));
    const firstDetect = steps.find((s) => objectiveEvent(objective, s, "blue", "detected"));
    const firstContain = steps.find((s) => objectiveEvent(objective, s, "blue", "contained"));
    if (firstRed && firstDetect) {
      const d = (Date.parse(firstDetect.groundTruth!.at) - Date.parse(firstRed.groundTruth!.at)) / 60000;
      if (Number.isFinite(d) && d >= 0) detectDeltas.push(d);
    }
    if (firstDetect && firstContain) {
      const d = (Date.parse(firstContain.groundTruth!.at) - Date.parse(firstDetect.groundTruth!.at)) / 60000;
      if (Number.isFinite(d) && d >= 0) respondDeltas.push(d);
    }
  }

  const total = Math.max(1, spec.objectives.length);
  return {
    analyticCoverage: achieved.length / total,
    exactTechniqueCoverage: spec.objectives.filter((o) => steps.some((s) => objectiveEvent(o, s, "blue", "detected"))).length / total,
    visibilityCoverage: steps.length ? steps.filter((s) => s.matched).length / steps.length : 0,
    mttdMinutesP50: median(detectDeltas),
    containmentCorrectness: achieved.length ? achieved.filter((o) => steps.some((s) => s.groundTruth?.techniqueId === o.techniqueId && s.hostId === o.asset && s.groundTruth?.actor === "blue" && s.groundTruth?.outcome === "contained")).length / achieved.length : undefined,
    objectivesAchieved: achieved.length,
    objectivesTotal: spec.objectives.length,
    pointsEarned, pointsTotal,
    mttrMinutesP50: median(respondDeltas),
  };
}

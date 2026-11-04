import { redactText, type DatasetExport } from "../observability/export.js";

/** Training consumer surface (follow-on): SFT steps + preference pairs from exports. */
export interface SftExample { runId: string; hostId: string; techniqueId?: string; prompt: string; completion: string; succeeded: boolean }
export interface PreferencePair { runId: string; techniqueId?: string; chosen: string; rejected: string }

const EXCLUDED = new Set(["proof", "noise", "platform"]);

function excluded(s: DatasetExport["join"]["steps"][number]): boolean {
  const a = s.groundTruth?.actor;
  const t = s.trajectory?.actor;
  return (a !== undefined && EXCLUDED.has(a)) || (t !== undefined && EXCLUDED.has(t)) || a === "blue";
}

export function sftExamples(exp: DatasetExport): SftExample[] {
  // Red trajectory steps only: blue "contained" rows are defender actions and
  // must never be labelled as (un)successful red completions (§7.2, §11).
  return exp.join.steps.filter((s) => s.trajectory?.actor === "red" && !excluded(s)).map((s) => ({
    runId: exp.meta.runId,
    hostId: s.hostId,
    techniqueId: s.groundTruth?.techniqueId ?? s.techniqueId,
    prompt: redactText(s.trajectory!.observation) ?? "",
    completion: redactText(s.trajectory!.action ?? s.trajectory!.toolCall ?? "") ?? "",
    // Success is labelled from joined ground-truth outcome only (§11).
    succeeded: s.groundTruth?.actor === "red" && s.groundTruth?.outcome === "succeeded",
  }));
}

export function preferencePairs(exp: DatasetExport): PreferencePair[] {
  const all = sftExamples(exp);
  const pairs: PreferencePair[] = [];
  const usedRejected = new Set<number>();
  all.forEach((ok, okIndex) => {
    if (!ok.succeeded) return;
    const badIndex = all.findIndex((e, i) => i !== okIndex && !e.succeeded && e.techniqueId === ok.techniqueId && e.completion !== ok.completion && !usedRejected.has(i));
    if (badIndex >= 0) {
      usedRejected.add(badIndex);
      pairs.push({ runId: ok.runId, techniqueId: ok.techniqueId, chosen: ok.completion, rejected: all[badIndex].completion });
    }
  });
  return pairs;
}

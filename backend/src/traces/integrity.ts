import type { Label } from "@musearena/shared";
import { computeExportHash, type DatasetExport } from "../observability/export.js";

export { verifyExportHash, assertExportIntegrity, assertNoProofRows, exportPayload, computeExportHash } from "./integrity-crypto.js";

/** Adjudication queue (Req §11.2): adjudicated labels supersede auto-labels, versioned. */
export interface LabelDispute { id: string; runId: string; stepAt: string; auto: Label; adjudicated?: Label; version: number }

export class AdjudicationQueue {
  private items: LabelDispute[] = [];
  file(runId: string, stepAt: string, auto: Label): LabelDispute {
    const d: LabelDispute = { id: `disp-${this.items.length + 1}`, runId, stepAt, auto, version: 1 };
    this.items.push(d);
    return d;
  }
  adjudicate(id: string, label: Label): LabelDispute {
    const d = this.items.find((i) => i.id === id);
    if (!d) throw new Error(`unknown dispute ${id}`);
    d.adjudicated = label; d.version++;
    return d;
  }
  pending(): LabelDispute[] { return this.items.filter((i) => !i.adjudicated); }
  list(runId?: string): LabelDispute[] { return this.items.filter((i) => !runId || i.runId === runId); }
  effective(d: LabelDispute): Label { return d.adjudicated ?? d.auto; }
}

/**
 * Family split (Req §11.3): same scenario family never straddles splits (leakage
 * check). Families are hashed so the split is deterministic and reproducible —
 * insertion/index order must not change which split a family lands in.
 */
export function splitByFamily(runIds: string[], familyOf: (runId: string) => string): Record<"train" | "val" | "test", string[]> {
  const out: Record<string, string[]> = { train: [], val: [], test: [] };
  const familySplit = new Map<string, "train" | "val" | "test">();
  const order = ["train", "val", "test"] as const;
  const seen = new Set<string>();
  for (const id of runIds) {
    if (seen.has(id)) continue;
    seen.add(id);
    const fam = familyOf(id);
    if (!familySplit.has(fam)) {
      const sum = [...fam].reduce((a, c) => a + c.charCodeAt(0), 0);
      familySplit.set(fam, order[sum % 3]);
    }
    out[familySplit.get(fam)!].push(id);
  }
  return out as Record<"train" | "val" | "test", string[]>;
}

const sameInstant = (a: string, b: string): boolean => {
  const ta = Date.parse(a); const tb = Date.parse(b);
  return Number.isFinite(ta) && Number.isFinite(tb) ? ta === tb : a === b;
};

/** Adjudicated labels feed exports (Req §11.2): the effective label replaces the auto-label. */
export function applyAdjudications(exp: DatasetExport, queue: AdjudicationQueue): DatasetExport {
  const copy: DatasetExport = JSON.parse(JSON.stringify(exp));
  for (const step of copy.join.steps) {
    if (!step.groundTruth) continue;
    // Database rows round-trip through timestamptz, so compare instants, not
    // the formatting Postgres happened to return.
    const dispute = queue.list().find((d) => d.runId === exp.meta.runId && sameInstant(d.stepAt, step.at));
    if (!dispute) continue;
    const eff = queue.effective(dispute);
    step.groundTruth = { ...step.groundTruth, techniqueId: eff.techniqueId, stepId: eff.stepId, actor: eff.actor, outcome: eff.outcome };
  }
  copy.meta.contentHash = computeExportHash(copy);
  return copy;
}

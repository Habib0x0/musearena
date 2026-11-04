import { canonicalJson, sha256Hex } from "../lib/digest.js";
import type { DatasetExport } from "../observability/export.js";

/**
 * Export integrity primitives. The hashed payload canonically covers meta
 * (with the hash field itself blanked), the run pins, and the redacted join.
 * Export and verification use this exact function, so a verified hash means
 * untampered. Kept apart from the adjudication queue: callers here need only
 * a type-only reference back to the export shape, so no runtime cycle.
 */
export function exportPayload(exp: DatasetExport): string {
  return canonicalJson({ meta: { ...exp.meta, contentHash: "" }, run: exp.run, join: exp.join });
}

export function computeExportHash(exp: DatasetExport): string {
  return "sha256:" + sha256Hex(exportPayload(exp));
}

/** Exact verification: recompute the canonical payload hash and compare. Any tampering fails. */
export function verifyExportHash(exp: DatasetExport): boolean {
  return typeof exp?.meta?.contentHash === "string" && exp.meta.contentHash.length > 0 && exp.meta.contentHash === computeExportHash(exp);
}

/** Throws unless the export hash verifies (no loose/structural fallback). */
export function assertExportIntegrity(exp: DatasetExport): void {
  if (!verifyExportHash(exp)) throw new Error(`dataset export hash mismatch for run ${exp?.meta?.runId ?? "unknown"}`);
  const mismatched = exp.join.steps.filter((s) => (s.trajectory && s.trajectory.runId !== exp.meta.runId) || (s.groundTruth && s.groundTruth.runId !== exp.meta.runId));
  if (mismatched.length) throw new Error(`dataset export contains ${mismatched.length} rows from another run`);
}

/** Training exports contain zero proof/noise/platform rows (Req §11, T-13 acceptance). */
export function assertNoProofRows(exp: DatasetExport): boolean {
  return exp.join.steps.every((s) => !["proof", "noise", "platform"].includes(s.groundTruth?.actor ?? ""));
}

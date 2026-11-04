import { createHash } from "node:crypto";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import type { DatasetExport } from "../observability/export.js";
import { sftExamples, preferencePairs } from "./pairs.js";

export interface TrainingManifest {
  runId: string; sftCount: number; pairCount: number;
  sftHash: string; pairsHash: string; files: string[];
}

/** Write SFT + preference JSONL training files with a content manifest. */
export async function writeTrainingFiles(exp: DatasetExport, outDir: string): Promise<TrainingManifest> {
  await mkdir(outDir, { recursive: true });
  const sft = sftExamples(exp).map((e) => JSON.stringify(e)).join("\n") + "\n";
  const pairs = preferencePairs(exp).map((e) => JSON.stringify(e)).join("\n") + "\n";
  const sftPath = path.join(outDir, "sft.jsonl");
  const pairsPath = path.join(outDir, "preference-pairs.jsonl");
  await writeFile(sftPath, sft);
  await writeFile(pairsPath, pairs);
  const manifest: TrainingManifest = {
    runId: exp.meta.runId,
    sftCount: sftExamples(exp).length,
    pairCount: preferencePairs(exp).length,
    sftHash: "sha256:" + createHash("sha256").update(sft).digest("hex"),
    pairsHash: "sha256:" + createHash("sha256").update(pairs).digest("hex"),
    files: [sftPath, pairsPath],
  };
  await writeFile(path.join(outDir, "manifest.json"), JSON.stringify(manifest, null, 2));
  return manifest;
}

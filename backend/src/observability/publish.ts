import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { EnvironmentSpec, Run } from "@musearena/shared";
import { navigatorLayer } from "../evaluator/rubric.js";
import { serviceClient } from "../lib/supabase.js";
import { exportDataset, joinRun, type DatasetExport } from "./export.js";
import type { EventStore } from "./events.js";
import { recordDataset } from "./recorder.js";
import { AdjudicationQueue, applyAdjudications, assertExportIntegrity } from "../traces/integrity.js";
import { loadAdjudicationQueue } from "../traces/adjudication.js";
import { writeTrainingFiles } from "../training/exporter.js";
import { isMissingLearningSchemaError, persistRunTraces } from "../training/traces.js";
import { applyContinualGraders } from "../learning/signals.js";
import { GZ, GZ_TYPE, decodeObject, encodeObject } from "./dataset-object.js";

/**
 * Publish a run's dataset (Req §4.4, §11.3): export (join + redaction +
 * proof/noise exclusion + content hash), write SFT/preference training files,
 * upload everything to the private `datasets` bucket under <org>/<run>/<hash>/,
 * re-download the export and verify its hash, then record the dataset row.
 * Objects are immutable (upsert=false): a second publish of the same content
 * reuses the existing snapshot instead of overwriting it.
 */
export interface PublishResult { datasetId: string | null; storagePath: string; contentHash: string; sftCount: number; pairCount: number; traceCount: number; reused: boolean }

export async function publishRunDataset(run: Run, opts: { store?: EventStore; split?: DatasetExport["meta"]["split"]; spec?: EnvironmentSpec } = {}): Promise<PublishResult> {
  let exp = exportDataset(run, opts.split ?? "train", { store: opts.store });
  // Adjudicated labels supersede auto-labels before the snapshot is hashed
  // (Req §2.2.4). The adjudicated export is what is stored and verified.
  let adjudications: AdjudicationQueue;
  try {
    adjudications = await loadAdjudicationQueue(run.orgId, run.runId);
  } catch (err) {
    if (!isMissingLearningSchemaError(err)) throw err;
    console.warn(`[traces] learning schema is not installed; publishing without adjudicated labels (${err instanceof Error ? err.message : String(err)})`);
    adjudications = new AdjudicationQueue();
  }
  if (adjudications.list(run.runId).length > 0) {
    exp = applyAdjudications(exp, adjudications);
    assertExportIntegrity(exp);
  }
  // Coverage artifact (Req §7.1): Navigator layer from the pinned STIX index, over the full (unfiltered) join.
  const layer = opts.spec ? navigatorLayer(opts.spec, run, joinRun(run.runId, opts.store)) : null;
  const hash = exp.meta.contentHash.replace(/^sha256:/, "");
  const prefix = `${run.orgId}/${run.runId}/${hash}`;
  const sb = serviceClient();
  const bucket = sb.storage.from("datasets");

  const dir = await mkdtemp(path.join(tmpdir(), "musearena-ds-"));
  try {
    const manifest = await writeTrainingFiles(exp, dir);
    // Every object is gzip-encoded (see dataset-object.ts); names carry .gz.
    const files: [string, string][] = [
      ["export.json", JSON.stringify(exp)],
      ["sft.jsonl", await readFile(path.join(dir, "sft.jsonl"), "utf8")],
      ["preference-pairs.jsonl", await readFile(path.join(dir, "preference-pairs.jsonl"), "utf8")],
      ...(layer ? [["navigator-layer.json", JSON.stringify(layer, null, 2)] as [string, string]] : []),
      ["manifest.json", JSON.stringify({ ...manifest, files: [`sft.jsonl${GZ}`, `preference-pairs.jsonl${GZ}`], encoding: "gzip", exportHash: exp.meta.contentHash, modelIds: run.modelIds ?? {} }, null, 2)],
    ];
    let reused = false;
    for (const [name, body] of files) {
      const { error } = await bucket.upload(`${prefix}/${name}${GZ}`, encodeObject(body), { contentType: GZ_TYPE, upsert: false });
      if (error && /exists|Duplicate/i.test(error.message)) { reused = true; continue; }
      if (error) throw new Error(`upload ${name} failed: ${error.message}`);
    }

    // Verify what is actually stored, not the in-memory copy.
    const { data: blob, error: dlErr } = await bucket.download(`${prefix}/export.json${GZ}`);
    if (dlErr || !blob) throw new Error(`stored export unreadable: ${dlErr?.message}`);
    assertExportIntegrity(JSON.parse(await decodeObject(blob)) as DatasetExport);

    const { data: existing } = await sb.from("datasets").select("id").eq("org_id", run.orgId).eq("content_hash", exp.meta.contentHash).maybeSingle();
    const datasetId = existing?.id as string | undefined
      ?? await recordDataset({ orgId: run.orgId, name: `${run.runId}-${exp.meta.split}`, exp, storagePath: `datasets/${prefix}` });
    // Traces are the reviewable record; the snapshot stays immutable (F-4).
    const traceCount = await persistRunTraces(exp, run.orgId, datasetId);
    // New traces get the org's enabled continual graders (F-6, Req §2.9.1).
    await applyContinualGraders({ orgId: run.orgId, runId: run.runId });
    return { datasetId, storagePath: `datasets/${prefix}`, contentHash: exp.meta.contentHash, sftCount: manifest.sftCount, pairCount: manifest.pairCount, traceCount, reused: reused || Boolean(existing) };
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

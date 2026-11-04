import { createHash } from "node:crypto";
import { z } from "zod";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { redactText } from "../observability/export.js";
import { GZ, GZ_TYPE, decodeObject, encodeObject } from "../observability/dataset-object.js";
import { CATALOG_VERSION } from "../configurator/catalog.js";
import { PROFILE_VERSION } from "../configurator/profiles.js";
import { BAKED_CATALOG_VERSION, GOLDEN_CATALOG_VERSION } from "../provisioner/images.js";
import { realismShare, type RealismReport } from "../exercise/tradecraft.js";
import type { TraceRow } from "../training/traces.js";
import { TRACE_SOURCES, type TraceSource } from "../training/traces.js";
import type { PreferencePair, SftExample } from "../training/pairs.js";

/**
 * Role-aware dataset builder (F-7, design §3.4, Req §2.4).
 *
 * Selects from the queryable trace rows by role/run/technique/outcome/signal
 * hit/correction kind, applies adjudicated labels then reviewer corrections at
 * build time (the trace rows themselves are never mutated), and writes one
 * immutable, content-hashed snapshot. Red and blue files are separate; the
 * legacy `sft.jsonl`/`preference-pairs.jsonl` names stay red-only.
 */
export const DATASET_ROLES = ["red", "blue"] as const;
export type DatasetRole = (typeof DATASET_ROLES)[number];
export const DATASET_SPLITS = ["train", "val", "test"] as const;
export type DatasetSplit = (typeof DATASET_SPLITS)[number];

export const DatasetSelection = z.object({
  name: z.string().trim().min(1).max(120).optional(),
  family: z.string().trim().min(1).max(120),
  split: z.enum(DATASET_SPLITS).default("train"),
  roles: z.array(z.enum(DATASET_ROLES)).min(1).default([...DATASET_ROLES]),
  runIds: z.array(z.string().min(1)).optional(),
  techniqueIds: z.array(z.string().min(1)).optional(),
  outcomes: z.array(z.string().min(1)).optional(),
  signalId: z.string().uuid().optional(),
  correctionKind: z.enum(["approve", "reject", "edit", "reprompt", "label"]).optional(),
  /** Restrict to traces from these provenances; omit to blend everything. */
  sources: z.array(z.enum(TRACE_SOURCES)).optional(),
  /** Refuse a snapshot whose real (imported + field) share is below this 0..1 floor. */
  minRealShare: z.number().min(0).max(1).optional(),
  limit: z.number().int().positive().max(10000).optional(),
}).strict();
export type DatasetSelection = z.infer<typeof DatasetSelection>;

export class FamilySplitCollision extends Error {}
export class EmptyDataset extends Error {}
export class InsufficientRealShare extends Error {}

const EXCLUDED = new Set(["proof", "noise", "platform"]);

export interface CorrectionRow {
  id: string;
  trace_id: string;
  kind: string;
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  created_at: string;
}

export interface AdjudicationRow {
  id: string;
  run_id: string;
  step_at: string;
  status: string;
  adjudicated_label: Record<string, unknown> | null;
}

export interface EffectiveAction {
  observation: string; action: string | null; toolCall: string | null;
  outcome: string | null; techniqueId: string | null; appliedCorrections: string[];
}

const sameInstant = (a: string, b: string): boolean => {
  const ta = Date.parse(a); const tb = Date.parse(b);
  return Number.isFinite(ta) && Number.isFinite(tb) ? ta === tb : a === b;
};

/** Adjudicated labels supersede the auto-label before the selection is shaped. */
export function applyAdjudication(row: TraceRow, disputes: AdjudicationRow[]): { row: TraceRow; applied: string[] } {
  const dispute = disputes.find((d) => d.run_id === row.run_id && sameInstant(d.step_at, row.at) && d.status === "adjudicated");
  if (!dispute?.adjudicated_label) return { row, applied: [] };
  const label = dispute.adjudicated_label;
  return {
    row: {
      ...row,
      actor: typeof label.actor === "string" ? label.actor : row.actor,
      outcome: typeof label.outcome === "string" ? label.outcome : row.outcome,
      technique_id: typeof label.techniqueId === "string" ? label.techniqueId : row.technique_id,
    },
    applied: [dispute.id],
  };
}

/**
 * Reviewer corrections win at build time. An `edit`/`reprompt` (or any
 * correction carrying the field) replaces the exported action or observation;
 * the stored trace row's original action stays readable.
 */
export function applyCorrections(row: TraceRow, corrections: CorrectionRow[]): EffectiveAction {
  let observation = row.observation ?? "";
  let action = row.action;
  let toolCall = row.tool_call;
  let outcome = row.outcome;
  let techniqueId = row.technique_id;
  const appliedCorrections: string[] = [];
  // Oldest first: the newest correction wins field by field.
  for (const correction of [...corrections].sort((a, b) => a.created_at.localeCompare(b.created_at))) {
    let touched = false;
    const nextAction = correction.after.action ?? correction.after.completion;
    if (typeof nextAction === "string") { action = nextAction; touched = true; }
    const nextObservation = correction.after.observation ?? correction.after.prompt;
    if (typeof nextObservation === "string") { observation = nextObservation; touched = true; }
    const nextToolCall = correction.after.toolCall;
    if (typeof nextToolCall === "string") { toolCall = nextToolCall; touched = true; }
    if (typeof correction.after.outcome === "string") { outcome = correction.after.outcome; touched = true; }
    const nextTechnique = correction.after.techniqueId ?? correction.after.technique_id;
    if (typeof nextTechnique === "string") { techniqueId = nextTechnique; touched = true; }
    if (touched) appliedCorrections.push(correction.id);
  }
  // Same redaction rule as the snapshot exporter (Req §2.4.5).
  return {
    observation: redactText(observation) ?? "",
    action: redactText(action),
    toolCall: redactText(toolCall),
    outcome,
    techniqueId,
    appliedCorrections,
  };
}

function example(row: TraceRow, eff: EffectiveAction, role: DatasetRole): SftExample {
  return {
    runId: row.run_id,
    hostId: row.host_id,
    techniqueId: eff.techniqueId ?? undefined,
    prompt: eff.observation,
    completion: redactText(eff.action ?? eff.toolCall ?? "") ?? "",
    succeeded: role === "red" ? eff.outcome === "succeeded" : eff.outcome === "contained",
  };
}

/** The same pairing rule as `training/pairs.ts`, applied per role. */
function pairsFor(examples: SftExample[]): PreferencePair[] {
  const pairs: PreferencePair[] = [];
  const usedRejected = new Set<number>();
  examples.forEach((ok, okIndex) => {
    if (!ok.succeeded) return;
    const badIndex = examples.findIndex((e, i) => i !== okIndex && !e.succeeded && e.techniqueId === ok.techniqueId && e.completion !== ok.completion && !usedRejected.has(i));
    if (badIndex >= 0) {
      usedRejected.add(badIndex);
      pairs.push({ runId: ok.runId, techniqueId: ok.techniqueId, chosen: ok.completion, rejected: examples[badIndex].completion });
    }
  });
  return pairs;
}

export interface RoleExamples { sft: SftExample[]; pairs: PreferencePair[]; appliedCorrections: string[] }

/** Shape one role's files from rows already filtered to that role. */
export function roleExamples(rows: TraceRow[], corrections: Map<string, CorrectionRow[]>, role: DatasetRole): RoleExamples {
  const sft: SftExample[] = [];
  const appliedCorrections: string[] = [];
  for (const row of rows) {
    if (row.actor !== role || EXCLUDED.has(row.actor)) continue;
    const eff = applyCorrections(row, corrections.get(row.id ?? "") ?? []);
    appliedCorrections.push(...eff.appliedCorrections);
    sft.push(example(row, eff, role));
  }
  return { sft, pairs: pairsFor(sft), appliedCorrections };
}

function jsonl(rows: unknown[]): string {
  return rows.map((row) => JSON.stringify(row)).join("\n") + "\n";
}

function sha256(body: string): string {
  return "sha256:" + createHash("sha256").update(body).digest("hex");
}

export interface SelectionRecord {
  filters: DatasetSelection;
  runIds: string[];
  counts: {
    traces: number; red: number; blue: number; excluded: number;
    correctionsApplied: number; adjudicationsApplied: number;
    sources: Record<string, number>; realShare: number; realism: RealismReport;
  };
  corrections: string[];
  adjudications: string[];
}

export interface BuiltMeta {
  formatVersion: 2;
  contentHash: string;
  split: DatasetSplit;
  redactionPolicyVersion: "v1";
  catalogVersion: string;
  profileVersion: string;
  imageVersion: string;
  specDigests: string[];
  techniquePackVersions: string[];
  modelIds: Record<string, Record<string, string>>;
}

export interface BuiltSnapshot {
  meta: BuiltMeta;
  selection: SelectionRecord;
  roles: Record<DatasetRole, { sft: SftExample[]; pairs: PreferencePair[] }>;
}

/** Hash over the snapshot with its own hash field blanked, so verification is stable. */
export function snapshotHash(snapshot: BuiltSnapshot): string {
  return sha256(JSON.stringify({ ...snapshot, meta: { ...snapshot.meta, contentHash: "" } }));
}

export interface BuildResult {
  datasetId: string;
  contentHash: string;
  storagePath: string;
  family: string;
  split: DatasetSplit;
  roles: DatasetRole[];
  sources: TraceSource[];
  selection: SelectionRecord;
  counts: { redSft: number; redPairs: number; blueSft: number; bluePairs: number };
  reused: boolean;
}

interface SelectedRows { rows: TraceRow[]; runIds: string[]; excluded: number }

async function selectRows(orgId: string, selection: DatasetSelection): Promise<SelectedRows> {
  const sb = serviceClient();
  // Tombstoned traces are curated out: never built into a snapshot.
  let query = sb.from("traces").select("*").eq("org_id", orgId).is("tombstoned_at", null).limit(selection.limit ?? 2000);
  if (selection.runIds) {
    if (!selection.runIds.length) return { rows: [], runIds: [], excluded: 0 };
    query = query.in("run_id", selection.runIds);
  }
  if (selection.techniqueIds && !selection.techniqueIds.length) return { rows: [], runIds: [], excluded: 0 };
  if (selection.outcomes && !selection.outcomes.length) return { rows: [], runIds: [], excluded: 0 };
  if (selection.sources) {
    if (!selection.sources.length) return { rows: [], runIds: [], excluded: 0 };
    query = query.in("source", selection.sources);
  }
  if (selection.signalId) {
    const { data, error } = await sb.from("signal_hits").select("trace_id, label").eq("org_id", orgId).eq("signal_id", selection.signalId);
    if (error) throw new Error(`signal hits unreadable: ${error.message}`);
    const ids = [...new Set((data ?? [])
      .filter((r) => (r as { label?: { matched?: unknown } | null }).label?.matched !== false)
      .map((r) => (r as { trace_id: string }).trace_id))];
    if (!ids.length) return { rows: [], runIds: [], excluded: 0 };
    query = query.in("id", ids);
  }
  if (selection.correctionKind) {
    const { data, error } = await sb.from("corrections").select("trace_id").eq("org_id", orgId).eq("kind", selection.correctionKind);
    if (error) throw new Error(`corrections unreadable: ${error.message}`);
    const ids = [...new Set((data ?? []).map((r) => (r as { trace_id: string }).trace_id))];
    if (!ids.length) return { rows: [], runIds: [], excluded: 0 };
    query = query.in("id", ids);
  }
  const { data, error } = await query;
  if (error) throw new Error(`traces unreadable: ${error.message}`);
  const raw = (data ?? []) as TraceRow[];
  if (!raw.length) return { rows: [], runIds: [], excluded: 0 };

  // Adjudications can change the actor/outcome, so selection filters apply after.
  const { data: disputeData, error: disputeError } = await sb.from("label_disputes")
    .select("id, run_id, step_at, status, adjudicated_label")
    .eq("org_id", orgId)
    .eq("status", "adjudicated")
    .in("run_id", [...new Set(raw.map((r) => r.run_id))]);
  if (disputeError) throw new Error(`adjudications unreadable: ${disputeError.message}`);
  const disputes = (disputeData ?? []) as AdjudicationRow[];

  // Reviewer label corrections also supersede the stored outcome/technique
  // for selection; filtering on the pre-correction label would silently drop
  // or include the wrong rows.
  const traceIds = raw.map((r) => r.id).filter((id): id is string => typeof id === "string");
  const corrections = new Map<string, CorrectionRow[]>();
  if (traceIds.length) {
    const { data: correctionData, error: correctionError } = await sb.from("corrections")
      .select("id, trace_id, kind, before, after, created_at")
      .eq("org_id", orgId)
      .in("trace_id", traceIds)
      .order("created_at", { ascending: true });
    if (correctionError) throw new Error(`corrections unreadable: ${correctionError.message}`);
    for (const c of (correctionData ?? []) as CorrectionRow[]) {
      corrections.set(c.trace_id, [...(corrections.get(c.trace_id) ?? []), c]);
    }
  }

  const rows: TraceRow[] = [];
  let excluded = 0;
  for (const original of raw) {
    const { row: adjudicated } = applyAdjudication(original, disputes);
    const effective = applyCorrections(adjudicated, corrections.get(adjudicated.id ?? "") ?? []);
    const row = { ...adjudicated, outcome: effective.outcome, technique_id: effective.techniqueId };
    const actor = row.actor ?? "";
    if (EXCLUDED.has(actor)) { excluded++; continue; }
    if (!selection.roles.includes(actor as DatasetRole)) continue;
    if (selection.techniqueIds?.length && !selection.techniqueIds.includes(row.technique_id ?? "")) continue;
    if (selection.outcomes?.length && !selection.outcomes.includes(row.outcome ?? "")) continue;
    rows.push(row);
  }
  return { rows, runIds: [...new Set(rows.map((r) => r.run_id))].sort(), excluded };
}

async function appliedDisputeIds(orgId: string, rows: TraceRow[]): Promise<string[]> {
  if (!rows.length) return [];
  const { data, error } = await serviceClient().from("label_disputes")
    .select("id, run_id, step_at, status")
    .eq("org_id", orgId)
    .eq("status", "adjudicated")
    .in("run_id", [...new Set(rows.map((r) => r.run_id))]);
  if (error) throw new Error(`adjudications unreadable: ${error.message}`);
  return (data ?? [])
    .filter((d) => {
      const dispute = d as AdjudicationRow;
      return rows.some((row) => row.run_id === dispute.run_id && sameInstant(dispute.step_at, row.at));
    })
    .map((d) => (d as { id: string }).id);
}

async function runLineage(orgId: string, runIds: string[]): Promise<{
  specDigests: string[]; techniquePackVersions: string[]; modelIds: Record<string, Record<string, string>>;
}> {
  if (!runIds.length) return { specDigests: [], techniquePackVersions: [], modelIds: {} };
  const { data, error } = await serviceClient().from("runs")
    .select("run_id, spec_digest, technique_pack_version, model_ids")
    .eq("org_id", orgId)
    .in("run_id", runIds);
  if (error) throw new Error(`runs unreadable: ${error.message}`);
  const specDigests = [...new Set((data ?? []).map((r) => (r as { spec_digest: string }).spec_digest))].sort();
  const techniquePackVersions = [...new Set((data ?? []).map((r) => (r as { technique_pack_version: string }).technique_pack_version))].sort();
  const modelIds: Record<string, Record<string, string>> = {};
  for (const r of data ?? []) {
    const row = r as { run_id: string; model_ids: Record<string, string> | null };
    modelIds[row.run_id] = row.model_ids ?? {};
  }
  return { specDigests, techniquePackVersions, modelIds };
}

const IMAGE_VERSION = `${GOLDEN_CATALOG_VERSION}+${BAKED_CATALOG_VERSION}`;

export async function buildDataset(input: { orgId: string; selection: DatasetSelection }): Promise<BuildResult> {
  const { orgId, selection } = input;
  const sb = serviceClient();

  const { data: familyRows, error: familyError } = await sb.from("datasets")
    .select("id, split, content_hash").eq("org_id", orgId).eq("family", selection.family);
  if (familyError) throw new Error(`dataset family unreadable: ${familyError.message}`);
  const clash = (familyRows ?? []).find((r) => (r as { split: string }).split !== selection.split);
  if (clash) {
    throw new FamilySplitCollision(`family ${selection.family} already has a ${(clash as { split: string }).split} snapshot; it cannot also be ${selection.split}`);
  }

  const selected = await selectRows(orgId, selection);
  if (!selected.rows.length) throw new EmptyDataset("selection matched no traces");

  const sourceCounts: Record<string, number> = {};
  for (const row of selected.rows) sourceCounts[row.source] = (sourceCounts[row.source] ?? 0) + 1;
  const sources = [...new Set(selected.rows.map((r) => r.source))].sort() as TraceSource[];
  const realShare = selected.rows.filter((r) => r.source !== "synthetic").length / selected.rows.length;
  const realism = realismShare(selected.rows.filter((r) => r.actor === "red").map((r) => ({ action: r.action, tool_call: r.tool_call })));
  if (selection.minRealShare !== undefined && realShare < selection.minRealShare) {
    throw new InsufficientRealShare(
      `selection is ${Math.round(realShare * 100)}% real (imported + field), below the requested ${Math.round(selection.minRealShare * 100)}%`,
    );
  }

  const traceIds = selected.rows.map((r) => r.id);
  const { data: correctionData, error: correctionError } = await sb.from("corrections")
    .select("id, trace_id, kind, before, after, created_at")
    .eq("org_id", orgId)
    .in("trace_id", traceIds)
    .order("created_at", { ascending: true });
  if (correctionError) throw new Error(`corrections unreadable: ${correctionError.message}`);
  const corrections = new Map<string, CorrectionRow[]>();
  for (const c of (correctionData ?? []) as CorrectionRow[]) {
    corrections.set(c.trace_id, [...(corrections.get(c.trace_id) ?? []), c]);
  }

  const red = roleExamples(selected.rows, corrections, "red");
  const blue = roleExamples(selected.rows, corrections, "blue");
  const adjudications = await appliedDisputeIds(orgId, selected.rows);
  const lineage = await runLineage(orgId, selected.runIds);
  const appliedCorrections = [...new Set([...red.appliedCorrections, ...blue.appliedCorrections])].sort();

  const selectionRecord: SelectionRecord = {
    filters: selection,
    runIds: selected.runIds,
    counts: {
      traces: selected.rows.length,
      red: selected.rows.filter((r) => r.actor === "red").length,
      blue: selected.rows.filter((r) => r.actor === "blue").length,
      excluded: selected.excluded,
      correctionsApplied: appliedCorrections.length,
      adjudicationsApplied: adjudications.length,
      sources: sourceCounts,
      realShare,
      realism,
    },
    corrections: appliedCorrections,
    adjudications,
  };

  const snapshot: BuiltSnapshot = {
    meta: {
      formatVersion: 2,
      contentHash: "",
      split: selection.split,
      redactionPolicyVersion: "v1",
      catalogVersion: CATALOG_VERSION,
      profileVersion: PROFILE_VERSION,
      imageVersion: IMAGE_VERSION,
      specDigests: lineage.specDigests,
      techniquePackVersions: lineage.techniquePackVersions,
      modelIds: lineage.modelIds,
    },
    selection: selectionRecord,
    roles: {
      red: { sft: red.sft, pairs: red.pairs },
      blue: { sft: blue.sft, pairs: blue.pairs },
    },
  };
  snapshot.meta.contentHash = snapshotHash(snapshot);
  const hash = snapshot.meta.contentHash;
  const prefix = `${orgId}/built/${hash.replace(/^sha256:/, "")}`;
  const storagePath = `datasets/${prefix}`;

  const { data: existing, error: existingError } = await sb.from("datasets")
    .select("id, content_hash, storage_path, family, split, roles, sources, selection")
    .eq("org_id", orgId).eq("content_hash", hash).maybeSingle();
  if (existingError) throw new Error(`dataset lookup failed: ${existingError.message}`);
  if (existing) {
    const row = existing as { id: string };
    return {
      datasetId: row.id, contentHash: hash, storagePath: (existing as { storage_path: string }).storage_path,
      family: (existing as { family: string }).family, split: (existing as { split: DatasetSplit }).split,
      roles: (existing as { roles: DatasetRole[] }).roles,
      sources: ((existing as { sources?: TraceSource[] }).sources ?? sources),
      selection: ((existing as { selection: SelectionRecord }).selection) ?? selectionRecord,
      counts: { redSft: red.sft.length, redPairs: red.pairs.length, blueSft: blue.sft.length, bluePairs: blue.pairs.length },
      reused: true,
    };
  }

  const manifest = {
    version: 2,
    family: selection.family,
    split: selection.split,
    roles: selection.roles,
    sources,
    counts: {
      redSft: red.sft.length, redPairs: red.pairs.length, blueSft: blue.sft.length, bluePairs: blue.pairs.length,
      traces: selected.rows.length,
    },
    files: [
      `sft.jsonl${GZ}`, `preference-pairs.jsonl${GZ}`, `red-sft.jsonl${GZ}`, `red-preference-pairs.jsonl${GZ}`,
      `blue-sft.jsonl${GZ}`, `blue-preference-pairs.jsonl${GZ}`,
    ],
    encoding: "gzip",
    exportHash: hash,
    meta: snapshot.meta,
  };
  const files: [string, string][] = [
    ["export.json", JSON.stringify(snapshot)],
    // Legacy names stay red-only (Req §2.4.7).
    ["sft.jsonl", jsonl(red.sft)],
    ["preference-pairs.jsonl", jsonl(red.pairs)],
    ["red-sft.jsonl", jsonl(red.sft)],
    ["red-preference-pairs.jsonl", jsonl(red.pairs)],
    ["blue-sft.jsonl", jsonl(blue.sft)],
    ["blue-preference-pairs.jsonl", jsonl(blue.pairs)],
    ["manifest.json", JSON.stringify(manifest, null, 2)],
  ];
  const bucket = sb.storage.from("datasets");
  for (const [name, body] of files) {
    const { error } = await bucket.upload(`${prefix}/${name}${GZ}`, encodeObject(body), { contentType: GZ_TYPE, upsert: false });
    if (error && /exists|Duplicate/i.test(error.message)) continue;
    if (error) throw new Error(`upload ${name} failed: ${error.message}`);
  }

  // Verify the stored snapshot, not the in-memory copy.
  const { data: blob, error: downloadError } = await bucket.download(`${prefix}/export.json${GZ}`);
  if (downloadError || !blob) throw new Error(`stored dataset export unreadable: ${downloadError?.message}`);
  const stored = JSON.parse(await decodeObject(blob)) as BuiltSnapshot;
  if (snapshotHash(stored) !== hash) throw new Error("stored dataset export does not match its content hash");

  const { data: datasetRow, error: insertError } = await sb.from("datasets").insert({
    org_id: orgId,
    name: selection.name ?? `${selection.family}-${selection.split}`,
    content_hash: hash,
    format_version: 2,
    split: selection.split,
    redaction_policy_version: "v1",
    storage_path: storagePath,
    family: selection.family,
    selection: selectionRecord,
    roles: selection.roles,
    sources,
  }).select("id").single();
  if (insertError) throw new Error(`dataset insert failed: ${insertError.message}`);

  const datasetId = (datasetRow as { id: string }).id;
  await audit({
    orgId, actor: "dataset-builder", action: "DATASET_BUILT", subjectType: "dataset", subjectId: datasetId,
    detail: {
      family: selection.family, split: selection.split, hash, roles: selection.roles,
      counts: manifest.counts, corrections: appliedCorrections, adjudications,
    },
  });
  return {
    datasetId, contentHash: hash, storagePath, family: selection.family, split: selection.split,
    roles: selection.roles, sources, selection: selectionRecord,
    counts: manifest.counts, reused: false,
  };
}

export class DatasetNotFound extends Error {}
/** Restore was requested for a snapshot that is not archived. */
export class DatasetNotArchived extends Error {}

export interface DatasetSummary {
  id: string;
  name: string;
  family: string | null;
  split: DatasetSplit;
  roles: DatasetRole[];
  sources: TraceSource[];
  contentHash: string;
  formatVersion: number;
  redactionPolicyVersion: string;
  storagePath: string;
  selection: SelectionRecord | Record<string, never>;
  createdAt: string;
  archivedAt: string | null;
  leakage: "clear" | "collision";
}

export async function listDatasets(orgId: string, options: { includeArchived?: boolean } = {}): Promise<DatasetSummary[]> {
  let query = serviceClient().from("datasets")
    .select("id, name, family, split, roles, sources, content_hash, format_version, redaction_policy_version, storage_path, selection, created_at, archived_at")
    .eq("org_id", orgId)
    .order("created_at", { ascending: false });
  if (!options.includeArchived) query = query.is("archived_at", null);
  const { data, error } = await query;
  if (error) throw new Error(`datasets unreadable: ${error.message}`);
  const rows = (data ?? []) as {
    id: string; name: string; family: string | null; split: DatasetSplit; roles: DatasetRole[] | null;
    sources: TraceSource[] | null; archived_at: string | null;
    content_hash: string; format_version: number; redaction_policy_version: string; storage_path: string;
    selection: SelectionRecord | null; created_at: string;
  }[];
  const splitsByFamily = new Map<string, Set<string>>();
  for (const row of rows) {
    if (!row.family) continue;
    const splits = splitsByFamily.get(row.family) ?? new Set<string>();
    splits.add(row.split);
    splitsByFamily.set(row.family, splits);
  }
  return rows.map((row) => ({
    id: row.id,
    name: row.name,
    family: row.family,
    split: row.split,
    roles: row.roles ?? [],
    sources: row.sources ?? [],
    contentHash: row.content_hash,
    formatVersion: row.format_version,
    redactionPolicyVersion: row.redaction_policy_version,
    storagePath: row.storage_path,
    selection: row.selection ?? {},
    createdAt: row.created_at,
    archivedAt: row.archived_at,
    leakage: row.family && (splitsByFamily.get(row.family)?.size ?? 0) > 1 ? "collision" : "clear",
  }));
}

const DATASET_COLUMNS = "id, name, family, split, roles, sources, content_hash, format_version, redaction_policy_version, storage_path, selection, created_at, archived_at";

type DatasetDbRow = {
  id: string; name: string; family: string | null; split: DatasetSplit; roles: DatasetRole[] | null;
  sources: TraceSource[] | null; archived_at: string | null;
  content_hash: string; format_version: number; redaction_policy_version: string; storage_path: string;
  selection: SelectionRecord | null; created_at: string;
};

function toSummary(row: DatasetDbRow): DatasetSummary {
  return {
    id: row.id,
    name: row.name,
    family: row.family,
    split: row.split,
    roles: row.roles ?? [],
    sources: row.sources ?? [],
    contentHash: row.content_hash,
    formatVersion: row.format_version,
    redactionPolicyVersion: row.redaction_policy_version,
    storagePath: row.storage_path,
    selection: row.selection ?? {},
    createdAt: row.created_at,
    archivedAt: row.archived_at,
    leakage: "clear",
  };
}

async function datasetFor(orgId: string, id: string): Promise<{ id: string; archived_at: string | null } | null> {
  const { data, error } = await serviceClient().from("datasets")
    .select("id, archived_at").eq("org_id", orgId).eq("id", id).maybeSingle();
  if (error) throw new Error(`dataset lookup failed: ${error.message}`);
  return (data as { id: string; archived_at: string | null } | null) ?? null;
}

/** Rename is metadata on an immutable snapshot; the content hash never moves. */
export async function renameDataset(orgId: string, id: string, name: string, actor: string): Promise<DatasetSummary> {
  if (!(await datasetFor(orgId, id))) throw new DatasetNotFound(`dataset ${id} not found`);
  const { data, error } = await serviceClient().from("datasets")
    .update({ name }).eq("org_id", orgId).eq("id", id)
    .select(DATASET_COLUMNS).single();
  if (error) throw new Error(`dataset rename failed: ${error.message}`);
  await audit({ orgId, actor, action: "DATASET_RENAMED", subjectType: "dataset", subjectId: id, detail: { name } });
  return toSummary(data as DatasetDbRow);
}

/** Archiving hides a snapshot from builders without deleting the evidence. */
export async function archiveDataset(orgId: string, id: string, actor: string): Promise<DatasetSummary> {
  if (!(await datasetFor(orgId, id))) throw new DatasetNotFound(`dataset ${id} not found`);
  const { data, error } = await serviceClient().from("datasets")
    .update({ archived_at: new Date().toISOString() }).eq("org_id", orgId).eq("id", id)
    .select(DATASET_COLUMNS).single();
  if (error) throw new Error(`dataset archive failed: ${error.message}`);
  await audit({ orgId, actor, action: "DATASET_ARCHIVED", subjectType: "dataset", subjectId: id, detail: {} });
  return toSummary(data as DatasetDbRow);
}

/** Restore makes an archived snapshot buildable again. */
export async function restoreDataset(orgId: string, id: string, actor: string): Promise<DatasetSummary> {
  const existing = await datasetFor(orgId, id);
  if (!existing) throw new DatasetNotFound(`dataset ${id} not found`);
  if (!existing.archived_at) throw new DatasetNotArchived(`dataset ${id} is not archived`);
  const { data, error } = await serviceClient().from("datasets")
    .update({ archived_at: null }).eq("org_id", orgId).eq("id", id)
    .select(DATASET_COLUMNS).single();
  if (error) throw new Error(`dataset restore failed: ${error.message}`);
  await audit({ orgId, actor, action: "DATASET_RESTORED", subjectType: "dataset", subjectId: id, detail: {} });
  return toSummary(data as DatasetDbRow);
}

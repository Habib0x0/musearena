import type { Label } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { AdjudicationQueue } from "./integrity.js";

/**
 * Durable label disputes (design §3.11, F-5).
 *
 * The in-memory queue is the pure contract; this module is the persisted one.
 * A dispute is keyed by `(org, run, step instant)`, so the same auto-label can
 * never be filed twice, and the row keeps both values with a version so an
 * export can always show what changed and when.
 */
export interface LabelDisputeRow {
  id: string;
  org_id: string;
  run_id: string;
  step_at: string;
  auto_label: Label;
  adjudicated_label: Label | null;
  version: number;
  status: "pending" | "adjudicated";
  filed_by: string;
  adjudicated_by: string | null;
  created_at: string;
  updated_at: string;
}

/** A second file for the same run step is a conflict, not a new dispute. */
export class DuplicateDispute extends Error {}

/** Adjudicating a dispute that does not belong to the org is a 404, not a 500. */
export class DisputeNotFound extends Error {}

export async function listLabelDisputes(orgId: string, opts: { runId?: string; status?: "pending" | "adjudicated" } = {}): Promise<LabelDisputeRow[]> {
  let query = serviceClient()
    .from("label_disputes")
    .select("*")
    .eq("org_id", orgId)
    .order("created_at", { ascending: true });
  if (opts.runId) query = query.eq("run_id", opts.runId);
  if (opts.status) query = query.eq("status", opts.status);
  const { data, error } = await query;
  if (error) throw new Error(`label disputes unreadable: ${error.message}`);
  return (data ?? []) as LabelDisputeRow[];
}

export async function fileLabelDispute(input: {
  orgId: string; runId: string; stepAt: string; auto: Label; filedBy: string;
}): Promise<LabelDisputeRow> {
  const { data, error } = await serviceClient().from("label_disputes").insert({
    org_id: input.orgId,
    run_id: input.runId,
    step_at: input.stepAt,
    auto_label: input.auto,
    filed_by: input.filedBy,
  }).select("*").single();
  if (error) {
    if (error.code === "23505") throw new DuplicateDispute(`a dispute already exists for ${input.runId} at ${input.stepAt}`);
    throw new Error(`label dispute insert failed: ${error.message}`);
  }
  await audit({
    orgId: input.orgId, actor: input.filedBy, action: "LABEL_DISPUTE_FILED",
    subjectType: "run", subjectId: input.runId,
    detail: { stepAt: input.stepAt, auto: input.auto },
  });
  return data as LabelDisputeRow;
}

export async function adjudicateLabel(input: {
  orgId: string; disputeId: string; label: Label; reviewer: string;
}): Promise<LabelDisputeRow> {
  const sb = serviceClient();
  const { data: current, error: readError } = await sb.from("label_disputes")
    .select("*").eq("org_id", input.orgId).eq("id", input.disputeId).maybeSingle();
  if (readError) throw new Error(`label dispute unreadable: ${readError.message}`);
  if (!current) throw new DisputeNotFound(`unknown dispute ${input.disputeId}`);

  const row = current as LabelDisputeRow;
  const { data, error } = await sb.from("label_disputes").update({
    adjudicated_label: input.label,
    adjudicated_by: input.reviewer,
    version: row.version + 1,
  }).eq("org_id", input.orgId).eq("id", input.disputeId).select("*").single();
  if (error) throw new Error(`label adjudication failed: ${error.message}`);

  await audit({
    orgId: input.orgId, actor: input.reviewer, action: "LABEL_ADJUDICATED",
    subjectType: "run", subjectId: row.run_id,
    detail: { disputeId: input.disputeId, version: row.version + 1, from: row.auto_label, to: input.label },
  });
  return data as LabelDisputeRow;
}

/**
 * Rebuild the pure queue from rows. `applyAdjudications` matches by
 * `(runId, stepAt)` as instants, so database ids need not survive the trip.
 */
export function queueFromRows(rows: LabelDisputeRow[]): AdjudicationQueue {
  const queue = new AdjudicationQueue();
  for (const row of rows) {
    const dispute = queue.file(row.run_id, row.step_at, row.auto_label);
    if (row.adjudicated_label) queue.adjudicate(dispute.id, row.adjudicated_label);
  }
  return queue;
}

export async function loadAdjudicationQueue(orgId: string, runId: string): Promise<AdjudicationQueue> {
  return queueFromRows(await listLabelDisputes(orgId, { runId }));
}

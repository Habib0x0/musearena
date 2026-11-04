import { serviceClient } from "./supabase.js";

export type AuditAction =
  | "ENVIRONMENT_CREATE" | "ENVIRONMENT_DESTROY"
  | "DEPLOYMENT_START" | "DEPLOYMENT_STOP" | "DEPLOYMENT_DESTROY"
  | "RUN_START" | "RUN_END" | "PROOF_GATE_DECISION"
  | "SCORE_COMPUTED" | "DATASET_EXPORTED" | "DATASET_BUILT" | "SECRET_DESTROYED"
  | "DATASET_RENAMED" | "DATASET_ARCHIVED" | "DATASET_RESTORED"
  | "RUN_DELETED" | "TRACE_DELETED" | "TRACE_RESTORED"
  | "MODEL_UPDATED" | "GRADER_UPDATED" | "GRADER_DELETED"
  | "CAPTURE_KEY_REJECTED" | "CAPTURE_KEY_ISSUED" | "CAPTURE_KEY_REVOKED"
  | "CORRECTION_RECORDED" | "LABEL_DISPUTE_FILED" | "LABEL_ADJUDICATED"
  | "TRAINING_RUN_CREATED" | "TRAINING_RUN_APPROVED" | "TRAINING_RUN_AWAITING_TRAINER"
  | "TRAINING_RUN_SUCCEEDED" | "TRAINING_RUN_FAILED" | "TRAINING_RUN_CANCELLED"
  | "EVALUATION_CREATED" | "EVALUATION_SUCCEEDED" | "EVALUATION_FAILED"
  | "MODEL_PROMOTED" | "MODEL_PROMOTION_REFUSED" | "MODEL_DEPLOYMENT_ROLLED_BACK" | "MODEL_DEPLOYMENT_RESTORED"
  | "TRAINING_PROPOSAL_CREATED" | "TRAINING_PROPOSAL_APPROVED" | "TRAINING_PROPOSAL_REJECTED"
  | "CONFIG_REMEDIATION"
  | "ADMIN_LIMITS_UPDATED" | "ADMIN_LAB_STOPPED" | "ADMIN_DEPLOYMENT_REFUSED"
  | "ADMIN_MEMBER_INVITED" | "ADMIN_MEMBER_ROLE_CHANGED" | "ADMIN_MEMBER_REMOVED";

export interface AuditEntry {
  orgId: string;
  actor: string; // user id or "orchestrator"
  action: AuditAction;
  subjectType: string;
  subjectId: string;
  detail?: Record<string, unknown>;
}

/**
 * Append-only, hash-chained audit. The database trigger links prev_hash and
 * computes entry_hash over the stored row (migration 0003); UPDATE/DELETE are
 * refused. `verifyAuditChain` recomputes the chain server-side.
 */
export async function audit(entry: AuditEntry): Promise<void> {
  const sb = serviceClient();
  const { error } = await sb.from("audit_log").insert({
    org_id: entry.orgId,
    actor: entry.actor,
    action: entry.action,
    subject_type: entry.subjectType,
    subject_id: entry.subjectId,
    detail: entry.detail ?? {},
    entry_hash: "pending", // replaced by the chain trigger
  });
  if (error) throw new Error(`audit insert failed: ${error.message}`);
}

/** First broken link for an org's audit chain, or null when the chain verifies. */
export async function verifyAuditChain(orgId: string): Promise<{ brokenId: number; reason: string } | null> {
  const { data, error } = await serviceClient().rpc("audit_verify", { p_org: orgId });
  if (error) throw new Error(`audit verify failed: ${error.message}`);
  const row = (data as { broken_id: number; reason: string }[] | null)?.[0];
  return row ? { brokenId: row.broken_id, reason: row.reason } : null;
}

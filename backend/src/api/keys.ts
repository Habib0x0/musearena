import { createHash, randomBytes } from "node:crypto";
import { serviceClient } from "../lib/supabase.js";
import { ApiError } from "./auth.js";

/**
 * Capture keys (design §3.10): machine ingestion without a Clerk session.
 *
 * The raw key is shown once. Only a prefix (for display) and a SHA-256 hash are
 * stored, and the org comes from the stored row — never from the key itself.
 */
const PREFIX = "muse_ck_";
const RAW_BYTES = 32;
const KEY_RE = /^muse_ck_[A-Za-z0-9_-]{43}$/;
const DISPLAY_PREFIX_LENGTH = 12;

export interface NewCaptureKey {
  /** Returned to the caller once, never stored. */
  raw: string;
  prefix: string;
  hash: string;
}

export function newCaptureKey(): NewCaptureKey {
  const raw = PREFIX + randomBytes(RAW_BYTES).toString("base64url");
  return { raw, prefix: raw.slice(0, DISPLAY_PREFIX_LENGTH), hash: hashCaptureKey(raw) };
}

export function hashCaptureKey(raw: string): string {
  return createHash("sha256").update(raw).digest("hex");
}

export function isCaptureKeyFormat(raw: string): boolean {
  return KEY_RE.test(raw);
}

export interface CaptureKeyRecord {
  id: string;
  orgId: string;
  revokedAt: string | null;
}

export interface CaptureKeyStore {
  find(hash: string): Promise<CaptureKeyRecord | null>;
  touch(id: string): Promise<void>;
}

export interface RejectionAudit {
  reason: "malformed" | "unknown" | "revoked";
  orgId?: string;
}

/**
 * Resolve a capture key to its org. A rejected key never reaches a handler, and
 * the rejection is audited even though the request is already refused.
 */
export async function verifyCaptureKey(
  raw: string,
  store: CaptureKeyStore,
  auditRejection: (input: RejectionAudit) => Promise<void>,
): Promise<string> {
  if (!isCaptureKeyFormat(raw)) {
    await auditRejection({ reason: "malformed" });
    throw new ApiError(401, "invalid capture key");
  }
  const record = await store.find(hashCaptureKey(raw));
  if (!record) {
    await auditRejection({ reason: "unknown" });
    throw new ApiError(401, "unknown capture key");
  }
  if (record.revokedAt) {
    await auditRejection({ reason: "revoked", orgId: record.orgId });
    throw new ApiError(401, "revoked capture key");
  }
  // Best effort: a failed usage timestamp must not reject a valid key.
  await store.touch(record.id).catch(() => {});
  return record.orgId;
}

/** Supabase-backed store; used once F-4 creates the `capture_keys` table. */
export function supabaseCaptureKeyStore(): CaptureKeyStore {
  const sb = serviceClient();
  return {
    async find(hash) {
      const { data, error } = await sb
        .from("capture_keys")
        .select("id, org_id, revoked_at")
        .eq("key_hash", hash)
        .maybeSingle();
      if (error) throw new Error(`capture key lookup failed: ${error.message}`);
      if (!data) return null;
      return {
        id: data.id as string,
        orgId: data.org_id as string,
        revokedAt: (data.revoked_at as string | null) ?? null,
      };
    },
    async touch(id) {
      const { error } = await sb
        .from("capture_keys")
        .update({ last_used_at: new Date().toISOString() })
        .eq("id", id);
      if (error) throw new Error(`capture key touch failed: ${error.message}`);
    },
  };
}

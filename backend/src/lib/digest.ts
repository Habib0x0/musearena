import { createHash } from "node:crypto";

/**
 * Canonical JSON: object keys sorted recursively, `undefined` dropped, arrays
 * preserved in order. Digests computed over this form are key-order invariant,
 * so the designer, template registry, Pulumi labels, and dataset pins all agree
 * on one spec digest (full sha256 — never truncated).
 */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(",")}}`;
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

/** Full content digest of a spec-shaped value: `sha256:<64 hex>`. */
export function digestOfSpec(spec: unknown): string {
  return "sha256:" + sha256Hex(canonicalJson(spec));
}

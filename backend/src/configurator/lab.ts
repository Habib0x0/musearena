import { createHash } from "node:crypto";

/**
 * Deterministic per-run lab credentials shared by configuration (Ansible
 * seeds the service) and readiness (the probe authenticates). Derived from
 * the run id and a label so neither side has to persist a secret, and a
 * value from one run never opens another.
 */
export function labSecret(runId: string, label: string): string {
  return `Arena-${createHash("sha256").update(`${runId}:${label}`).digest("hex").slice(0, 16)}`;
}

/**
 * The directory uid a persona is seeded as. Seeding and every consumer that
 * authenticates *as* the persona must derive the name identically, or a probe
 * would test a user that does not exist.
 */
export function ipaUserIdFor(personaId: string): string {
  return personaId.toLowerCase().replace(/[^a-z0-9._-]/g, "").slice(0, 32);
}

/** Password seeded for a persona's directory account. */
export function ipaUserSecret(runId: string, personaId: string): string {
  return labSecret(runId, `ipa-user-${ipaUserIdFor(personaId)}`);
}

/**
 * Sign-up/sign-in domain allowlist (hosted deployments).
 *
 * Off unless MUSEARENA_ALLOWED_EMAIL_DOMAINS is set, so local development is
 * unaffected. When set, a session is accepted only if the user's *verified*
 * email address belongs to one of the domains (exact domain match; subdomains
 * are not implied). The address comes from Clerk's Backend API for the token's
 * subject, never from a client-supplied field.
 */

export function allowedDomains(env: NodeJS.ProcessEnv = process.env): string[] | null {
  const raw = env.MUSEARENA_ALLOWED_EMAIL_DOMAINS?.trim();
  if (!raw) return null;
  return raw.split(",").map((d) => d.trim().toLowerCase().replace(/^@/, "")).filter(Boolean);
}

export function emailAllowed(email: string, domains: string[]): boolean {
  const at = email.lastIndexOf("@");
  if (at < 1) return false;
  const domain = email.slice(at + 1).trim().toLowerCase();
  return domains.includes(domain);
}

type ClerkUser = { email_addresses?: { email_address: string; verification?: { status?: string } | null }[] };
export type UserFetcher = (userId: string) => Promise<ClerkUser>;

const defaultFetcher: UserFetcher = async (userId) => {
  const key = process.env.CLERK_SECRET_KEY;
  if (!key) throw new Error("CLERK_SECRET_KEY is required when MUSEARENA_ALLOWED_EMAIL_DOMAINS is set");
  const res = await fetch(`https://api.clerk.com/v1/users/${encodeURIComponent(userId)}`, { headers: { Authorization: `Bearer ${key}` } });
  if (!res.ok) throw new Error(`Clerk user lookup failed (${res.status})`);
  return (await res.json()) as ClerkUser;
};

const cache = new Map<string, { ok: boolean; at: number }>();
const TTL_MS = 5 * 60_000;

/**
 * Throws when the allowlist is on and the user has no verified address in it.
 * Results are cached per user for five minutes.
 */
export async function assertEmailAllowed(userId: string, opts: { env?: NodeJS.ProcessEnv; fetchUser?: UserFetcher; now?: number } = {}): Promise<void> {
  const domains = allowedDomains(opts.env);
  if (!domains) return;
  const now = opts.now ?? Date.now();
  const hit = cache.get(userId);
  let ok: boolean;
  if (hit && now - hit.at < TTL_MS) ok = hit.ok;
  else {
    const user = await (opts.fetchUser ?? defaultFetcher)(userId);
    ok = (user.email_addresses ?? []).some((e) => e.verification?.status === "verified" && emailAllowed(e.email_address, domains));
    cache.set(userId, { ok, at: now });
  }
  if (!ok) throw new EmailNotAllowed(`access is limited to ${domains.map((d) => `@${d}`).join(", ")} accounts`);
}

export class EmailNotAllowed extends Error {}

/** Test hook. */
export function resetEmailAllowlistCache(): void { cache.clear(); }

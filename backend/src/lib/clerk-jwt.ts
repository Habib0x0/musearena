import { createPublicKey, createVerify } from "node:crypto";

type JsonWebKey = { kty?: string; n?: string; e?: string; [k: string]: unknown };

/**
 * Minimal Clerk session-token verification (RS256 via the issuer's JWKS) for
 * worker-hosted endpoints. Checks signature, kid, iss, exp/nbf (with skew).
 */
export interface ClerkClaims { sub: string; iss: string; exp: number; o?: { id?: string; rol?: string }; [k: string]: unknown }

/** Issuer from CLERK_ISSUER, else decoded from the publishable key (pk_test_<base64 host$>). */
export function clerkIssuer(env: NodeJS.ProcessEnv = process.env): string | null {
  if (env.CLERK_ISSUER) return env.CLERK_ISSUER.replace(/\/$/, "");
  const pk = env.CLERK_PUBLISHABLE_KEY ?? env.VITE_CLERK_PUBLISHABLE_KEY;
  const enc = pk?.split("_")[2];
  if (!enc) return null;
  const host = Buffer.from(enc, "base64").toString("utf8").replace(/\$$/, "");
  return /^[a-z0-9.-]+$/i.test(host) ? `https://${host}` : null;
}

const b64urlJson = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));

export type JwksFetcher = (url: string) => Promise<{ keys: (JsonWebKey & { kid?: string })[] }>;
const defaultFetcher: JwksFetcher = async (url) => (await (await fetch(url)).json()) as { keys: (JsonWebKey & { kid?: string })[] };

let cache: { url: string; at: number; keys: (JsonWebKey & { kid?: string })[] } | null = null;

export async function verifyClerkToken(token: string, issuer: string, opts: { fetchJwks?: JwksFetcher; now?: number; skewSec?: number } = {}): Promise<ClerkClaims> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  const header = b64urlJson(parts[0]) as { alg?: string; kid?: string };
  if (header.alg !== "RS256") throw new Error(`unsupported alg ${header.alg}`);
  const url = `${issuer}/.well-known/jwks.json`;
  const fetchJwks = opts.fetchJwks ?? defaultFetcher;
  if (!cache || cache.url !== url || Date.now() - cache.at > 10 * 60_000 || !cache.keys.some((k) => k.kid === header.kid)) {
    cache = { url, at: Date.now(), keys: (await fetchJwks(url)).keys };
  }
  const jwk = cache.keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("unknown signing key");
  const ok = createVerify("RSA-SHA256").update(`${parts[0]}.${parts[1]}`).verify(createPublicKey({ key: jwk, format: "jwk" }), Buffer.from(parts[2], "base64url"));
  if (!ok) throw new Error("bad signature");
  const claims = b64urlJson(parts[1]) as ClerkClaims;
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  const skew = opts.skewSec ?? 30;
  if (claims.iss !== issuer) throw new Error("wrong issuer");
  if (typeof claims.exp !== "number" || claims.exp + skew < now) throw new Error("token expired");
  if (typeof claims.nbf === "number" && claims.nbf - skew > now) throw new Error("token not yet valid");
  if (!claims.sub) throw new Error("token has no subject");
  return claims;
}

/** Test hook: drop cached keys. */
export function resetJwksCache(): void { cache = null; }

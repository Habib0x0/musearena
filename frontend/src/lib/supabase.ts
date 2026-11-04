import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const env = (import.meta as { env?: Record<string, string> }).env ?? {};
const url = env.VITE_SUPABASE_URL;
const publishableKey = env.VITE_SUPABASE_PUBLISHABLE_KEY;

let tokenProvider: (() => Promise<string | null>) | null = null;

/** Clerk session bridge registers its token getter here (see ClerkAuth). */
export function setClerkTokenProvider(fn: (() => Promise<string | null>) | null): void {
  tokenProvider = fn;
}

/** Current Clerk session token (null when signed out). */
export async function sessionToken(): Promise<string | null> {
  return tokenProvider ? tokenProvider() : null;
}

let client: SupabaseClient | null = null;

/**
 * User-scoped Supabase client. Clerk is registered as a Supabase third-party
 * auth provider, so the Clerk session token is forwarded per request and RLS
 * evaluates auth.jwt() org claims. No token (signed out) → RLS returns nothing.
 */
export function supabase(): SupabaseClient {
  if (!url || !publishableKey) throw new Error("Supabase not configured: set VITE_SUPABASE_URL and VITE_SUPABASE_PUBLISHABLE_KEY");
  if (!client) {
    client = createClient(url, publishableKey, {
      accessToken: async () => (tokenProvider ? tokenProvider() : null),
      auth: { persistSession: false },
    });
  }
  return client;
}

export const supabaseConfigured = Boolean(url && publishableKey);

import { createClient, SupabaseClient } from "@supabase/supabase-js";

let cached: SupabaseClient | null = null;

/**
 * Service client for workers. Uses the service-role key and must set
 * per-request org context — RLS is enforced for user traffic via Clerk JWTs;
 * workers scope every query to the job's org explicitly.
 */
export function serviceClient(): SupabaseClient {
  if (cached) return cached;
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY ?? process.env.SUPABASE_SECRET_KEY;
  if (!url || !key) throw new Error("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_SECRET_KEY) not set");
  cached = createClient(url, key, { auth: { persistSession: false } });
  return cached;
}

/**
 * User-scoped client: forwards the caller's Clerk session JWT so RLS
 * policies evaluate `auth.jwt()->>'sub'` / org claims. Workers use this
 * when acting on behalf of a user; otherwise serviceClient + explicit org.
 */
export function userClient(clerkJwt: string): SupabaseClient {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_ANON_KEY ?? process.env.SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) throw new Error("SUPABASE_URL / SUPABASE_ANON_KEY (or SUPABASE_PUBLISHABLE_KEY) not set");
  return createClient(url, key, {
    auth: { persistSession: false },
    global: { headers: { Authorization: `Bearer ${clerkJwt}` } },
  });
}

/**
 * Learning API client (F-13). The learning host is a separate service from
 * the Designer; every call carries the Clerk session token and surfaces the
 * server's own error text instead of masking a gated surface as empty data.
 */
const DEFAULT_LEARNING_API_URL = "http://127.0.0.1:8788";

export function learningApiUrl(): string {
  const env = (import.meta as { env?: Record<string, string> }).env;
  return (env?.VITE_LEARNING_API_URL || DEFAULT_LEARNING_API_URL).replace(/\/$/, "");
}

export async function learningFetch<T>(
  getToken: () => Promise<string | null>,
  path: string,
  init: RequestInit = {},
): Promise<T> {
  const token = await getToken();
  if (!token) throw new Error("no Clerk session token is available for the learning API");
  const response = await fetch(`${learningApiUrl()}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
      ...(init.headers ?? {}),
    },
  });
  const body = await response.json().catch(() => null) as { error?: string } | null;
  if (!response.ok) {
    throw new Error(body?.error ?? `learning API ${response.status} for ${path}`);
  }
  return body as T;
}

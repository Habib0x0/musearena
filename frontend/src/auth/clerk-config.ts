export const clerkKey = (import.meta as { env?: Record<string, string> }).env?.VITE_CLERK_PUBLISHABLE_KEY ?? "";
export const clerkEnabled = Boolean(clerkKey);

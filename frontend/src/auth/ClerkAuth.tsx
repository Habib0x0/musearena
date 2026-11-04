import { ClerkLoading, ClerkProvider, OrganizationSwitcher, SignInButton, SignUpButton, SignedIn, SignedOut, UserButton, useAuth, useClerk, useOrganization, useUser } from "@clerk/clerk-react";
import { PostHogIdentity } from "../analytics/posthog.tsx";
import type { ReactNode } from "react";
import { Ctx, type Session } from "./AuthContext";
import { setClerkTokenProvider } from "../lib/supabase";
import { useTheme } from "../hooks/useTheme";

/**
 * Real Clerk wiring. Active only when VITE_CLERK_PUBLISHABLE_KEY is set;
 * without it the app renders an authentication-not-configured error.
 * Maps Clerk user + active organization onto the app Session shape; sign-in
 * itself is Clerk's hosted/embedded flow (LoginPage links out when enabled).
 */
function ClerkSessionBridge({ children }: { children: ReactNode }) {
  const { isSignedIn, getToken } = useAuth();
  // Forward Clerk session tokens to Supabase (third-party auth → RLS claims).
  setClerkTokenProvider(async () => { try { return await getToken(); } catch { return null; } });
  const { user } = useUser();
  const { organization, membership } = useOrganization();
  const { signOut: clerkSignOut } = useClerk();

  // No active Clerk organization or recognized membership role means no app
  // session. Inventing "personal"/"member" would send writes under an org
  // and role the identity provider never granted.
  const clerkRole = membership?.role ?? "";
  const role: Session["role"] | null = clerkRole.includes("admin")
    ? "admin"
    : clerkRole.includes("member")
      ? "member"
      : null;
  const session: Session | null = isSignedIn && user && organization && role ? {
    userId: user.id,
    email: user.primaryEmailAddress?.emailAddress ?? "",
    orgId: organization.id,
    orgName: organization.name,
    role,
  } : null;

  // Hosted deployments set VITE_ALLOWED_EMAIL_DOMAINS (same list as the
  // backend's MUSEARENA_ALLOWED_EMAIL_DOMAINS). This screen is for the user;
  // the backend enforces the same rule on every API call.
  const allowed = (import.meta as { env?: Record<string, string> }).env?.VITE_ALLOWED_EMAIL_DOMAINS
    ?.split(",").map((d) => d.trim().toLowerCase().replace(/^@/, "")).filter(Boolean) ?? [];
  const verified = (user?.emailAddresses ?? []).filter((e) => e.verification?.status === "verified").map((e) => e.emailAddress.toLowerCase());
  if (isSignedIn && user && allowed.length > 0 && !verified.some((e) => allowed.includes(e.slice(e.lastIndexOf("@") + 1)))) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-ink p-6">
        <div className="max-w-md rounded-xl border border-line bg-panel p-6 text-sm">
          <h1 className="text-base font-semibold text-paper">Access is limited</h1>
          <p className="mt-2 leading-6 text-muted">MuseArena is currently open to {allowed.map((d) => `@${d}`).join(", ")} accounts. {user.primaryEmailAddress?.emailAddress ?? "This account"} is not on the list.</p>
          <button type="button" onClick={() => void clerkSignOut()} className="mt-4 rounded-md border border-line bg-panel2 px-3 py-1.5 text-xs font-medium text-paper">Sign out</button>
        </div>
      </div>
    );
  }

  return (
    <Ctx.Provider value={{
      session,
      signIn: () => { /* Clerk owns the sign-in UI/flow */ },
      signOut: () => { void clerkSignOut(); },
      switchOrg: () => { /* org switching via Clerk OrganizationSwitcher */ },
    }}>{children}</Ctx.Provider>
  );
}

export function ClerkAuthProvider({ children, publishableKey }: { children: ReactNode; publishableKey: string }) {
  const { resolved } = useTheme();
  return (
    <ClerkProvider
      key={resolved}
      publishableKey={publishableKey}
      appearance={{
        variables: {
          colorPrimary: "var(--signal)",
          colorBackground: "var(--panel)",
          colorText: "var(--paper)",
          colorTextSecondary: "var(--muted)",
          colorInputBackground: "var(--panel)",
          colorInputText: "var(--paper)",
          colorNeutral: "var(--paper)",
          borderRadius: "10px",
          fontFamily: '"Geist", "Inter", system-ui, sans-serif',
        },
      }}
    >
      <ClerkSessionBridge>
        <PostHogIdentity />
        {children}
      </ClerkSessionBridge>
    </ClerkProvider>
  );
}

/** Visible auth controls for the app chrome (Core 2 control components). */
export function ClerkControls() {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <ClerkLoading>
        <span className="inline-flex items-center rounded-md border border-line bg-panel2 px-3.5 py-2 text-sm text-muted" role="status">Loading authentication…</span>
      </ClerkLoading>
      <SignedOut>
        <SignInButton mode="modal"><button className="rounded-lg bg-signal px-3.5 py-2 text-sm font-medium text-signalcontrast shadow-sm hover:bg-signalhover">Sign in</button></SignInButton>
        <SignUpButton mode="modal"><button className="rounded-lg border border-line bg-panel px-3.5 py-2 text-sm font-medium text-paper shadow-sm hover:bg-panel2">Sign up</button></SignUpButton>
      </SignedOut>
      <SignedIn>
        <OrganizationSwitcher hidePersonal />
        <UserButton />
      </SignedIn>
    </div>
  );
}

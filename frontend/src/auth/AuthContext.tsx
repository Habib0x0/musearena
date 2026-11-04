import { createContext, useContext } from "react";

// Session context. The only provider is Clerk (see ClerkAuth.tsx); without a
// Clerk key the session stays null and the app shows a configuration error.
export interface Session { userId: string; email: string; orgId: string; orgName: string; role: "admin" | "member" }
interface AuthCtx { session: Session | null; signIn(email: string): void; signOut(): void; switchOrg(orgId: string): void }

export const Ctx = createContext<AuthCtx>({ session: null, signIn: () => {}, signOut: () => {}, switchOrg: () => {} });

export const useSession = () => useContext(Ctx);

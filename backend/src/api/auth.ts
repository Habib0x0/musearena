import type { ClerkClaims } from "../lib/clerk-jwt.js";

/**
 * Authorization for the learning API (design §4).
 *
 * Clerk proves who the caller is; the org claim gives the tenant and the role
 * claim gives what they may do. RLS stays the backstop — this is the check that
 * runs before a row is touched, so a missing role is refused here rather than
 * silently reading as an empty result.
 */
export type OrgRole = "reviewer" | "trainer" | "operator";

const ROLES: readonly OrgRole[] = ["reviewer", "trainer", "operator"];
const RANK: Record<OrgRole, number> = { reviewer: 1, trainer: 2, operator: 3 };

export const ORG_ROLES = ROLES;

export interface Session {
  orgId: string;
  role: OrgRole;
  subject: string;
}

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly requiredRole?: OrgRole,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

/** `Bearer <token>` from an Authorization header, or null. */
export function bearerToken(header: string | undefined): string | null {
  const match = /^Bearer\s+(\S+)$/i.exec(header ?? "");
  return match ? match[1] : null;
}

/**
 * The org and role come only from verified claims. A body field named
 * `org_id` is never consulted.
 */
export function sessionFromClaims(claims: ClerkClaims): Session {
  const orgId = claims.o?.id;
  if (typeof orgId !== "string" || !orgId) throw new ApiError(403, "token carries no organization claim");
  // Clerk's built-in org roles map onto ours: the org admin who owns the
  // workspace is an operator; a plain member reviews. Custom roles keep their name.
  const given = typeof claims.o?.rol === "string" ? claims.o.rol.replace(/^org:/, "") : "";
  const raw = given === "admin" ? "operator" : given === "member" ? "reviewer" : given;
  if (!(ROLES as readonly string[]).includes(raw)) {
    throw new ApiError(403, `token carries no recognized organization role (${ROLES.join(", ")}, or Clerk admin/member)`);
  }
  return { orgId, role: raw as OrgRole, subject: claims.sub };
}

/** Operator implies trainer implies reviewer. */
export function requireRole(session: Session, role: OrgRole, action: string): void {
  if (RANK[session.role] < RANK[role]) {
    throw new ApiError(403, `${action} requires the ${role} role`, role);
  }
}

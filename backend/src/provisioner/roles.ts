// Role → container image for the local Docker runtime. Images are real
// role-appropriate services (no stand-ins): PHP/Apache for web, Postgres for
// db. Telemetry each role emits to its container log (read out-of-band by the
// collector): Apache access/error log for web, Postgres statement +
// connection log for db.
//
// Weak DB credentials are PLANTED training content (Req §3.1), not secrets.

export interface RoleImage {
  image: string;
  envs?: string[];
  command?: string[];
  /** Telemetry the role emits on its own; undefined = no sensor source (gates fail). */
  telemetry?: "apache-log" | "postgres-log";
}

export const WEAK_DB_USER = "app";
export const WEAK_DB_PASSWORD = "Summer2024!";

/** Planted FreeIPA weakness: service account + password, only when planted. */
export const WEAK_IPA_USER = "svc-report";
export const WEAK_IPA_PASSWORD = "Summer2024!";

const ROLES: Record<string, RoleImage> = {
  web: { image: "php:8.2-apache", telemetry: "apache-log" },
  db: {
    image: "postgres:16-alpine",
    envs: [`POSTGRES_USER=${WEAK_DB_USER}`, `POSTGRES_PASSWORD=${WEAK_DB_PASSWORD}`, "POSTGRES_DB=app"],
    // log_line_prefix gives every line user/db/client so telemetry is attributable by source.
    command: ["postgres", "-c", "log_statement=all", "-c", "log_connections=on", "-c", "listen_addresses=*",
      "-c", "log_line_prefix=%m [%p] user=%u db=%d client=%h "],
    telemetry: "postgres-log",
  },
  // Red vantage: has psql + busybox wget, no services, never on the host network.
  attacker: { image: "postgres:16-alpine", command: ["sleep", "infinity"] },
};

/** Roles without a real image yet run as a generic Linux host with no telemetry source. */
const GENERIC: RoleImage = { image: "alpine:3.20", command: ["sleep", "infinity"] };

export function roleImage(role: string): RoleImage {
  return ROLES[role] ?? GENERIC;
}

/** Vuln types the local runtime can actually plant and prove, per role. */
export const PLANTABLE: Record<string, string[]> = { web: ["code-flaw", "cve"], db: ["weak-cred"] };

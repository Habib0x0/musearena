import type { ServiceDecl, ServiceKind } from "@musearena/shared";

/**
 * Runtime service catalog (spec §3, T-16): the closed vocabulary the designer
 * may declare. Every entry names the Debian package set, the systemd unit,
 * the config/seed task groups and the probe that proves the service works.
 * Anything outside this table is rejected at design/deployability time —
 * the platform never approximates a service it cannot install and verify.
 *
 * Catalog entries describe HOW a service is realized; the Ansible tasks
 * that execute the groups live in `profiles.ts`. Bump CATALOG_VERSION when
 * any entry changes semantics; the version is pinned per run.
 */
export const CATALOG_VERSION = "arena-catalog-4";

export interface CatalogEntry {
  kind: ServiceKind;
  impl: string;
  packages: string[];
  /** Packages on the Rocky guest family, when its names differ (freeipa). */
  rockyPackages?: string[];
  /** systemd units to enable (empty for client-only kinds like log shipping). */
  units: string[];
  defaultPort: number;
  readyWhen: ServiceDecl["readyWhen"];
  /** Ordered task-group names (install → configure → seed → enable). */
  groups: string[];
  /** Telemetry the service emits once running (drives requiredTelemetry checks). */
  telemetry: string[];
}

const e = (kind: ServiceKind, impl: string, rest: Omit<CatalogEntry, "kind" | "impl">): CatalogEntry => ({ kind, impl, ...rest });

export const SERVICE_CATALOG: CatalogEntry[] = [
  e("ssh", "openssh", {
    packages: ["openssh-server"], units: ["ssh"], defaultPort: 22, readyWhen: "ssh-login",
    groups: ["ssh-install", "ssh-configure", "ssh-enable"], telemetry: ["auth.log"],
  }),
  e("router", "nftables", {
    packages: ["nftables"], units: ["nftables"], defaultPort: 22, readyWhen: "ssh-login",
    groups: ["router-install", "router-configure", "router-enable"], telemetry: ["nftables.log", "auth.log"],
  }),
  e("dns", "dnsmasq", {
    packages: ["dnsmasq"], units: ["dnsmasq"], defaultPort: 53, readyWhen: "dns-query",
    groups: ["dns-install", "dns-configure", "dns-enable"], telemetry: ["dnsmasq.log"],
  }),
  e("dhcp", "dnsmasq", {
    packages: ["dnsmasq"], units: ["dnsmasq"], defaultPort: 67, readyWhen: "dhcp-lease",
    groups: ["dhcp-configure", "dhcp-enable"], telemetry: ["dnsmasq.log"],
  }),
  e("ldap", "openldap", {
    packages: ["slapd", "ldap-utils"], units: ["slapd"], defaultPort: 389, readyWhen: "ldap-bind",
    groups: ["ldap-install", "ldap-configure", "ldap-seed-directory", "ldap-enable"], telemetry: ["slapd.log"],
  }),
  // Linux AD: Kerberos KDC + 389-ds + integrated DNS + Dogtag CA. The
  // installer owns and starts the daemons, so no unit is enabled here.
  // Server: Rocky 9 only (Debian/Ubuntu ship the client stack, not the
  // server packages) — deployability enforces the OS; members may be Debian.
  // The Debian set is the client stack, so the Debian bake never names a
  // package apt cannot install; the Rocky set is the server installer.
  e("ldap", "freeipa", {
    packages: ["freeipa-client", "krb5-user"],
    rockyPackages: ["ipa-server", "ipa-server-dns", "ipa-client", "krb5-workstation"],
    units: [], defaultPort: 389, readyWhen: "ldap-bind",
    groups: ["freeipa-install", "freeipa-configure", "freeipa-seed-directory", "freeipa-enable"],
    telemetry: ["ipa.log", "krb5kdc.log", "dirsrv-access.log", "auth.log"],
  }),
  e("smtp", "postfix", {
    packages: ["postfix"], units: ["postfix"], defaultPort: 25, readyWhen: "smtp-imap-roundtrip",
    groups: ["smtp-install", "smtp-configure", "smtp-enable"], telemetry: ["mail.log"],
  }),
  e("imap", "dovecot", {
    packages: ["dovecot-imapd", "dovecot-ldap", "dovecot-gssapi"], units: ["dovecot"], defaultPort: 143, readyWhen: "smtp-imap-roundtrip",
    groups: ["imap-install", "imap-configure", "imap-seed-mailboxes", "imap-enable"], telemetry: ["mail.log"],
  }),
  e("http", "apache-php", {
    packages: ["apache2", "php", "libapache2-mod-php", "libapache2-mod-auth-gssapi"], units: ["apache2"], defaultPort: 80, readyWhen: "http-2xx",
    groups: ["http-install", "http-configure", "http-deploy-app", "http-enable"], telemetry: ["apache-access.log", "apache-error.log"],
  }),
  e("db", "postgres", {
    packages: ["postgresql"], units: ["postgresql"], defaultPort: 5432, readyWhen: "sql-select",
    groups: ["db-install", "db-configure", "db-seed", "db-enable"], telemetry: ["postgres.log"],
  }),
  // P3: Gitea with directory login. The binary is baked (Debian has no
  // package); its `[[auth.ldap]]` source binds as the user in 389-ds, so a
  // successful /api/v1/user is directory authentication, not a local account.
  e("git", "gitea", {
    packages: ["git"], units: ["gitea"], defaultPort: 3000, readyWhen: "git-ldap-login",
    groups: ["git-install", "git-configure", "git-seed", "git-enable"], telemetry: ["gitea.log"],
  }),
  e("log", "rsyslog-collector", {
    packages: ["rsyslog"], units: ["rsyslog"], defaultPort: 514, readyWhen: "tcp",
    groups: ["log-install", "log-configure-collector", "log-enable"], telemetry: ["collector.log"],
  }),
];

const byKey = new Map(SERVICE_CATALOG.map((c) => [`${c.kind}/${c.impl}`, c]));

/** Catalog entry for a declared service, or null when it is not provisionable. */
export function catalogEntry(decl: { kind: string; impl: string }): CatalogEntry | null {
  return byKey.get(`${decl.kind}/${decl.impl}`) ?? null;
}

/** Every implementation known for a kind (for error messages and the designer prompt). */
export function implsFor(kind: string): string[] {
  return SERVICE_CATALOG.filter((c) => c.kind === kind).map((c) => c.impl);
}

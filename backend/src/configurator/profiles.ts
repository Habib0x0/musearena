import type { EnvironmentSpec } from "@musearena/shared";
import { catalogEntry, CATALOG_VERSION, SERVICE_CATALOG, type CatalogEntry } from "./catalog.js";

/**
 * Machine-profile resolver (spec §3, T-16): role + structured services →
 * ordered Ansible task groups with declared packages and tools.
 *
 * A host is not real because it booted; it is real because its profile was
 * installed, seeded, enabled, and probe-verified. The resolver is pure and
 * deterministic: the same spec always resolves to the same groups, and any
 * service outside the catalog makes resolution fail with the reason.
 */

export interface ProfileTaskGroup {
  name: string;
  stage: "install" | "configure" | "seed" | "enable" | "verify";
}

export interface MachineProfile {
  hostId: string;
  role: string;
  groups: ProfileTaskGroup[];
  packages: string[];
  unitsToEnable: string[];
  /** Client tools this host's users/agents rely on (declared, never guessed). */
  clientTools: string[];
  catalogEntries: CatalogEntry[];
}

/**
 * Base profile on every VM host (spec §12.1): SSH, auditd + osquery sensors,
 * log shipping to the sensor, time sync, diagnostics. Sensor state is real
 * guest state — never the local harness stand-in.
 */
const BASE_PACKAGES = ["openssh-server", "auditd", "osquery", "rsyslog", "chrony", "curl", "jq", "dnsutils", "iputils-ping", "iptables"];
const BASE_GROUPS: ProfileTaskGroup[] = [
  { name: "base-users", stage: "configure" },
  { name: "base-ssh", stage: "configure" },
  { name: "base-sensors", stage: "install" },
  { name: "base-log-shipping", stage: "configure" },
  { name: "base-time-sync", stage: "enable" },
];

/** Client tools per service kind a host CONSUMES (persona workstations, web tiers). */
const CLIENT_TOOLS: Record<string, string[]> = {
  ldap: ["ldap-utils"],
  smtp: ["swaks"],
  imap: ["mutt", "dovecot-core"],
  http: ["curl", "lynx"],
  db: ["postgresql-client"],
  dns: ["dnsutils"],
  ssh: ["openssh-client"],
  git: ["git", "curl"],
};

/** Red toolbox on the attacker host: protocol clients for the whole catalog. */
const ATTACKER_TOOLS = ["nmap", "curl", "wget", "postgresql-client", "ldap-utils", "swaks", "dnsutils", "jq", "python3"];

/**
 * Tools the readiness probe itself needs ON the host that declares the
 * service. A probe that cannot run is a failed gate, so the tool ships with
 * the profile rather than depending on the baked image happening to carry it.
 */
const PROBE_TOOLS: Record<string, string[]> = {
  smtp: ["swaks"],
  git: ["curl"],
};

/**
 * Packages a domain member needs to join FreeIPA and resolve domain users
 * through SSSD. Only hosts that depend on a `ldap/freeipa` server get these.
 */
const FREEIPA_CLIENT_TOOLS = ["freeipa-client", "krb5-user", "sssd", "sssd-tools", "libpam-sss", "libnss-sss"];

/**
 * Rocky 9 FreeIPA server packages (P2). Debian ships the client stack only —
 * the server installer exists on Rocky as `ipa-server`. Kept separate from
 * the Debian catalog so the Debian bake never names a package apt cannot
 * install. The Rocky bake installs exactly `BASE_PACKAGES` (dnf equivalents)
 * plus this set; members join from either family.
 */
export const FREEIPA_ROCKY_SERVER_PACKAGES = ["ipa-server", "ipa-server-dns", "ipa-client", "krb5-workstation"];

const stageOf = (group: string): ProfileTaskGroup["stage"] =>
  group.endsWith("-install") ? "install"
  : group.endsWith("-enable") ? "enable"
  : group.includes("seed") ? "seed"
  : "configure";

export const PROFILE_VERSION = `arena-profiles-1+${CATALOG_VERSION}`;

/**
 * Every package any profile can need: base + catalog servers + client tools +
 * the attacker toolbox + the FreeIPA client stack. The baked golden image
 * installs exactly this union, so configuration never depends on package
 * egress (spec §3 offline story). Derived from the catalog, so a new
 * service's packages join the bake automatically; the manifest test pins
 * the resulting list. The Rocky FreeIPA server (P2) has its own bake; it
 * is not in this union.
 */
export function allProvisionablePackages(): string[] {
  const packages = new Set(BASE_PACKAGES);
  // entry.packages is the Debian set; Rocky-only names (rockyPackages) must
  // never enter the Debian bake or plan's known-packages gate.
  for (const entry of SERVICE_CATALOG) for (const p of entry.packages) packages.add(p);
  for (const tools of Object.values(CLIENT_TOOLS)) for (const p of tools) packages.add(p);
  for (const p of FREEIPA_CLIENT_TOOLS) packages.add(p);
  for (const p of ATTACKER_TOOLS) packages.add(p);
  return [...packages].sort();
}

/** Debian→Rocky package name mapping; null = unavailable in Rocky base repos (never faked). */
const ROCKY_PACKAGE_MAP = new Map<string, string | null>([
  ["auditd", "audit"],
  // Both families use the same vendor package; the Rocky bake adds the RPM
  // repo and installs it, so a Rocky guest no longer loses the sensor.
  ["osquery", "osquery"],
  ["dnsutils", "bind-utils"],
  ["iputils-ping", "iputils"],
  ["iptables", "iptables-nft"],
  // Rocky splits the SSH client tools into a plural package name.
  ["openssh-client", "openssh-clients"],
  // Debian's MTA test client and lynx are not in Rocky base repos.
  ["lynx", null],
  // Rocky ships the GSSAPI SASL plugin inside the main dovecot package and the
  // Apache module as `mod_auth_gssapi`; Debian splits both out.
  ["dovecot-gssapi", "dovecot"],
  ["libapache2-mod-auth-gssapi", "mod_auth_gssapi"],
]);
const rockyPackage = (p: string) => (ROCKY_PACKAGE_MAP.has(p) ? ROCKY_PACKAGE_MAP.get(p)! : p);

/** Packages for one resolved profile, specialized per guest OS family. */
export function resolveProfilePackages(profile: MachineProfile, os: string): string[] {
  if (!/rocky/i.test(os)) return profile.packages;
  const packages = new Set<string>();
  const add = (p: string) => { const mapped = rockyPackage(p); if (mapped) packages.add(mapped); };
  for (const p of BASE_PACKAGES) add(p);
  for (const entry of profile.catalogEntries) {
    for (const p of entry.rockyPackages ?? entry.packages) add(p);
  }
  if (profile.catalogEntries.some((e) => e.kind === "ldap" && e.impl === "freeipa")) {
    for (const p of FREEIPA_ROCKY_SERVER_PACKAGES) packages.add(p);
  }
  for (const t of profile.clientTools) add(t);
  return [...packages].sort();
}

/** Units for one resolved profile, specialized per guest OS family. */
export function resolveProfileUnits(profile: MachineProfile, os: string): string[] {
  if (!/rocky/i.test(os)) return profile.unitsToEnable;
  const unitMap = new Map<string, string | null>([
    ["ssh", "sshd"],
    ["chrony", "chronyd"],
    ["auditd", "auditd"], // package is `audit`, unit stays auditd on both families
    ["osqueryd", "osqueryd"], // same unit name as Debian
  ]);
  const out = new Set<string>();
  for (const u of profile.unitsToEnable) {
    if (unitMap.has(u)) { const v = unitMap.get(u)!; if (v) out.add(v); } else out.add(u);
  }
  return [...out].sort();
}

/**
 * Resolve one host's machine profile. Throws (with host + service named)
 * when a declared service is not in the catalog — the designer/deployability
 * boundary, not a runtime surprise.
 */
export function resolveProfile(spec: EnvironmentSpec, hostId: string): MachineProfile {
  const inst = spec.instances.find((i) => i.hostId === hostId);
  if (!inst) throw new Error(`unknown host ${hostId}`);
  const groups: ProfileTaskGroup[] = [...BASE_GROUPS];
  const packages = new Set(BASE_PACKAGES);
  const units = new Set(["ssh", "auditd", "osqueryd", "rsyslog", "chrony"]);
  const entries: CatalogEntry[] = [];
  for (const decl of inst.serviceDecls ?? []) {
    const entry = catalogEntry(decl);
    if (!entry) throw new Error(`${hostId}: service ${decl.kind}/${decl.impl} is not in the runtime catalog (${CATALOG_VERSION})`);
    entries.push(entry);
    for (const g of entry.groups) if (!groups.some((x) => x.name === g)) groups.push({ name: g, stage: stageOf(g) });
    for (const p of entry.packages) packages.add(p);
    for (const t of PROBE_TOOLS[entry.kind] ?? []) packages.add(t);
    for (const u of entry.units) units.add(u);
  }
  // Dependencies pull in client tools only (server side lives on the dep host).
  const tools = new Set<string>();
  for (const depId of inst.dependsOn ?? []) {
    const dep = spec.instances.find((i) => i.hostId === depId);
    for (const d of dep?.serviceDecls ?? []) for (const t of CLIENT_TOOLS[d.kind] ?? []) tools.add(t);
  }
  // A member of a FreeIPA domain needs the join tooling and SSSD, not just
  // ldap-utils: the directory is Kerberos-backed and resolves POSIX identities.
  const joinsFreeipa = (inst.dependsOn ?? []).some((depId) => {
    const dep = spec.instances.find((i) => i.hostId === depId);
    return (dep?.serviceDecls ?? []).some((d) => d.kind === "ldap" && d.impl === "freeipa");
  });
  if (joinsFreeipa) {
    for (const t of FREEIPA_CLIENT_TOOLS) tools.add(t);
    if (!groups.some((g) => g.name === "ipa-client-join")) groups.push({ name: "ipa-client-join", stage: "configure" });
  }
  if (inst.role === "attacker") for (const t of ATTACKER_TOOLS) tools.add(t);
  for (const t of tools) packages.add(t);
  // A persona's workstation runs the employee shift actions (web, db, mail,
  // lookup) against peer services, so it gets those clients installed. They
  // are not counted as dependency client tools: a workstation with no
  // dependsOn edge must still fail coherence.
  if ((spec.personas ?? []).some((p) => p.workstation === hostId) && (inst.dependsOn ?? []).length > 0) {
    for (const peer of spec.instances) {
      if (peer.hostId === hostId || peer.role === "attacker") continue;
      for (const d of peer.serviceDecls ?? []) if (["http", "db", "smtp", "dns"].includes(d.kind)) for (const t of CLIENT_TOOLS[d.kind] ?? []) packages.add(t);
    }
  }
  return {
    hostId, role: inst.role,
    groups, packages: [...packages].sort(), unitsToEnable: [...units].sort(),
    clientTools: [...tools].sort(), catalogEntries: entries,
  };
}

/** Resolve every host in a spec; the first unprovisionable service fails the whole design. */
export function resolveProfiles(spec: EnvironmentSpec): MachineProfile[] {
  return spec.instances.map((i) => resolveProfile(spec, i.hostId));
}

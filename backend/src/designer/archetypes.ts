import type { EnvironmentSpec, ServiceDecl } from "@musearena/shared";
import { digestOfSpec } from "../lib/digest.js";
import { CATALOG_VERSION } from "../configurator/catalog.js";
import { BAKED_CATALOG_VERSION } from "../provisioner/images.js";

/**
 * Versioned org archetypes (T-17). An archetype is the data behind an org:
 * which hosts exist, what each declares, which weaknesses are planted and
 * which techniques are exercised. Materialising one is a pure function, so a
 * given archetype version always produces the same spec and digest.
 *
 * Bump `version` whenever the shape changes — runs pin `${id}@${version}`.
 */
export const PROFILE_VERSION = "arena-profile-2";

export interface ArchetypeInstance {
  hostId: string;
  role: string;
  services: ServiceDecl[];
  databases?: string[];
  dependsOn?: string[];
  resources: { vcpu: number; memoryMb: number; diskGb: number };
}

export interface ArchetypeObjective {
  id: string;
  asset: string;
  techniqueId: string;
  successSignal: string;
  points: number;
  /** "weakness" objectives target a planted vuln; "detection" ones an activity. */
  kind: "weakness" | "detection";
}

export interface OrgArchetype {
  id: string;
  version: number;
  prompt: string;
  description: string;
  topology: EnvironmentSpec["topology"];
  instances: ArchetypeInstance[];
  personas: Array<{ id: string; role: string; workstation: string }>;
  objectives: ArchetypeObjective[];
  vulns: Array<{ id: string; type: "code-flaw" | "weak-cred"; techniqueId: string; targetHostId: string; pinnedVersion: string }>;
  requiredTelemetry: string[];
}

/** The 12-person clinic: gateway/DNS, directory, mail, intranet, patient DB, log collector. */
export const CLINIC_ARCHETYPE: OrgArchetype = {
  id: "clinic",
  version: 1,
  prompt: "12-person clinic: gateway/DNS, directory, mail with webmail, intranet, patient DB, logging, 8 personas, two weaknesses",
  description: "Small healthcare org: six Debian guests, eight staff, two planted weaknesses plus an SSH credential-guessing objective.",
  topology: {
    cidr: "10.2.0.0/16",
    subnets: [{ name: "clinic-lan", cidr: "10.2.32.0/20", zone: "a" }],
    firewallRules: [],
  },
  instances: [
    { hostId: "gw-01", role: "gateway", services: [{ kind: "dns", impl: "dnsmasq", port: 53, readyWhen: "dns-query" }],
      resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
    { hostId: "dc-01", role: "dc", services: [{ kind: "ldap", impl: "openldap", port: 389, readyWhen: "ldap-bind" }],
      dependsOn: ["gw-01"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
    { hostId: "mail-01", role: "mail", services: [
        { kind: "smtp", impl: "postfix", port: 25, readyWhen: "smtp-imap-roundtrip" },
        { kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" }],
      dependsOn: ["dc-01"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
    { hostId: "web-01", role: "web", services: [{ kind: "http", impl: "apache-php", port: 80, readyWhen: "http-2xx" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 8 } },
    { hostId: "db-01", role: "db", services: [{ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }],
      databases: ["app"], dependsOn: ["web-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 8 } },
    { hostId: "log-01", role: "sensor", services: [{ kind: "log", impl: "rsyslog-collector", port: 514, readyWhen: "tcp" }],
      resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
  ],
  personas: [
    { id: "p1", role: "nurse", workstation: "web-01" },
    { id: "p2", role: "nurse", workstation: "web-01" },
    { id: "p3", role: "receptionist", workstation: "web-01" },
    { id: "p4", role: "physician", workstation: "web-01" },
    { id: "p5", role: "pharmacist", workstation: "web-01" },
    { id: "p6", role: "lab-tech", workstation: "web-01" },
    { id: "p7", role: "billing", workstation: "web-01" },
    { id: "p8", role: "it-admin", workstation: "db-01" },
  ],
  objectives: [
    { id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 10, kind: "weakness" },
    { id: "o2", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10, kind: "weakness" },
    { id: "o3", asset: "dc-01", techniqueId: "T1110", successSignal: "auth-failures", points: 10, kind: "detection" },
  ],
  vulns: [
    { id: "v1", type: "code-flaw", techniqueId: "T1059", targetHostId: "web-01", pinnedVersion: "8.2" },
    { id: "v2", type: "weak-cred", techniqueId: "T1078", targetHostId: "db-01", pinnedVersion: "16" },
  ],
  requiredTelemetry: ["auditd"],
};

export const ARCHETYPES: OrgArchetype[] = [CLINIC_ARCHETYPE];

export function findArchetype(id: string, version?: number): OrgArchetype | undefined {
  return ARCHETYPES.find((a) => a.id === id && (version === undefined || a.version === version));
}

/** Deterministic archetype → spec. The same archetype version always yields the same digest. */
export function materializeArchetype(a: OrgArchetype, opts: { ttlHours?: number } = {}): EnvironmentSpec {
  return {
    version: 1, name: a.id, provider: "kvm", seed: a.id, difficulty: "standard", truthLayer: "mirror-only",
    topology: a.topology,
    instances: a.instances.map((i) => ({
      hostId: i.hostId, name: i.hostId, role: i.role, runtime: "vm", os: "Debian 12",
      stack: [], services: i.services.map((s) => s.kind), databases: i.databases ?? [],
      serviceDecls: i.services, dependsOn: i.dependsOn ?? [], resources: i.resources,
    })),
    personas: a.personas.map((p) => ({
      id: p.id, role: p.role, workstation: p.workstation, access: ["intranet"],
      credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [],
    })),
    objectives: a.objectives.map(({ kind: _kind, ...o }) => o),
    requiredTelemetry: a.requiredTelemetry,
    plantedVulns: a.vulns.map((v, n) => ({
      id: v.id, type: v.type, techniqueId: v.techniqueId, targetHostId: v.targetHostId,
      pinnedVersion: v.pinnedVersion, proofAtomicGuid: `g${n + 1}`, difficulty: "standard",
    })),
    budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: opts.ttlHours ?? 8 },
  };
}

/** Text for the designer prompt: the org shapes the runtime can actually build. */
export function archetypeCatalogText(): string {
  return ARCHETYPES.map((a) => `- ${a.id}@${a.version}: ${a.description} (prompt: "${a.prompt}")`).join("\n");
}

export interface DesignPin { archetype: string; catalog: string; profile: string; image: string }

/** Versions that produced a design. `null` archetype = model-authored spec. */
export function designPin(archetype: OrgArchetype | null): DesignPin {
  return {
    archetype: archetype ? `${archetype.id}@${archetype.version}` : "model",
    catalog: CATALOG_VERSION,
    profile: PROFILE_VERSION,
    image: BAKED_CATALOG_VERSION,
  };
}

/** Digest over the spec AND the versions that produced it (never the bare spec digest). */
export function pinnedDesignDigest(spec: EnvironmentSpec, pin: DesignPin): string {
  return digestOfSpec({ spec, pin });
}

/**
 * Provenance for a stored spec (T-17): materialisation is deterministic, so
 * a spec that digest-equals an archetype's materialisation *is* that
 * archetype — no schema field or row stamp needed. Budgets are excluded
 * (a TTL change is not a different design), and the opt-in attacker guest
 * is stripped before comparing (it is an exercise vantage, not org shape).
 * Anything else pins as model-authored with the executing build's versions.
 */
export function pinForSpec(spec: EnvironmentSpec): DesignPin {
  const bare = (s: EnvironmentSpec) => digestOfSpec({ ...s, budgets: { maxInstances: 0, maxDollarsPerHour: 0, ttlHours: 0 } });
  const target = bare(spec);
  const stripped = { ...spec, instances: spec.instances.filter((i) => i.role !== "attacker") };
  for (const a of ARCHETYPES) {
    const m = bare(materializeArchetype(a));
    if (m === target || m === bare(stripped)) return designPin(a);
  }
  return designPin(null);
}

import type { EnvironmentSpec, FirewallPolicy, Site, Zone } from "@musearena/shared";
import { labPlanFor } from "../provisioner/lab-network.js";
import { CATALOG_VERSION } from "./catalog.js";
import { PROFILE_VERSION, allProvisionablePackages, resolveProfile, type MachineProfile } from "./profiles.js";
import { domainUserFor, labProbesFor, probeFor } from "./readiness.js";
import { hostOrder, tasksFor } from "./ansible.js";
import { labDomainFor, ldapBaseFor, ipaBaseFor } from "./dns.js";
import { normalizeOrg, reachabilityFor, segmentsFor, nftablesFor, negativeProbeCommands, type NegativeProbe, type OrgSegment, type ReachEdge } from "../designer/org-topology.js";
import { zoneProbesFor } from "./readiness.js";
import { estimateCostPerHour } from "../designer/cost.js";
import { BAKED_CATALOG_VERSION } from "../provisioner/images.js";

/**
 * Deployment plan. The spec declares intent; this expands it into the
 * bill of materials, the wiring and the execution order that the configurator
 * will actually realize. It is pure and derived from the same resolvers the
 * executor uses (`resolveProfile`, `labPlanFor`, `probeFor`, `tasksFor`), so a
 * plan cannot describe a different machine than the one that boots.
 *
 * The designer never authors packages or config files: it names services from
 * the closed catalog. Anything it names that expands to nothing is a gap and
 * blocks provisioning.
 */

export interface PlanConfig { path: string; purpose: string }
export interface PlanSeed { target: string; purpose: string }
export interface PlanProbe { probe: string; kind: string; expect?: string }
export interface PlanHost {
  hostId: string;
  role: string;
  runtime: string;
  os: string;
  resources: { vcpu: number; memoryMb: number; diskGb: number };
  subnet?: string;
  address?: string;
  packages: string[];
  units: string[];
  clientTools: string[];
  dependsOn: string[];
  config: PlanConfig[];
  seeds: PlanSeed[];
  readiness: PlanProbe[];
  tasks: string[];
}
export interface PlanEdge {
  from: string;
  to: string;
  protocol: string;
  port: number;
  address?: string;
  purpose: string;
}
export interface PlanStep { hostId: string; phase: "install" | "configure" | "enable" | "seed" | "verify"; task: string }
/** Cross-host acceptance: proves the segment and a remote listener, not just self-reachability. */
export interface PlanLabProbe { from: string; to: string; probe: string; kind: string; expect?: string }
export interface DeploymentPlan {
  versions: { catalog: string; profile: string; image: string };
  topology: {
    cidr: string;
    domain: string;
    subnets: EnvironmentSpec["topology"]["subnets"];
    addresses: Record<string, string>;
    /** Org topology (v2). Absent for v1 flat labs. */
    sites?: Site[];
    zones?: Zone[];
    policies?: FirewallPolicy[];
    segments?: OrgSegment[];
    routerRules?: string;
    reachability?: { allowed: ReachEdge[]; denied: ReachEdge[] };
  };
  hosts: PlanHost[];
  edges: PlanEdge[];
  labProbes: PlanLabProbe[];
  /** Denied-path probes at execution shape (P1 runtime runs them). */
  negativeProbes?: NegativeProbe[];
  steps: PlanStep[];
  totals: { instances: number; vcpu: number; memoryMb: number; diskGb: number; dollarsPerHour: number };
  gaps: string[];
}

const CONFIG: Record<string, PlanConfig[]> = {
  db: [
    { path: "/etc/postgresql/*/main/pg_hba.conf", purpose: "app role over TCP (scram) plus local trust for seeding" },
    { path: "/etc/postgresql/*/main/postgresql.conf", purpose: "listen on the lab address; log_statement=all with client addresses" },
  ],
  dns: [{ path: "/etc/dnsmasq.d/arena.conf", purpose: "host records for every guest in the environment's derived domain, bound to the lab address" }],
  ldap: [
    { path: "slapd debconf", purpose: "the environment's derived domain and the admin secret" },
  ],
  smtp: [{ path: "/etc/postfix/main.cf", purpose: "mailname, inet_interfaces on the lab address, Maildir" }],
  imap: [{ path: "/etc/dovecot/conf.d/99-arena.conf", purpose: "maildir location and plaintext auth on the lab address" }],
  http: [
    { path: "/var/www/html/index.php", purpose: "intranet page naming the org's personas" },
    { path: "/var/www/html/diag.php", purpose: "planted command injection, only when code-flaw is planted" },
  ],
  log: [{ path: "/etc/rsyslog.d/50-arena.conf", purpose: "imtcp on 514 writing /var/log/arena/remote.log" }],
};

const SEEDS: Record<string, PlanSeed[]> = {
  db: [
    { target: "role app + database app", purpose: "application identity; weak password only when weak-cred is planted" },
    { target: "employees, secrets", purpose: "persona table and each objective's canary value" },
  ],
  imap: [{ target: "probe mailbox", purpose: "a mailbox the SMTP→IMAP roundtrip can read" }],
  http: [{ target: "/var/www/html", purpose: "intranet application files" }],
};

const phaseOf = (task: string): PlanStep["phase"] =>
  task.includes("install") ? "install"
  : task.includes("seed") ? "seed"
  : task.includes("enable") ? "enable"
  : task.startsWith("verify") || task.startsWith("wait_") ? "verify"
  : "configure";

function configFor(profile: MachineProfile, spec: EnvironmentSpec, hostId: string, domain: string, collector?: string): PlanConfig[] {
  const out: PlanConfig[] = [];
  for (const entry of profile.catalogEntries) {
    // FreeIPA is not slapd-with-a-base-DN: the installer owns the realm file
    // and every daemon it starts.
    if (entry.kind === "ldap" && entry.impl === "freeipa") {
      out.push({ path: "/etc/ipa/default.conf", purpose: "FreeIPA realm, domain and XML-RPC endpoint" });
      out.push({ path: "/var/log/arena/ipa-install.log", purpose: "installer output kept for diagnosis (no secrets)" });
      continue;
    }
    out.push(...(CONFIG[entry.kind] ?? []));
    if (entry.kind === "ldap") out.push({ path: ldapBaseFor(domain), purpose: "seed ou=people and the probe user" });
  }
  const inst = spec.instances.find((i) => i.hostId === hostId);
  const vm = inst?.runtime === "vm";
  if (vm && collector && collector !== hostId) {
    out.push({ path: "/etc/rsyslog.d/40-arena-forward.conf", purpose: `queue and forward to ${collector} on 514` });
  }
  return out;
}

function seedsFor(profile: MachineProfile, domain: string): PlanSeed[] {
  return profile.catalogEntries.flatMap((e) =>
    e.kind === "ldap"
      ? e.impl === "freeipa"
        ? [{ target: `cn=users,cn=accounts,${ipaBaseFor(domain)}`, purpose: "personas as directory users and role groups" }]
        : [{ target: `ou=people,${ldapBaseFor(domain)}`, purpose: "directory entries for the probe user" }]
      : (SEEDS[e.kind] ?? []));
}

/** Expand one spec into what will be installed, configured, wired and run. */
export function planDeployment(spec: EnvironmentSpec, opts: { runId?: string } = {}): DeploymentPlan {
  const runId = opts.runId ?? "plan";
  const domain = labDomainFor(spec);
  const gaps: string[] = [];
  const isOrgV2 = (spec.topology.sites?.length ?? 0) > 0 || (spec.topology.zones?.length ?? 0) > 0;
  let orgModel: ReturnType<typeof normalizeOrg> | undefined;
  let orgReach: ReturnType<typeof reachabilityFor> | undefined;
  let orgSegments: OrgSegment[] = [];
  let orgRules = "";
  let orgNegatives: NegativeProbe[] = [];
  if (isOrgV2) {
    try {
      orgModel = normalizeOrg(spec);
      orgReach = reachabilityFor(spec, orgModel);
      orgSegments = segmentsFor(spec, runId, orgModel);
      orgRules = nftablesFor(spec, orgModel);
      orgNegatives = negativeProbeCommands(spec, orgModel);
    } catch (err) {
      gaps.push(`org topology cannot be derived: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  let labEntries: ReturnType<typeof labPlanFor> = [];
  if (isOrgV2) {
    // Org addresses come from normalizeOrg; the flat lab plan does not apply.
  } else if (spec.topology.subnets.length === 0) {
    gaps.push("topology declares no subnet");
  } else {
    try {
      labEntries = labPlanFor(spec, runId);
    } catch (err) {
      gaps.push(`topology cannot be planned: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  const lab = new Map(labEntries.map((e) => [e.hostId, e]));
  const collector = spec.instances.find((i) => (i.serviceDecls ?? []).some((d) => d.kind === "log"))?.hostId;

  // Cross-host acceptance uses the same planner as readiness, so the plan
  // cannot promise a proof the gate will not run. Commands are deliberately
  // dropped: they carry per-run secrets (the LDAP admin password).
  let labProbes: PlanLabProbe[] = [];
  // v1 flat-lab probes assume the single labPlanFor segment. Org topologies
  // get their allowed/denied zone edges from the reachability graph instead.
  if (!isOrgV2 && labEntries.length > 0) {
    try {
      labProbes = labProbesFor(spec, runId).map(({ from, to, probe, kind, expect }) => ({ from, to, probe, kind, ...(expect ? { expect } : {}) }));
    } catch (err) {
      gaps.push(`cross-host probes cannot be planned: ${err instanceof Error ? err.message : String(err)}`);
    }
  } else if (isOrgV2) {
    try {
      labProbes = zoneProbesFor(spec).map(({ from, to, probe, kind }) => ({ from, to, probe, kind }));
    } catch (err) {
      gaps.push(`cross-host probes cannot be planned: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  const hosts: PlanHost[] = [];
  for (const inst of spec.instances) {
    let profile: MachineProfile;
    try {
      profile = resolveProfile(spec, inst.hostId);
    } catch (err) {
      gaps.push(`${inst.hostId}: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }
    const decls = inst.serviceDecls ?? [];
    const probes: PlanProbe[] = [];
    if (!decls.some((d) => d.kind === "ssh")) probes.push({ probe: "ssh-login", kind: "ssh/openssh", expect: "arena" });
    const domainUser = domainUserFor(spec, inst.hostId, runId);
    for (const decl of decls) {
      const check = probeFor(decl, { hostId: inst.hostId, runId, sshUser: "arena", services: decls, domain, ...(domainUser ? { domainUser } : {}) });
      probes.push({ probe: check.probe, kind: check.kind, ...(check.expect ? { expect: check.expect } : {}) });
    }
    hosts.push({
      hostId: inst.hostId,
      role: inst.role,
      runtime: inst.runtime,
      os: inst.os,
      resources: inst.resources ?? { vcpu: 1, memoryMb: 1024, diskGb: 6 },
      ...(inst.subnet ? { subnet: inst.subnet } : {}),
      ...(orgModel?.byHost.get(inst.hostId)
        ? { address: `${orgModel.byHost.get(inst.hostId)!.address}/${orgModel.byHost.get(inst.hostId)!.prefix}` }
        : lab.get(inst.hostId)
          ? { address: `${lab.get(inst.hostId)!.address}/${lab.get(inst.hostId)!.prefix}` }
          : {}),
      packages: profile.packages,
      units: profile.unitsToEnable,
      clientTools: profile.clientTools,
      dependsOn: [...(inst.dependsOn ?? [])],
      config: configFor(profile, spec, inst.hostId, domain, collector),
      seeds: seedsFor(profile, domain),
      readiness: probes,
      tasks: tasksFor(spec, runId, inst.hostId).map((t) => t.name),
    });
  }

  // Declared dependencies are the service interactions the design promises;
  // log shipping is implicit on every guest and is listed explicitly.
  const byHost = new Map(spec.instances.map((i) => [i.hostId, i]));
  const addrOf = (hostId: string): string | undefined =>
    orgModel?.byHost.get(hostId)?.address ?? lab.get(hostId)?.address;
  const edges: PlanEdge[] = [];
  for (const inst of spec.instances) {
    for (const dep of inst.dependsOn ?? []) {
      const depInst = byHost.get(dep);
      for (const d of depInst?.serviceDecls ?? []) {
        edges.push({
          from: inst.hostId, to: dep, protocol: d.kind, port: d.port,
          ...(addrOf(dep) ? { address: addrOf(dep)! } : {}),
          purpose: `${inst.hostId} consumes ${d.kind} from ${dep}`,
        });
      }
    }
    if (collector && inst.runtime === "vm" && inst.hostId !== collector) {
      edges.push({
        from: inst.hostId, to: collector, protocol: "syslog", port: 514,
        ...(addrOf(collector) ? { address: addrOf(collector)! } : {}),
        purpose: "queued log forwarding to the collector",
      });
    }
  }

  // Steps follow the executor's dependency order, not the order the designer
  // happened to emit instances in; `hosts` stays in spec order for display.
  const planned = new Map(hosts.map((h) => [h.hostId, h]));
  const steps: PlanStep[] = hostOrder(spec).flatMap((hostId) => {
    const h = planned.get(hostId);
    return (h?.tasks ?? []).map((task) => ({ hostId, phase: phaseOf(task), task }));
  });
  const totals = {
    instances: spec.instances.length,
    vcpu: spec.instances.reduce((n, i) => n + (i.resources?.vcpu ?? 1), 0),
    memoryMb: spec.instances.reduce((n, i) => n + (i.resources?.memoryMb ?? 1024), 0),
    diskGb: spec.instances.reduce((n, i) => n + (i.resources?.diskGb ?? 6), 0),
    dollarsPerHour: estimateCostPerHour(spec),
  };
  // An unknown package can only come from a catalog/profile drift; fail the
  // plan rather than promise an install the image cannot satisfy.
  const known = new Set(allProvisionablePackages());
  for (const h of hosts) {
    for (const p of h.packages) if (!known.has(p)) gaps.push(`${h.hostId}: package ${p} is not in the baked image set`);
  }

  return {
    versions: { catalog: CATALOG_VERSION, profile: PROFILE_VERSION, image: BAKED_CATALOG_VERSION },
    topology: {
      cidr: spec.topology.cidr,
      domain,
      subnets: orgModel
        ? orgModel.subnets.map((s) => ({ name: s.name, cidr: s.cidr, zone: s.zone, site: s.site }))
        : spec.topology.subnets,
      addresses: orgModel
        ? Object.fromEntries(orgModel.endpoints.map((e) => [e.hostId, `${e.address}/${e.prefix}`]))
        : Object.fromEntries([...lab.values()].map((e) => [e.hostId, `${e.address}/${e.prefix}`])),
      ...(orgModel ? {
        sites: orgModel.sites,
        zones: orgModel.zones,
        policies: orgModel.policies,
        segments: orgSegments,
        routerRules: orgRules,
        ...(orgReach ? { reachability: orgReach } : {}),
      } : {}),
    },
    hosts, edges, labProbes, steps, totals, gaps,
    ...(isOrgV2 ? { negativeProbes: orgNegatives } : {}),
  };
}

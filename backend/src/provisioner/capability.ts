import type { EnvironmentSpec } from "@musearena/shared";
import { PLANTABLE, roleImage } from "./roles.js";
import { isLinuxOs, isWindowsOs, windowsImagePath, MIN_VM_DISK_GB, guestOsFamily } from "./images.js";
import { catalogEntry, CATALOG_VERSION, SERVICE_CATALOG } from "../configurator/catalog.js";
import { hostCapabilities, type HostCapabilities } from "./host-capabilities.js";

/**
 * Runtime capability contract between the designer and the provisioner.
 * The designer may phrase roles freely; they are normalized to the canonical
 * set the runtime understands. A design is only provisionable when every
 * instance, vuln and gate it needs can actually be realized and verified —
 * otherwise provisioning is blocked with the reason (Req §1.5, §3.3).
 */
export const CANONICAL_ROLES = ["web", "db", "dc", "workstation", "sensor", "attacker"] as const;

const SYNONYMS: [RegExp, string][] = [
  [/^(web|www|webserver|web-server|web_server|app|app-server|application|frontend|php)/i, "web"],
  [/^(db|database|postgres|postgresql|mysql|mariadb|sql)/i, "db"],
  [/^(dc|domain-controller|domain_controller|ad|active-directory|ldap)/i, "dc"],
  [/^(workstation|desktop|endpoint|client|ws|laptop)/i, "workstation"],
  [/^(sensor|zeek|ids|suricata|tap)/i, "sensor"],
];

export function normalizeRole(role: string): string {
  const r = role.trim();
  for (const [re, canon] of SYNONYMS) if (re.test(r)) return canon;
  return r.toLowerCase();
}

export function normalizeSpec(spec: EnvironmentSpec): EnvironmentSpec {
  return { ...spec, instances: spec.instances.map((i) => ({ ...i, role: normalizeRole(i.role) })) };
}

/**
 * Reasons this spec cannot be provisioned AND verified on the local runtime;
 * empty = deployable. Host-dependent reasons are passed in so the designer
 * gates against the worker it will actually run on, not a static catalog.
 */
export function deployability(spec: EnvironmentSpec, opts: { caps?: HostCapabilities } = {}): string[] {
  const caps = opts.caps ?? hostCapabilities();
  const reasons: string[] = [];
  if (spec.provider !== "kvm") {
    reasons.push(`provider "${spec.provider}" is not the local kvm runtime — cloud providers are not silently realized as local labs; choose provider "kvm"`);
  }
  const runtimes = new Set(spec.instances.map((i) => i.runtime));
  if (runtimes.size > 1) {
    reasons.push(`mixed runtime lab declares ${[...runtimes].join(" and ")} instances; choose one runtime — no mixed container/VM exercise driver exists`);
  }
  if (spec.instances.some((i) => i.runtime === "vm") && !caps.vmRuns) {
    reasons.push(`VM guests cannot boot on this worker (acceleration ${caps.accel}) — design a container lab`);
  }
  if (spec.instances.some((i) => i.runtime === "container") && !caps.container) {
    reasons.push("container labs need docker, which this worker does not have");
  }
  if (spec.truthLayer === "kvm-vmi" && caps.accel !== "kvm") {
    reasons.push(`truthLayer kvm-vmi needs a KVM host; this worker offers ${caps.accel}`);
  }
  if (spec.instances.length > caps.maxVmInstances) {
    reasons.push(`instances ${spec.instances.length} > this worker's lab limit ${caps.maxVmInstances}`);
  }
  // One flat segment is what the container runtime builds (one Docker network).
  // A multi-subnet design on the container path is not approximated: it is
  // refused until routing and firewall enforcement exist there.
  if (!spec.instances.some((i) => i.runtime === "vm") && spec.topology.subnets.length > 1) {
    reasons.push(`topology declares ${spec.topology.subnets.length} subnets; the container runtime realizes one flat network — declare exactly one subnet`);
  }
  // Org topology (P1b): single-site, VM-only, one router. Multi-site needs WAN
  // links realized between sites (P5); a site without a router has no
  // enforcement point, so its segmentation would be a promise without a gate.
  const sites = spec.topology.sites ?? [];
  const zones = spec.topology.zones ?? [];
  if (sites.length > 0 || zones.length > 0) {
    if (sites.length > 1) {
      reasons.push(`org topology declares ${sites.length} sites; the P1 runtime realizes one site — WAN links between sites are not enforced yet`);
    }
    if (spec.instances.some((i) => i.runtime !== "vm")) {
      reasons.push("org topology (sites/zones) needs the VM multi-segment runtime; container instances cannot join zone segments");
    }
    const siteId = sites[0]?.id;
    const siteZones = zones.filter((z) => !siteId || z.site === siteId);
    if (siteZones.length > 1) {
      const routers = spec.instances.filter((i) =>
        i.site === siteId || (!i.site && sites.length === 1)
          ? i.role === "router" || (i.serviceDecls ?? []).some((d) => d.kind === "router")
          : false);
      if (routers.length === 0) {
        reasons.push(`site "${siteId ?? "default"}" declares ${siteZones.length} zones but no router — one router per multi-zone site enforces the policy`);
      }
    }
  }
  const byHost = new Map(spec.instances.map((i) => [i.hostId, i]));
  const subnetNames = new Set(spec.topology.subnets.map((s) => s.name));
  // Installed by the base profile on every VM guest; a display name may name
  // them without a serviceDecl because nothing more needs to be declared.
  const BASE_PROFILE_KINDS = new Set(["ssh", "auditd", "osquery", "rsyslog", "chrony"]);
  for (const i of spec.instances) {
    // Structured services are checked on every runtime: an unknown kind/impl
    // is unprovisionable everywhere, never approximated.
    const seenKinds = new Set<string>();
    for (const d of i.serviceDecls ?? []) {
      if (!catalogEntry(d)) reasons.push(`${i.hostId}: service ${d.kind}/${d.impl} is not in the runtime catalog (${CATALOG_VERSION})`);
      // DHCP is a VM lab service: dnsmasq leases from the top of the lab
      // subnet and readiness leases one from a peer guest. Containers have
      // no lab NIC or profile tasks, so there it would configure nothing.
      if (d.kind === "dhcp" && i.runtime !== "vm") reasons.push(`${i.hostId}: service dhcp/${d.impl} needs the VM runtime (lab segment leases)`);
      if (d.kind === "dhcp" && i.runtime === "vm" && spec.topology.subnets.length === 0) reasons.push(`${i.hostId}: service dhcp/${d.impl} needs a lab subnet in the topology to lease from`);
      if (seenKinds.has(d.kind)) reasons.push(`${i.hostId}: duplicate ${d.kind} service declared`);
      seenKinds.add(d.kind);
    }
    // `services` is display-only. On a VM guest it must mirror what will
    // actually be installed, or the design promises software that never
    // arrives (the host would pass readiness on ssh alone).
    if (i.runtime === "vm") {
      const declared = new Set<string>((i.serviceDecls ?? []).map((d) => d.kind));
      for (const s of i.services) {
        if (!declared.has(s) && !BASE_PROFILE_KINDS.has(s)) {
          reasons.push(`${i.hostId}: service "${s}" is a display name with no serviceDecl — nothing would install it`);
        }
      }
    }
    if (i.runtime === "vm" && i.resources && i.resources.diskGb < MIN_VM_DISK_GB) {
      reasons.push(`${i.hostId}: disk ${i.resources.diskGb}G is smaller than the catalog image (${MIN_VM_DISK_GB}G) — the guest cannot boot`);
    }
    if (i.subnet && !subnetNames.has(i.subnet)) reasons.push(`${i.hostId}: subnet "${i.subnet}" is not declared in the topology`);
    for (const dep of i.dependsOn ?? []) if (!byHost.has(dep)) reasons.push(`${i.hostId}: depends on unknown host ${dep}`);
    if (i.runtime === "container") {
      if (!roleImage(i.role).telemetry) reasons.push(`${i.hostId}: role "${i.role}" has no telemetry source on the container runtime (canary cannot pass)`);
    } else if (isWindowsOs(i.os) && !windowsImagePath()) {
      reasons.push(`${i.hostId}: Windows VM needs a licensed image (KVM_WINDOWS_IMAGE) — none configured`);
    } else if (!isLinuxOs(i.os) && !isWindowsOs(i.os)) {
      reasons.push(`${i.hostId}: no guest image for OS "${i.os}"`);
    }
  }
  // FreeIPA is a real server stack (389-ds + KDC + Dogtag + integrated DNS),
  // not a 1 GB guest. Its installer also owns port 53, so it cannot share a
  // host with the gateway's dnsmasq. One realm per environment until replicas
  // are modelled.
  const ipaHosts = spec.instances.filter((i) => (i.serviceDecls ?? []).some((d) => d.kind === "ldap" && d.impl === "freeipa"));
  if (ipaHosts.length > 1) {
    reasons.push(`FreeIPA declares ${ipaHosts.length} servers; one realm per environment is modelled (replicas are not)`);
  }
  for (const i of ipaHosts) {
    if (i.runtime !== "vm") reasons.push(`${i.hostId}: FreeIPA needs the VM runtime`);
    // The FreeIPA server installer exists only on Rocky 9; Debian/Ubuntu
    // ship the client stack, not the server packages. A Debian server would
    // fail apt at configure time, so it is refused here instead.
    if (!/^Rocky Linux 9(?:[-\s.]|$)/i.test(i.os)) {
      reasons.push(`${i.hostId}: FreeIPA server needs Rocky Linux 9 (ipa-server); ${i.os} is not a supported FreeIPA server image`);
    }
    if (normalizeRole(i.role) !== "dc") {
      reasons.push(`${i.hostId}: FreeIPA server needs role "dc"; got role "${i.role}"`);
    }
    const r = i.resources;
    if (!r || r.vcpu < 2) reasons.push(`${i.hostId}: FreeIPA needs at least 2 vCPU`);
    if (!r || r.memoryMb < 2048) reasons.push(`${i.hostId}: FreeIPA needs at least 2048 MB (389-ds + KDC + Dogtag)`);
    if (!r || r.diskGb < 12) reasons.push(`${i.hostId}: FreeIPA needs at least 12 GB disk`);
    if ((i.serviceDecls ?? []).some((d) => d.kind === "dns" || d.kind === "dhcp")) {
      reasons.push(`${i.hostId}: FreeIPA's integrated DNS owns port 53 — do not co-locate dns/dhcp on the directory host`);
    }
  }
  // Gitea authenticates through an LDAP auth source bound to the realm; a
  // design that does not declare that membership would fall back to a local
  // account, which is not the claim.
  for (const i of spec.instances) {
    if (!(i.serviceDecls ?? []).some((d) => d.kind === "git")) continue;
    const joined = (i.dependsOn ?? []).some((dep) =>
      (byHost.get(dep)?.serviceDecls ?? []).some((d) => d.kind === "ldap" && d.impl === "freeipa"));
    if (!joined) reasons.push(`${i.hostId}: git/gitea needs a declared dependsOn on the FreeIPA server (directory login)`);
    if (i.runtime !== "vm") reasons.push(`${i.hostId}: git/gitea needs the VM runtime`);
  }
  for (const v of spec.plantedVulns) {
    const inst = byHost.get(v.targetHostId);
    if (!inst) continue; // reported by design validation
    if (inst.runtime === "container" && !(PLANTABLE[inst.role] ?? []).includes(v.type)) {
      reasons.push(`vuln ${v.id}: type "${v.type}" cannot be planted+proven on role "${inst.role}" (plantable: ${JSON.stringify(PLANTABLE)})`);
    }
    if (inst.runtime === "vm") {
      const declares = (kind: string) => (inst.serviceDecls ?? []).some((d) => d.kind === kind);
      if (v.type === "code-flaw" && !(inst.role === "web" && declares("http"))) {
        reasons.push(`vuln ${v.id}: type "code-flaw" is not provable on role "${inst.role}" in the VM runtime — needs a role "web" host declaring http`);
      } else if (v.type === "weak-cred" && !(inst.role === "db" && declares("db"))) {
        reasons.push(`vuln ${v.id}: type "weak-cred" is not provable on role "${inst.role}" in the VM runtime — needs a role "db" host declaring db service`);
      } else if (v.type !== "code-flaw" && v.type !== "weak-cred") {
        reasons.push(`vuln ${v.id}: type "${v.type}" is not provable on role "${inst.role}" in the VM runtime (web+http→code-flaw, db+db→weak-cred)`);
      }
    }
  }
  for (const o of spec.objectives) {
    const inst = byHost.get(o.asset);
    if (inst?.runtime !== "vm") continue;
    const declares = (kind: string) => (inst.serviceDecls ?? []).some((d) => d.kind === kind);
    if (o.techniqueId === "T1110") continue; // sshd runs on every guest.
    if (o.techniqueId === "T1059") {
      if (!(inst.role === "web" && declares("http"))) {
        reasons.push(`objective ${o.id}: T1059 needs a role "web" asset declaring http on the vm runtime; asset ${inst.hostId} has role "${inst.role}"`);
      }
    } else if (o.techniqueId === "T1078") {
      if (!(inst.role === "db" && declares("db"))) {
        reasons.push(`objective ${o.id}: T1078 needs a role "db" asset declaring db on the vm runtime; asset ${inst.hostId} has role "${inst.role}"`);
      }
    } else {
      reasons.push(`objective ${o.id}: no live technique ${o.techniqueId} for asset role "${inst.role}" on the vm runtime`);
    }
  }
  // Operator-pinned platform: the spec must be the lab that was approved,
  // not a different runtime that happens to pass its own runtime's gates.
  if (spec.platform) {
    for (const i of spec.instances) {
      if (i.runtime !== spec.platform.runtimeTarget) {
        reasons.push(`${i.hostId}: selected ${spec.platform.runtimeTarget} platform requires runtime "${spec.platform.runtimeTarget}", got "${i.runtime}"`);
      }
    }
    if (spec.platform.exerciseEngine === "agents" && spec.platform.runtimeTarget === "vm"
      && !spec.instances.some((i) => i.role === "attacker" && i.runtime === "vm")) {
      reasons.push("platform: model agents on the VM platform need an attacker guest in the spec (role \"attacker\", VM runtime)");
    }
  }
  return reasons;
}

/**
 * Base-profile telemetry names (mirrors BASE_TELEMETRY in designer/coherence;
 * duplicated here to keep the provisioner free of designer imports — the
 * drift is pinned by test). SERVICE_CATALOG telemetry is read live below.
 */
const BASE_TELEMETRY_NAMES = ["auditd", "audit.log", "osquery", "rsyslog", "syslog", "chrony", "auth.log"];

/** Human/model-readable catalog of what the runtime can build today. */
export function capabilityCatalog(worker?: string): string {
  const serviceTelemetry = [...new Set(SERVICE_CATALOG.flatMap((c) => c.telemetry))].sort();
  return [
    ...(worker ? [worker, ""] : []),
    "Deployable today (local container runtime, verified by live gates):",
    `- roles with telemetry: web (php:8.2-apache), db (postgres:16-alpine)`,
    `- plantable vulns: web → code-flaw (command injection, T1059); db → weak-cred (valid accounts, T1078)`,
    "- runtime must be \"container\" for these; workstation/other roles have no telemetry yet and block provisioning: for a deployable design, put personas on the web or db hosts (their workstation = that hostId) instead of adding workstation instances. The platform adds its own attacker container; do not emit an attacker instance here.",
    "",
    `Linux VM org labs (${CATALOG_VERSION}, scripted):`,
    "- deployable on the baked Debian image except the FreeIPA server below (VM disks must be at least 6 GB; smaller overlays cannot boot); every deployable catalog service is configured and probe-gated: dns+dhcp (dnsmasq), ldap (openldap, freeipa), smtp (postfix), imap (dovecot), http (apache-php), db (postgres), git (gitea, directory login — its host must dependsOn the FreeIPA server), ssh (openssh), log (rsyslog-collector), router (nftables, org-topology only)",
    "- FreeIPA server hard constraints: role \"dc\", os \"Rocky Linux 9\" (never Debian/Ubuntu — they provide only the client), VM runtime, at least 2 vCPU / 2048 MB / 12 GB, exactly one server per environment, and no dns or dhcp service declaration on that host because integrated DNS owns port 53. Its directory domain is declared through topology.domain or a dns service elsewhere, never invented per host.",
    "- VM exercise placement is role-exact: code-flaw planted vulns and T1059 objectives only on a role \"web\" host declaring http; weak-cred planted vulns and T1078 objectives only on a role \"db\" host declaring db; mail, dc, gateway, workstation, sensor, git, and router assets may carry only T1110 detection objectives. Never plant a vuln or objective on mail unless it is T1110.",
    "- dhcp (dnsmasq) is deployable on a VM gateway: it leases from the top of the lab subnet (static guest addresses are never leased) and readiness proves a real lease from a peer guest. Declare it alongside dns on the gateway host; it needs the VM runtime and a topology subnet.",
    "- org topology (single site): one zone segment per zone, a router VM with one NIC per segment, nftables compiled from the structured policies, and allowed/denied cross-zone probes in readiness. Multi-site (WAN links between sites) is refused — one site per environment until P5",
    "- `services` display names must mirror `serviceDecls`; a name with no declaration is rejected (nothing would install it). Base-profile names (ssh, auditd, osquery, rsyslog, chrony) are exempt",
    `- requiredTelemetry vocabulary (exact names only): base profile ${BASE_TELEMETRY_NAMES.join(", ")}; declared services add ${serviceTelemetry.join(", ")}. A name outside this list is rejected.`,
    "- scripted red/blue supports web command injection (T1059), db weak credentials (T1078), and failed SSH authentication (T1110) on any guest (sshd is in the base profile); model-driven agents need an attacker guest IN the spec (role \"attacker\", VM runtime) — a VM design without one cannot run a model exercise",
    "- canonical org roles: gateway (dns), dc→directory (ldap), mail (smtp/imap), web, db, workstation, sensor (log collector), attacker (red toolbox), router (nftables). Canonical role names in designs: web, db, dc, workstation, sensor, attacker, router — plus gateway and mail for VM hosts whose declared services are dns resp. smtp+imap.",
  ].join("\n");
}

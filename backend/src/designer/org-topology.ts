import { createHash } from "node:crypto";
import type { EnvironmentSpec, FirewallPolicy, Site, WanLink, Zone } from "@musearena/shared";
import { labDomainFor } from "../configurator/dns.js";

/**
 * Org topology (P0): sites, zones, subnets, placement and reachability.
 *
 * Everything here is pure and derived. The designer names sites, zones and
 * hosts; this module owns the arithmetic (addresses, FQDNs), the policy
 * evaluation and the positive/negative reachability edges the plan and the
 * probes consume. A v1 spec (one flat subnet, no sites) normalizes to a
 * single default site and is unchanged.
 */

export const MAX_SITES = 15;
export const MAX_ZONES_PER_SITE = 16;
export const MAX_HOSTS_PER_SUBNET = 253;
/** Third octets at or above this are reserved for WAN/mgmt, not zones. */
const WAN_THIRD_OCTET = 240;

export interface OrgSubnet {
  name: string;
  site: string;
  zone: string;
  cidr: string;
  prefix: number;
}

export interface OrgEndpoint {
  hostId: string;
  fqdn: string;
  site: string;
  zone: string;
  subnet: string;
  cidr: string;
  address: string;
  prefix: number;
  /** The host that owns the subnet's .1 (router/resolver). */
  router: boolean;
}

export interface OrgModel {
  sites: Site[];
  zones: Zone[];
  subnets: OrgSubnet[];
  policies: FirewallPolicy[];
  links: WanLink[];
  endpoints: OrgEndpoint[];
  byHost: Map<string, OrgEndpoint>;
}

export interface ReachEdge {
  from: string;
  to: string;
  fromZone: string;
  toZone: string;
  proto: string;
  port: number;
  reason: string;
}

export interface Reachability {
  allowed: ReachEdge[];
  denied: ReachEdge[];
}

export interface OrgSegment {
  name: string;
  site: string;
  zone: string;
  cidr: string;
  /** Loopback port of this segment's hub (P1 runtime). */
  hubPort: number;
}

export interface RouterInterface {
  segment: string;
  cidr: string;
  address: string;
  prefix: number;
}

export interface RouterAttachment {
  hostId: string;
  site: string;
  interfaces: RouterInterface[];
}

export interface NegativeProbe {
  from: string;
  to: string;
  port: number;
  command: string;
}

const ipToInt = (ip: string): number =>
  ip.split(".").reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;

const intToIp = (n: number): string =>
  [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");

function parseCidr(cidr: string): { network: number; prefix: number } {
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(cidr.trim());
  if (!m) throw new Error(`org topology: ${cidr} is not a CIDR`);
  const prefix = Number(m[2]);
  if (prefix < 8 || prefix > 30) throw new Error(`org topology: /${prefix} is not a usable subnet`);
  const network = ipToInt(m[1]) & ((0xffffffff << (32 - prefix)) >>> 0);
  return { network, prefix };
}

/** The deployment's /16 second octet; 42 is a stable planning default. */
export function envOctetOf(cidr: string, fallback = 42): number {
  const m = /^10\.(\d+)\./.exec(cidr.trim());
  return m ? Number(m[1]) : fallback;
}

function inferZoneKind(id: string): Zone["kind"] {
  const z = id.toLowerCase();
  if (/edge|wan|internet/.test(z)) return "edge";
  if (/dmz|public|ext/.test(z)) return "dmz";
  if (/server|private|internal|app|data/.test(z)) return "server";
  if (/ot|ics|scada/.test(z)) return "ot";
  if (/mgmt|admin|ops/.test(z)) return "mgmt";
  return "corp";
}

function zoneKey(site: string, zone: string): string {
  return `${site}/${zone}`;
}

/**
 * Normalize any spec to a total org model. Declared sites/zones/subnets win;
 * missing subnets are derived; a v1 spec gets one default site and one zone
 * per declared subnet.
 */
export function normalizeOrg(spec: EnvironmentSpec, opts: { octet?: number } = {}): OrgModel {
  const octet = opts.octet ?? envOctetOf(spec.topology.cidr);
  const declaredSites = spec.topology.sites ?? [];
  const sites: Site[] = declaredSites.length
    ? [...declaredSites]
    : [{ id: "default", name: "Default", kind: "hq" }];
  const defaultSite = sites[0].id;

  let zones: Zone[] = [...(spec.topology.zones ?? [])];
  if (!zones.length) {
    const ids = [...new Set(spec.topology.subnets.map((s) => s.zone || "default"))];
    zones = (ids.length ? ids : ["default"]).map((id) => ({
      id, site: defaultSite, kind: inferZoneKind(id),
    }));
  }
  // A declared site with no zone is still total: it gets a corp zone. The
  // validator reports the design error; the model must not throw while the
  // plan is being reviewed.
  for (const site of sites) {
    if (!zones.some((z) => z.site === site.id)) zones.push({ id: "corp", site: site.id, kind: "corp" });
  }

  const subnets: OrgSubnet[] = [];
  for (const s of spec.topology.subnets) {
    const { prefix } = parseCidr(s.cidr);
    subnets.push({ name: s.name, site: s.site ?? defaultSite, zone: s.zone || "default", cidr: s.cidr, prefix });
  }
  for (const zone of zones) {
    if (subnets.some((s) => s.site === zone.site && s.zone === zone.id)) continue;
    const siteIdx = sites.findIndex((s) => s.id === zone.site);
    const zoneIdx = zones.filter((z) => z.site === zone.site).findIndex((z) => z.id === zone.id);
    const third = ((Math.max(siteIdx, 0) << 4) | Math.max(zoneIdx, 0));
    const cidr = `10.${octet}.${third}.0/24`;
    subnets.push({ name: `${zone.site}-${zone.id}`, site: zone.site, zone: zone.id, cidr, prefix: 24 });
  }

  const byHost = new Map<string, OrgEndpoint>();
  const used = new Map<string, Set<number>>();
  const sorted = [...spec.instances].sort((a, b) => a.hostId.localeCompare(b.hostId));
  for (const inst of sorted) {
    const subnet = subnetFor(inst, subnets, zones, spec, defaultSite);
    const { network, prefix } = parseCidr(subnet.cidr);
    const taken = used.get(subnet.name) ?? new Set<number>();
    used.set(subnet.name, taken);
    // v2: the router owns .1 and may be multi-homed across its site's zones.
    // v1: the gateway/DNS host owns .1 (the router kind did not exist).
    const isV2 = (spec.topology.sites?.length ?? 0) > 0;
    const router = isV2
      ? inst.role === "router" || (inst.serviceDecls ?? []).some((d) => d.kind === "router")
      : inst.role === "gateway" || inst.role === "router" ||
        (inst.serviceDecls ?? []).some((d) => d.kind === "dns");
    let host: number;
    if (router && !taken.has(1)) host = 1;
    else {
      host = 10;
      while (taken.has(host)) host++;
    }
    taken.add(host);
    const defaultOnly = sites.length === 1 && sites[0].id === "default";
    byHost.set(inst.hostId, {
      hostId: inst.hostId,
      fqdn: defaultOnly ? `${inst.hostId}.${labDomainFor(spec)}` : `${inst.hostId}.${subnet.site}.${labDomainFor(spec)}`,
      site: subnet.site,
      zone: subnet.zone,
      subnet: subnet.name,
      cidr: subnet.cidr,
      address: intToIp(network + host),
      prefix,
      router,
    });
  }

  return {
    sites, zones, subnets,
    policies: [...(spec.topology.policies ?? [])],
    links: [...(spec.topology.links ?? [])],
    endpoints: [...byHost.values()],
    byHost,
  };
}

function subnetFor(
  inst: EnvironmentSpec["instances"][number],
  subnets: OrgSubnet[],
  zones: Zone[],
  spec: EnvironmentSpec,
  defaultSite: string,
): OrgSubnet {
  if (inst.subnet) {
    const named = subnets.find((s) => s.name === inst.subnet);
    if (named) return named;
  }
  if (inst.site || inst.zone) {
    const site = inst.site ?? defaultSite;
    const named = subnets.find((s) => s.site === site && s.zone === (inst.zone ?? zones.find((z) => z.site === site)?.id));
    if (named) return named;
  }
  if (subnets.length === 1) return subnets[0];
  // Unplaced in a multi-zone topology: the validator rejects it. Pick the
  // first zone of the declared site (or the first subnet) so planning remains
  // total and the refusal names the host.
  const site = inst.site ?? defaultSite;
  return subnets.find((s) => s.site === site) ?? subnets[0];
}

function refMatches(ref: string, site: string, zone: string): boolean {
  if (ref === "any") return true;
  const [s, z] = ref.split("/");
  return Boolean(s && z) && (s === "*" || s === site) && (z === "*" || z === zone);
}

function refValid(ref: string, sites: Site[], zones: Zone[]): boolean {
  if (ref === "any") return true;
  const [s, z] = ref.split("/");
  if (!s || !z) return false;
  if (s !== "*" && !sites.some((x) => x.id === s)) return false;
  if (z !== "*" && s !== "*" && !zones.some((x) => x.id === z && x.site === s)) return false;
  if (z !== "*" && s === "*" && !zones.some((x) => x.id === z)) return false;
  return true;
}

export function orgZoneRef(ep: { site: string; zone: string }): string {
  return zoneKey(ep.site, ep.zone);
}

function decision(
  model: OrgModel,
  from: OrgEndpoint,
  to: OrgEndpoint,
  proto: string,
  port: number,
): { allow: boolean; reason: string } {
  const sameZone = from.site === to.site && from.zone === to.zone;
  if (sameZone) return { allow: true, reason: "same zone (L2)" };
  const rules = model.policies.filter((p) =>
    refMatches(p.from, from.site, from.zone) && refMatches(p.to, to.site, to.zone) &&
    p.proto === proto && (p.port === undefined || p.port === port));
  const deny = rules.find((p) => p.action === "deny");
  if (deny) return { allow: false, reason: `denied by ${deny.reason}` };
  const allow = rules.find((p) => p.action === "allow");
  if (allow) return { allow: true, reason: `allowed by ${allow.reason}` };
  if (from.site !== to.site) {
    const link = model.links.find((l) =>
      (l.from === from.site && l.to === to.site) || (l.to === from.site && l.from === to.site));
    if (link?.allowed.some((a) => a.port === port && (a.proto === proto || a.proto === "tcp"))) {
      return { allow: true, reason: "allowed by WAN link" };
    }
  }
  return { allow: false, reason: "default deny" };
}

/**
 * Allowed and denied cross-zone edges, one representative per zone pair and
 * service port. The plan renders them; P1's probes execute them.
 */
export function reachabilityFor(spec: EnvironmentSpec, model = normalizeOrg(spec)): Reachability {
  const endpoints = model.endpoints;
  const zones = [...new Set(endpoints.map((e) => orgZoneRef(e)))].sort();
  const allowed: ReachEdge[] = [];
  const denied: ReachEdge[] = [];
  const seen = new Set<string>();

  for (const fromKey of zones) {
    const from = endpoints.find((e) => orgZoneRef(e) === fromKey);
    if (!from) continue;
    for (const toKey of zones) {
      if (toKey === fromKey) continue;
      // The probe client is a non-router host when the origin zone has one:
      // the router's own forwarding is what the probes verify, so it must not
      // grade its own homework. Single-host zones keep their only endpoint.
      const originHosts = endpoints.filter((e) => orgZoneRef(e) === fromKey);
      const client = originHosts.find((e) => !e.router) ?? from;
      const targets = endpoints.filter((e) => orgZoneRef(e) === toKey);
      for (const target of targets) {
        const decls = spec.instances.find((i) => i.hostId === target.hostId)?.serviceDecls ?? [];
        for (const decl of decls) {
          const key = `${fromKey}->${toKey}:${decl.kind}:${decl.port}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const d = decision(model, client, target, "tcp", decl.port);
          const edge: ReachEdge = {
            from: client.hostId, to: target.hostId, fromZone: fromKey, toZone: toKey,
            proto: decl.kind, port: decl.port, reason: d.reason,
          };
          (d.allow ? allowed : denied).push(edge);
        }
      }
    }
  }
  return { allowed, denied };
}

/** One denied edge per zone pair that has no allowed service path at all. */
export function negativeProbesFor(spec: EnvironmentSpec, model = normalizeOrg(spec)): ReachEdge[] {
  const reach = reachabilityFor(spec, model);
  const allowedPairs = new Set(reach.allowed.map((e) => `${e.fromZone}->${e.toZone}`));
  const out: ReachEdge[] = [];
  const seen = new Set<string>();
  for (const edge of reach.denied) {
    const pair = `${edge.fromZone}->${edge.toZone}`;
    if (allowedPairs.has(pair) || seen.has(pair)) continue;
    seen.add(pair);
    out.push(edge);
  }
  return out;
}

/** Deterministic hub port for one segment, outside the SSH hostfwd range. */
export function segmentHubPortFor(runId: string, segment: string): number {
  const b = createHash("sha256").update(`segment:${runId}:${segment}`).digest();
  return 45000 + ((b[0] << 8 | b[1]) % 15000);
}

/** One L2 segment per zone subnet; ports are stable per run and unique. */
export function segmentsFor(spec: EnvironmentSpec, runId: string, model = normalizeOrg(spec)): OrgSegment[] {
  const used = new Set<number>();
  return model.subnets.map((s) => {
    let port = segmentHubPortFor(runId, s.name);
    while (used.has(port)) port = 45000 + ((port - 45000 + 1) % 15000);
    used.add(port);
    return { name: s.name, site: s.site, zone: s.zone, cidr: s.cidr, hubPort: port };
  });
}

/** Routers attach to every zone subnet of their site and own .1 there. */
export function routerAttachmentsFor(spec: EnvironmentSpec, model = normalizeOrg(spec)): RouterAttachment[] {
  const routers = spec.instances.filter((i) =>
    i.role === "router" || (i.serviceDecls ?? []).some((d) => d.kind === "router"));
  const out: RouterAttachment[] = [];
  for (const r of routers) {
    const site = r.site ?? model.sites[0]?.id;
    if (!site) continue;
    const interfaces: RouterInterface[] = model.subnets.filter((s) => s.site === site).map((s) => {
      const { network, prefix } = parseCidr(s.cidr);
      return { segment: s.name, cidr: s.cidr, address: intToIp(network + 1), prefix };
    });
    out.push({ hostId: r.hostId, site, interfaces });
  }
  return out;
}

function cidrsFor(ref: string, model: OrgModel): string[] {
  if (ref === "any") return model.subnets.map((s) => s.cidr);
  const [site, zone] = ref.split("/");
  return model.subnets
    .filter((s) => (site === "*" || s.site === site) && (zone === "*" || s.zone === zone))
    .map((s) => s.cidr);
}

function ruleLine(
  action: "allow" | "deny",
  from: string[],
  to: string[],
  proto: string,
  port: number | undefined,
): string | undefined {
  if (!from.length || !to.length) return undefined;
  const src = `ip saddr { ${from.join(", ")} } ip daddr { ${to.join(", ")} }`;
  const match = proto === "icmp"
    ? `${src} ip protocol icmp`
    : port === undefined
      ? `${src} ${proto}`
      : `${src} ${proto} dport ${port}`;
  return action === "deny"
    ? `    ${match} limit rate 10/second log prefix "arena-deny " drop`
    : `    ${match} accept`;
}

/**
 * The router's forward chain: explicit denies first (deny wins), then allows,
 * then WAN link ports, then the policy drop. Input/output are unfiltered so
 * the management plane can still reach the guest over its separate NIC.
 */
export function nftablesFor(spec: EnvironmentSpec, model = normalizeOrg(spec)): string {
  const lines = [
    "table inet arena {",
    "  chain forward {",
    "    type filter hook forward priority filter; policy drop;",
    "    ct state established,related accept",
  ];
  const policies = spec.topology.policies ?? [];
  for (const p of policies.filter((x) => x.action === "deny")) {
    const line = ruleLine("deny", cidrsFor(p.from, model), cidrsFor(p.to, model), p.proto, p.port);
    if (line) lines.push(line);
  }
  for (const p of policies.filter((x) => x.action === "allow")) {
    const line = ruleLine("allow", cidrsFor(p.from, model), cidrsFor(p.to, model), p.proto, p.port);
    if (line) lines.push(line);
  }
  for (const link of model.links) {
    const from = model.subnets.filter((s) => s.site === link.from).map((s) => s.cidr);
    const to = model.subnets.filter((s) => s.site === link.to).map((s) => s.cidr);
    for (const a of link.allowed) {
      const fwd = ruleLine("allow", from, to, a.proto, a.port);
      const rev = ruleLine("allow", to, from, a.proto, a.port);
      if (fwd) lines.push(fwd);
      if (rev) lines.push(rev);
    }
  }
  lines.push("  }", "}", "");
  return lines.join("\n");
}

/** Executable negative probes: a real TCP connect from a real guest. */
export function negativeProbeCommands(spec: EnvironmentSpec, model = normalizeOrg(spec)): NegativeProbe[] {
  const out: NegativeProbe[] = [];
  for (const edge of negativeProbesFor(spec, model)) {
    const target = model.byHost.get(edge.to);
    if (!target) continue;
    out.push({
      from: edge.from, to: edge.to, port: edge.port,
      command: `timeout 3 bash -c '</dev/tcp/${target.address}/${edge.port}'`,
    });
  }
  return out;
}

/**
 * Design-time topology validation. Returns named reasons; an empty list means
 * the design is total enough to plan. Deployment still refuses multi-zone
 * until P1 realizes segments and routers.
 */
export function validateOrgTopology(spec: EnvironmentSpec): string[] {
  const errors: string[] = [];
  const sites = spec.topology.sites ?? [];
  const zones = spec.topology.zones ?? [];
  const declaredSubnets = spec.topology.subnets;
  const hasOrg = sites.length > 0 || zones.length > 0;
  if (!hasOrg) return errors; // v1 flat lab: unchanged

  const siteIds = new Set<string>();
  for (const s of sites) {
    if (siteIds.has(s.id)) errors.push(`site "${s.id}" is duplicated`);
    siteIds.add(s.id);
  }
  if (sites.length > MAX_SITES) errors.push(`topology declares ${sites.length} sites; the address plan allows ${MAX_SITES}`);
  if (!sites.length) errors.push("org topology declares zones but no sites");

  const zoneKeys = new Set<string>();
  for (const z of zones) {
    if (!siteIds.has(z.site)) errors.push(`zone "${z.id}" references unknown site "${z.site}"`);
    const key = zoneKey(z.site, z.id);
    if (zoneKeys.has(key)) errors.push(`zone "${key}" is duplicated`);
    zoneKeys.add(key);
  }
  for (const s of sites) {
    const count = zones.filter((z) => z.site === s.id).length;
    if (count === 0) errors.push(`site "${s.id}" declares no zone`);
    if (count > MAX_ZONES_PER_SITE) errors.push(`site "${s.id}" declares ${count} zones; the address plan allows ${MAX_ZONES_PER_SITE}`);
  }

  const subnetNames = new Set<string>();
  for (const s of declaredSubnets) {
    if (subnetNames.has(s.name)) errors.push(`subnet "${s.name}" is duplicated`);
    subnetNames.add(s.name);
    const site = s.site ?? sites[0]?.id;
    if (site && !siteIds.has(site)) errors.push(`subnet "${s.name}" references unknown site "${site}"`);
    if (s.zone && !zones.some((z) => z.id === s.zone && z.site === (site ?? z.site))) {
      errors.push(`subnet "${s.name}" references unknown zone "${s.zone}"`);
    }
    try { parseCidr(s.cidr); } catch (err) { errors.push(err instanceof Error ? err.message : String(err)); }
  }

  const multiZone = zones.length > 1;
  for (const inst of spec.instances) {
    if (inst.site && !siteIds.has(inst.site)) errors.push(`instance ${inst.hostId}: unknown site "${inst.site}"`);
    if (inst.zone && !zones.some((z) => z.id === inst.zone && z.site === (inst.site ?? z.site))) {
      errors.push(`instance ${inst.hostId}: unknown zone "${inst.zone}"`);
    }
    if (multiZone && !inst.subnet && !(inst.site && inst.zone)) {
      errors.push(`instance ${inst.hostId}: no placement in a ${zones.length}-zone topology`);
    }
    if (inst.subnet && declaredSubnets.length > 0 && !declaredSubnets.some((s) => s.name === inst.subnet)) {
      errors.push(`instance ${inst.hostId}: subnet "${inst.subnet}" is not declared`);
    }
  }

  // One router per site; it is the only host that owns .1 in each zone.
  // A multi-zone site without a router has no enforcement point, so the
  // segmentation it declares would be a promise without a gate.
  const routerSites = new Set<string>();
  const zonesBySite = new Map<string, number>();
  for (const z of zones) zonesBySite.set(z.site, (zonesBySite.get(z.site) ?? 0) + 1);
  for (const r of spec.instances.filter((i) => i.role === "router" || (i.serviceDecls ?? []).some((d) => d.kind === "router"))) {
    const site = r.site ?? (sites.length === 1 ? sites[0].id : undefined);
    if (!site) { errors.push(`router ${r.hostId}: no site declared`); continue; }
    if (routerSites.has(site)) errors.push(`site "${site}" declares more than one router`);
    routerSites.add(site);
  }
  for (const s of sites) {
    if ((zonesBySite.get(s.id) ?? 0) > 1 && !routerSites.has(s.id)) {
      errors.push(`site "${s.id}" declares ${zonesBySite.get(s.id)} zones but no router — one router per multi-zone site enforces the policy`);
    }
  }

  // Policy references and exact contradictions.
  const policySeen = new Map<string, FirewallPolicy["action"]>();
  for (const p of spec.topology.policies ?? []) {
    if (!refValid(p.from, sites, zones)) errors.push(`policy from "${p.from}" does not name a site/zone`);
    if (!refValid(p.to, sites, zones)) errors.push(`policy to "${p.to}" does not name a site/zone`);
    const key = `${p.from}->${p.to}:${p.proto}:${p.port ?? "*"}`;
    const prior = policySeen.get(key);
    if (prior && prior !== p.action) errors.push(`policy ${key} is both allow and deny`);
    policySeen.set(key, p.action);
  }

  let model: OrgModel;
  try {
    model = normalizeOrg(spec);
  } catch (err) {
    errors.push(`topology cannot be derived: ${err instanceof Error ? err.message : String(err)}`);
    return errors;
  }
  const attacker = spec.instances.find((i) => i.role === "attacker");
  if (attacker) {
    const ep = model.byHost.get(attacker.hostId);
    if (ep && zones.find((z) => z.site === ep.site && z.id === ep.zone)?.kind === "server") {
      errors.push(`attacker ${attacker.hostId} is placed in a server zone`);
    }
    const reach = reachabilityFor(spec, model);
    const attackerZone = ep ? orgZoneRef(ep) : "";
    const graph = new Map<string, Set<string>>();
    for (const e of reach.allowed) {
      if (!graph.has(e.fromZone)) graph.set(e.fromZone, new Set());
      graph.get(e.fromZone)!.add(e.toZone);
    }
    const reachableZones = new Set<string>([attackerZone]);
    const queue = [attackerZone];
    while (queue.length) {
      const z = queue.shift()!;
      for (const next of graph.get(z) ?? []) {
        if (!reachableZones.has(next)) { reachableZones.add(next); queue.push(next); }
      }
    }
    for (const o of spec.objectives) {
      const target = model.byHost.get(o.asset);
      if (!target) continue;
      const targetZone = orgZoneRef(target);
      if (targetZone !== attackerZone && !reachableZones.has(targetZone)) {
        errors.push(`objective ${o.id}: no allowed path from attacker ${attacker.hostId} to ${targetZone}`);
      }
      if (zones.find((z) => z.site === target.site && z.id === target.zone)?.kind === "edge") {
        errors.push(`objective ${o.id}: asset ${o.asset} is placed in an edge zone`);
      }
    }
  }

  // Hosts per subnet at the plan's /24 default.
  const perSubnet = new Map<string, number>();
  for (const ep of model.endpoints) perSubnet.set(ep.subnet, (perSubnet.get(ep.subnet) ?? 0) + 1);
  for (const [name, n] of perSubnet) {
    if (n > MAX_HOSTS_PER_SUBNET) errors.push(`subnet ${name}: ${n} hosts exceed ${MAX_HOSTS_PER_SUBNET}`);
  }
  return errors;
}

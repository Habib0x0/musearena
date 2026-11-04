import { createHash } from "node:crypto";
import type { EnvironmentSpec } from "@musearena/shared";
import { normalizeOrg, routerAttachmentsFor, segmentsFor, type OrgModel } from "../designer/org-topology.js";

/**
 * Lab L2 plan (T-15) for the QEMU runtime.
 *
 * On a Linux reference host the lab segment is a per-run bridge with taps. On
 * the macOS dev host there is no bridge/tap privilege, so the segment is a
 * user-space hub (`lab-hub.ts`): every guest's second NIC connects to one
 * loopback TCP port and the hub relays frames between them. The management
 * NIC stays on user-mode networking (SSH hostfwd is unaffected) and the lab
 * NIC gets a static address with no default route — `apt` keeps using the
 * management NIC, and only lab traffic crosses the segment.
 *
 * Pure functions: the same spec and run id always produce the same addresses,
 * MACs and hub port. The hub process itself is lifecycle state, not a plan.
 */

const MGMT_MAC_PREFIX = "52:54:00";

export interface LabEndpoint {
  hostId: string;
  /** Static address on the lab NIC, e.g. 10.2.32.10. */
  address: string;
  prefix: number;
  /** The subnet this address belongs to (from the spec topology). */
  cidr: string;
  /** Loopback port of this run's lab hub; every guest connects to it. */
  hubPort: number;
  /** Deterministic MAC for the lab NIC; the guest seed configures by it. */
  mac: string;
  /** The gateway host owns the subnet's .1 address. */
  gateway: boolean;
}

function bytes(seed: string): Buffer {
  return createHash("sha256").update(seed).digest();
}

/** Locally administered unicast MAC, deterministic per host and NIC slot. */
export function nicMac(hostId: string, slot: "mgmt" | "lab", index = 0): string {
  const seed = slot === "lab" && index > 0 ? `nic:lab:${hostId}:${index}` : `nic:${slot}:${hostId}`;
  const b = bytes(seed);
  return [MGMT_MAC_PREFIX, b[0], b[1], b[2]].map((x) => (typeof x === "number" ? x.toString(16).padStart(2, "0") : x)).join(":");
}

/**
 * Loopback port for one run's lab hub. Chosen outside the SSH hostfwd range
 * (22000–42000) so the two never collide on one host.
 */
export function labHubPortFor(runId: string): number {
  const b = bytes(`lab-hub:${runId}`);
  return 45000 + ((b[0] << 8 | b[1]) % 15000);
}

function ipToInt(ip: string): number {
  return ip.split(".").reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
}

function intToIp(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

function parseCidr(cidr: string): { network: number; prefix: number } {
  const m = /^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/.exec(cidr.trim());
  if (!m) throw new Error(`lab network: ${cidr} is not a CIDR`);
  const prefix = Number(m[2]);
  if (prefix < 8 || prefix > 30) throw new Error(`lab network: /${prefix} is not a usable lab subnet`);
  const base = ipToInt(m[1]) & (prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0);
  return { network: base, prefix };
}

/**
 * DHCP lease pool for a lab subnet: the top 32 usable addresses. Static lab
 * addresses are assigned from the bottom (.1 gateway, .10+ hosts), so a lease
 * can never collide with a configured guest. Small subnets shrink the pool
 * rather than underflow below the network address.
 */
export function dhcpPoolFor(cidr: string): { start: string; end: string; netmask: string } {
  const { network, prefix } = parseCidr(cidr);
  const size = 2 ** (32 - prefix);
  const broadcast = (network + size - 1) >>> 0;
  const poolSize = Math.min(32, Math.max(1, size - 3));
  const end = (broadcast - 1) >>> 0;
  const start = (end - poolSize + 1) >>> 0;
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { start: intToIp(start), end: intToIp(end), netmask: intToIp(mask) };
}

/**
 * Address plan for a spec's VM instances. The gateway takes .1; every other
 * host takes .10 upward in spec order. Throws when the subnet cannot hold the
 * hosts rather than silently overlapping.
 */
export function labPlanFor(spec: EnvironmentSpec, runId: string): LabEndpoint[] {
  const vms = spec.instances.filter((i) => i.runtime === "vm");
  if (!vms.length) return [];
  const hubPort = labHubPortFor(runId);
  // The gateway is the host that serves DNS. Role is only a fallback: the
  // designer's role vocabulary has no `gateway`, so a model-authored org names
  // its DNS host `dc`/`sensor`/anything and still owns the segment's .1.
  const gatewayId = vms.find((i) => (i.serviceDecls ?? []).some((d) => d.kind === "dns"))?.hostId
    ?? vms.find((i) => i.role === "gateway")?.hostId;
  const usable = (() => {
    const s = spec.topology.subnets[0];
    if (!s) throw new Error("lab network: the spec declares no subnets");
    return parseCidr(s.cidr);
  })();
  const cidrOf = (hostId: string) => {
    const inst = vms.find((i) => i.hostId === hostId)!;
    const named = inst.subnet ? spec.topology.subnets.find((s) => s.name === inst.subnet) : undefined;
    return named?.cidr ?? spec.topology.subnets[0].cidr;
  };
  const out: LabEndpoint[] = [];
  let next = 10;
  for (const inst of vms) {
    const cidr = cidrOf(inst.hostId);
    const { network, prefix } = parseCidr(cidr);
    const gateway = inst.hostId === gatewayId;
    const host = gateway ? 1 : next++;
    const address = intToIp(network + host);
    const size = 2 ** (32 - prefix);
    if (host >= size - 1) throw new Error(`lab network: ${cidr} cannot hold ${vms.length} guests`);
    out.push({ hostId: inst.hostId, address, prefix, cidr, hubPort, mac: nicMac(inst.hostId, "lab"), gateway });
  }
  return out;
}

/**
 * One lab NIC per zone segment a host touches (P1b runtime).
 *
 * A v2 org spec derives its addresses from the org model, not the flat plan:
 * a regular host gets one NIC on its zone's segment; the site router gets one
 * NIC per zone segment of its site (at .1 there). The v1 flat segment is not
 * expressible here — callers use `labPlanFor` for specs without sites/zones.
 */
export interface SegmentAttachment {
  hostId: string;
  segment: string;
  site: string;
  zone: string;
  address: string;
  prefix: number;
  cidr: string;
  /** Loopback port of this segment's hub; one hub process per segment. */
  hubPort: number;
  /** Deterministic MAC for this NIC; unique per host and segment. */
  mac: string;
  /** The router is the only host that owns .1 in a zone. */
  router: boolean;
  /** Same-site subnets reachable only via this zone's router (.1) — guest routes. */
  routesVia?: { cidr: string; via: string }[];
}

export function labSegmentsFor(spec: EnvironmentSpec, runId: string, model: OrgModel = normalizeOrg(spec)): SegmentAttachment[] {
  const vms = spec.instances.filter((i) => i.runtime === "vm");
  if (!vms.length) return [];
  const vmIds = new Set(vms.map((i) => i.hostId));
  const segments = segmentsFor(spec, runId, model);
  const portOf = new Map(segments.map((s) => [s.name, s.hubPort]));
  const routers = new Map(routerAttachmentsFor(spec, model).map((r) => [r.hostId, r]));
  const out: SegmentAttachment[] = [];
  for (const inst of vms) {
    const router = routers.get(inst.hostId);
    if (router) {
      router.interfaces.forEach((iface, idx) => {
        const seg = segments.find((s) => s.name === iface.segment)!;
        const hubPort = portOf.get(iface.segment);
        if (hubPort === undefined) throw new Error(`lab segments: no hub port for segment ${iface.segment}`);
        out.push({
          hostId: inst.hostId, segment: iface.segment, site: seg.site, zone: seg.zone,
          address: iface.address, prefix: iface.prefix, cidr: iface.cidr,
          hubPort, mac: nicMac(inst.hostId, "lab", idx), router: true,
        });
      });
      continue;
    }
    const ep = model.byHost.get(inst.hostId);
    if (!ep) throw new Error(`lab segments: ${inst.hostId} has no org endpoint (unplaced host)`);
    const seg = segments.find((s) => s.name === ep.subnet);
    const hubPort = seg ? portOf.get(seg.name) : undefined;
    if (!seg || hubPort === undefined) throw new Error(`lab segments: no segment ${ep.subnet} for ${inst.hostId}`);
    // Other zones of the same site are reached via this zone's router at .1.
    const foreigners = model.subnets.filter((s) => s.site === seg.site && s.name !== seg.name);
    const { network } = parseCidr(ep.cidr);
    const routerAddr = intToIp(network + 1);
    out.push({
      hostId: inst.hostId, segment: seg.name, site: seg.site, zone: seg.zone,
      address: ep.address, prefix: ep.prefix, cidr: ep.cidr,
      hubPort, mac: nicMac(inst.hostId, "lab"), router: false,
      ...(foreigners.length ? { routesVia: foreigners.map((s) => ({ cidr: s.cidr, via: routerAddr })) } : {}),
    });
  }
  for (const a of out) {
    if (!vmIds.has(a.hostId)) throw new Error(`lab segments: attachment for unknown host ${a.hostId}`);
  }
  return out;
}

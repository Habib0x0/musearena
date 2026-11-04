import type { EnvironmentSpec } from "@musearena/shared";
import { labDomainFor } from "../configurator/dns.js";

/** Topology map derived from a spec — the data behind the artifact-pane diagram. */
export interface TopologyNode {
  hostId: string;
  name: string;
  role: string;
  runtime: string;
  os: string;
  services: string[];
  subnet: string;
  vulnCount: number;
}

export interface TopologySubnet {
  name: string;
  cidr: string;
  zone: string;
  nodes: TopologyNode[];
}

export interface TopologyEdge {
  from: string;
  to: string;
  label: string;
  kind: "route" | "firewall" | "service";
}

export interface TopologyMap {
  cidr: string;
  /** Environment-specific DNS namespace derived from the spec. */
  domain: string;
  subnets: TopologySubnet[];
  edges: TopologyEdge[];
  firewallRules: string[];
}

function subnetForInstance(spec: EnvironmentSpec, index: number): string {
  if (spec.topology.subnets.length === 0) return "default";
  // Fallback only for legacy specs with no explicit placement: round-robin so
  // every declared subnet renders. A declared `subnet` always wins — the map
  // must show the placement the lab plan actually uses.
  return spec.topology.subnets[index % spec.topology.subnets.length].name;
}

export function topologyFor(spec: EnvironmentSpec): TopologyMap {
  const bySubnet = new Map<string, TopologyNode[]>();
  for (const s of spec.topology.subnets) bySubnet.set(s.name, []);

  spec.instances.forEach((inst, i) => {
    const subnet = inst.subnet ?? subnetForInstance(spec, i);
    const node: TopologyNode = {
      hostId: inst.hostId,
      name: inst.name,
      role: inst.role,
      runtime: inst.runtime,
      os: inst.os,
      services: [...inst.services],
      subnet,
      vulnCount: spec.plantedVulns.filter((v) => v.targetHostId === inst.hostId).length,
    };
    if (!bySubnet.has(subnet)) bySubnet.set(subnet, []);
    bySubnet.get(subnet)!.push(node);
  });

  const subnets: TopologySubnet[] = spec.topology.subnets.map((s) => ({
    name: s.name,
    cidr: s.cidr,
    zone: s.zone,
    nodes: bySubnet.get(s.name) ?? [],
  }));
  // Subnets referenced by placement but not declared still surface.
  for (const [name, nodes] of bySubnet) {
    if (!subnets.some((s) => s.name === name)) {
      subnets.push({ name, cidr: spec.topology.cidr, zone: "a", nodes });
    }
  }

  const edges: TopologyEdge[] = [];
  for (let i = 0; i + 1 < subnets.length; i++) {
    edges.push({ from: subnets[i].name, to: subnets[i + 1].name, label: "route", kind: "route" });
  }
  for (const rule of spec.topology.firewallRules) {
    edges.push({ from: "firewall", to: rule, label: rule, kind: "firewall" });
  }
  for (const inst of spec.instances) {
    for (const svc of inst.services) {
      edges.push({ from: inst.hostId, to: svc, label: svc, kind: "service" });
    }
  }

  return { cidr: spec.topology.cidr, domain: labDomainFor(spec), subnets, edges, firewallRules: [...spec.topology.firewallRules] };
}

import * as pulumi from "@pulumi/pulumi";
import * as docker from "@pulumi/docker";
import type { EnvironmentSpec } from "@musearena/shared";
import { remapSubnets, subnetsFor } from "./cidr.js";
import { detectHost, vmPlanFor } from "./kvm.js";
import { digestOfSpec } from "../lib/digest.js";
import { roleImage, type RoleImage } from "./roles.js";
import { ATTACKER_HOST_ID, containerName, networkName } from "./names.js";

// EnvironmentSpec → Pulumi (Docker runtime for local/KVM-proof path).
// AWS/GCP branches come behind this same Input surface; canonical resource
// names (per-instance role) never raw URN strings.
export interface GenInput {
  spec: EnvironmentSpec;
  orgId: string;
  runId: string;
  cidrOctet: number;
}

function containerFor(inst: { name: string; hostId: string }, runId: string, image: RoleImage, imageRef: pulumi.Input<string>,
  net: docker.Network, labels: { label: string; value: string }[]) {
  // Isolation (NFR): attached ONLY to the run's internal network — no default
  // bridge, no published ports, no egress. hostId is the in-env DNS name.
  return new docker.Container(inst.name, {
    name: containerName(runId, inst.hostId),
    image: imageRef,
    labels,
    // networksAdvanced only: combining it with networkMode drops the aliases,
    // leaving in-env hostnames unresolvable (found in live run).
    networksAdvanced: [{ name: net.name, aliases: [inst.hostId] }],
    envs: image.envs,
    command: image.command,
    mustRun: true,
    restart: "no",
  });
}

export function program({ spec, orgId, runId, cidrOctet }: GenInput) {
  if (spec.provider !== "kvm") {
    throw new Error(`provider "${spec.provider}" is not realized by this worker; only the local kvm provider is supported`);
  }
  // The design's topology is the source of truth. VM guests use it verbatim
  // (their segment is per-run). Containers must share one Docker network per
  // host, so their copy is moved into this run's allocated /16.
  const vmDefs = spec.provider === "kvm" ? vmPlanFor(spec, detectHost()) : [];
  const adoptedSubnets = vmDefs.length > 0
    ? spec.topology.subnets
    : spec.topology.subnets.length > 0
      ? remapSubnets(spec.topology.subnets, cidrOctet)
      : subnetsFor(cidrOctet);
  const baseLabels = [
    { label: "arena.run_id", value: runId },
    { label: "arena.org", value: orgId },
    { label: "arena.ttl_hours", value: String(spec.budgets.ttlHours) },
    { label: "arena.spec_digest", value: digestOfSpec(spec) },
  ];

  const outputs: Record<string, pulumi.Output<string>> = {};
  // KVM provider: vm-runtime instances are QEMU guests (booted by deploy.ts),
  // never containers. Container-runtime instances keep the Docker path.
  const vmHostIds = new Set(vmDefs.map((v) => v.hostId));
  for (const def of vmDefs) outputs[def.hostId] = pulumi.output(`vm:${def.guestArch}:${def.accel}`);

  const containers = spec.instances.filter((i) => !vmHostIds.has(i.hostId));
  if (containers.length > 0) {
    // One network means one realized subnet; the design's first subnet is it.
    const privateSubnet = adoptedSubnets[0];
    const net = new docker.Network("env-net", {
      name: networkName(runId),
      internal: true, // default-deny egress; unreachable from the host's published ports
      ipamConfigs: [{ subnet: privateSubnet.cidr }],
      labels: baseLabels,
    });
    const images = new Map<string, docker.RemoteImage>();
    const imageRef = (name: string) => {
      if (!images.has(name)) images.set(name, new docker.RemoteImage(`img-${name.replace(/[^a-z0-9]/gi, "-")}`, { name, keepLocally: true }));
      return images.get(name)!.imageId;
    };
    for (const inst of [...containers, { name: ATTACKER_HOST_ID, hostId: ATTACKER_HOST_ID, role: "attacker" }]) {
      const ri = roleImage(inst.role);
      const c = containerFor(inst, runId, ri, imageRef(ri.image), net, [
        ...baseLabels,
        { label: "arena.host_id", value: inst.hostId },
        { label: "arena.role", value: inst.role },
      ]);
      outputs[inst.hostId] = c.name;
    }
    outputs["network"] = net.name;
  }

  return { outputs, subnets: adoptedSubnets };
}

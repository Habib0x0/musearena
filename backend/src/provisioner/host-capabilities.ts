import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { detectHost, type Accel, type GuestArch, type HostVirt } from "./kvm.js";
import { bakedManifestPath, imageCacheDir, parseBakedManifest } from "./images.js";

/**
 * What the worker the designer runs on can actually build (T-4/T-17).
 *
 * The designer used to receive a static capability catalog, so it could
 * happily design a VM org lab for a worker with no usable acceleration and
 * the design was only rejected afterwards. This is the same contract, probed
 * from the host at design time: acceleration, guest arch, whether the baked
 * catalog image is staged, and whether the container runtime is present.
 *
 * Pure apart from the injected probes, so tests can describe a host instead of
 * needing one.
 */

export type BakedStatus = "staged" | "pinned-but-missing" | "absent";

export interface HostCapabilities {
  platform: string;
  arch: string;
  guestArch: GuestArch;
  accel: Accel;
  /** Guests can boot here: startRunVms refuses tcg/none. */
  vmRuns: boolean;
  /** Docker runtime available for container labs. */
  container: boolean;
  /** Baked catalog artifact for the guest arch. */
  bakedCatalog: BakedStatus;
  /** This repo never claims VMI truth from KVM alone. */
  truthLayerCap: "mirror-only";
  /** Acceptance limit for one org lab; a design above it is refused. */
  maxVmInstances: number;
  notes: string[];
}

export interface HostProbe {
  container?: boolean;
  baked?: BakedStatus;
  maxVmInstances?: number;
}

function hasBin(bin: string): boolean {
  for (const d of (process.env.PATH ?? "").split(path.delimiter)) if (existsSync(path.join(d, bin))) return true;
  return ["/usr/local/bin", "/usr/bin", "/opt/homebrew/bin"].some((d) => existsSync(path.join(d, bin)));
}

/** Is the baked catalog artifact for this arch pinned and present in the cache? */
export function bakedStatusFor(guestArch: GuestArch, cacheDir = process.env.GOLDEN_IMAGE_DIR ?? imageCacheDir()): BakedStatus {
  const raw = (() => { try { return readFileSync(bakedManifestPath(), "utf8"); } catch { return null; } })();
  if (!raw) return "absent";
  let manifest;
  try { manifest = parseBakedManifest(raw); } catch { return "absent"; }
  const entry = manifest.images[guestArch];
  if (!entry) return "absent";
  return existsSync(path.join(cacheDir, entry.file)) ? "staged" : "pinned-but-missing";
}

export function hostCapabilities(host: HostVirt = detectHost(), probe: HostProbe = {}): HostCapabilities {
  const vmRuns = host.accel === "kvm" || host.accel === "hvf";
  const bakedCatalog = probe.baked ?? bakedStatusFor(host.hostArch);
  const container = probe.container ?? hasBin("docker");
  const notes: string[] = [host.reason];
  if (!vmRuns) notes.push(`VM guests cannot boot here (accel ${host.accel})`);
  if (bakedCatalog === "pinned-but-missing") notes.push("the baked catalog image is pinned but not staged: configure will install packages, needs egress");
  if (bakedCatalog === "absent") notes.push("no baked catalog image for this arch: runs fall back to the base Debian cloud image and need package egress");
  if (!container) notes.push("docker not found: container labs cannot run here");
  return {
    platform: host.platform, arch: host.arch, guestArch: host.hostArch, accel: host.accel,
    vmRuns, container, bakedCatalog, truthLayerCap: "mirror-only",
    maxVmInstances: probe.maxVmInstances ?? 8, notes,
  };
}

/** The prompt section: facts about this worker plus what they imply for the design. */
export function hostBrief(caps: HostCapabilities): string {
  const guidance = caps.vmRuns
    ? "VM guests are available on this worker. An org lab (provider kvm, runtime vm) is the primary shape; container designs are the fast web/db regression shape, not an equivalent substitute."
    : "VM guests cannot run on this worker. Design a container lab (web + db, runtime container) instead; a design that needs VMs must be refused with that reason rather than emitted.";
  const baked = caps.bakedCatalog === "staged"
    ? "staged for this arch (no package egress at run time)"
    : caps.bakedCatalog === "pinned-but-missing"
      ? "pinned but not staged (configure installs packages; egress required)"
      : "absent for this arch (base Debian image; configure installs packages; egress required)";
  return [
    "## This worker (detected, not assumed)",
    `- platform ${caps.platform}/${caps.arch}, guest arch ${caps.guestArch}, acceleration ${caps.accel}`,
    `- VM guests: ${caps.vmRuns ? "available" : "NOT available"}`,
    `- container labs: ${caps.container ? "available" : "NOT available"}`,
    `- baked catalog image: ${baked}`,
    `- truth layer cap: ${caps.truthLayerCap} (KVM alone is not VMI)`,
    `- max instances per lab: ${caps.maxVmInstances}`,
    ...caps.notes.map((n) => `- note: ${n}`),
    `Design for this worker: ${guidance}`,
  ].join("\n");
}

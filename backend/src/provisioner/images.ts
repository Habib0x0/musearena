import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream, existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);

/**
 * Guest images, two tiers:
 * - Probe tier: Alpine netboot kernel (~10 MB) + minirootfs initramfs
 *   (~4 MB) — boot markers only, never a scored org-lab guest.
 * - Org-lab tier: Debian 12 cloud images (generic, cloud-init), pinned
 *   below by Debian's published SHA512. Downloaded once, hashed before
 *   use, cloned per run as CoW overlays (see vm-lifecycle.ts). The
 *   platform never boots an image whose hash it has not verified.
 * Windows guests fail closed until a licensed image is supplied.
 */
const ALPINE = "https://dl-cdn.alpinelinux.org/alpine/v3.20/releases";

export interface TinyImage { guestArch: "x86_64" | "aarch64"; kernelUrl: string; rootfsUrl: string; kernelFile: string; rootfsFile: string }

const CATALOG: Record<string, TinyImage> = {
  aarch64: {
    guestArch: "aarch64",
    kernelUrl: `${ALPINE}/aarch64/netboot/vmlinuz-lts`,
    rootfsUrl: `${ALPINE}/aarch64/alpine-minirootfs-3.20.0-aarch64.tar.gz`,
    kernelFile: "vmlinuz-lts-aarch64", rootfsFile: "alpine-minirootfs-aarch64.tar.gz",
  },
  x86_64: {
    guestArch: "x86_64",
    kernelUrl: `${ALPINE}/x86_64/netboot/vmlinuz-lts`,
    rootfsUrl: `${ALPINE}/x86_64/alpine-minirootfs-3.20.0-x86_64.tar.gz`,
    kernelFile: "vmlinuz-lts-x86_64", rootfsFile: "alpine-minirootfs-x86_64.tar.gz",
  },
};

// Package-anchored like deploy.ts backendRoot: a cwd-relative cache made
// root-run scripts miss the staged golden images entirely.
export const imageCacheDir = () => process.env.KVM_IMAGE_CACHE ?? path.join(path.dirname(new URL(import.meta.url).pathname), "../../.kvm-images");

export type GuestArchName = "x86_64" | "aarch64";

export interface GoldenImage {
  guestArch: GuestArchName;
  name: string;
  url: string;
  file: string;
  format: "qcow2";
  /** Debian-published SHA512 (cloud.debian.org/.../SHA512SUMS) — verified before any boot. */
  sha512: string;
  /** What a run records about this image: file digest + catalog pin. */
  digest: string;
}

// Debian 12 (bookworm) generic cloud images, pinned 2026-10-26 checksums.
// To bump: re-read SHA512SUMS, update the two hashes, bump nothing else —
// the resolved digest is recorded per run.
export const GOLDEN_CATALOG_VERSION = "arena-golden-debian12-1";
const DEBIAN_CLOUD = "https://cloud.debian.org/images/cloud/bookworm/latest";

export const GOLDEN_IMAGES: Record<GuestArchName, GoldenImage> = {
  x86_64: {
    guestArch: "x86_64", name: "debian-12-generic", url: `${DEBIAN_CLOUD}/debian-12-generic-amd64.qcow2`,
    file: "debian-12-generic-amd64.qcow2", format: "qcow2",
    sha512: "ba6073af9f789c0f7d6b73ec1b23bb207f07f06f2d31bfd3ce5e550fe43eb9415ef983dc0e039014cd59797e0cbea5c32592e6900fa8f974f2e4466b88ff0d80",
    digest: "",
  },
  aarch64: {
    guestArch: "aarch64", name: "debian-12-generic", url: `${DEBIAN_CLOUD}/debian-12-generic-arm64.qcow2`,
    file: "debian-12-generic-arm64.qcow2", format: "qcow2",
    sha512: "45d5918f1d6272931f87a0a3af8a9fcd4373947369c4d1d2cbad463882d0c3a24acbd6a27cf8b6cd422c23af05d5deaf3cc2d968313649da4d896b707974ad42",
    digest: "",
  },
};
for (const g of Object.values(GOLDEN_IMAGES)) g.digest = `sha512:${g.sha512.slice(0, 16)}…/${GOLDEN_CATALOG_VERSION}`;

export function goldenImageFor(guestArch: GuestArchName): GoldenImage { return GOLDEN_IMAGES[guestArch]; }

export async function hashFile(file: string, algo: "sha512" | "sha256" = "sha512"): Promise<string> {
  const h = createHash(algo);
  for await (const chunk of createReadStream(file)) h.update(chunk as Buffer);
  return h.digest("hex");
}

/**
 * Ensure the pinned golden image is cached and hash-verified.
 * A cached file with a wrong hash is deleted and re-downloaded once;
 * a second mismatch throws — the platform never boots an unverified image.
 * `GOLDEN_IMAGE_DIR` points at a pre-staged cache (e.g. in a worker image).
 */
export async function ensureGoldenImage(guestArch: GuestArchName, opts: { cacheDir?: string; downloadImpl?: (url: string, dest: string) => Promise<void>; expectedSha512?: string } = {}): Promise<{ image: GoldenImage; path: string }> {
  const image = goldenImageFor(guestArch);
  const expected = opts.expectedSha512 ?? image.sha512;
  const dir = opts.cacheDir ?? process.env.GOLDEN_IMAGE_DIR ?? imageCacheDir();
  await mkdir(dir, { recursive: true });
  const dest = path.join(dir, image.file);
  const fetch = opts.downloadImpl ?? (async (url: string, d: string) => { await run("curl", ["-fL", "--retry", "3", "-o", d + ".tmp", url]); await run("mv", [d + ".tmp", d]); });
  for (let attempt = 0; attempt < 2; attempt++) {
    if (!existsSync(dest)) await fetch(image.url, dest);
    if ((await hashFile(dest, "sha512")) === expected) return { image, path: dest };
    if (attempt === 1) throw new Error(`golden image ${image.file} failed SHA512 verification twice (expected ${expected.slice(0, 16)}…); refusing to boot it`);
    await run("rm", ["-f", dest]).catch(() => undefined);
  }
  throw new Error("unreachable");
}

/**
 * Baked org-lab image (spec §3 "offline package story", option: baked golden
 * image). Built from the pinned Debian cloud image by
 * `scripts/build-catalog-image.mjs`, which apt-installs the union of base,
 * catalog, client and attacker packages, then records the artifact digest in
 * `golden/baked-images.json`. Runs prefer the baked image so configuration
 * never needs package egress; the manifest is the pin, the artifact is staged
 * (worker image / GOLDEN_IMAGE_DIR) like the base image cache.
 */
export const BAKED_IMAGE_NAME = "debian-12-catalog";
export const BAKED_CATALOG_VERSION = "arena-golden-debian12-catalog-3";
export const ROCKY_BAKED_IMAGE_NAME = "rocky-9-freeipa";
export const ROCKY_BAKED_CATALOG_VERSION = "arena-golden-rocky9-freeipa-1";

/** Rocky 9 FreeIPA base cloud images (GenericCloud), SHA256-pinned. */
export const ROCKY_GOLDEN_CATALOG_VERSION = "arena-golden-rocky9-1";
const ROCKY_CLOUD = "https://dl.rockylinux.org/pub/rocky/9/images";

/** Published SHA256 for the pinned Rocky GenericCloud artifacts. */
export const ROCKY_SHA256: Record<GuestArchName, string> = {
  x86_64: "92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8",
  aarch64: "24692a444f1f0b8bb95375c38c8b43f8099a115347623691be2c330b40c8a1fe",
};

export const ROCKY_GOLDEN_IMAGES: Record<GuestArchName, GoldenImage> = {
  x86_64: {
    guestArch: "x86_64", name: "rocky-9-generic", url: `${ROCKY_CLOUD}/x86_64/Rocky-9-GenericCloud.latest.x86_64.qcow2`,
    file: "Rocky-9-GenericCloud.latest.x86_64.qcow2", format: "qcow2",
    sha512: "",
    // SHA256 pin (Rocky publishes SHA256, not SHA512).
    digest: "",
  },
  aarch64: {
    guestArch: "aarch64", name: "rocky-9-generic", url: `${ROCKY_CLOUD}/aarch64/Rocky-9-GenericCloud.latest.aarch64.qcow2`,
    file: "Rocky-9-GenericCloud.latest.aarch64.qcow2", format: "qcow2",
    sha512: "",
    digest: "",
  },
};
for (const g of Object.values(ROCKY_GOLDEN_IMAGES)) {
  g.digest = `sha256:${ROCKY_SHA256[g.guestArch].slice(0, 16)}…/${ROCKY_GOLDEN_CATALOG_VERSION}`;
}

export function rockyGoldenImageFor(guestArch: GuestArchName): GoldenImage { return ROCKY_GOLDEN_IMAGES[guestArch]; }

/** Ensure the pinned Rocky base image is cached and SHA256-verified (no fallback). */
export async function ensureRockyGoldenImage(guestArch: GuestArchName, opts: { cacheDir?: string; downloadImpl?: (url: string, dest: string) => Promise<void> } = {}): Promise<{ image: GoldenImage; path: string }> {
  const image = rockyGoldenImageFor(guestArch);
  const expected = ROCKY_SHA256[guestArch];
  const dir = opts.cacheDir ?? process.env.GOLDEN_IMAGE_DIR ?? imageCacheDir();
  await mkdir(dir, { recursive: true });
  const dest = path.join(dir, image.file);
  const fetch = opts.downloadImpl ?? (async (url: string, d: string) => { await run("curl", ["-fL", "--retry", "3", "-o", d + ".tmp", url]); await run("mv", [d + ".tmp", d]); });
  for (let attempt = 0; attempt < 2; attempt++) {
    if (!existsSync(dest)) await fetch(image.url, dest);
    if ((await hashFile(dest, "sha256")) === expected) return { image, path: dest };
    if (attempt === 1) throw new Error(`rocky image ${image.file} failed SHA256 verification twice (expected ${expected.slice(0, 16)}…); refusing to boot it`);
    await run("rm", ["-f", dest]).catch(() => undefined);
  }
  throw new Error("unreachable");
}

export type GuestOsFamily = "debian" | "rocky";

export function guestOsFamily(os: string): GuestOsFamily {
  return /rocky/i.test(os) ? "rocky" : "debian";
}

/**
 * Package references recorded in the baked manifest are names only; the run
 * never boots an artifact whose package set cannot satisfy the catalog's
 * offline claim. The FreeIPA tier is verified by name (its server packages
 * are the whole point of the tier) plus the same SHA512 pin as Debian.
 */
export const ROCKY_FREEIPA_PACKAGES = [
  "ipa-server", "ipa-server-dns", "ipa-client", "krb5-workstation",
  "sssd", "sssd-tools", "nftables", "osquery",
];

/**
 * Virtual size of the baked catalog image. A qcow2 overlay created smaller
 * than its backing file truncates the partition table: the guest drops to
 * initramfs with "PARTUUID ... does not exist". Explicitly smaller disks are
 * rejected at design time and again before boot.
 */
export const MIN_VM_DISK_GB = 6;

export interface BakedImageEntry {
  file: string;
  sha512: string;
  packages: string[];
  builtAt: string;
  /** Digest of the pinned Debian cloud image this artifact was built from. */
  baseDigest: string;
}

export interface BakedImageManifest {
  version: 1;
  catalogVersion: string;
  images: Partial<Record<GuestArchName, BakedImageEntry>>;
}

/** Manifest lives beside the backend, not in dist; override for staged builds. */
export const bakedManifestPath = () =>
  process.env.ARENA_GOLDEN_MANIFEST ?? path.join(path.dirname(new URL(import.meta.url).pathname), "../../golden/baked-images.json");

/**
 * Rocky has a different catalog tier and package set, so it gets its own
 * manifest instead of sharing the Debian one (a single manifestVersion cannot
 * name both). The build script writes this file; runs resolve it only for a
 * Rocky host, and a missing artifact falls back to the pinned base exactly
 * like the Debian tier.
 */
export const rockyBakedManifestPath = () =>
  process.env.ARENA_ROCKY_GOLDEN_MANIFEST ?? path.join(path.dirname(new URL(import.meta.url).pathname), "../../golden/baked-rocky-images.json");

/** Parse + validate the manifest; a malformed pin is an error, never "no baked image". */
export function parseBakedManifest(raw: string): BakedImageManifest {
  const data = JSON.parse(raw) as Partial<BakedImageManifest>;
  if (data.version !== 1) throw new Error(`baked image manifest version ${String(data.version)} is not 1`);
  if (typeof data.catalogVersion !== "string" || !data.catalogVersion) throw new Error("baked image manifest has no catalogVersion");
  const images = data.images ?? {};
  for (const [arch, entry] of Object.entries(images)) {
    if (!entry || typeof entry.file !== "string" || !entry.file) throw new Error(`baked image ${arch} has no file`);
    if (typeof entry.sha512 !== "string" || !/^[0-9a-f]{128}$/.test(entry.sha512)) throw new Error(`baked image ${arch} has no valid SHA512`);
    if (!Array.isArray(entry.packages) || entry.packages.some((p) => typeof p !== "string")) throw new Error(`baked image ${arch} has no package list`);
    if (typeof entry.builtAt !== "string") throw new Error(`baked image ${arch} has no builtAt`);
    if (typeof entry.baseDigest !== "string") throw new Error(`baked image ${arch} has no baseDigest`);
  }
  return { version: 1, catalogVersion: data.catalogVersion, images };
}

export interface GoldenResolutionOpts {
  cacheDir?: string;
  manifestPath?: string;
  downloadImpl?: (url: string, dest: string) => Promise<void>;
  expectedSha512?: string;
  /** Guest OS family whose baked tier to prefer (defaults to Debian). */
  family?: GuestOsFamily;
}

/**
 * Baked image when the manifest pins one and the artifact is staged, else
 * null. A pinned-but-missing artifact falls back to the base image with a
 * warning (dev machines can still boot); a present-but-tampered artifact
 * throws — the platform never boots an image whose hash it has not verified.
 */
export async function ensureBakedImage(guestArch: GuestArchName, opts: GoldenResolutionOpts = {}): Promise<{ image: GoldenImage; path: string } | null> {
  const family = opts.family ?? "debian";
  const bakedName = family === "rocky" ? ROCKY_BAKED_IMAGE_NAME : BAKED_IMAGE_NAME;
  const manifestPath = opts.manifestPath ?? (family === "rocky" ? rockyBakedManifestPath() : bakedManifestPath());
  const raw = await readFile(manifestPath, "utf8").catch(() => null);
  if (!raw) return null;
  const manifest = parseBakedManifest(raw);
  const entry = manifest.images[guestArch];
  if (!entry) return null;
  if (manifest.catalogVersion !== (family === "rocky" ? ROCKY_BAKED_CATALOG_VERSION : BAKED_CATALOG_VERSION)) {
    return null;
  }
  if (family === "rocky") {
    // The manifest's package list is the offline claim; a Rocky artifact that
    // does not name the FreeIPA server packages cannot satisfy it and is
    // refused rather than booted (it would fall back to dnf over mgmt).
    const have = new Set(entry.packages);
    const missing = ROCKY_FREEIPA_PACKAGES.filter((p) => !have.has(p));
    if (missing.length) {
      throw new Error(`rocky baked image ${entry.file} is missing FreeIPA packages (${missing.join(", ")}); refusing to boot it`);
    }
    if (!entry.file.startsWith("rocky-")) {
      throw new Error(`rocky baked image entry ${entry.file} is not a Rocky artifact; refusing to boot it`);
    }
  } else if (entry.file.startsWith("rocky-")) {
    return null;
  }
  const dir = opts.cacheDir ?? process.env.GOLDEN_IMAGE_DIR ?? imageCacheDir();
  const file = path.join(dir, entry.file);
  if (!existsSync(file)) {
    const build = family === "rocky" ? "scripts/build-rocky-image.mjs" : "scripts/build-catalog-image.mjs";
    console.warn(`[images] ${entry.file} is pinned but not staged in ${dir}; run ${build} (falling back to the base image)`);
    return null;
  }
  const actual = await hashFile(file, "sha512");
  if (actual !== entry.sha512) {
    throw new Error(`baked image ${entry.file} failed SHA512 verification (expected ${entry.sha512.slice(0, 16)}…, got ${actual.slice(0, 16)}…); refusing to boot it`);
  }
  return {
    image: {
      guestArch, name: bakedName, url: "", file: entry.file, format: "qcow2", sha512: entry.sha512,
      digest: `sha512:${entry.sha512.slice(0, 16)}…/${manifest.catalogVersion}`,
    },
    path: file,
  };
}

/** Org-lab image for a run: baked catalog image when available, else the pinned cloud image. */
export async function resolveGoldenImage(guestArch: GuestArchName, opts: GoldenResolutionOpts = {}): Promise<{ image: GoldenImage; path: string }> {
  return (await ensureBakedImage(guestArch, opts)) ?? ensureGoldenImage(guestArch, opts);
}

/**
 * Rocky 9 FreeIPA tier resolution (P2). A FreeIPA server without the baked
 * server packages cannot satisfy the offline claim: a missing pin falls back
 * to the pinned Rocky base only when the caller accepts mgmt-time package
 * installs (build/scripts), while a present-but-wrong artifact is refused.
 * Returns null when no Rocky artifact is pinned.
 */
export async function ensureRockyFreeipaImage(guestArch: GuestArchName, opts: GoldenResolutionOpts = {}): Promise<{ image: GoldenImage; path: string } | null> {
  return ensureBakedImage(guestArch, { ...opts, family: "rocky" });
}

export function isLinuxOs(os: string): boolean {
  return /ubuntu|debian|linux|alpine|fedora|centos|rocky/i.test(os) && !/windows/i.test(os);
}

export function isWindowsOs(os: string): boolean { return /windows/i.test(os); }

/** Windows guests need a user-supplied licensed image (no download source). */
export function windowsImagePath(): string | null {
  const p = process.env.KVM_WINDOWS_IMAGE;
  return p && existsSync(p) ? p : null;
}

export function tinyImageFor(guestArch: "x86_64" | "aarch64"): TinyImage { return CATALOG[guestArch]; }

async function download(url: string, dest: string): Promise<string> {
  if (!existsSync(dest)) {
    await run("curl", ["-fL", "--retry", "3", "-o", dest + ".tmp", url]);
    await run("mv", [dest + ".tmp", dest]);
  }
  return dest;
}

export interface GuestRootfs { kernel: string; initramfs: string }

/**
 * Build the guest initramfs once per arch: minirootfs + an /init that mounts
 * proc/sys, prints the boot marker on the console, and execs a login shell.
 */
export async function ensureGuestRootfs(guestArch: "x86_64" | "aarch64"): Promise<GuestRootfs> {
  const img = tinyImageFor(guestArch);
  const dir = imageCacheDir();
  await mkdir(dir, { recursive: true });
  const kernel = await download(img.kernelUrl, path.join(dir, img.kernelFile));
  const rootfsTar = await download(img.rootfsUrl, path.join(dir, img.rootfsFile));
  const initramfs = path.join(dir, `initramfs-${guestArch}.gz`);
  if (!existsSync(initramfs)) {
    const stage = path.join(dir, `stage-${guestArch}`);
    await mkdir(stage, { recursive: true });
    await run("tar", ["-xzf", rootfsTar, "-C", stage]);
    await writeFile(path.join(stage, "init"), [
      "#!/bin/sh",
      "mount -t proc proc /proc 2>/dev/null",
      "mount -t sysfs sysfs /sys 2>/dev/null",
      "echo MUSEARENA-LINUX-BOOT $(uname -s) $(uname -m) $(cat /etc/alpine-release 2>/dev/null)",
      "echo 'login: root (tiny guest, no password in scope)'",
      "exec cttyhack sh",
      "",
    ].join("\n"), { mode: 0o755 });
    await run("sh", ["-c", `cd "${stage}" && find . | cpio -o -H newc 2>/dev/null | gzip > "${initramfs}"`]);
  }
  return { kernel, initramfs };
}

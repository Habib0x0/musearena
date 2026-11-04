/**
 * Build the baked org-lab golden image (T-16b, offline package story).
 *
 *   node scripts/build-catalog-image.mjs [--arch aarch64|x86_64] [--keep]
 *
 * Boots the pinned Debian cloud image once, apt-installs the union of every
 * package any machine profile can need (base + catalog + client + attacker),
 * powers off, compresses the artifact and pins its SHA512 in
 * `golden/baked-images.json`. Runs then prefer this image, so configuration
 * never needs package egress.
 *
 * Requires: native acceleration (kvm/hvf), the host-arch QEMU binary, UEFI
 * firmware for aarch64, and network egress during the build only. The build
 * is a release/operator step — workers consume the staged artifact
 * (GOLDEN_IMAGE_DIR or the same cache dir), never build at run time.
 */
import { spawn } from "node:child_process";
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import { detectHost, firmwareNearBinary, scoredVmAccel, uefiFirmwareFor } from "../dist/provisioner/kvm.js";
import { qemuRunArgs } from "../dist/provisioner/vm-lifecycle.js";
import {
  BAKED_CATALOG_VERSION, bakedManifestPath, ensureGoldenImage, hashFile, imageCacheDir, parseBakedManifest,
} from "../dist/provisioner/images.js";
import { writeSeedIso } from "../dist/provisioner/seed-iso.js";
import { allProvisionablePackages } from "../dist/configurator/profiles.js";

const run = promisify(execFile);
const args = process.argv.slice(2);
const keep = args.includes("--keep");
const archIdx = args.indexOf("--arch");
const archArg = archIdx >= 0 ? args[archIdx + 1] : undefined;
const host = detectHost();
if (args.includes("--arch") && !["aarch64", "x86_64"].includes(archArg)) throw new Error(`--arch must be aarch64 or x86_64`);
const guestArch = archArg ?? host.hostArch;
if (guestArch !== host.hostArch) {
  throw new Error(`cannot build ${guestArch} on a ${host.hostArch} host: the baked image needs native acceleration`);
}
const accel = scoredVmAccel(host);
if (!accel) throw new Error(`refusing to build on ${host.platform}/${host.arch}: ${host.reason}`);

const binary = guestArch === "aarch64" ? host.qemuArm : host.qemuX86;
if (!binary || !existsSync(binary)) throw new Error(`no ${guestArch} QEMU binary (looked for ${binary || "unset"})`);
const firmware = uefiFirmwareFor(guestArch) ?? firmwareNearBinary(binary, guestArch);
if (guestArch === "aarch64" && !firmware) throw new Error("aarch64 cloud images need EDK2 UEFI firmware (set QEMU_EDK2_AARCH64)");

const packages = allProvisionablePackages();
// A bake always starts from the pinned Debian cloud image, never from a
// previous bake.
const baseImage = await ensureGoldenImage(guestArch);

const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const workRoot = await mkdtemp(path.join(os.tmpdir(), "arena-bake-"));
const work = path.join(workRoot, "work.qcow2");
const iso = path.join(workRoot, "seed.iso");
// qemuRunArgs names the per-guest files after the guest hostId ("bake").
const serial = path.join(workRoot, "bake-serial.log");
const pidfile = path.join(workRoot, "bake.pid");
const outDir = imageCacheDir();
const outFile = `debian-12-catalog-${guestArch}.qcow2`;
const out = path.join(outDir, outFile);
const marker = `ARENA-BAKE-COMPLETE ${stamp}`;
let qemuPid = 0;

console.log(`[bake] host=${host.platform}/${host.arch} accel=${accel} guest=${guestArch}`);
console.log(`[bake] base=${baseImage.image.file} (${baseImage.image.digest})`);
console.log(`[bake] packages (${packages.length}): ${packages.join(" ")}`);

try {
  await mkdir(outDir, { recursive: true });
  await copyFile(baseImage.path, work);
  // Headroom for the catalog packages; cloud-init growpart expands the root.
  await run("qemu-img", ["resize", work, "6G"]);
  await writeSeedIso(iso, seedFiles(marker, packages, guestArch));

  const def = {
    hostId: "bake", name: "bake", role: "sensor", guestArch, binary,
    accel, memoryMb: 2048, cpus: 2,
  };
  // No SSH is needed for the bake; the hostfwd still has to bind, so pick a
  // port away from the lifecycle range's usual suspects.
  const sshHostPort = 24000 + Math.floor(Math.random() * 4000);
  const qemuArgs = qemuRunArgs(def, {
    stateDir: workRoot, overlay: work, seedIso: iso, sshHostPort, runId: `bake-${stamp}`, firmware,
  });
  console.log("[bake] booting base image (apt install follows)…");
  const child = spawn(binary, qemuArgs, { stdio: ["ignore", "pipe", "pipe"] });
  let qemuErr = "";
  child.stderr.on("data", (d) => { qemuErr += d; });
  const pid = await waitForPidfile(pidfile, 20_000).catch((e) => {
    throw new Error(`${e.message}; qemu stderr: ${qemuErr.slice(0, 800)}`);
  });
  qemuPid = pid;
  const deadline = Date.now() + 90 * 60_000;
  let log = "";
  while (Date.now() < deadline) {
    await sleep(3000);
    log = existsSync(serial) ? await readFile(serial, "utf8") : "";
    if (log.includes(marker)) break;
    if (!alive(pid)) throw new Error(`bake guest exited before ${marker} (serial tail: ${tail(log)})`);
  }
  if (!log.includes(marker)) throw new Error(`bake guest did not finish within 40 min (serial tail: ${tail(log)})`);
  console.log("[bake] packages installed; guest powered off");
  await waitForExit(pid, 5 * 60_000);
  child.unref();

  console.log("[bake] compressing artifact…");
  await run("qemu-img", ["convert", "-O", "qcow2", "-c", work, out], { maxBuffer: 16 * 1024 * 1024 });
  const sha512 = await hashFile(out, "sha512");
  console.log(`[bake] artifact ${out} sha512:${sha512.slice(0, 16)}…`);

  const manifestPath = bakedManifestPath();
  const existing = existsSync(manifestPath) ? parseBakedManifest(await readFile(manifestPath, "utf8")) : null;
  const manifest = {
    version: 1,
    catalogVersion: BAKED_CATALOG_VERSION,
    images: {
      ...(existing?.images ?? {}),
      [guestArch]: { file: outFile, sha512, packages, builtAt: new Date().toISOString(), baseDigest: baseImage.image.digest },
    },
  };
  await mkdir(path.dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`[bake] pinned ${manifestPath}`);
  console.log(JSON.stringify({ arch: guestArch, file: out, sha512, packages: packages.length }));
} finally {
  // Never let a failed bake leak the guest.
  if (qemuPid && alive(qemuPid)) { try { process.kill(qemuPid, "SIGKILL"); } catch { /* gone */ } }
  if (!keep) await rm(workRoot, { recursive: true, force: true });
  else console.log(`[bake] kept work dir ${workRoot}`);
}

function seedFiles(marker, pkgs, guestArch = "aarch64") {
  const meta = [
    `instance-id: arena-bake-${Date.now().toString(36)}`,
    "local-hostname: arena-bake",
    "network:",
    "  version: 2",
    "  ethernets:",
    "    all-en:",
    "      match:",
    '        name: "en*"',
    "      dhcp4: true",
    "",
  ].join("\n");
  const user = [
    "#cloud-config",
    "hostname: arena-bake",
    "preserve_hostname: false",
    "runcmd:",
    "  - |",
    "    exec > /dev/console 2>&1",
    "    set -e",
    "    export DEBIAN_FRONTEND=noninteractive",
    '    echo "postfix postfix/main_mailer_type select No configuration" | debconf-set-selections',
    '    echo "slapd slapd/no_configuration boolean true" | debconf-set-selections',
    "    apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 update",
    "    apt-get install -y curl ca-certificates",
    // osquery is not in Debian; it comes from the vendor repo. The key is
    // fetched at build time only — the artifact is hash-pinned afterwards.
    "    curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg -o /etc/apt/trusted.gpg.d/osquery.asc",
    "    echo 'deb [signed-by=/etc/apt/trusted.gpg.d/osquery.asc] https://pkg.osquery.io/deb deb main' > /etc/apt/sources.list.d/osquery.list",
    "    apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 update",
    `    apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 install -y ${pkgs.join(" ")}`,
    // Gitea has no Debian package; the official binary is downloaded at BUILD
    // time (the artifact is hash-pinned afterwards), so guests never need
    // egress for it.
    `    curl -fsSL -o /usr/local/bin/gitea https://dl.gitea.com/gitea/1.22.6/gitea-1.22.6-linux-${guestArch === "aarch64" ? "arm64" : "amd64"}`,
    "    chmod 755 /usr/local/bin/gitea",
    "    /usr/local/bin/gitea --version",
    "    apt-get clean",
    "    rm -rf /var/lib/apt/lists/*",
    `    echo "${marker}"`,
    "    sync",
    "    poweroff",
    "",
  ].join("\n");
  return { "meta-data": meta, "user-data": user, "network-config": "" };
}

function alive(pid) { try { process.kill(pid, 0); return true; } catch { return false; } }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function tail(s) { return JSON.stringify((s ?? "").slice(-1200)); }

async function waitForPidfile(file, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (existsSync(file)) {
      const pid = Number((await readFile(file, "utf8")).trim());
      if (Number.isFinite(pid) && pid > 0) return pid;
    }
    await sleep(100);
  }
  throw new Error(`qemu pidfile ${file} did not appear within ${timeoutMs}ms`);
}

async function waitForExit(pid, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!alive(pid)) return;
    await sleep(500);
  }
  try { process.kill(pid, "SIGKILL"); } catch { /* gone */ }
  throw new Error(`bake guest pid ${pid} did not exit after poweroff`);
}

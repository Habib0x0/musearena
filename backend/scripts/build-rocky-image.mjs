/**
 * Build the baked Rocky 9 FreeIPA golden image (P2 offline tier).
 *
 *   node scripts/build-rocky-image.mjs [--arch aarch64|x86_64] [--keep]
 *
 * Boots the pinned Rocky GenericCloud image once, dnf-installs the FreeIPA
 * server package set, powers off, compresses the artifact and pins its SHA512
 * in `golden/baked-rocky-images.json`. A FreeIPA server then configures with
 * `ipa-server-install` only; `profile-install` finds every package already
 * present and never reaches the network at configure time.
 *
 * Requires: native acceleration (kvm/hvf), the host-arch QEMU binary, UEFI
 * firmware for aarch64, and network egress during the build only. Workers
 * consume the staged artifact (GOLDEN_IMAGE_DIR), never build at run time.
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
  ROCKY_FREEIPA_PACKAGES, ROCKY_BAKED_CATALOG_VERSION, ensureRockyGoldenImage,
  hashFile, imageCacheDir, parseBakedManifest, rockyBakedManifestPath,
} from "../dist/provisioner/images.js";
import { writeSeedIso } from "../dist/provisioner/seed-iso.js";

const run = promisify(execFile);
const args = process.argv.slice(2);
const keep = args.includes("--keep");
const archIdx = args.indexOf("--arch");
const archArg = archIdx >= 0 ? args[archIdx + 1] : undefined;
const host = detectHost();
if (args.includes("--arch") && !["aarch64", "x86_64"].includes(archArg)) throw new Error("--arch must be aarch64 or x86_64");
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

// The bake must cover exactly what a Rocky FreeIPA server profile re-verifies
// plus the packages the Rocky tier manifest promises. Dependencies (bind,
// dogtag, 389-ds, firewalld) come in through dnf.
const packages = [...new Set([
  ...ROCKY_FREEIPA_PACKAGES,
  "openssh-server", "audit", "chrony", "curl", "jq", "bind-utils",
  "iputils", "iptables-nft", "rsyslog",
])].sort();

const baseImage = await ensureRockyGoldenImage(guestArch);
const stamp = new Date().toISOString().replace(/[:.]/g, "-");
const workRoot = await mkdtemp(path.join(os.tmpdir(), "arena-rocky-bake-"));
const work = path.join(workRoot, "work.qcow2");
const iso = path.join(workRoot, "seed.iso");
const serial = path.join(workRoot, "bake-serial.log");
const pidfile = path.join(workRoot, "bake.pid");
const outDir = imageCacheDir();
const outFile = `rocky-9-freeipa-${guestArch}.qcow2`;
const out = path.join(outDir, outFile);
const marker = `ARENA-ROCKY-BAKE-COMPLETE ${stamp}`;
let qemuPid = 0;

console.log(`[rocky-bake] host=${host.platform}/${host.arch} accel=${accel} guest=${guestArch}`);
console.log(`[rocky-bake] base=${baseImage.image.file} (${baseImage.image.digest})`);
console.log(`[rocky-bake] packages (${packages.length}): ${packages.join(" ")}`);

try {
  await mkdir(outDir, { recursive: true });
  await copyFile(baseImage.path, work);
  // The Rocky base is 10G; FreeIPA packages fit without growing the virtual
  // size. Keeping it at 10G means a 12G FreeIPA overlay remains valid.
  await writeSeedIso(iso, seedFiles(marker, packages));

  const def = {
    hostId: "bake", name: "bake", role: "sensor", guestArch, binary,
    accel, memoryMb: 4096, cpus: 2,
  };
  const sshHostPort = 24000 + Math.floor(Math.random() * 4000);
  const qemuArgs = qemuRunArgs(def, {
    stateDir: workRoot, overlay: work, seedIso: iso, sshHostPort, runId: `rocky-bake-${stamp}`, firmware,
  });
  console.log("[rocky-bake] booting base image (dnf install follows)…");
  const child = spawn(binary, qemuArgs, { stdio: ["ignore", "pipe", "pipe"] });
  let qemuErr = "";
  child.stderr.on("data", (d) => { qemuErr += d; });
  const pid = await waitForPidfile(pidfile, 20_000).catch((e) => {
    throw new Error(`${e.message}; qemu stderr: ${qemuErr.slice(0, 800)}`);
  });
  qemuPid = pid;
  const deadline = Date.now() + 75 * 60_000;
  let log = "";
  while (Date.now() < deadline) {
    await sleep(3000);
    log = existsSync(serial) ? await readFile(serial, "utf8") : "";
    if (log.includes(marker)) break;
    if (!alive(pid)) throw new Error(`bake guest exited before ${marker} (serial tail: ${tail(log)})`);
  }
  if (!log.includes(marker)) throw new Error(`bake guest did not finish within 75 min (serial tail: ${tail(log)})`);
  console.log("[rocky-bake] packages installed; guest powered off");
  await waitForExit(pid, 5 * 60_000);
  child.unref();

  console.log("[rocky-bake] compressing artifact…");
  await run("qemu-img", ["convert", "-O", "qcow2", "-c", work, out], { maxBuffer: 16 * 1024 * 1024 });
  const sha512 = await hashFile(out, "sha512");
  console.log(`[rocky-bake] artifact ${out} sha512:${sha512.slice(0, 16)}…`);

  const manifestPath = rockyBakedManifestPath();
  const existing = existsSync(manifestPath) ? parseBakedManifest(await readFile(manifestPath, "utf8")) : null;
  const manifest = {
    version: 1,
    catalogVersion: ROCKY_BAKED_CATALOG_VERSION,
    images: {
      ...(existing?.images ?? {}),
      [guestArch]: { file: outFile, sha512, packages, builtAt: new Date().toISOString(), baseDigest: baseImage.image.digest },
    },
  };
  await mkdir(path.dirname(manifestPath), { recursive: true });
  await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  console.log(`[rocky-bake] pinned ${manifestPath}`);
  console.log(JSON.stringify({ arch: guestArch, file: out, sha512, packages: packages.length }));
} finally {
  if (qemuPid && alive(qemuPid)) { try { process.kill(qemuPid, "SIGKILL"); } catch { /* gone */ } }
  if (!keep) await rm(workRoot, { recursive: true, force: true });
  else console.log(`[rocky-bake] kept work dir ${workRoot}`);
}

function seedFiles(marker, pkgs) {
  const meta = [
    `instance-id: arena-rocky-bake-${Date.now().toString(36)}`,
    "local-hostname: arena-rocky-bake",
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
    "hostname: arena-rocky-bake",
    "preserve_hostname: false",
    "runcmd:",
    "  - |",
    "    exec > /dev/console 2>&1",
    "    set -e",
    // osquery has no Rocky base package; the vendor RPM repo is added at
    // build time only, so the baked guest has no runtime repo dependency.
    "    curl -fsSL https://pkg.osquery.io/rpm/GPG -o /etc/pki/rpm-gpg/RPM-GPG-KEY-osquery",
    "    cat > /etc/yum.repos.d/osquery.repo <<'EOF'",
    // Keep every heredoc line inside the YAML literal block (4 spaces);
    // an unindented line ends `runcmd` and cloud-init drops the whole script.
    "    [osquery-s3-rpm-repo]",
    "    name=osquery RPM repository - $basearch",
    "    baseurl=https://pkg.osquerypackages.com/rpm/$basearch/",
    "    enabled=1",
    "    gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-osquery",
    "    gpgcheck=1",
    "    EOF",
    "    dnf -y makecache",
    `    dnf -y install ${pkgs.join(" ")}`,
    `    for p in ${pkgs.join(" ")}; do rpm -q "$p" >/dev/null 2>&1 || { echo "rocky-bake: missing $p"; exit 1; }; done`,
    "    dnf clean all",
    "    rm -rf /var/cache/dnf",
    `    echo "${marker}"`,
    "    sync",
    "    poweroff",
    "",
  ].join("\n");
  return { "meta-data": meta, "user-data": user, "network-config": "" };
}

function alive(pid) { try { process.kill(pid, 0); return true; } catch { return false; } }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function tail(s) { return JSON.stringify((s ?? "").slice(-1600)); }

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

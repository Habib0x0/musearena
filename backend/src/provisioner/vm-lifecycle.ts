import { execFile, spawn, type ChildProcess } from "node:child_process";
import { connect as netConnect } from "node:net";
import { existsSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import type { EnvironmentSpec } from "@musearena/shared";
import { resolveGoldenImage, ensureRockyFreeipaImage, ensureRockyGoldenImage, guestOsFamily, type GoldenImage, type GuestOsFamily } from "./images.js";
import { detectHost, firmwareNearBinary, scoredVmAccel, uefiFirmwareFor, vmPlanFor, type VmDef } from "./kvm.js";
import { writeSeedIso } from "./seed-iso.js";
import { labHubPortFor, labPlanFor, labSegmentsFor, nicMac, type SegmentAttachment } from "./lab-network.js";

const run = promisify(execFile);

/**
 * Persistent VM lifecycle for org labs (T-15b).
 *
 * Each run gets a state directory (`<stateRoot>/kvm/<runId>/`) holding one
 * copy-on-write qcow2 overlay per host (backed by the hash-verified Debian
 * golden image), a NoCloud seed ISO (hostname, user, SSH key, run
 * identity), serial console log, pidfile, and a `vms.json` registry.
 * The registry is what deploy, teardown, the orphan sweeper and drift
 * agree on — QEMU has no Docker-style name lookup.
 *
 * Networking (bridges/taps) is deliberately NOT here yet: guests start
 * with user-mode networking so lifecycle semantics (start/stop/destroy,
 * overlays, state) can be proven anywhere, including an HVF dev host.
 * Every guest also gets a lab NIC (T-15) on the run's L2 segment, so
 * `netMode` says whether guests can reach each other, not just the host.
 */

export type VmNetMode = "user" | "lab";

export interface VmSeedCore {
  hostname: string;
  sshAuthorizedKey: string;
  /** Extra `/etc/arena/identity` content; injected keys are visible in `user-data`. */
  identity: Record<string, string>;
}

export interface VmSeed extends VmSeedCore {
  /** Management NIC MAC: the base netplan matches it instead of `en*`. */
  mgmtMac: string;
  /** Lab NIC (T-15): static address on the run's segment, no default route. */
  lab?: { address: string; prefix: number; mac: string };
  /** Zone NICs (P1b): one static address per segment the host touches. When
   * present it replaces `lab`; the first entry is the host's primary address. */
  labs?: { segment: string; address: string; prefix: number; mac: string; routes?: { to: string; via: string }[] }[];
}

export interface VmInstanceState {
  hostId: string;
  profile: string;
  pid: number;
  overlay: string;
  seedIso: string;
  goldenDigest: string;
  /** Image tier actually booted (`debian-12-catalog` when the baked pin is staged). */
  imageName?: string;
  accel: string;
  netMode: VmNetMode;
  /** Lab L2 address (T-15); absent on registries written before the lab NIC. */
  lab?: { address: string; prefix: number };
  /** Zone segment addresses (P1b); absent on v1 flat-segment registries. The
   * first entry is the primary address and mirrors `lab`. */
  labs?: { segment: string; address: string; prefix: number }[];
  startedAt: string;
  stoppedAt?: string;
  /** pids whose spawn this process performed; empty after a re-read from disk */
  inProcess: boolean;
  /**
   * Management-plane SSH endpoint (QEMU user-net hostfwd on loopback).
   * The configurer reaches the guest only through this; lab networking
   * (T-16/T-18) will add the guest's lab address alongside it.
   */
  ssh?: { host: string; port: number; user: string; privateKeyPath: string };
}

/**
 * The image pin each guest actually booted, for durable run records: the
 * registry that carries `imageName`/`goldenDigest` is deleted at teardown,
 * so deploy stamps these into the deployment record while they exist.
 * Rows missing either field (pre-tier registries) pin nothing.
 */
export function guestImagePins(state: VmRunState): Record<string, { name: string; digest: string }> {
  const pins: Record<string, { name: string; digest: string }> = {};
  for (const inst of Object.values(state.instances)) {
    if (inst.imageName && inst.goldenDigest) pins[inst.hostId] = { name: inst.imageName, digest: inst.goldenDigest };
  }
  return pins;
}

export interface VmRunState {
  runId: string;
  specName: string;
  netMode: VmNetMode;
  /** Per-run lab hub process (T-15); absent on user-net-only runs. */
  labHub?: { port: number; pid: number };
  /** Per-segment hub processes (P1b); absent on v1 flat-segment runs. */
  labHubs?: { segment: string; port: number; pid: number }[];
  instances: Record<string, VmInstanceState>;
}

export interface LifecycleOpts {
  stateRoot: string;
  runId: string;
  /** qemu-img binary; overridable for tests. */
  qemuImg?: string;
  /** External ISO writer; when unset the built-in pure-Node writer is used. */
  isoTool?: string;
  /** startVm deadline for the SSH/cloud-init serial marker, ms. */
  readyTimeoutMs?: number;
  /** Test/operator override for the QEMU binary (defaults to the host plan). */
  qemuBinary?: string;
  /** Pre-verified golden image; skips the cache/download path when set. */
  golden?: { image: GoldenImage; path: string };
  /** Pre-verified image per guest OS family (P2: Rocky server + Debian members). */
  goldenByFamily?: Partial<Record<GuestOsFamily, { image: GoldenImage; path: string }>>;
  /** Attach the lab NIC (T-15). Default on; false reproduces the user-net-only guest. */
  labNetwork?: boolean;
}

export const vmStateDir = (opts: Pick<LifecycleOpts, "stateRoot" | "runId">) => path.join(opts.stateRoot, "kvm", opts.runId);
const registryPath = (dir: string) => path.join(dir, "vms.json");

/** Per-run SSH keypair for configurer access (private key never leaves the state dir, 0600). */
export async function ensureRunSshKey(dir: string): Promise<{ privateKey: string; publicKey: string }> {
  const priv = path.join(dir, "id_ed25519");
  const pub = `${priv}.pub`;
  if (!existsSync(priv)) await run("ssh-keygen", ["-t", "ed25519", "-N", "", "-C", "musearena-run", "-f", priv]);
  if (!existsSync(pub)) await run("ssh-keygen", ["-y", "-f", priv]).then(async ({ stdout }) => writeFile(pub, stdout.trim() + "\n", { mode: 0o644 }));
  return { privateKey: priv, publicKey: (await readFile(pub, "utf8")).trim() };
}

/** Render the NoCloud seed for one host. The run's `spec.seed` is NOT a secret; SSH access is the keypair. */
export function seedFilesFor(input: { runId: string; specName: string; seed: string; host: VmSeed }): Record<string, string> {
  // Match NICs by MAC rather than `en*`. Lab NICs are declared static in the
  // network config itself: a bare `ip addr replace` in runcmd is undone on
  // NetworkManager guests (Rocky), where NM's default DHCP profile for the
  // unmanaged lab NIC times out and flushes the address. Declaring the lab
  // NIC here makes netplan (Debian) and NM (Rocky) both own it persistently.
  // Labs (P1b multi-NIC) replace the single lab entry; first is primary.
  const labNics = input.host.labs ?? (input.host.lab ? [{ segment: "lab", ...input.host.lab }] : []);
  const meta = [
    `instance-id: ${input.runId}-${input.host.hostname}`,
    `local-hostname: ${input.host.hostname}`,
    "",
  ].join("\n");
  // NoCloud network config lives in its own seed file; a `network:` block in
  // meta-data is ignored by some renderers (Rocky/NetworkManager), which then
  // DHCP-profiles the lab NIC, times out, and flushes the runcmd address.
  const network = [
    "version: 2",
    "ethernets:",
    "  mgmt0:",
    "    match:",
    `      macaddress: "${input.host.mgmtMac}"`,
    "    dhcp4: true",
    ...labNics.flatMap((nic, i) => [
      `  lab${i}:`,
      "    match:",
      `      macaddress: "${nic.mac}"`,
      "    dhcp4: false",
      "    addresses:",
      `      - ${nic.address}/${nic.prefix}`,
      ...((nic as { routes?: { to: string; via: string }[] }).routes?.length ? [
        "    routes:",
        ...(nic as { routes?: { to: string; via: string }[] }).routes!.flatMap((r) => [`      - to: ${r.to}`, `        via: ${r.via}`]),
      ] : []),
    ]),
    "",
  ].join("\n");
  const user = [
    "#cloud-config",
    `hostname: ${input.host.hostname}`,
    "preserve_hostname: false",
    "users:",
    "  - name: arena",
    "    groups: [sudo]",
    "    shell: /bin/bash",
    "    sudo: ALL=(ALL) NOPASSWD:ALL",
    "    lock_passwd: true",
    `    ssh_authorized_keys:`,
    `      - ${input.host.sshAuthorizedKey}`,
    "write_files:",
    "  - path: /etc/arena/identity",
    "    permissions: '0644'",
    "    content: |",
    ...Object.entries(input.host.identity).map(([k, v]) => `      ${k}=${v}`),
    "runcmd:",
    // One address line per lab NIC. Each resolves its own interface through
    // sysfs by MAC, so interface names never matter. `labs` (P1b multi-NIC)
    // replaces the single `lab` entry; the first lab is the primary address.
    ...((input.host.labs ?? (input.host.lab ? [{ segment: "lab", ...input.host.lab }] : [])).flatMap((nic) => [
      `  - 'IF=$(for d in /sys/class/net/*; do [ "$(cat "$d/address")" = "${nic.mac}" ] && basename "$d"; done); [ -n "$IF" ] && ip addr replace ${nic.address}/${nic.prefix} dev "$IF" && ip link set "$IF" up'`,
      ...((nic as { routes?: { to: string; via: string }[] }).routes ?? []).map((r) =>
        `  - 'IF=$(for d in /sys/class/net/*; do [ "$(cat "$d/address")" = "${nic.mac}" ] && basename "$d"; done); [ -n "$IF" ] && ip route replace ${r.to} via ${r.via} dev "$IF"'`),
    ])),
    "  - mkdir -p /etc/arena && printf '%s\\n' 'MUSEARENA-GUEST-READY' > /dev/console || true",
    "",
  ].join("\n");
  return { "meta-data": meta, "user-data": user, "network-config": network };
}

async function buildSeedIso(dir: string, hostId: string, files: Record<string, string>, isoTool?: string): Promise<string> {
  const seedDir = path.join(dir, `${hostId}-seed`);
  await mkdir(seedDir, { recursive: true });
  for (const [name, body] of Object.entries(files)) await writeFile(path.join(seedDir, name), body, { mode: 0o644 });
  const iso = path.join(dir, `${hostId}-seed.iso`);
  // NoCloud requires the `cidata` volume label; default is the built-in writer.
  if (isoTool) await run(isoTool, ["-output", iso, "-volid", "cidata", "-joliet", "-rock", seedDir]);
  else await writeSeedIso(iso, files);
  return iso;
}

export interface RunningVm { def: VmDef; state: VmInstanceState; child?: ChildProcess }

async function loadRegistry(dir: string): Promise<VmRunState | null> {
  try { return JSON.parse(await readFile(registryPath(dir), "utf8")) as VmRunState; } catch { return null; }
}

/** Read a run's VM registry from disk (deploy/teardown/sweeper entry point). */
export async function readVmRunState(lifecycle: Pick<LifecycleOpts, "stateRoot" | "runId">): Promise<VmRunState | null> {
  return loadRegistry(vmStateDir(lifecycle));
}

async function saveRegistry(dir: string, state: VmRunState): Promise<void> {
  await writeFile(registryPath(dir), JSON.stringify(state, null, 2) + "\n", { mode: 0o600 });
}

const alive = (pid: number) => { try { process.kill(pid, 0); return true; } catch { return false; } };

async function waitForPidfile(file: string, timeoutMs: number): Promise<number> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const txt = await readFile(file, "utf8").catch(() => "");
    const pid = Number(txt.trim());
    if (Number.isFinite(pid) && pid > 0) return pid;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`qemu pidfile ${file} did not appear within ${timeoutMs}ms`);
}

/**
 * QEMU args for a persistent run guest. Networking is user-mode until the
 * lab bridge lands (T-16/T-18); the guest is still a real, persistent
 * Debian system reachable for configuration via SSH hostfwd.
 */
export function qemuRunArgs(def: VmDef, opts: { stateDir: string; overlay: string; seedIso: string; sshHostPort: number; runId: string; firmware?: string | null; lab?: { hubPort: number }; labs?: { hubPort: number; mac: string }[] }): string[] {
  const args = [
    "-name", `musearena-${opts.runId}-${def.hostId}`,
    "-machine", def.guestArch === "aarch64" ? "virt" : "q35",
    "-accel", def.accel,
    // KVM needs the host CPU model too: on aarch64 `virt` the default is
    // cortex-a57, which not every arm64 KVM host supports.
    ...(def.accel === "hvf" || def.accel === "kvm" ? ["-cpu", "host"] : []),
    ...(opts.firmware ? ["-bios", opts.firmware] : []),
    "-m", String(def.memoryMb),
    "-smp", String(def.cpus),
    "-drive", `file=${opts.overlay},format=qcow2,if=virtio`,
    "-drive", `file=${opts.seedIso},format=raw,if=virtio,readonly=on`,
    "-netdev", `user,id=net0,hostfwd=tcp:127.0.0.1:${opts.sshHostPort}-:22`,
    "-device", `virtio-net-pci,netdev=net0,mac=${nicMac(def.hostId, "mgmt")}`,
    // Lab segments: one socket NIC per zone segment the host touches (P1b).
    // The single-`lab` path is the v1 flat segment; `labs` replaces it, never
    // alongside it. netdev ids stay dense (net1, net2, …) per guest.
    ...(() => {
      const nics = opts.labs ?? (opts.lab ? [{ hubPort: opts.lab.hubPort, mac: nicMac(def.hostId, "lab") }] : []);
      return nics.flatMap((nic, i) => [
        "-netdev", `socket,id=net${i + 1},connect=127.0.0.1:${nic.hubPort}`,
        "-device", `virtio-net-pci,netdev=net${i + 1},mac=${nic.mac}`,
      ]);
    })(),
    "-serial", `file:${path.join(opts.stateDir, `${def.hostId}-serial.log`)}`,
    "-display", "none",
    "-daemonize",
    "-pidfile", path.join(opts.stateDir, `${def.hostId}.pid`),
  ];
  return args;
}

export interface StartRunResult { state: VmRunState; golden: GoldenImage }

/** Spawn the per-run lab hub and wait until it accepts connections. */
async function startLabHubProcess(port: number, runId: string): Promise<number> {
  const main = path.join(path.dirname(new URL(import.meta.url).pathname), "lab-hub-main.js");
  const child = spawn(process.execPath, [main, String(port), runId], { detached: true, stdio: "ignore" });
  child.unref();
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    const ok = await new Promise<boolean>((resolve) => {
      const probe = netConnect(port, "127.0.0.1");
      probe.once("connect", () => { probe.destroy(); resolve(true); });
      probe.once("error", () => resolve(false));
    });
    if (ok) return child.pid ?? 0;
    await new Promise((r) => setTimeout(r, 100));
  }
  try { child.kill("SIGKILL"); } catch { /* already gone */ }
  throw new Error(`lab hub for ${runId} did not listen on 127.0.0.1:${port}`);
}

export async function startRunVms(spec: EnvironmentSpec, lifecycle: LifecycleOpts, seedFor: (hostId: string, pubKey: string) => VmSeedCore): Promise<StartRunResult> {
  const host = detectHost();
  const accel = scoredVmAccel(host);
  if (!accel) throw new Error(`refusing persistent VM run on ${host.platform}/${host.arch}: ${host.reason} (scored VM runs require native KVM; dev hosts report hvf)`);
  const planned = vmPlanFor(spec, host);
  const plan = lifecycle.qemuBinary ? planned.map((d) => ({ ...d, binary: lifecycle.qemuBinary! })) : planned;
  if (!plan.length) throw new Error("spec has no VM instances to start");
  const isOrgV2 = (spec.topology.sites?.length ?? 0) > 0 || (spec.topology.zones?.length ?? 0) > 0;
  // v2 org specs attach per zone segment (one hub each); v1 flat labs keep the
  // single shared hub. The two shapes never mix in one run.
  const segments: SegmentAttachment[] = (lifecycle.labNetwork === false || !isOrgV2)
    ? []
    : labSegmentsFor(spec, lifecycle.runId);
  const labPlan = lifecycle.labNetwork === false || isOrgV2 ? [] : labPlanFor(spec, lifecycle.runId);
  const lab = new Map(labPlan.map((e) => [e.hostId, e]));
  const segByHost = new Map<string, SegmentAttachment[]>();
  for (const a of segments) segByHost.set(a.hostId, [...(segByHost.get(a.hostId) ?? []), a]);
  const dir = vmStateDir(lifecycle);
  await mkdir(dir, { recursive: true });
  const existing = await loadRegistry(dir);
  if (existing && Object.values(existing.instances).some((i) => alive(i.pid))) {
    throw new Error(`run ${lifecycle.runId} already has live VM pids; destroy it before starting again`);
  }
  // aarch64 cloud images boot only via UEFI; fail before creating anything.
  const firmware = new Map<string, string | null>();
  for (const def of plan) {
    const fw = uefiFirmwareFor(def.guestArch) ?? firmwareNearBinary(def.binary, def.guestArch);
    if (def.guestArch === "aarch64" && !fw) {
      throw new Error(`no EDK2 UEFI firmware for aarch64 guests (set QEMU_EDK2_AARCH64); cloud images cannot boot on 'virt' without it`);
    }
    firmware.set(def.hostId, fw);
  }
  const key = await ensureRunSshKey(dir);
  const state: VmRunState = { runId: lifecycle.runId, specName: spec.name, netMode: "user", instances: {} };
  // Every hub must be listening before any guest's socket netdev connects.
  if (segments.length) {
    const bySegment = new Map<string, number>();
    for (const a of segments) if (!bySegment.has(a.segment)) bySegment.set(a.segment, a.hubPort);
    state.labHubs = [];
    for (const [segment, port] of [...bySegment.entries()].sort(([a], [b]) => (a < b ? -1 : 1))) {
      const pid = await startLabHubProcess(port, lifecycle.runId);
      state.labHubs.push({ segment, port, pid });
    }
    state.netMode = "lab";
    // Persist before the guests start: a crash mid-start must leave a registry
    // the sweeper (and destroy) can find the hubs from.
    await saveRegistry(dir, state);
  } else if (labPlan.length) {
    // The lab hub must be listening before any guest's socket netdev connects.
    const hubPort = labHubPortFor(lifecycle.runId);
    const hubPid = await startLabHubProcess(hubPort, lifecycle.runId);
    state.labHub = { port: hubPort, pid: hubPid };
    state.netMode = "lab";
    // Persist before the guests start: a crash mid-start must leave a registry
    // the sweeper (and destroy) can find the hub from.
    await saveRegistry(dir, state);
  }
  const started: RunningVm[] = [];
  // Resolve per host family once (P2: a Rocky FreeIPA server beside Debian
  // members). A Rocky host prefers the baked FreeIPA tier, else the pinned
  // Rocky base (configure then installs over mgmt, and the plan says so);
  // a missing/wrong artifact still fails closed via ensureRockyFreeipaImage.
  const goldenCache = new Map<string, { image: GoldenImage; path: string }>();
  const osOf = new Map(spec.instances.map((i) => [i.hostId, i.os]));
  const resolveGolden = async (guestArch: string, hostId: string) => {
    const family = guestOsFamily(osOf.get(hostId) ?? "");
    const key = `${guestArch}:${family}`;
    const hit = goldenCache.get(key);
    if (hit) return hit;
    let resolved: { image: GoldenImage; path: string };
    if (lifecycle.goldenByFamily?.[family]) resolved = lifecycle.goldenByFamily[family]!;
    // A caller-supplied image is the Debian tier; it must never be booted as a
    // Rocky guest (no dnf, no FreeIPA). `Object.values` on a Map is always
    // empty, so the old guard handed it to every family.
    else if (lifecycle.golden && family === "debian") resolved = lifecycle.golden;
    else if (family === "rocky") resolved = (await ensureRockyFreeipaImage(guestArch as "x86_64" | "aarch64")) ?? await ensureRockyGoldenImage(guestArch as "x86_64" | "aarch64");
    else resolved = await resolveGoldenImage(guestArch as "x86_64" | "aarch64");
    goldenCache.set(key, resolved);
    return resolved;
  };
  try {
    for (const [idx, def] of plan.entries()) {
      const golden = await resolveGolden(def.guestArch, def.hostId);
      const overlay = path.join(dir, `${def.hostId}.qcow2`);
      const qemuImg = lifecycle.qemuImg ?? "qemu-img";
      if (!existsSync(overlay)) {
        if (def.diskGb) {
          // A smaller overlay truncates the backing image's partition table and
          // the guest drops to initramfs. Fail now instead of after a long SSH
          // retry loop. If the image size cannot be read the design-time gate
          // is still in force, so this stays best-effort.
          let baseGb = 0;
          try {
            const info = await run(qemuImg, ["info", "--output=json", golden.path]);
            baseGb = Math.ceil(Number(JSON.parse(info.stdout).virtualSize ?? 0) / 1024 ** 3);
          } catch { baseGb = 0; }
          if (baseGb > 0 && def.diskGb < baseGb) {
            throw new Error(`${def.hostId}: disk ${def.diskGb}G is smaller than the catalog image (${baseGb}G) — raise resources.diskGb`);
          }
        }
        const createArgs = ["create", "-f", "qcow2", "-b", golden.path, "-F", "qcow2", overlay, ...(def.diskGb ? [`${def.diskGb}G`] : [])];
        await run(qemuImg, createArgs);
      }
      const core = seedFor(def.hostId, key.publicKey);
      const endpoint = lab.get(def.hostId);
      const segNics = segByHost.get(def.hostId);
      const seed: VmSeed = {
        ...core,
        mgmtMac: nicMac(def.hostId, "mgmt"),
        ...(endpoint ? { lab: { address: endpoint.address, prefix: endpoint.prefix, mac: endpoint.mac } } : {}),
        ...(segNics ? { labs: segNics.map((a) => ({ segment: a.segment, address: a.address, prefix: a.prefix, mac: a.mac, ...(a.routesVia?.length ? { routes: a.routesVia.map((r) => ({ to: r.cidr, via: r.via })) } : {}) })) } : {}),
      };
      const iso = await buildSeedIso(dir, def.hostId, seedFilesFor({ runId: lifecycle.runId, specName: spec.name, seed: spec.seed, host: seed }), lifecycle.isoTool);
      const sshHostPort = 22000 + (Math.abs([...lifecycle.runId].reduce((a, c) => a + c.charCodeAt(0), 0)) % 20000) + idx;
      const args = qemuRunArgs(def, {
        stateDir: dir, overlay, seedIso: iso, sshHostPort, runId: lifecycle.runId, firmware: firmware.get(def.hostId),
        ...(endpoint ? { lab: { hubPort: endpoint.hubPort } } : {}),
        ...(segNics ? { labs: segNics.map((a) => ({ hubPort: a.hubPort, mac: a.mac })) } : {}),
      });
      const child = spawn(def.binary, args, { stdio: "ignore" });
      const pid = await waitForPidfile(path.join(dir, `${def.hostId}.pid`), 15_000).catch(async (e) => {
        child.kill("SIGKILL");
        throw e;
      });
      const primary = segNics?.[0];
      const inst: VmInstanceState = {
        hostId: def.hostId, profile: `${def.guestArch}/${def.memoryMb}MB/${def.cpus}cpu`, pid, overlay, seedIso: iso,
        goldenDigest: golden.image.digest, imageName: golden.image.name, accel: def.accel, netMode: (endpoint || primary) ? "lab" : "user",
        ...(endpoint ? { lab: { address: endpoint.address, prefix: endpoint.prefix } } : {}),
        ...(primary ? {
          lab: { address: primary.address, prefix: primary.prefix },
          labs: segNics!.map((a) => ({ segment: a.segment, address: a.address, prefix: a.prefix })),
        } : {}),
        startedAt: new Date().toISOString(), inProcess: true,
        ssh: { host: "127.0.0.1", port: sshHostPort, user: "arena", privateKeyPath: key.privateKey },
      };
      state.instances[def.hostId] = inst;
      await saveRegistry(dir, state);
      started.push({ def, state: inst, child });
    }
  } catch (err) {
    // Partial start must not leak running guests or the hubs. The registry may
    // not exist yet (the first guest can fail), so stop the hubs in memory too.
    for (const h of state.labHubs ?? []) if (alive(h.pid)) { try { process.kill(h.pid, "SIGTERM"); } catch { /* gone */ } }
    if (state.labHub && alive(state.labHub.pid)) { try { process.kill(state.labHub.pid, "SIGTERM"); } catch { /* gone */ } }
    await destroyRunVms(lifecycle).catch(() => undefined);
    throw err;
  }
  const golden = await resolveGolden(plan[0].guestArch, plan[0].hostId);
  return { state, golden: golden.image };
}

export async function stopRunVms(lifecycle: LifecycleOpts): Promise<VmRunState | null> {
  const dir = vmStateDir(lifecycle);
  const state = await loadRegistry(dir);
  if (!state) return null;
  for (const inst of Object.values(state.instances)) {
    if (!alive(inst.pid)) continue;
    try { process.kill(inst.pid, "SIGTERM"); } catch { /* already gone */ }
  }
  const deadline = Date.now() + 15_000;
  for (const inst of Object.values(state.instances)) {
    while (alive(inst.pid) && Date.now() < deadline) await new Promise((r) => setTimeout(r, 100));
    if (alive(inst.pid)) { try { process.kill(inst.pid, "SIGKILL"); } catch { /* gone */ } }
    inst.stoppedAt = new Date().toISOString();
  }
  // Hubs outlive the guests' sockets unless stopped explicitly: every
  // per-segment hub (P1b) and the legacy single hub (v1).
  for (const h of state.labHubs ?? []) {
    if (alive(h.pid)) { try { process.kill(h.pid, "SIGTERM"); } catch { /* gone */ } }
  }
  if (state.labHub && alive(state.labHub.pid)) {
    try { process.kill(state.labHub.pid, "SIGTERM"); } catch { /* gone */ }
  }
  await saveRegistry(dir, state);
  return state;
}

export async function destroyRunVms(lifecycle: LifecycleOpts): Promise<{ removed: boolean }> {
  const dir = vmStateDir(lifecycle);
  if (!existsSync(dir)) return { removed: false };
  await stopRunVms(lifecycle);
  await rm(dir, { recursive: true, force: true });
  return { removed: true };
}

/** List run state dirs under the state root (sweeper input; tolerates a missing root). */
export async function listVmRuns(stateRoot: string): Promise<VmRunState[]> {
  const base = path.join(stateRoot, "kvm");
  if (!existsSync(base)) return [];
  const { readdir } = await import("node:fs/promises");
  const out: VmRunState[] = [];
  for (const name of await readdir(base)) {
    const s = await loadRegistry(path.join(base, name));
    if (s) out.push(s);
  }
  return out;
}

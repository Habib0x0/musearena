import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, writeFile, readFile } from "node:fs/promises";
import path from "node:path";
import type { EnvironmentSpec } from "@musearena/shared";
import { ensureGuestRootfs, isLinuxOs, isWindowsOs, windowsImagePath } from "./images.js";

/**
 * KVM/QEMU backend (spec §2: provider `kvm`, per-instance `vm` runtime).
 * Linux + /dev/kvm gives real KVM and may stamp truth `kvm-vmi`. Everywhere
 * else QEMU still boots guests (hvf on Apple silicon for ARM guests, tcg
 * emulation otherwise) but truth is capped at `mirror-only` — the gate fails
 * closed rather than stamping a truth layer the host cannot provide.
 */
export type Accel = "kvm" | "hvf" | "tcg" | "none";

export type GuestArch = "x86_64" | "aarch64";

export interface HostVirt {
  platform: string;
  arch: string;
  /** Host CPU architecture in guest terms (arm64 → aarch64). */
  hostArch: GuestArch;
  accel: Accel;
  canKvmVmi: boolean;
  qemuX86: string | null;
  qemuArm: string | null;
  reason: string;
}

function which(bin: string): string | null {
  const dirs = (process.env.PATH ?? "").split(path.delimiter);
  for (const d of dirs) { const p = path.join(d, bin); if (existsSync(p)) return p; }
  for (const p of [`/opt/homebrew/bin/${bin}`, `/usr/local/bin/${bin}`, `/usr/bin/${bin}`]) if (existsSync(p)) return p;
  return null;
}

/** Node arch → guest arch; unknown node arches have no guest plan. */
export function guestArchOf(nodeArch: string): GuestArch | null {
  if (nodeArch === "x64") return "x86_64";
  if (nodeArch === "arm64") return "aarch64";
  return null;
}

/**
 * Pure host classification: `/dev/kvm` matters only on Linux and only
 * together with the QEMU binary for the HOST architecture (an aarch64 Linux
 * host with only qemu-system-x86_64 installed cannot run native guests).
 */
export function classifyHost(input: {
  platform: string; arch: string; hasKvmDevice: boolean;
  qemuX86: string | null; qemuArm: string | null;
}): HostVirt {
  const { platform, arch, hasKvmDevice, qemuX86, qemuArm } = input;
  const hostArch = guestArchOf(arch);
  const base = { platform, arch, qemuX86, qemuArm, canKvmVmi: false };
  if (platform === "linux" && hasKvmDevice && hostArch) {
    const binary = hostArch === "aarch64" ? qemuArm : qemuX86;
    if (binary) return { ...base, hostArch, accel: "kvm", canKvmVmi: true, reason: `Linux /dev/kvm with native ${hostArch} QEMU` };
    return { ...base, hostArch, accel: "tcg", reason: `Linux /dev/kvm present but qemu-system-${hostArch === "aarch64" ? "aarch64" : "x86_64"} not installed; native guests unavailable` };
  }
  if (platform === "darwin" && arch === "arm64" && qemuArm) return { ...base, hostArch: "aarch64", accel: "hvf", reason: "macOS Hypervisor.framework (hvf) for ARM guests, tcg for x86 guests; no KVM" };
  if (hostArch && (qemuX86 || qemuArm)) return { ...base, hostArch, accel: "tcg", reason: "QEMU emulation (tcg) only" };
  return { ...base, hostArch: hostArch ?? "x86_64", accel: "none", reason: "no QEMU binary found" };
}

export function detectHost(): HostVirt {
  return classifyHost({
    platform: process.platform,
    arch: process.arch,
    hasKvmDevice: process.platform === "linux" && existsSync("/dev/kvm"),
    qemuX86: which("qemu-system-x86_64"),
    qemuArm: which("qemu-system-aarch64"),
  });
}

/**
 * Acceleration a scored VM run may use on this host. Emulation (tcg) and
 * "no QEMU" return null: scored runs fail closed instead of silently
 * running slowly under emulation and stamping a score anyway.
 * Unscored dev boot probes may still use tcg (see bootProbeGuest).
 */
export function scoredVmAccel(host: HostVirt): "kvm" | "hvf" | null {
  return host.accel === "kvm" || host.accel === "hvf" ? host.accel : null;
}

/**
 * UEFI firmware (EDK2) for an arch, or null. aarch64 `virt` guests boot
 * cloud images only via UEFI; x86_64 `q35` ships SeaBIOS defaults that
 * boot the Debian cloud image without explicit firmware.
 */
export function uefiFirmwareFor(guestArch: GuestArch, env: NodeJS.ProcessEnv = process.env): string | null {
  const override = env[guestArch === "aarch64" ? "QEMU_EDK2_AARCH64" : "QEMU_EDK2_X86_64"];
  if (override) return existsSync(override) ? override : null;
  if (guestArch === "x86_64") return null; // SeaBIOS default on q35 boots the cloud image
  const candidates = [
    "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
    "/usr/local/share/qemu/edk2-aarch64-code.fd",
    "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
    "/usr/share/AAVMF/AAVMF_CODE.fd",
    "/usr/share/qemu/edk2-aarch64-code.fd",
  ];
  for (const p of candidates) if (existsSync(p)) return p;
  return null;
}

/** Discover EDK2 next to a QEMU binary (…/bin/qemu-system-* → …/share/qemu/edk2-*-code.fd). */
export function firmwareNearBinary(binary: string, guestArch: GuestArch): string | null {
  if (!binary || guestArch !== "aarch64") return null;
  const share = path.join(path.dirname(binary), "..", "share", "qemu", "edk2-aarch64-code.fd");
  return existsSync(share) ? share : null;
}

/** Gate: returns the truth layer this host may honestly stamp for the spec. */
export function assertKvmUsable(spec: EnvironmentSpec, host: HostVirt = detectHost()): { truthLayer: string } {
  if (host.accel === "none") throw new Error(`KVM provider unavailable on this host: ${host.reason}`);
  if (spec.truthLayer === "kvm-vmi" && !host.canKvmVmi) {
    throw new Error(`truthLayer kvm-vmi requires Linux /dev/kvm; this host offers ${host.accel} (${host.reason}). Use mirror-only or run on a KVM host.`);
  }
  // Linux guests use tiny images; Windows guests need a user-supplied licensed
  // image (KVM_WINDOWS_IMAGE). Anything else fails closed, never containerized.
  const unsupported = spec.instances.filter((i) => i.runtime === "vm" && !isLinuxOs(i.os) && !(isWindowsOs(i.os) && windowsImagePath()));
  if (unsupported.length) {
    throw new Error(`no guest image for: ${unsupported.map((i) => `${i.hostId} (${i.os})`).join(", ")} — Linux uses tiny Alpine images; Windows requires KVM_WINDOWS_IMAGE pointing at a licensed qcow2/ISO`);
  }
  return { truthLayer: host.canKvmVmi ? spec.truthLayer : "mirror-only" };
}

export interface VmDef {
  hostId: string;
  name: string;
  role: string;
  guestArch: GuestArch;
  binary: string;
  accel: Accel;
  memoryMb: number;
  cpus: number;
  /** Overlay virtual disk size; unset inherits the golden image's size. */
  diskGb?: number;
}

/**
 * Hybrid rule: `vm`-runtime instances with a guest image become VMs;
 * containers stay containers. Guest architecture follows the HOST (native
 * acceleration only): an OS string asking for the other arch fails closed
 * rather than silently emulating. Windows needs its licensed image and
 * takes its arch from the host too.
 */
export function vmPlanFor(spec: EnvironmentSpec, host: HostVirt = detectHost()): VmDef[] {
  return spec.instances.filter((i) => i.runtime === "vm" && (isLinuxOs(i.os) || (isWindowsOs(i.os) && windowsImagePath()))).map((inst) => {
    if (/arm|aarch/i.test(inst.os) && host.hostArch !== "aarch64") {
      throw new Error(`${inst.hostId}: OS "${inst.os}" needs an aarch64 guest but the host is ${host.hostArch}; cross-arch scored VMs are not supported`);
    }
    if (/(x86|amd64|x64)/i.test(inst.os) && host.hostArch !== "x86_64") {
      throw new Error(`${inst.hostId}: OS "${inst.os}" needs an x86_64 guest but the host is ${host.hostArch}; cross-arch scored VMs are not supported`);
    }
    const guestArch = host.hostArch;
    const binary = (guestArch === "aarch64" ? host.qemuArm : host.qemuX86) ?? "";
    const accel: Accel = scoredVmAccel(host) ?? host.accel;
    return {
      hostId: inst.hostId, name: inst.name, role: inst.role, guestArch, binary, accel,
      memoryMb: inst.resources?.memoryMb ?? 1024,
      cpus: inst.resources?.vcpu ?? 2,
      ...(inst.resources?.diskGb ? { diskGb: inst.resources.diskGb } : {}),
    };
  });
}

export function qemuArgsFor(def: VmDef, opts: { stateDir: string; bootImage?: string }): string[] {
  const drive = opts.bootImage ?? path.join(opts.stateDir, `${def.hostId}-boot.img`);
  return [
    "-machine", def.guestArch === "aarch64" ? "virt" : "pc",
    "-accel", def.accel,
    "-m", String(def.memoryMb),
    "-smp", String(def.cpus),
    "-drive", `file=${drive},format=raw,if=${def.guestArch === "aarch64" ? "virtio" : "ide"}`,
    "-serial", `file:${path.join(opts.stateDir, `${def.hostId}-serial.log`)}`,
    "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
    "-display", "none",
    "-pidfile", path.join(opts.stateDir, `${def.hostId}.pid`),
  ];
}

/** 512-byte x86 boot sector: prints the boot marker to COM1, then exits QEMU via isa-debug-exit. */
export function bootSectorImage(marker = "MUSEARENA-KVM-BOOT\r\n"): Buffer {
  const code: number[] = [];
  const push = (...b: number[]) => code.push(...b);
  push(0xFA);                       // cli
  push(0x31, 0xC0);                 // xor ax,ax
  push(0x8E, 0xD8);                 // mov ds,ax
  push(0x8E, 0xD0);                 // mov ss,ax
  push(0xBC, 0x00, 0x7C);           // mov sp,0x7c00
  // COM1 init: 9600 8N1
  push(0xBA, 0xFB, 0x03, 0xB0, 0x80, 0xEE); // LCR=0x80
  push(0xBA, 0xF8, 0x03, 0xB0, 0x01, 0xEE); // divisor=1
  push(0xBA, 0xF9, 0x03, 0x30, 0xC0, 0xEE); // IER=0
  push(0xBA, 0xFB, 0x03, 0xB0, 0x03, 0xEE); // LCR=0x03
  const msgAddrPatch = code.length + 1;
  push(0xBE, 0x00, 0x00);           // mov si,msg (patched below)
  const loopStart = code.length;
  push(0xAC);                       // lodsb
  push(0x84, 0xC0);                 // test al,al
  const jzPatch = code.length + 1;
  push(0x74, 0x00);                 // jz done (patched)
  push(0xBA, 0xF8, 0x03, 0xEE);     // out COM1,al
  push(0xEB, loopStart - (code.length + 2)); // jmp loop
  const done = code.length;
  code[jzPatch] = done - (jzPatch + 1);
  push(0xBA, 0xF4, 0x00, 0xB0, 0x10, 0xEE); // exit via isa-debug-exit (code 0x10)
  push(0xF4, 0xEB, 0xFD);           // hlt; jmp hlt
  const msgOffset = code.length;
  code[msgAddrPatch] = (0x7C00 + msgOffset) & 0xFF;
  code[msgAddrPatch + 1] = ((0x7C00 + msgOffset) >> 8) & 0xFF;
  for (const ch of marker) code.push(ch.charCodeAt(0));
  code.push(0x00);
  const img = Buffer.alloc(512, 0);
  Buffer.from(code).copy(img, 0);
  img[510] = 0x55; img[511] = 0xAA;
  return img;
}

export interface BootResult { hostId: string; accel: Accel; exitCode: number | null; serialLog: string }

export async function bootVm(def: VmDef, opts: { stateDir: string; timeoutMs?: number }): Promise<BootResult> {
  await mkdir(opts.stateDir, { recursive: true });
  const imgPath = path.join(opts.stateDir, `${def.hostId}-boot.img`);
  await writeFile(imgPath, bootSectorImage());
  const args = qemuArgsFor(def, { stateDir: opts.stateDir, bootImage: imgPath });
  const exitCode = await new Promise<number | null>((resolve) => {
    const child = spawn(def.binary, args, { stdio: "ignore" });
    const timer = setTimeout(() => { child.kill("SIGKILL"); resolve(null); }, opts.timeoutMs ?? 30000);
    child.on("error", () => { clearTimeout(timer); resolve(null); });
    child.on("exit", (c) => { clearTimeout(timer); resolve(c); });
  });
  const serialLog = await readFile(path.join(opts.stateDir, `${def.hostId}-serial.log`), "utf8").catch(() => "");
  return { hostId: def.hostId, accel: def.accel, exitCode, serialLog };
}

/** Proof-boot every planned VM (boot-sector guest). Real OS images replace the probe image per instance. */
export async function bootProbeGuest(opts: { stateDir: string }): Promise<BootResult> {
  const host = detectHost();
  const def: VmDef = { hostId: "probe", name: "probe", role: "probe", guestArch: "x86_64", binary: host.qemuX86 ?? "", accel: host.canKvmVmi ? "kvm" : "tcg", memoryMb: 64, cpus: 1 };
  return bootVm(def, opts);
}

export async function bootEnvironment(spec: EnvironmentSpec, opts: { stateDir: string; runId: string }): Promise<BootResult[]> {
  const host = detectHost();
  assertKvmUsable(spec, host);
  const plan = vmPlanFor(spec, host);
  const dir = path.join(opts.stateDir, opts.runId);
  const results: BootResult[] = [];
  for (const def of plan) results.push(await bootLinuxVm(def, { stateDir: dir }));
  return results;
}

/** Boot a real tiny Linux guest (Alpine kernel + minirootfs) and await its console marker. */
export async function bootLinuxVm(def: VmDef, opts: { stateDir: string; timeoutMs?: number }): Promise<BootResult> {
  await mkdir(opts.stateDir, { recursive: true });
  const { kernel, initramfs } = await ensureGuestRootfs(def.guestArch);
  const serialPath = path.join(opts.stateDir, `${def.hostId}-serial.log`);
  const args = [
    "-machine", def.guestArch === "aarch64" ? "virt" : "pc",
    "-accel", def.accel,
    ...(def.accel === "hvf" ? ["-cpu", "host"] : []),
    "-m", "256",
    "-smp", String(def.cpus),
    "-kernel", kernel,
    "-initrd", initramfs,
    "-append", def.guestArch === "aarch64" ? "console=ttyAMA0" : "console=ttyS0",
    "-serial", `file:${serialPath}`,
    "-display", "none",
    "-pidfile", path.join(opts.stateDir, `${def.hostId}.pid`),
  ];
  const exitCode = await new Promise<number | null>((resolve) => {
    const child = spawn(def.binary, args, { stdio: "ignore" });
    const deadline = Date.now() + (opts.timeoutMs ?? 90000);
    const poll = setInterval(async () => {
      const log = await readFile(serialPath, "utf8").catch(() => "");
      if (log.includes("MUSEARENA-LINUX-BOOT") || Date.now() > deadline) {
        clearInterval(poll);
        child.kill("SIGKILL");
        resolve(null);
      }
    }, 500);
    child.on("error", () => { clearInterval(poll); resolve(null); });
    child.on("exit", (c) => { clearInterval(poll); resolve(c); });
  });
  const serialLog = await readFile(serialPath, "utf8").catch(() => "");
  return { hostId: def.hostId, accel: def.accel, exitCode, serialLog };
}

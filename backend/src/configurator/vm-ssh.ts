import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { VmInstanceState } from "../provisioner/vm-lifecycle.js";
import type { InstanceTarget } from "./ansible.js";

const run = promisify(execFile);

/**
 * Guest SSH access for persistent VMs (T-15c): the management-plane channel
 * the configurer uses. Access is key-only against the per-run keypair in the
 * registry; host keys are run-scoped (accept-new into a throwaway known_hosts
 * the caller owns) because guests are cloned per run and destroyed.
 */

export interface GuestIdentity {
  hostname: string;
  user: string;
  runId: string;
  hostId: string;
  /** Raw /etc/arena/identity as KEY=VALUE pairs (beyond RUN_ID/HOST_ID). */
  extra: Record<string, string>;
}

export function parseGuestExecOutput(stdout: string): GuestIdentity {
  const pick = (key: string) => {
    const m = new RegExp(`^${key}=(.*)$`, "m").exec(stdout);
    if (!m) throw new Error(`guest exec output missing ${key}`);
    return m[1].trim();
  };
  const identityRaw = /(?:^|\n)IDENTITY-BEGIN\n([\s\S]*?)\nIDENTITY-END/.exec(stdout)?.[1] ?? "";
  const extra: Record<string, string> = {};
  for (const line of identityRaw.split("\n")) {
    const i = line.indexOf("=");
    if (i > 0) extra[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  }
  return { hostname: pick("HOSTNAME"), user: pick("USER"), runId: pick("RUN_ID"), hostId: pick("HOST_ID"), extra };
}

const IDENTITY_CMD = [
  'echo "HOSTNAME=$(hostname)"',
  'echo "USER=$(id -un)"',
  'echo "IDENTITY-BEGIN"',
  "cat /etc/arena/identity 2>/dev/null || true",
  'echo "IDENTITY-END"',
].join("; ");

export interface SshExecResult { stdout: string; stderr: string }

/** Run one command in the guest over the run's SSH endpoint (batch mode: never prompts). */
export async function execInGuest(inst: VmInstanceState, command: string, opts: { timeoutMs?: number; sshBinary?: string } = {}): Promise<SshExecResult> {
  if (!inst.ssh) throw new Error(`VM ${inst.hostId} has no SSH endpoint in the registry (pre-endpoint registry?)`);
  const { host, port, user, privateKeyPath } = inst.ssh;
  const res = await run(opts.sshBinary ?? "ssh", [
    "-i", privateKeyPath,
    "-p", String(port),
    "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "ConnectTimeout=10",
    "-o", "LogLevel=ERROR",
    `${user}@${host}`,
    command,
  ], { timeout: opts.timeoutMs ?? 30_000, maxBuffer: 4 * 1024 * 1024 })
    .catch((e: Error & { stdout?: string; stderr?: string }) => { throw new Error(`ssh to ${inst.hostId} (${user}@${host}:${port}) failed: ${(e.stderr || e.message).slice(0, 300)}`); });
  return { stdout: res.stdout, stderr: res.stderr };
}

/**
 * Readiness probe for a freshly started guest: SSH answers, and the guest's
 * own identity (hostname, user, seeded RUN_ID/HOST_ID) matches the registry.
 * This is the first real proof that cloud-init consumed our seed — serial
 * logs alone only prove the kernel booted.
 */
export async function probeGuestIdentity(inst: VmInstanceState, expected: { runId: string }, opts: { attempts?: number; delayMs?: number; timeoutMs?: number; sshBinary?: string } = {}): Promise<GuestIdentity> {
  const attempts = opts.attempts ?? 30;
  let lastError: Error | undefined;
  for (let i = 0; i < attempts; i++) {
    try {
      const { stdout } = await execInGuest(inst, IDENTITY_CMD, opts);
      const identity = parseGuestExecOutput(stdout);
      if (identity.runId !== expected.runId) throw new Error(`guest ${inst.hostId} reports RUN_ID=${identity.runId}, expected ${expected.runId}`);
      if (identity.hostId !== inst.hostId) throw new Error(`guest reports HOST_ID=${identity.hostId}, expected ${inst.hostId}`);
      if (identity.hostname !== inst.hostId) throw new Error(`guest hostname is ${identity.hostname}, expected ${inst.hostId}`);
      if (identity.user !== (inst.ssh?.user ?? "arena")) throw new Error(`guest user is ${identity.user}, expected ${inst.ssh?.user}`);
      return identity;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (i + 1 < attempts) await new Promise((r) => setTimeout(r, opts.delayMs ?? 2_000));
    }
  }
  throw new Error(`guest ${inst.hostId} not SSH-ready after ${attempts} attempts: ${lastError?.message ?? "unknown error"}`);
}

/**
 * Wait until the guest's lab NIC carries its registry address. The lab
 * address is applied by cloud-init's final stage, which runs after SSH is
 * already answering, so a lab-dependent step must wait rather than race it.
 */
export async function waitForLabAddress(inst: VmInstanceState, opts: { attempts?: number; delayMs?: number; timeoutMs?: number } = {}): Promise<string> {
  if (!inst.lab) throw new Error(`VM ${inst.hostId} has no lab address in the registry`);
  const attempts = opts.attempts ?? 45;
  const want = `${inst.lab.address}/${inst.lab.prefix}`;
  let last = "";
  for (let i = 0; i < attempts; i++) {
    last = (await execInGuest(inst, "ip -4 -o addr show", { timeoutMs: opts.timeoutMs ?? 15_000 }).catch((e: Error) => ({ stdout: e.message, stderr: "" }))).stdout;
    if (last.includes(want)) return want;
    if (i + 1 < attempts) await new Promise((r) => setTimeout(r, opts.delayMs ?? 2_000));
  }
  throw new Error(`VM ${inst.hostId}: lab address ${want} did not appear (last: ${last.trim().slice(0, 200)})`);
}

/** Configurer targets from registry state: SSH via the loopback hostfwd, key in the run state dir. */
export function vmTargetsFromState(state: { instances: Record<string, VmInstanceState> }): (InstanceTarget & { ssh?: VmInstanceState["ssh"] })[] {
  return Object.values(state.instances).map((inst) => ({
    hostId: inst.hostId,
    name: inst.hostId,
    connectVia: inst.ssh ? `${inst.ssh.user}@${inst.ssh.host}:${inst.ssh.port}` : inst.hostId,
    ...(inst.ssh ? { ssh: inst.ssh } : {}),
  }));
}

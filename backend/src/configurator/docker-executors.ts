import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { EnvironmentSpec, PlantedVuln } from "@musearena/shared";
import { parseLine, rawLines, type NormalizedEvent } from "../observability/docker-telemetry.js";
import { ingest } from "../observability/collector.js";
import { localStore, type EventStore } from "../observability/events.js";
import { ATTACKER_HOST_ID, containerName } from "../provisioner/names.js";
import { PLANTABLE, roleImage, WEAK_DB_PASSWORD, WEAK_DB_USER } from "../provisioner/roles.js";
import type { GateOptions } from "./gates.js";
import { bindStep, vulnTargetFor } from "./vuln-targets.js";

const run = promisify(execFile);

/**
 * LIVE gate executors for the local Docker runtime (Req §12.3, §3.3).
 * The action runs INSIDE the environment (canary on the host, proof from the
 * attacker container across the internal network). Verification reads the
 * target's own service log through the Docker daemon — the management plane,
 * unreachable from inside the env — and only a matching log line becomes a
 * ground-truth event. Exit codes are never trusted.
 */
export interface DockerExecOptions { store?: EventStore; docker?: string; settleMs?: number }

async function dockerExec(docker: string, container: string, cmd: string[], env: string[] = []): Promise<void> {
  const envArgs = env.flatMap((e) => ["-e", e]);
  await run(docker, ["exec", ...envArgs, container, ...cmd], { timeout: 30_000 }).catch(() => undefined); // outcome judged by telemetry
}

/** Container log lines (stdout+stderr) — the out-of-band sensor feed for this runtime. */
export async function containerLog(container: string, docker = "docker"): Promise<string[]> {
  const { stdout, stderr } = await run(docker, ["logs", container], { timeout: 30_000, maxBuffer: 32 * 1024 * 1024 });
  return `${stdout}\n${stderr}`.split("\n");
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function observe(docker: string, container: string, match: (line: string) => boolean, settleMs: number): Promise<string | undefined> {
  for (let i = 0; i < 5; i++) {
    const hit = (await containerLog(container, docker).catch(() => [])).find(match);
    if (hit) return hit;
    await sleep(settleMs);
  }
  return undefined;
}

export function dockerGateOptions(spec: EnvironmentSpec, opts: DockerExecOptions = {}): GateOptions {
  const store = opts.store ?? localStore;
  const docker = opts.docker ?? "docker";
  const settleMs = opts.settleMs ?? 1_000;
  const roleOf = (hostId: string) => spec.instances.find((i) => i.hostId === hostId)?.role ?? "";

  return {
    store,
    executeCanary: async (runId, hostId, marker) => {
      const role = roleOf(hostId);
      const telemetry = roleImage(role).telemetry;
      if (!telemetry) throw new Error(`host ${hostId} (role ${role}) has no telemetry source on the docker runtime`);
      const target = containerName(runId, hostId);
      if (telemetry === "apache-log") {
        await dockerExec(docker, target, ["curl", "-s", "-o", "/dev/null", `http://127.0.0.1/arena-canary/${marker}`]);
      } else {
        await dockerExec(docker, target, ["psql", "-U", WEAK_DB_USER, "-d", "app", "-tAc", `SELECT '${marker}'`]);
      }
      const line = await observe(docker, target, (l) => l.includes(marker), settleMs);
      if (line) ingest({ runId, hostId, kind: marker, actor: "platform", at: new Date().toISOString(), detail: { executor: "docker", source: telemetry, line: line.slice(0, 300) } }, { store });
    },

    executeProof: async (vuln: PlantedVuln, runId: string) => {
      const role = roleOf(vuln.targetHostId);
      if (!(PLANTABLE[role] ?? []).includes(vuln.type)) {
        throw new Error(`vuln type ${vuln.type} is not plantable on role ${role || "?"} in the docker runtime`);
      }
      const attacker = containerName(runId, ATTACKER_HOST_ID);
      const target = containerName(runId, vuln.targetHostId);
      const proofMarker = `arena-proof-${vuln.proofAtomicGuid}-${runId.replace(/^run-/, "").slice(0, 8)}`.replace(/[^a-zA-Z0-9-]/g, "");
      if (vuln.type === "weak-cred") {
        // Valid-accounts style login with the planted weak credential from red's vantage.
        await dockerExec(docker, attacker,
          ["psql", "-h", vuln.targetHostId, "-U", WEAK_DB_USER, "-d", "app", "-tAc", `SELECT '${proofMarker}'`],
          [`PGPASSWORD=${WEAK_DB_PASSWORD}`, "PGCONNECT_TIMEOUT=5"]);
      } else if (vuln.type === "cve") {
        // Registry CVE: multi-step exploit from red's vantage across the
        // internal network. Unknown registry ids fail closed at the PLANTABLE
        // check above only for known roles; an unregistered id resolves to no
        // steps, so require a target or throw.
        const target = vulnTargetFor(vuln);
        if (!target) throw new Error(`cve target ${vuln.id} is not in the vuln-target registry`);
        for (const step of target.exploitSteps) {
          const bound = bindStep(step, vuln.targetHostId, proofMarker);
          await dockerExec(docker, attacker, ["sh", "-c", bound]);
        }
      } else {
        // Command injection (code-flaw): payload writes the marker to Apache's
        // stderr, i.e. the host's own log.
        const payload = encodeURIComponent(`x;echo ${proofMarker} 1>&2`);
        await dockerExec(docker, attacker, ["wget", "-q", "-T", "20", "-O", "/dev/null", `http://${vuln.targetHostId}/diag.php?host=${payload}`]);
      }
      // weak-cred: the statement line only exists if authentication succeeded.
      // code-flaw: a bare echo of the marker only exists if the shell ran it.
      // cve: the marker in the service log only exists if the exploit chain
      // (upload → execute, injection → run) actually fired.
      const match = vuln.type === "weak-cred"
        ? (l: string) => l.includes(`SELECT '${proofMarker}'`)
        : vuln.type === "cve"
          ? (l: string) => l.includes(proofMarker)
          : (l: string) => l.trim() === proofMarker;
      const line = await observe(docker, target, match, settleMs);
      if (!line) return;
      ingest({
        runId, hostId: vuln.targetHostId, kind: "process", actor: "proof",
        techniqueId: vuln.techniqueId, stepId: vuln.proofAtomicGuid, outcome: "succeeded",
        at: new Date().toISOString(), detail: { executor: "docker", vulnId: vuln.id, line: line.slice(0, 300) },
      }, { store });
    },
  };
}

/** Caller-supplied command from the agent; rejected unless it is a plain argv array. */
export function validateArgv(argv: unknown): string[] {
  if (!Array.isArray(argv) || argv.length === 0 || argv.length > 32) throw new Error("argv must be 1..32 items");
  const out: string[] = [];
  for (const a of argv) {
    if (typeof a !== "string" || a.length === 0) throw new Error("argv items must be non-empty strings");
    if (a.includes("\0")) throw new Error("argv item contains NUL");
    out.push(a);
  }
  if (out.some((a) => a === "..")) throw new Error("path traversal rejected");
  return out;
}

export async function execInContainer(container: string, argv: string[], opts: { docker?: string; timeoutMs?: number } = {}): Promise<{ container: string; command: string; stdout: string; stderr: string }> {
  const docker = opts.docker ?? "docker";
  const args = validateArgv(argv);
  const command = args.join(" ");
  const res = await run(docker, ["exec", container, ...args], { timeout: opts.timeoutMs ?? 30_000, maxBuffer: 4 * 1024 * 1024 })
    .catch((e: { stdout?: string; stderr?: string }) => ({ stdout: e.stdout ?? "", stderr: e.stderr ?? "" }));
  return { container, command, stdout: res.stdout.slice(0, 8000), stderr: res.stderr.slice(0, 2000) };
}

/**
 * Shell exec inside a run container for platform-generated probe commands
 * (readiness). Unlike `execInContainer` (agent argv, errors swallowed for
 * telemetry judging), failures throw so probes fail closed.
 */
export async function execInContainerShell(container: string, command: string, opts: { docker?: string; timeoutMs?: number } = {}): Promise<string> {
  const docker = opts.docker ?? "docker";
  const { stdout } = await run(docker, ["exec", container, "sh", "-c", command], { timeout: opts.timeoutMs ?? 30_000, maxBuffer: 4 * 1024 * 1024 });
  return stdout;
}

/** Evidence source for blue: normalized events from docker logs (never agent-authored). */
export async function agentSensorLog(spec: EnvironmentSpec, runId: string, hostId: string, opts: { docker?: string; since?: string } = {}): Promise<NormalizedEvent[]> {
  const docker = opts.docker ?? "docker";
  const inst = spec.instances.find((i) => i.hostId === hostId);
  if (!inst) throw new Error(`unknown host ${hostId}`);
  const lines = await rawLines(docker, containerName(runId, hostId), opts.since);
  return lines.map((l) => parseLine(hostId, inst.role, l)).filter((e): e is NormalizedEvent => e !== null);
}

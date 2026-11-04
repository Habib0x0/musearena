import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { EnvironmentSpec } from "@musearena/shared";
import type { GroundTruthEvent } from "./events.js";
import { roleImage } from "../provisioner/roles.js";
import { containerName } from "../provisioner/names.js";

const run = promisify(execFile);

/**
 * Out-of-band telemetry for the Docker runtime. The Docker daemon is the
 * management plane: container logs are read from the host, never from inside
 * the env, so a foothold cannot forge or suppress them. Each service line
 * becomes a normalized event (OCSF-ish: kind, src, user, detail.raw).
 *
 * Actor attribution is the collector's job, not the actor's: lines are labelled
 * by SOURCE ADDRESS (attacker container IP → red, the host itself → platform,
 * anything else → noise/unknown). Labels never come from the request content.
 */
export interface RawLine { at: string; text: string }

const APACHE_ACCESS = /^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"/;
const PG = /user=(\S+) db=(\S+) client=(\S+) LOG:\s+(connection authorized|statement): (.*)$/;
const PG_AUTH_FAIL = /user=(\S+) db=(\S+) client=(\S+) FATAL:\s+(password authentication failed.*)$/;

export interface NormalizedEvent {
  hostId: string; at: string; kind: string; src: string; user?: string; detail: Record<string, unknown>;
}

export function parseLine(hostId: string, role: string, line: RawLine): NormalizedEvent | null {
  const telemetry = roleImage(role).telemetry;
  if (telemetry === "apache-log") {
    const m = APACHE_ACCESS.exec(line.text);
    if (m) return { hostId, at: line.at, kind: "http.request", src: m[1], detail: { method: m[2], path: m[3], status: Number(m[4]), ua: m[5] } };
    const t = line.text.trim();
    // Apache stderr that is not an Apache-formatted log line is child-process output (e.g. a shell).
    if (t && !t.startsWith("[") && !/^AH\d+:/.test(t)) return { hostId, at: line.at, kind: "process.stderr", src: "local", detail: { output: t.slice(0, 500) } };
    return null;
  }
  if (telemetry === "postgres-log") {
    const f = PG_AUTH_FAIL.exec(line.text);
    if (f) return { hostId, at: line.at, kind: "auth.failure", src: f[3], user: f[1], detail: { db: f[2], reason: f[4].slice(0, 200) } };
    const m = PG.exec(line.text);
    if (!m) return null;
    const [, user, db, client, what, rest] = m;
    return {
      hostId, at: line.at, kind: what === "statement" ? "db.statement" : "auth.logon", src: client, user,
      detail: what === "statement" ? { db, statement: rest.slice(0, 500) } : { db },
    };
  }
  return null;
}

export async function containerIp(docker: string, name: string): Promise<string | null> {
  const { stdout } = await run(docker, ["inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", name]).catch(() => ({ stdout: "" }));
  return stdout.trim() || null;
}

export async function rawLines(docker: string, name: string, since?: string): Promise<RawLine[]> {
  const args = ["logs", "--timestamps", ...(since ? ["--since", since] : []), name];
  const { stdout, stderr } = await run(docker, args, { maxBuffer: 64 * 1024 * 1024, timeout: 30_000 });
  return `${stdout}\n${stderr}`.split("\n").filter(Boolean).map((l) => {
    const i = l.indexOf(" ");
    return { at: l.slice(0, i), text: l.slice(i + 1) };
  }).filter((l) => Number.isFinite(Date.parse(l.at)));
}

export interface CollectOptions {
  docker?: string; since?: string; attackerHostId?: string;
  /** Label for traffic originating on the host itself (platform gates vs in-run persona noise). */
  localActor?: "platform" | "noise";
}

/** Collect + normalize + attribute every service line for a run's container hosts. */
export async function collectTelemetry(spec: EnvironmentSpec, runId: string, opts: CollectOptions = {}): Promise<GroundTruthEvent[]> {
  const docker = opts.docker ?? "docker";
  const attackerIp = await containerIp(docker, containerName(runId, opts.attackerHostId ?? "attacker"));
  const out: GroundTruthEvent[] = [];
  for (const inst of spec.instances.filter((i) => i.runtime === "container")) {
    const lines = await rawLines(docker, containerName(runId, inst.hostId), opts.since).catch(() => []);
    for (const l of lines) {
      const ev = parseLine(inst.hostId, inst.role, l);
      if (!ev) continue;
      const actor: GroundTruthEvent["actor"] = attackerIp && ev.src === attackerIp ? "red"
        : ev.src === "127.0.0.1" || ev.src === "::1" || ev.src === "[local]" ? (opts.localActor ?? "platform")
        // Shell output on the web worker has no source address; the env runs no
        // legitimate child processes there, so it is attributed to red (inferred).
        : ev.src === "local" ? "red"
        : "noise";
      out.push({ runId, hostId: ev.hostId, kind: ev.kind, actor, at: new Date(ev.at).toISOString(), detail: { ...ev.detail, src: ev.src, user: ev.user, source: "docker-logs", attribution: ev.src === "local" ? "inferred" : "source-address" } });
    }
  }
  return out.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
}

/**
 * Start of a collection window on the TARGETS' clock (the Docker VM), taken as
 * the newest log timestamp seen so far. Host and VM clocks drift by up to ~1s
 * on Docker Desktop, so a host-clock cutoff would leak setup traffic into the
 * window (observed live). Everything after this mark happened after setup.
 */
export async function windowStart(spec: EnvironmentSpec, runId: string, docker = "docker"): Promise<number> {
  let last = 0;
  for (const inst of spec.instances.filter((i) => i.runtime === "container")) {
    const lines = await rawLines(docker, containerName(runId, inst.hostId)).catch(() => []);
    for (const l of lines) last = Math.max(last, Date.parse(l.at));
  }
  return last;
}

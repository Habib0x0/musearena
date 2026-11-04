import type { EnvironmentSpec } from "@musearena/shared";
import type { GroundTruthEvent } from "./events.js";
import { readVmRunState, type VmInstanceState, type VmRunState } from "../provisioner/vm-lifecycle.js";
import { vmLifecycleFor } from "../provisioner/deploy.js";
import { execInGuest } from "../configurator/vm-ssh.js";
import { parseLine, type RawLine } from "./docker-telemetry.js";

/**
 * Out-of-band telemetry for the VM runtime (T-18b). Guest logs are read over
 * the run's SSH endpoint (the management plane), never from inside the
 * exercise. Apache/PostgreSQL lines reuse the Docker normalizer so the same
 * Sigma rules apply; auditd user messages are parsed separately.
 *
 * Attribution: a line is red when it carries a per-objective marker the
 * platform generated for the exercise, or when its client address is a
 * declared red source (the attacker guest's lab address — T-15). The second
 * rule is what makes a same-second persona request distinguishable from the
 * attacker's request, and what gives blue a peer address to act on. Both are
 * properties of the telemetry line, never of anything the actor reported.
 */

const MONTHS: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

const pad = (n: number) => String(n).padStart(2, "0");

/** Apache access `[28/Oct/2026:16:00:00 +0000]`. */
function apacheAccessTime(line: string): string | null {
  const m = /\[(\d{2})\/(\w{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-]\d{4})\]/.exec(line);
  if (!m) return null;
  const [, d, mon, y, hh, mm, ss, tz] = m;
  const month = MONTHS[mon];
  if (month === undefined) return null;
  const iso = `${y}-${pad(month + 1)}-${d}T${hh}:${mm}:${ss}${tz.slice(0, 3)}:${tz.slice(3)}`;
  return Number.isFinite(Date.parse(iso)) ? new Date(iso).toISOString() : null;
}

/** Apache error `[Wed Oct 28 16:00:00.123456 2026]`. */
function apacheErrorTime(line: string): string | null {
  const m = /\[(\w{3}) (\w{3}) (\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.\d+)? (\d{4})\]/.exec(line);
  if (!m) return null;
  const [, , mon, d, hh, mm, ss, y] = m;
  const month = MONTHS[mon];
  if (month === undefined) return null;
  return `${y}-${pad(month + 1)}-${d}T${hh}:${mm}:${ss}Z`;
}

/** PostgreSQL `2026-10-28 16:00:00.123 UTC [pid] ...`. */
function postgresTime(line: string): string | null {
  const m = /^(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? UTC/.exec(line);
  return m ? `${m[1]}T${m[2]}Z` : null;
}

/** syslog `Oct 28 18:00:00` — no year, so anchor to the host clock. */
function syslogTime(line: string): string | null {
  const m = /^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})/.exec(line);
  if (!m) return null;
  const month = MONTHS[m[1]];
  if (month === undefined) return null;
  const now = Date.now();
  const build = (year: number) => `${year}-${pad(month + 1)}-${pad(Number(m[2]))}T${m[3]}:${m[4]}:${m[5]}Z`;
  let iso = build(new Date(now).getUTCFullYear());
  // A December line read in January belongs to the previous year.
  if (Date.parse(iso) - now > 24 * 3_600_000) iso = build(new Date(now).getUTCFullYear() - 1);
  return Number.isFinite(Date.parse(iso)) ? iso : null;
}

/** auditd `msg=audit(1793206254.529:220)`. */
function auditTime(line: string): string | null {
  const m = /msg=audit\((\d+(?:\.\d+)?):/.exec(line);
  return m ? new Date(Number(m[1]) * 1000).toISOString() : null;
}

export function vmLineTime(line: string): string | null {
  return apacheAccessTime(line) ?? apacheErrorTime(line) ?? postgresTime(line) ?? auditTime(line) ?? syslogTime(line);
}

/** sshd auth failures: enumeration and failed logons, attributable by user. */
function parseAuthLine(line: string): { user: string; src: string; method: string } | null {
  const invalid = /Invalid user (\S+) from (\S+) port \d+/.exec(line);
  if (invalid) return { user: invalid[1], src: invalid[2], method: "invalid-user" };
  const failed = /Failed (\w+) for (?:invalid user )?(\S+) from (\S+) port \d+/.exec(line);
  if (failed) return { user: failed[2], src: failed[3], method: failed[1].toLowerCase() };
  return null;
}

export interface ParsedVmLine { at: string; text: string }

/** Turn one raw guest log line into a normalized ground-truth event, or null. */
export function parseVmLogLine(hostId: string, role: string, line: ParsedVmLine, redMarkers: string[], redSources: string[] = []): GroundTruthEvent | null {
  const red = redMarkers.some((m) => m.length > 0 && line.text.includes(m)) ||
    redSources.some((src) => src.length > 0 && line.text.includes(src));
  const canary = /canary-[A-Za-z0-9-]+/.test(line.text);
  const actor = red ? "red" : canary ? "platform" : "noise";
  const at = vmLineTime(line.text) ?? line.at;

  if (line.text.startsWith("type=") || /^audit/.test(line.text)) {
    const type = /type=(\w+)/.exec(line.text)?.[1] ?? "UNKNOWN";
    const text = /text=([^\n]*?)(?:\s+UID=|\s*$)/.exec(line.text)?.[1] ?? "";
    return { runId: "", hostId, kind: "audit.user", actor, at, detail: { auditType: type, text: text.slice(0, 300), source: "auditd", line: line.text.slice(0, 300) } };
  }

  const auth = parseAuthLine(line.text);
  if (auth) {
    return { runId: "", hostId, kind: "auth.login.failed", actor, at, detail: { ...auth, source: "vm-auth", line: line.text.slice(0, 300) } };
  }

  const parsed = parseLine(hostId, role, line as RawLine);
  if (!parsed) return null;
  return {
    runId: "", hostId, kind: parsed.kind, actor, at,
    detail: { ...parsed.detail, user: parsed.user, src: parsed.src, source: "vm-logs", line: line.text.slice(0, 300) },
  };
}

export interface VmTelemetryOptions {
  state?: VmRunState;
  exec?: (inst: VmInstanceState, command: string, timeoutMs?: number) => Promise<string>;
  since?: string;
  redMarkers?: string[];
  /** Lab addresses whose traffic is red (the attacker guest). */
  redSources?: string[];
  tailLines?: number;
}

/** Read the guest telemetry the exercise scores from (management plane only). */
export async function collectVmTelemetry(spec: EnvironmentSpec, runId: string, opts: VmTelemetryOptions = {}): Promise<GroundTruthEvent[]> {
  const state = opts.state ?? await readVmRunState(vmLifecycleFor({ runId }));
  if (!state) throw new Error(`no VM registry for ${runId}; cannot collect telemetry`);
  const exec = opts.exec ?? (async (inst, command, timeoutMs) => (await execInGuest(inst, command, { timeoutMs })).stdout);
  const tail = opts.tailLines ?? 400;
  const sinceMs = opts.since ? Date.parse(opts.since) : 0;
  const redMarkers = opts.redMarkers ?? [];
  const redSources = opts.redSources ?? [];
  const files = [
    { path: "/var/log/apache2/access.log", needs: (role: string) => role === "web" },
    { path: "/var/log/apache2/error.log", needs: (role: string) => role === "web" },
    { path: "/var/log/postgresql/postgresql-*-main.log", needs: (role: string) => role === "db" },
    { path: "/var/log/audit/audit.log", needs: () => true },
    // sshd auth failures: Debian writes auth.log, Rocky writes secure. The
    // absent file simply reads empty, so both are always collected; without
    // secure a T1110 objective on a Rocky guest could never be observed.
    { path: "/var/log/auth.log", needs: () => true },
    { path: "/var/log/secure", needs: () => true },
  ];
  const events: GroundTruthEvent[] = [];
  for (const inst of spec.instances) {
    if (inst.runtime !== "vm") continue;
    const vm = state.instances[inst.hostId];
    if (!vm) continue;
    for (const file of files) {
      if (!file.needs(inst.role)) continue;
      const text = await exec(vm, `sudo -n tail -n ${tail} ${file.path} 2>/dev/null || true`, 15_000).catch(() => "");
      for (const raw of text.split("\n")) {
        if (!raw.trim()) continue;
        // Exact gate-proof markers are verification artifacts, not exercise
        // activity. A red-attributed line that merely mentions the proof file
        // path is real attack telemetry and must survive collection.
        const gateProofMarkers = spec.plantedVulns.map((v) =>
          `arena-proof-${v.proofAtomicGuid}-${runId.replace(/^run-/, "").slice(0, 8)}`.replace(/[^A-Za-z0-9-]/g, ""));
        const redLine = redMarkers.some((m) => m.length > 0 && raw.includes(m)) ||
          redSources.some((src) => src.length > 0 && raw.includes(src));
        if (!redLine && gateProofMarkers.some((m) => raw.includes(m))) continue;
        // Apache's bare child-process line has no timestamp; only keep it when
        // it is red-attributed, so an older gate-proof line cannot masquerade
        // as fresh red activity.
        if (!vmLineTime(raw) && !redLine) continue;
        const event = parseVmLogLine(inst.hostId, inst.role, { at: new Date().toISOString(), text: raw }, redMarkers, redSources);
        if (!event) continue;
        if (sinceMs && Number.isFinite(Date.parse(event.at)) && Date.parse(event.at) < sinceMs) continue;
        events.push({ ...event, runId });
      }
    }
  }
  return events;
}

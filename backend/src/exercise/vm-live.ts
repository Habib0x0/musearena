import type { EnvironmentSpec, Run } from "@musearena/shared";
import { ingest } from "../observability/collector.js";
import { EventStore, localStore } from "../observability/events.js";
import { LocalTrajectoryRecorder } from "../observability/trajectory.js";
import { incr } from "../observability/metrics.js";
import { collectVmTelemetry } from "../observability/vm-telemetry.js";
import { joinRun } from "../observability/export.js";
import { DetectionStore, type Alert } from "../detections/sigma.js";
import { canaryValue } from "../configurator/ansible.js";
import { WEAK_DB_PASSWORD } from "../provisioner/roles.js";
import { readVmRunState, type VmInstanceState, type VmRunState } from "../provisioner/vm-lifecycle.js";
import { vmLifecycleFor } from "../provisioner/deploy.js";
import { execInGuest } from "../configurator/vm-ssh.js";
import { nicMac } from "../provisioner/lab-network.js";
import { LangfuseSink, TeeRecorder, langfuseConfig, type LangfuseConfig } from "../observability/langfuse.js";
import { scoreExercise, type Scorecard } from "./evaluator.js";

/**
 * Scripted LIVE exercise on the VM runtime (T-18b), the VM counterpart of
 * exercise/live.ts. Red acts inside the guests (same-host until lab L2
 * exists); the collector reads the guests' own logs over the management
 * plane and labels only marker-bearing lines as red. Blue sees the collected
 * stream only and detects via promoted Sigma rules. Scoring and dataset
 * export are the same code paths as the Docker loop.
 */
export interface VmLiveExerciseOptions {
  store?: EventStore;
  detections: DetectionStore;
  state?: VmRunState;
  exec?: (inst: VmInstanceState, command: string, timeoutMs?: number) => Promise<string>;
  enforceResponse?: boolean;
  control?: boolean;
  noiseRounds?: number;
  /** Langfuse sink; default from env, null disables. */
  langfuse?: LangfuseConfig | null;
}

export interface VmEnforcement { hostId: string; response: string; target?: string; enforced: boolean; detail: string }

export interface VmLiveExerciseResult {
  run: Run; scorecard: Scorecard; redSteps: number; alerts: Alert[]; falsePositives: number; benignEvents: number;
  falsePositiveDetail: { ruleId: string; hostId: string; kind: string; sample: string }[];
  langfuseEvents: number;
  /** Responses blue proposed, and whether the guest really applied them. */
  enforcement: VmEnforcement[];
}

interface RedStep { objectiveId: string; hostId: string; techniqueId: string; action: string; succeeded: boolean; evidence: string }

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
const sqlLit = (s: string) => `'${s.replace(/'/g, "''")}'`;

export function vmRedMarker(runId: string, objectiveId: string): string {
  return `RED-${objectiveId}-${runId.replace(/^run-/, "").slice(0, 8)}`.replace(/[^A-Za-z0-9-]/g, "");
}

/**
 * One scripted red action per objective. With an attacker guest in the spec
 * (T-15) red acts from it over the lab segment, so the target's own logs carry
 * a real peer source address; without one it acts on the target itself.
 */
async function redAct(spec: EnvironmentSpec, runId: string, objectiveId: string, ctx: {
  exec: (i: VmInstanceState, c: string, t?: number) => Promise<string>;
  instOf: (h: string) => Promise<VmInstanceState>;
  addressOf: (h: string) => string;
  attackerHostId?: string;
}): Promise<RedStep> {
  const { exec, instOf, addressOf, attackerHostId } = ctx;
  const o = spec.objectives.find((x) => x.id === objectiveId)!;
  const target = spec.instances.find((i) => i.hostId === o.asset);
  const base = { objectiveId: o.id, hostId: o.asset, techniqueId: o.techniqueId };
  const marker = vmRedMarker(runId, o.id);
  const actor = await instOf(attackerHostId ?? o.asset);
  // Without an attacker guest red acts on the target itself, so loopback is
  // the honest address; using the target's own lab address would make a local
  // session look remote in the target's log.
  const targetAddr = attackerHostId ? addressOf(o.asset) : "127.0.0.1";
  if (o.techniqueId === "T1110") {
    // Credential guessing against the guest's own sshd. The marker is the
    // username, so sshd's own log attributes the attempt to this objective
    // without trusting anything the actor prints.
    // Keep the marker's exact case: attribution is a case-sensitive substring
    // match on the guest's own log line.
    const user = marker;
    const cmd = `for i in 1 2 3 4 5; do ssh -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -o PreferredAuthentications=publickey ${user}@${targetAddr} true 2>&1; done; true`;
    const out = await exec(actor, cmd, 60_000).catch(() => "");
    const denied = /Permission denied|No supported authentication methods/i.test(out);
    return { ...base, action: "repeated failed SSH publickey logins", succeeded: denied, evidence: denied ? marker : out.slice(0, 120) };
  }
  if (target?.role === "web") {
    const out = await exec(actor, `curl -s --max-time 20 "http://${targetAddr}/diag.php?host=${encodeURIComponent(`x;echo ${marker}`)}"`, 30_000).catch(() => "");
    return { ...base, action: "command injection via /diag.php", succeeded: out.includes(marker), evidence: out.includes(marker) ? marker : out.slice(0, 120) };
  }
  if (target?.role === "db") {
    const q = `SELECT value FROM secrets WHERE objective_id=${sqlLit(o.id)} /* ${marker} */`;
    const out = await exec(actor, `PGPASSWORD=${shq(WEAK_DB_PASSWORD)} psql -h ${targetAddr} -U app -d app -tAc ${shq(q)}`, 20_000).catch(() => "");
    const want = canaryValue(runId, o.id);
    return { ...base, action: "psql login with weak app credential; read secrets", succeeded: out.trim() === want, evidence: out.trim().slice(0, 120) };
  }
  return { ...base, action: "no live technique for this asset role", succeeded: false, evidence: "" };
}

/** Benign persona activity on the hosts so blue's FP rate is measured on real noise. */
async function personaNoise(spec: EnvironmentSpec, exec: (i: VmInstanceState, c: string, t?: number) => Promise<string>, instOf: (h: string) => Promise<VmInstanceState>): Promise<void> {
  for (const inst of spec.instances) {
    if (inst.runtime !== "vm") continue;
    const vm = await instOf(inst.hostId).catch(() => null);
    if (!vm) continue;
    if (inst.role === "web") await exec(vm, `curl -s -o /dev/null --max-time 5 http://127.0.0.1/`, 15_000).catch(() => "");
    if (inst.role === "db") await exec(vm, `psql -U app -d app -tAc "SELECT count(*) FROM employees"`, 15_000).catch(() => "");
  }
}

/**
 * Apply a `block IP` response on the guest that saw the activity. The rule is
 * read back before the response counts as enforced: a firewall that is missing
 * or refused must not be recorded as a successful containment.
 */
export async function blockPeer(
  hostId: string, peerIp: string,
  exec: (i: VmInstanceState, c: string, t?: number) => Promise<string>,
  instOf: (h: string) => Promise<VmInstanceState>,
): Promise<{ enforced: boolean; detail: string }> {
  const ip = peerIp.replace(/[^0-9a-fA-F:.]/g, "");
  if (!ip) return { enforced: false, detail: "empty source address" };
  // The SSH user's PATH has no /usr/sbin, so probe absolute paths: `iptables`
  // is a sudo-only binary on Debian.
  const cmd = [
    "if [ -x /usr/sbin/iptables ]; then",
    `  sudo -n iptables -C INPUT -s ${ip} -j DROP 2>/dev/null || sudo -n iptables -A INPUT -s ${ip} -j DROP`,
    `  sudo -n iptables -S INPUT | grep -q -- "-s ${ip}/32 -j DROP" && echo enforced`,
    "elif [ -x /usr/sbin/nft ]; then",
    `  sudo -n nft add rule inet filter input ip saddr ${ip} drop 2>/dev/null`,
    `  sudo -n nft list ruleset | grep -q "${ip}" && echo enforced`,
    "else echo 'no firewall tool on this guest'; fi",
  ].join("\n");
  const out = await exec(await instOf(hostId), cmd, 15_000).catch((e: Error) => `error: ${e.message}`);
  return { enforced: out.includes("enforced"), detail: out.trim().slice(0, 200) || "no output" };
}

/**
 * Apply `isolate host` by taking the guest off the lab segment. The management
 * NIC stays up, so the platform can still collect and tear down; the lab link
 * state is read back before the response counts.
 */
export async function isolateHost(
  hostId: string,
  exec: (i: VmInstanceState, c: string, t?: number) => Promise<string>,
  instOf: (h: string) => Promise<VmInstanceState>,
): Promise<{ enforced: boolean; detail: string }> {
  const mac = nicMac(hostId, "lab");
  const cmd = [
    `IF=$(for d in /sys/class/net/*; do [ "$(cat "$d/address")" = "${mac}" ] && basename "$d"; done)`,
    `if [ -z "$IF" ]; then echo "no lab NIC on this guest"; exit 0; fi`,
    `sudo -n ip link set "$IF" down`,
    `ip -o link show "$IF" | grep -q "state DOWN" && echo isolated`,
  ].join("\n");
  const out = await exec(await instOf(hostId), cmd, 15_000).catch((e: Error) => `error: ${e.message}`);
  return { enforced: out.includes("isolated"), detail: out.trim().slice(0, 200) || "no output" };
}

export async function runVmExercise(input: { spec: EnvironmentSpec; run: Run }, opts: VmLiveExerciseOptions): Promise<VmLiveExerciseResult> {
  const { spec, run: runRec } = input;
  const store = opts.store ?? localStore;
  const runId = runRec.runId;
  const state = opts.state ?? await readVmRunState(vmLifecycleFor({ runId }));
  if (!state) throw new Error(`no VM registry for ${runId}; cannot run the VM exercise`);
  const exec = opts.exec ?? (async (inst, command, timeoutMs) => (await execInGuest(inst, command, { timeoutMs })).stdout);
  const instOf = async (hostId: string) => {
    const inst = state.instances[hostId];
    if (!inst) throw new Error(`no VM ${hostId} in the run registry`);
    return inst;
  };
  const addressOf = (hostId: string) => state.instances[hostId]?.lab?.address ?? "127.0.0.1";
  const attackerHostId = spec.instances.find((i) => i.runtime === "vm" && i.role === "attacker")?.hostId;
  const lf = opts.langfuse === undefined ? langfuseConfig() : opts.langfuse;
  const sink = lf ? new LangfuseSink(lf, { orgId: runRec.orgId, specDigest: runRec.specDigest, mode: runRec.mode, backend: runRec.backend }) : null;
  const recorder = new TeeRecorder(new LocalTrajectoryRecorder(store), sink);
  // Settle after configure/gates: a window that starts now (second-aligned)
  // keeps setup seeds and gate-proof lines out of blue's benign stream.
  await sleep(2_000);
  const startedAt = Date.now();
  const since = new Date(Math.floor(startedAt / 1000) * 1000).toISOString();

  for (let i = 0; i < (opts.noiseRounds ?? 1); i++) await personaNoise(spec, exec, instOf);

  const steps: RedStep[] = [];
  for (const o of opts.control ? [] : spec.objectives) {
    const s = await redAct(spec, runId, o.id, { exec, instOf, addressOf, attackerHostId });
    steps.push(s);
    recorder.record({
      runId, hostId: s.hostId, actor: "red", observation: s.evidence || "(no output)",
      reasoning: `attempt ${s.techniqueId} against ${s.hostId}`, toolCall: "vm-exec",
      action: `${s.action} [${s.objectiveId}]`, techniqueId: s.techniqueId, at: new Date().toISOString(),
    });
  }

  // Logs flush asynchronously; collect out of band after red acts.
  await sleep(1_500);
  const redMarkers = steps.map((s) => vmRedMarker(runId, s.objectiveId));
  const telemetry = await collectVmTelemetry(spec, runId, {
    state, exec, since, redMarkers,
    redSources: attackerHostId ? [addressOf(attackerHostId)] : [],
  });
  for (const e of telemetry) ingest(e, { store });

  for (const s of steps) {
    const observed = telemetry.some((e) => e.hostId === s.hostId && e.actor === "red");
    const objective = spec.objectives.find((o) => o.id === s.objectiveId)!;
    const lastRed = telemetry.filter((e) => e.hostId === s.hostId && e.actor === "red").at(-1)?.at ?? new Date().toISOString();
    ingest({
      runId, hostId: s.hostId, kind: "objective", actor: "red", techniqueId: s.techniqueId,
      outcome: s.succeeded && observed ? "succeeded" : "failed", at: lastRed,
      detail: { objectiveId: s.objectiveId, signal: objective.successSignal, verified: s.succeeded, observed },
    }, { store });
  }

  // Blue sees only the collected stream. Labels are used afterwards by the scorer.
  const alerts = opts.detections.liveAlerts(telemetry);
  const benign = telemetry.filter((e) => e.actor !== "red");
  const fpAlerts = opts.detections.liveAlerts(benign);
  const truePositive = opts.detections.liveAlerts(telemetry.filter((e) => e.actor === "red"));
  const firstByTech = new Map<string, Alert>();
  for (const a of truePositive.sort((x, y) => Date.parse(x.at) - Date.parse(y.at))) if (!firstByTech.has(`${a.hostId}|${a.techniqueId}`)) firstByTech.set(`${a.hostId}|${a.techniqueId}`, a);

  const enforcement: VmEnforcement[] = [];
  for (const a of firstByTech.values()) {
    const detectAt = new Date().toISOString();
    ingest({ runId, hostId: a.hostId, kind: "alert", actor: "blue", techniqueId: a.techniqueId, outcome: "detected", at: detectAt, detail: { signal: "sigma-match", ruleId: a.ruleId, ruleVersion: a.ruleVersion, confidence: a.confidence, eventAt: a.at } }, { store });
    // The alerting event's source is the peer address blue may act on. It is a
    // lab address only when red came from another guest (attacker host).
    // Prefer the red event at that instant: persona noise can share the second.
    const rawSrc = (telemetry.find((e) => e.hostId === a.hostId && e.at === a.at && e.actor === "red")
      ?? telemetry.find((e) => e.hostId === a.hostId && e.at === a.at))?.detail?.src;
    const src = typeof rawSrc === "string" ? rawSrc : undefined;
    const peer = src && Object.values(state.instances).some((i) => i.lab?.address === src) ? src : undefined;
    // A peer source can be blocked by address. Without one (red acted on the
    // host itself) the honest containment is to take the host off the lab
    // segment; both are read back before they count.
    const response = peer ? "block IP" : "isolate host";
    const result = peer ? await blockPeer(a.hostId, peer, exec, instOf) : await isolateHost(a.hostId, exec, instOf);
    enforcement.push({ hostId: a.hostId, response, target: peer, enforced: result.enforced, detail: result.detail });
    if (result.enforced) {
      ingest({
        runId, hostId: a.hostId, kind: "response", actor: "blue", techniqueId: a.techniqueId,
        outcome: "contained", at: new Date().toISOString(),
        detail: { response, ...(peer ? { target: peer } : {}), verify: result.detail },
      }, { store });
    }
    recorder.record({
      runId, hostId: a.hostId, actor: "blue",
      observation: `alert ${a.ruleId}@${a.ruleVersion} (${a.techniqueId}) conf ${a.confidence}`,
      action: result.enforced ? `${response}${peer ? ` ${peer}` : ""} (enforced)` : `${response} (audited, unenforced — ${result.detail})`,
      techniqueId: a.techniqueId, at: detectAt,
    });
  }

  // Same trace contract as the container loop: one trace per run_id, one span
  // per red/blue step; a failed flush throws so a run cannot claim a trace
  // that never arrived.
  // Trace export is optional observability: a rejected export is logged and
  // counted as zero, never allowed to fail an already-scored run.
  const langfuseEvents = sink ? await sink.flush().catch((e: Error) => { console.warn(`langfuse export skipped: ${e.message.slice(0, 160)}`); return 0; }) : 0;
  incr("arena_exercises_total", { backend: runRec.backend, runtime: "vm" });
  incr("arena_telemetry_events_total", { runtime: "vm" }, telemetry.length);
  incr("arena_alerts_total", { runtime: "vm" }, alerts.length);
  incr("arena_false_positives_total", { runtime: "vm" }, fpAlerts.length);
  const join = joinRun(runId, store);
  const scorecard = scoreExercise(spec, join);
  incr("arena_objectives_achieved_total", { runtime: "vm" }, scorecard.objectivesAchieved);
  const falsePositiveRate = benign.length ? fpAlerts.length / benign.length : 0;
  const score = { ...scorecard, falsePositiveRate };
  const falsePositiveDetail = fpAlerts.map((a) => {
    const e = benign.find((x) => x.hostId === a.hostId && x.at === a.at);
    return { ruleId: a.ruleId, hostId: a.hostId, kind: e?.kind ?? "?", sample: JSON.stringify(e?.detail ?? {}).slice(0, 160) };
  });
  return { run: { ...runRec, score }, scorecard: score, redSteps: steps.length, alerts, falsePositives: fpAlerts.length, benignEvents: benign.length, falsePositiveDetail, langfuseEvents, enforcement };
}

import type { EnvironmentSpec, Run } from "@musearena/shared";
import { randomBytes } from "node:crypto";
import { ingest } from "../observability/collector.js";
import { EventStore, localStore } from "../observability/events.js";
import { LocalTrajectoryRecorder } from "../observability/trajectory.js";
import { LangfuseSink, TeeRecorder, langfuseConfig, type LangfuseConfig } from "../observability/langfuse.js";
import { collectVmTelemetry } from "../observability/vm-telemetry.js";
import { joinRun } from "../observability/export.js";
import type { NormalizedEvent } from "../observability/docker-telemetry.js";
import type { DetectionStore, Alert } from "../detections/sigma.js";
import {
  redObjective, runRedCampaign, blueInvestigate, personaShift, scriptedShift, capsFromEnv, newGuardrailLog, AUTH_FAILURE_THRESHOLD, isAuthFailureObjective,
  type AgentCaps, type AgentState, type BlueProposal, type GuardrailLog, type ShiftResult,
} from "./agents.js";
import type { AgentRunResult } from "./agents-live.js";
import { blockPeer, isolateHost } from "./vm-live.js";
import { effectiveAgentSurface, type AgentClient } from "../lib/model.js";
import { resolveAgentClients } from "../learning/models.js";
import { personaKerberosFor } from "./persona-auth.js";
import { scoreExercise, type Scorecard } from "./evaluator.js";
import { incr } from "../observability/metrics.js";
import { execInGuest } from "../configurator/vm-ssh.js";
import { readVmRunState, type VmInstanceState, type VmRunState } from "../provisioner/vm-lifecycle.js";
import { vmLifecycleFor } from "../provisioner/deploy.js";

/**
 * Model-driven red/blue on the VM org lab (T-19).
 *
 * The container loop's attacker container does not exist here; an opt-in
 * attacker guest on the lab segment plays that role, and red's argv runs on it
 * over the management plane. That is the same transport a real foothold would
 * give an adversary (a shell on a peer), not a shortcut that reads the target
 * directly — the planted proof is unreadable to the attacker user.
 *
 * Blue sees the collected VM telemetry only, and a response is enforced the
 * same way the scripted loop enforces it (block the cited lab peer, or take
 * the host off the segment), read back before it counts.
 */

export interface VmAgentRunOptions {
  store?: EventStore;
  detections: DetectionStore;
  state?: VmRunState;
  exec?: (inst: VmInstanceState, command: string, timeoutMs?: number) => Promise<string>;
  langfuse?: LangfuseConfig | null;
  caps?: AgentCaps;
  traceEnabled?: boolean;
  agent?: AgentClient;
  red?: AgentClient;
  blue?: AgentClient;
  /** Persona agent client; when set, personas run model-driven shifts. When
   * unset, shifts are scripted (deterministic baseline). Never both silently:
   * the mode is recorded per persona in `agentStates` and `shiftReport`. */
  personas?: AgentClient;
  /** Caps for persona shifts; defaults to roughly half the agent caps. */
  personaCaps?: AgentCaps;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const shq = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
const sqlLit = (s: string) => `'${s.replace(/'/g, "''")}'`;

/**
 * Fresh proofs on the target hosts, planted over the management plane before
 * the telemetry window opens. db: the objective's row in `secrets`; web: a
 * file outside the docroot owned by www-data (the injected command runs as
 * www-data; the attacker user cannot read it).
 */
async function plantVmProofs(
  spec: EnvironmentSpec, runId: string,
  instOf: (hostId: string) => VmInstanceState,
  exec: (inst: VmInstanceState, command: string, timeoutMs?: number) => Promise<string>,
): Promise<Map<string, string>> {
  const proofs = new Map<string, string>();
  for (const o of spec.objectives) {
    const role = spec.instances.find((i) => i.hostId === o.asset)?.role;
    const nonce = `MUSE-PROOF-${randomBytes(12).toString("hex")}`;
    const id = o.id.replace(/[^A-Za-z0-9_-]/g, "");
    if (role === "db") {
      // Same connection the seed used (local trust on the app database).
      await exec(instOf(o.asset), `psql -U app -d app -tAc ${shq(`UPDATE secrets SET value=${sqlLit(nonce)} WHERE objective_id=${sqlLit(o.id)}`)}`, 20_000);
    } else if (role === "web") {
      await exec(instOf(o.asset), `printf %s ${shq(nonce)} | sudo -n tee /var/www/arena-proof-${id} >/dev/null && sudo -n chown root:www-data /var/www/arena-proof-${id} && sudo -n chmod 640 /var/www/arena-proof-${id}`, 20_000);
    } else continue;
    proofs.set(o.id, nonce);
  }
  return proofs;
}

/**
 * Persona shifts (P4): with a persona client, each persona on a VM workstation
 * runs a model-driven shift through the allowlist; without one (or when a
 * persona has no VM workstation) the scripted baseline command runs so the
 * run still has real noise. The mode is recorded per persona — scripted
 * fallback is labelled, never presented as model activity.
 */
type RecorderLike = { record: (step: { runId: string; hostId?: string; actor: "persona"; observation: string; reasoning?: string; toolCall?: string; action?: string; techniqueId?: string; at: string }) => unknown };

export async function personaShifts(
  spec: EnvironmentSpec,
  runId: string,
  exec: (i: VmInstanceState, c: string, t?: number) => Promise<string>,
  instOf: (h: string) => Promise<VmInstanceState>,
  opts: { agent?: AgentClient; caps: AgentCaps; recorder: RecorderLike; traceEnabled?: boolean },
): Promise<{ shifts: ShiftResult[]; agentStates: Record<string, AgentState> }> {
  const shifts: ShiftResult[] = [];
  const agentStates: Record<string, AgentState> = {};
  for (const persona of spec.personas) {
    const ws = spec.instances.find((i) => i.hostId === persona.workstation);
    const runWs = async (command: string, timeoutMs: number): Promise<string> => {
      const vm = await instOf(persona.workstation);
      return exec(vm, command, timeoutMs);
    };
    if (opts.agent && ws?.runtime === "vm") {
      // A FreeIPA member runs the shift as the directory user with its own
      // ticket, proven by setup before the model gets a turn. A failed kinit
      // or GSSAPI bind throws; it never degrades to the SSH user.
      const kerberos = personaKerberosFor(spec, runId, persona);
      if (kerberos) {
        const setup = await runWs(kerberos.setupCommand, 60_000);
        if (!setup.includes("kerberos-ready")) throw new Error(`persona ${persona.id}: kinit did not produce a usable ticket`);
      }
      const r = await personaShift(opts.agent, {
        spec, runId, persona, caps: opts.caps,
        recorder: opts.recorder, traceEnabled: opts.traceEnabled,
        execute: runWs,
        kerberos: kerberos ? { user: kerberos.user, ccache: kerberos.ccache } : undefined,
      });
      shifts.push(r);
      agentStates[`persona:${persona.id}`] = r.state;
      continue;
    }
    // Scripted baseline: the same fixed command the pre-P4 noise ran.
    const s = await scriptedShift(persona, spec, runWs);
    if (s) await runWs(s.command, 15_000).catch(() => "");
    const state: AgentState = {
      steps: s ? 1 : 0, inputTokens: 0, outputTokens: 0,
      modelId: opts.agent?.modelId ?? "scripted-1",
      ...(s ? {} : { stoppedByCap: "no VM workstation" }),
    };
    shifts.push({
      personaId: persona.id, workstation: persona.workstation,
      performed: s ? [{ action: "web_fetch", detail: s.detail }] : [],
      refused: [], mode: "scripted", auth: "local", state, guardrails: newGuardrailLog(),
    });
    agentStates[`persona:${persona.id}`] = state;
  }
  return { shifts, agentStates };
}

/** VM ground truth → the shape blue's tool pages through. */
function normalized(ev: { hostId: string; at: string; kind: string; detail?: Record<string, unknown> }): NormalizedEvent {
  const d = ev.detail ?? {};
  return {
    hostId: ev.hostId, at: ev.at, kind: ev.kind,
    src: typeof d.src === "string" ? d.src : "local",
    user: typeof d.user === "string" ? d.user : undefined,
    detail: d,
  };
}

function summarize(logs: GuardrailLog[]): AgentRunResult["guardrails"] {
  const all = logs.reduce((acc, l) => ({ rejected: [...acc.rejected, ...l.rejected], unverifiedClaims: [...acc.unverifiedClaims, ...l.unverifiedClaims] }), newGuardrailLog());
  const byKind: Record<string, number> = {};
  for (const r of all.rejected) byKind[r.kind] = (byKind[r.kind] ?? 0) + 1;
  return {
    rejected: all.rejected.length, byKind, unverifiedClaims: all.unverifiedClaims.length,
    samples: [...all.rejected.map((r) => `${r.kind}: ${r.detail}`), ...all.unverifiedClaims].slice(0, 8).map((x) => x.slice(0, 200)),
  };
}

export async function runVmAgentExercise(input: { spec: EnvironmentSpec; run: Run }, opts: VmAgentRunOptions): Promise<AgentRunResult> {
  const { spec, run: runRec } = input;
  const store = opts.store ?? localStore;
  const runId = runRec.runId;
  const state = opts.state ?? await readVmRunState(vmLifecycleFor({ runId }));
  if (!state) throw new Error(`no VM registry for ${runId}; cannot run the VM agent exercise`);
  const attacker = spec.instances.find((i) => i.runtime === "vm" && i.role === "attacker");
  if (!attacker) throw new Error(`model agents on the VM runtime need an attacker guest on the lab segment`);
  const atk = state.instances[attacker.hostId];
  if (!atk) throw new Error(`no VM ${attacker.hostId} in the run registry`);
  const instOf = async (hostId: string) => {
    const inst = state.instances[hostId];
    if (!inst) throw new Error(`no VM ${hostId} in the run registry`);
    return inst;
  };
  const exec = opts.exec ?? (async (inst: VmInstanceState, command: string, timeoutMs?: number) => (await execInGuest(inst, command, { timeoutMs })).stdout);
  const addressOf = (hostId: string) => state.instances[hostId]?.lab?.address ?? "127.0.0.1";
  const labAddresses = Object.values(state.instances).map((i) => i.lab?.address).filter((x): x is string => Boolean(x));
  // Red's argv runs on the attacker guest over the management plane.
  const execute = async (argv: string[]) => {
    const r = await execInGuest(atk, argv.map(shq).join(" "), { timeoutMs: 30_000 });
    return { stdout: r.stdout, stderr: r.stderr };
  };

  const lf = opts.langfuse === undefined ? langfuseConfig() : opts.langfuse;
  const sink = lf ? new LangfuseSink(lf, { orgId: runRec.orgId, specDigest: runRec.specDigest, mode: runRec.mode, backend: runRec.backend }) : null;
  const recorder = new TeeRecorder(new LocalTrajectoryRecorder(store), sink);
  const caps = opts.caps ?? capsFromEnv();
  const trace = opts.traceEnabled !== false;
  // Both roles come from the registry unless a caller injects a client; the
  // resolved served IDs are pinned into the returned run record (F-14).
  const { red, blue } = await resolveAgentClients(
    runRec.orgId,
    { red: opts.red ?? opts.agent, blue: opts.blue ?? opts.agent },
    { surface: effectiveAgentSurface(spec.platform?.modelSurface) },
  );
  const personaClient = opts.personas ?? opts.agent;
  const personaCaps = opts.personaCaps ?? { ...caps, maxSteps: Math.max(4, Math.ceil(caps.maxSteps / 2)), maxInputTokens: Math.ceil(caps.maxInputTokens / 2), maxOutputTokens: Math.ceil(caps.maxOutputTokens / 2) };

  // Fresh proofs before the window opens, so planting is never scored as activity.
  const proofs = await plantVmProofs(spec, runId, (h) => { const i = state.instances[h]; if (!i) throw new Error(`no VM ${h}`); return i; }, exec);
  await sleep(2_000);
  const since = new Date().toISOString();
  const agentStates: Record<string, AgentState> = {};
  const shifts = await personaShifts(spec, runId, exec, instOf, {
    agent: personaClient, caps: personaCaps, recorder, traceEnabled: trace,
  });
  Object.assign(agentStates, shifts.agentStates);
  const shiftReport = shifts.shifts.map((s) => ({
    personaId: s.personaId, workstation: s.workstation, mode: s.mode, auth: s.auth,
    performed: s.performed.length, refused: s.refused.length, modelId: s.state.modelId,
  }));

  const campaign = await runRedCampaign(red, {
    spec, runId, caps, recorder, traceEnabled: trace,
    executeObjective: async (o, directive) => {
      const vuln = spec.plantedVulns.find((v) => v.techniqueId === o.techniqueId && v.targetHostId === o.asset);
      const r = await redObjective(red, {
        spec, runId, objective: o, vuln, proof: proofs.get(o.id), directive, caps, recorder,
        traceEnabled: trace, execute, extraHosts: labAddresses,
      });
      // Brute force has no proof to bring back. Tell the orchestrator what the
      // target's own log recorded, so it does not report a success as a miss.
      // Final scoring re-reads the same log independently below.
      if (isAuthFailureObjective(o) && !r.retrieved) {
        const seen = await collectVmTelemetry({ ...spec, instances: spec.instances.filter((i) => i.hostId === o.asset) }, runId, {
          state, exec, since, redMarkers: [], redSources: [addressOf(attacker.hostId)],
        }).catch(() => []);
        const failed = seen.filter((e) => e.actor === "red" && e.kind === "auth.login.failed").length;
        if (failed >= AUTH_FAILURE_THRESHOLD) return { ...r, retrieved: true };
      }
      return r;
    },
  });
  const redResults = campaign.results.map((r) => ({ objectiveId: r.objectiveId, retrieved: r.retrieved, attempts: r.attempts.length }));
  const logs: GuardrailLog[] = [campaign.guardrails, ...campaign.results.map((r) => r.guardrails)];
  agentStates["red:orchestrator"] = campaign.state;
  for (const r of campaign.results) agentStates[`red:${r.objectiveId}`] = r.state;

  // Collect out of band after red acts; attribution is marker + attacker source.
  await sleep(2_000);
  const redMarkers = spec.objectives.map((o) => `RED-${o.id}-${runId.replace(/^run-/, "").slice(0, 8)}`.replace(/[^A-Za-z0-9-]/g, ""));
  const telemetry = await collectVmTelemetry(spec, runId, {
    state, exec, since, redMarkers,
    redSources: [addressOf(attacker.hostId)],
  });
  for (const e of telemetry) ingest(e, { store });

  // Ground truth, established here rather than by any agent.
  for (const o of spec.objectives) {
    const r = redResults.find((x) => x.objectiveId === o.id)!;
    const observed = telemetry.some((e) => e.hostId === o.asset && e.actor === "red");
    // Brute force has no proof to return: the target's own log is the evidence.
    const failedLogons = telemetry.filter((e) => e.hostId === o.asset && e.actor === "red" && e.kind === "auth.login.failed").length;
    const verified = isAuthFailureObjective(o) ? failedLogons >= AUTH_FAILURE_THRESHOLD : r.retrieved;
    const lastRed = telemetry.filter((e) => e.hostId === o.asset && e.actor === "red").at(-1)?.at ?? new Date().toISOString();
    ingest({
      runId, hostId: o.asset, kind: "objective", actor: "red", techniqueId: o.techniqueId,
      outcome: verified && observed ? "succeeded" : "failed", at: lastRed,
      detail: { objectiveId: o.id, signal: o.successSignal, verified, observed, ...(isAuthFailureObjective(o) ? { failedLogons } : {}) },
    }, { store });
  }

  // Blue sees only the collected stream.
  const investigation = await blueInvestigate(blue, {
    spec, runId, since, caps, recorder, traceEnabled: trace,
    telemetry: telemetry.map(normalized),
  });
  agentStates["blue"] = investigation.state;
  logs.push(investigation.guardrails);

  // A proposal becomes an alert only when a promoted rule independently matches
  // red-attributed telemetry.
  const benign = telemetry.filter((e) => e.actor !== "red");
  const fpAlerts = opts.detections.liveAlerts(benign);
  const trueAlerts = opts.detections.liveAlerts(telemetry.filter((e) => e.actor === "red"));
  const agentAlerts: Alert[] = [];
  for (const p of investigation.proposals) {
    const match = trueAlerts.find((a) => a.hostId === p.hostId && a.techniqueId === p.techniqueId);
    if (!match) continue;
    const alert: Alert = { runId, hostId: p.hostId, techniqueId: match.techniqueId, ruleId: match.ruleId, ruleVersion: match.ruleVersion, confidence: match.confidence, at: new Date().toISOString() };
    agentAlerts.push(alert);
    ingest({ runId, hostId: p.hostId, kind: "alert", actor: "blue", techniqueId: match.techniqueId, outcome: "detected", at: alert.at, detail: { signal: "sigma-match", ruleId: match.ruleId, ruleVersion: match.ruleVersion, confidence: match.confidence, agentProposed: true, why: p.why, response: p.response } }, { store });
    recorder.record({ runId, hostId: p.hostId, actor: "blue", observation: `rule-confirmed alert ${match.ruleId}`, action: p.response, techniqueId: match.techniqueId, at: alert.at });
  }

  // Enforce at most one response, and only one the runtime can actually apply.
  const first = agentAlerts[0];
  const chosen = investigation.proposals.find((p) => first && p.hostId === first.hostId && p.techniqueId === first.techniqueId);
  let enforcement: AgentRunResult["enforcement"] = null;
  if (first && chosen) {
    enforcement = { response: chosen.response, hostId: first.hostId, enforced: false };
    if (chosen.response === "block IP" && chosen.ip && labAddresses.includes(chosen.ip)) {
      const r = await blockPeer(first.hostId, chosen.ip, exec, instOf);
      enforcement.enforced = r.enforced;
      enforcement.target = chosen.ip;
      if (!r.enforced) enforcement.reason = r.detail;
      if (r.enforced && chosen.ip === addressOf(attacker.hostId)) {
        // Prove the effect, not just the rule: the attacker guest tries the
        // blocked host's SSH port again; a refused or timed-out connect is the
        // evidence. The rule is checked first, so a pass here is not a fluke.
        const target = addressOf(first.hostId);
        const probe = await execInGuest(atk, `timeout 4 bash -c 'exec 3<>/dev/tcp/${target}/22' && echo reachable || echo blocked`, { timeoutMs: 15_000 })
          .then((x) => x.stdout.trim()).catch((e: Error) => `error: ${e.message}`);
        enforcement.verifiedBlocked = probe.endsWith("blocked");
        enforcement.verifyDetail = `attacker ${chosen.ip} -> ${first.hostId} ${target}:22 after block: ${probe.slice(-40)}`;
      }
    } else if (chosen.response === "isolate host") {
      const r = await isolateHost(first.hostId, exec, instOf);
      enforcement.enforced = r.enforced;
      if (!r.enforced) enforcement.reason = r.detail;
    } else {
      enforcement.reason = `"${chosen.response}" is not enforceable${chosen.ip && !labAddresses.includes(chosen.ip) ? ` for ${chosen.ip}` : ""} on the VM runtime`;
      recorder.record({ runId, hostId: first.hostId, actor: "blue", observation: enforcement.reason, action: "unenforced", techniqueId: first.techniqueId, at: new Date().toISOString() });
    }
    if (enforcement.enforced) {
      ingest({ runId, hostId: first.hostId, kind: "response", actor: "blue", techniqueId: first.techniqueId, outcome: "contained", at: new Date().toISOString(), detail: { response: chosen.response, enforced: true, target: enforcement.target, ip: chosen.ip, ruleId: first.ruleId } }, { store });
    }
  }

  // Trace export is optional observability: a rejected export is logged and
  // counted as zero, never allowed to fail an already-scored run.
  const langfuseEvents = sink ? await sink.flush().catch((e: Error) => { console.warn(`langfuse export skipped: ${e.message.slice(0, 160)}`); return 0; }) : 0;
  incr("arena_exercises_total", { backend: runRec.backend, mode: "agents-vm" });
  incr("arena_telemetry_events_total", { runtime: "vm" }, telemetry.length);
  incr("arena_alerts_total", { runtime: "vm" }, agentAlerts.length);
  incr("arena_false_positives_total", { runtime: "vm" }, fpAlerts.length);
  const join = joinRun(runId, store);
  const scorecard0 = scoreExercise(spec, join);
  incr("arena_objectives_achieved_total", { runtime: "vm" }, scorecard0.objectivesAchieved);
  const falsePositiveRate = benign.length ? fpAlerts.length / benign.length : 0;
  const scorecard: Scorecard = { ...scorecard0, falsePositiveRate };
  const falsePositiveDetail = fpAlerts.map((a) => {
    const e = benign.find((x) => x.hostId === a.hostId && x.at === a.at);
    return { ruleId: a.ruleId, hostId: a.hostId, kind: e?.kind ?? "?", sample: JSON.stringify(e?.detail ?? {}).slice(0, 160) };
  });
  return {
    run: { ...runRec, modelIds: { ...runRec.modelIds, red: red.modelId, blue: blue.modelId,
      ...(personaClient ? { persona: personaClient.modelId } : {}) }, score: scorecard }, scorecard,
    alerts: agentAlerts, falsePositives: fpAlerts.length, benignEvents: benign.length,
    falsePositiveDetail, langfuseEvents, agentStates,
    blueProposals: investigation.proposals, enforcement,
    redCampaign: { order: campaign.order, decisions: campaign.decisions, summary: campaign.summary },
    blueMonitoring: investigation.monitoring,
    shiftReport,
    guardrails: summarize(logs),
  };
}

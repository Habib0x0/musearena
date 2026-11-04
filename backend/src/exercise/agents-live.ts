import type { EnvironmentSpec, Run } from "@musearena/shared";
import { ingest } from "../observability/collector.js";
import { EventStore, localStore } from "../observability/events.js";
import { LocalTrajectoryRecorder } from "../observability/trajectory.js";
import { LangfuseSink, TeeRecorder, langfuseConfig, type LangfuseConfig } from "../observability/langfuse.js";
import { collectTelemetry, containerIp, windowStart } from "../observability/docker-telemetry.js";
import { joinRun } from "../observability/export.js";
import type { DetectionStore, Alert } from "../detections/sigma.js";
import { redObjective, runRedCampaign, blueInvestigate, capsFromEnv, plantProofs, newGuardrailLog, type AgentCaps, type AgentState, type BlueMonitoringSummary, type BlueProposal, type GuardrailLog, type RedCampaignResult } from "./agents.js";
import { effectiveAgentSurface, type AgentClient } from "../lib/model.js";
import { resolveAgentClients } from "../learning/models.js";
import { scoreExercise, type Scorecard } from "./evaluator.js";
import { incr } from "../observability/metrics.js";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { containerName, networkName, ATTACKER_HOST_ID } from "../provisioner/names.js";
import { execInContainer } from "../configurator/docker-executors.js";

const run = promisify(execFile);

export interface AgentRunOptions {
  store?: EventStore;
  detections: DetectionStore;
  docker?: string;
  langfuse?: LangfuseConfig | null;
  caps?: AgentCaps;
  traceEnabled?: boolean;
  /** Injected for tests; defaults to per-role Muse models over MaaS (one client plays both when set). */
  agent?: AgentClient;
  red?: AgentClient;
  blue?: AgentClient;
}

export interface AgentRunResult {
  run: Run; scorecard: Scorecard;
  alerts: Alert[]; falsePositives: number; benignEvents: number;
  falsePositiveDetail: { ruleId: string; hostId: string; kind: string; sample: string }[];
  langfuseEvents: number;
  agentStates: Record<string, AgentState>;
  blueProposals: BlueProposal[];
  /** Red orchestrator tasking order and verified per-objective outcomes. */
  redCampaign?: Pick<RedCampaignResult, "order" | "decisions" | "summary">;
  /** Blue deterministic log-monitor candidates and batch counts. */
  blueMonitoring?: BlueMonitoringSummary;
  /** Persona shifts (P4, VM path only): per-persona mode, action counts, model. */
  shiftReport?: { personaId: string; workstation: string; mode: "agent" | "scripted"; auth: "kerberos" | "local"; performed: number; refused: number; modelId: string }[];
  enforcement: { response: string; hostId: string; enforced: boolean; target?: string; reason?: string;
    /** After a block, the attacker tried the target again: true when that connection failed. */
    verifiedBlocked?: boolean; verifyDetail?: string } | null;
  /** Hallucination guardrail outcomes across red and blue (counts plus the first details). */
  guardrails: { rejected: number; byKind: Record<string, number>; unverifiedClaims: number; samples: string[] };
}

/** Allowlisted responses this Docker runtime can actually enforce; others are recorded as unenforced. */
const ENFORCEABLE = new Set(["block IP", "isolate host"]);

export async function runAgentExercise(input: { spec: EnvironmentSpec; run: Run }, opts: AgentRunOptions): Promise<AgentRunResult> {
  const { spec, run: runRec } = input;
  const store = opts.store ?? localStore;
  const docker = opts.docker ?? "docker";
  const runId = runRec.runId;
  // Fresh random proofs per run, planted before the telemetry window opens so
  // the platform's own write is never scored as activity.
  const proofs = await plantProofs(spec, runId, docker);
  const startedAt = await windowStart(spec, runId, docker);
  const since = new Date(startedAt).toISOString();
  const lf = opts.langfuse === undefined ? langfuseConfig() : opts.langfuse;
  const sink = lf ? new LangfuseSink(lf, { orgId: runRec.orgId, specDigest: runRec.specDigest, mode: runRec.mode, backend: runRec.backend }) : null;
  const recorder = new TeeRecorder(new LocalTrajectoryRecorder(store), sink);
  const caps = opts.caps ?? capsFromEnv();
  const trace = opts.traceEnabled !== false;
  // No injected client means the registry decides: the resolved served ID is
  // pinned into the returned run record below (F-14).
  const { red, blue } = await resolveAgentClients(
    runRec.orgId,
    { red: opts.red ?? opts.agent, blue: opts.blue ?? opts.agent },
    { surface: effectiveAgentSurface(spec.platform?.modelSurface) },
  );

  // Persona activity on the hosts first (benign traffic the agent must sift).
  for (const p of spec.personas) {
    const inst = spec.instances.find((i) => i.hostId === p.workstation);
    if (inst?.role === "web") await execInContainer(containerName(runId, inst.hostId), ["curl", "-s", "-o", "/dev/null", "http://127.0.0.1/"], { docker });
    for (const db of spec.instances.filter((i) => i.role === "db")) {
      await execInContainer(containerName(runId, db.hostId), ["psql", "-U", "app", "-d", "app", "-tAc", "SELECT count(*) FROM employees"], { docker });
    }
  }
  // Persona reads were executed on the hosts above so logs contain them;
  // wait for flush so the collection window includes them.

  const agentStates: Record<string, AgentState> = {};
  // --- red: an orchestrator coordinates one operator loop per objective ---
  const campaign = await runRedCampaign(red, {
    spec, runId, caps, recorder, traceEnabled: trace,
    executeObjective: async (o, directive) => {
      const vuln = spec.plantedVulns.find((v) => v.techniqueId === o.techniqueId && v.targetHostId === o.asset);
      return redObjective(red, { spec, runId, objective: o, vuln, proof: proofs.get(o.id), directive, caps, recorder, traceEnabled: trace, docker });
    },
  });
  const redResults = campaign.results.map((r) => ({ objectiveId: r.objectiveId, retrieved: r.retrieved, attempts: r.attempts.length }));
  const logs: GuardrailLog[] = [campaign.guardrails, ...campaign.results.map((r) => r.guardrails)];
  agentStates["red:orchestrator"] = campaign.state;
  for (const r of campaign.results) agentStates[`red:${r.objectiveId}`] = r.state;
  // --- collect + ingest real telemetry (actor labels from source address) ---
  await new Promise((r) => setTimeout(r, 1500));
  const telemetry = (await collectTelemetry(spec, runId, { docker, since, localActor: "noise" })).filter((e) => Date.parse(e.at) > startedAt);
  for (const e of telemetry) ingest(e, { store });

  // Ground truth (established here, not by any agent):
  for (const o of spec.objectives) {
    const r = redResults.find((x) => x.objectiveId === o.id)!;
    const observed = telemetry.some((e) => e.hostId === o.asset && e.actor === "red");
    ingest({
      runId, hostId: o.asset, kind: "objective", actor: "red", techniqueId: o.techniqueId,
      outcome: r.retrieved && observed ? "succeeded" : "failed",
      at: telemetry.filter((e) => e.hostId === o.asset && e.actor === "red").at(-1)?.at ?? new Date().toISOString(),
      detail: { objectiveId: o.id, signal: o.successSignal, verified: r.retrieved, observed },
    }, { store });
  }

  // --- blue: agent investigates via telemetry tool, then rule enforcement ---
  const investigation = await blueInvestigate(blue, { spec, runId, since, caps, recorder, traceEnabled: trace, docker });
  agentStates["blue"] = investigation.state;
  logs.push(investigation.guardrails);

  // Rule enforcement: blue's proposals become alerts only when a promoted
  // Sigma rule independently matches red-attributed telemetry.
  const benign = telemetry.filter((e) => e.actor !== "red");
  const fpAlerts = opts.detections.liveAlerts(benign);
  // Alerts from red telemetry (true positives)
  const trueAlerts = opts.detections.liveAlerts(telemetry.filter((e) => e.actor === "red"));
  const agentAlerts: Alert[] = [];
  for (const p of investigation.proposals) {
    const tech = p.techniqueId;
    const match = trueAlerts.find((a) => a.hostId === p.hostId && a.techniqueId === tech);
    if (!match) continue; // blue proposed something the rules don't confirm: not an alert
    const alert: Alert = { runId, hostId: p.hostId, techniqueId: match.techniqueId, ruleId: match.ruleId, ruleVersion: match.ruleVersion, confidence: match.confidence, at: new Date().toISOString() };
    agentAlerts.push(alert);
    ingest({ runId, hostId: p.hostId, kind: "alert", actor: "blue", techniqueId: match.techniqueId, outcome: "detected", at: alert.at, detail: { signal: "sigma-match", ruleId: match.ruleId, ruleVersion: match.ruleVersion, confidence: match.confidence, agentProposed: true, why: p.why, response: p.response } }, { store });
    recorder.record({ runId, hostId: p.hostId, actor: "blue", observation: `rule-confirmed alert ${match.ruleId}`, action: p.response, techniqueId: match.techniqueId, at: alert.at });
  }

  // Enforce at most one response here (first confirmed alert).
  const first = agentAlerts[0];
  const chosen = investigation.proposals.find((p) => first && p.hostId === first.hostId && p.techniqueId === first.techniqueId);
  let enforcement: AgentRunResult["enforcement"] = null;
  if (first && chosen) {
    enforcement = { response: chosen.response, hostId: first.hostId, enforced: false };
    if (ENFORCEABLE.has(chosen.response)) {
      // isolate host: cut the attacked host off. block IP: cut off whichever container
      // owns the IP blue cited — enforcing the agent's actual claim, not a stand-in.
      let target: string | null = chosen.response === "isolate host" ? first.hostId : null;
      if (chosen.response === "block IP") {
        for (const h of [ATTACKER_HOST_ID, ...spec.instances.map((i) => i.hostId)]) {
          if (chosen.ip && (await containerIp(docker, containerName(runId, h))) === chosen.ip) { target = h; break; }
        }
        if (!target) enforcement.reason = `no container on the run network owns ${chosen.ip}`;
      }
      const ok = target ? await run(docker, ["network", "disconnect", "-f", networkName(runId), containerName(runId, target)]).then(() => true, () => false) : false;
      enforcement.enforced = ok;
      if (target) enforcement.target = target;
      // Containment only counts when what got cut off is the attacker or the attacked host.
      const contains = ok && (target === ATTACKER_HOST_ID || target === first.hostId);
      if (ok && !contains) enforcement.reason = `blocked ${target}, which is neither the attacker nor ${first.hostId}`;
      if (contains) ingest({ runId, hostId: first.hostId, kind: "response", actor: "blue", techniqueId: first.techniqueId, outcome: "contained", at: new Date().toISOString(), detail: { response: chosen.response, enforced: true, target, ip: chosen.ip, ruleId: first.ruleId } }, { store });
    } else {
      // Allowlisted but not enforceable on this runtime: audited, earns no containment.
      recorder.record({ runId, hostId: first.hostId, actor: "blue", observation: `response "${chosen.response}" is not enforceable on the docker runtime`, action: "unenforced", techniqueId: first.techniqueId, at: new Date().toISOString() });
    }
  }

  // Trace export is optional observability: a rejected export is logged and
  // counted as zero, never allowed to fail an already-scored run.
  const langfuseEvents = sink ? await sink.flush().catch((e: Error) => { console.warn(`langfuse export skipped: ${e.message.slice(0, 160)}`); return 0; }) : 0;
  incr("arena_exercises_total", { backend: runRec.backend, mode: "agents" });
  incr("arena_telemetry_events_total", {}, telemetry.length);
  incr("arena_alerts_total", {}, agentAlerts.length);
  incr("arena_false_positives_total", {}, fpAlerts.length);
  const join = joinRun(runId, store);
  const scorecard0 = scoreExercise(spec, join);
  incr("arena_objectives_achieved_total", {}, scorecard0.objectivesAchieved);
  const falsePositiveRate = benign.length ? fpAlerts.length / benign.length : 0;
  const scorecard: Scorecard = { ...scorecard0, falsePositiveRate };
  const falsePositiveDetail = fpAlerts.map((a) => {
    const e = benign.find((x) => x.hostId === a.hostId && x.at === a.at);
    return { ruleId: a.ruleId, hostId: a.hostId, kind: e?.kind ?? "?", sample: JSON.stringify(e?.detail ?? {}).slice(0, 160) };
  });
  return {
    run: { ...runRec, modelIds: { ...runRec.modelIds, red: red.modelId, blue: blue.modelId }, score: scorecard }, scorecard,
    alerts: agentAlerts, falsePositives: fpAlerts.length, benignEvents: benign.length,
    falsePositiveDetail, langfuseEvents, agentStates,
    blueProposals: investigation.proposals, enforcement,
    redCampaign: { order: campaign.order, decisions: campaign.decisions, summary: campaign.summary },
    blueMonitoring: investigation.monitoring,
    guardrails: summarize(logs),
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

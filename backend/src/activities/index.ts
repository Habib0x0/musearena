import type { EnvironmentSpec, Run } from "@musearena/shared";
import { deployEnvironment, teardownEnvironment } from "../provisioner/deploy.js";
import { applyConfig, type InstanceTarget } from "../configurator/ansible.js";
import { proofGate, sensorCanary, type GateOptions } from "../configurator/gates.js";
import { gateOptionsFromEnv } from "../configurator/executors.js";
import { dockerGateOptions } from "../configurator/docker-executors.js";
import { vmGateOptions } from "../configurator/vm-executors.js";
import { runExercise } from "../exercise/runner.js";
import { livePack, runLiveExercise } from "../exercise/live.js";
import { runAgentExercise } from "../exercise/agents-live.js";
import { runVmExercise } from "../exercise/vm-live.js";
import { runVmAgentExercise } from "../exercise/vm-agents.js";
import { EventStore } from "../observability/events.js";
import { publishRunDataset } from "../observability/publish.js";
import { incr } from "../observability/metrics.js";
import { recordRunScore } from "../observability/recorder.js";
import { audit } from "../lib/audit.js";
import { markDeployment } from "../provisioner/deployment-status.js";
import { pinDeploymentsForRun, supabaseDeploymentStore } from "../learning/deployments.js";
import { baseModelFor, resolveModel, resolveServedModel } from "../learning/models.js";
import { effectiveAgentSurface, modalAgentClient, modalPersonaClient, personaClientOrFallback, type AgentClient } from "../lib/model.js";
import { workerRoutingConfig } from "../lib/worker-routing.js";

export async function noop(orgId: string): Promise<string> {
  return `ok:${orgId}`;
}

export async function deployActivity(input: { deploymentId: string; orgId: string; runId: string; spec: EnvironmentSpec }): Promise<string> {
  // Persona agents run on Muse Glimmer, which scales to zero: start its cold
  // start now so it overlaps the build instead of delaying the exercise.
  const p = input.spec.platform;
  const useAgents = p?.exerciseEngine ? p.exerciseEngine === "agents" : (process.env.MUSEARENA_AGENT_RUNTIME ?? "") === "maas";
  if (useAgents && effectiveAgentSurface(p?.modelSurface) === "meta-modal") {
    try {
      modalPersonaClient().wake().catch((e) => console.warn(`[personas] warm-up: ${e instanceof Error ? e.message : e}`));
    } catch (e) {
      console.warn(`[personas] warm-up: ${e instanceof Error ? e.message : e}`);
    }
  }
  const res = await deployEnvironment(input);
  return res.stackId;
}

export async function configureActivity(input: { deploymentId: string; orgId: string; runId: string; spec: EnvironmentSpec; targets: InstanceTarget[] }): Promise<string> {
  await markDeployment(input.deploymentId, { status: "configuring" });
  // VM guests get their real SSH endpoints from the lifecycle registry —
  // a bare hostId is not a reachable Ansible target.
  let targets = input.targets;
  if (input.spec.instances.some((i) => i.runtime === "vm")) {
    const { vmLifecycleFor } = await import("../provisioner/deploy.js");
    const { readVmRunState } = await import("../provisioner/vm-lifecycle.js");
    const { vmTargetsFromState } = await import("../configurator/vm-ssh.js");
    const state = await readVmRunState(vmLifecycleFor({ runId: input.runId }));
    if (!state) throw new Error(`no VM registry for ${input.runId}; deploy must start guests before configure`);
    targets = input.spec.instances.map((i) => {
      const vm = vmTargetsFromState(state).find((t) => t.hostId === i.hostId);
      return vm ?? input.targets.find((t) => t.hostId === i.hostId) ?? { hostId: i.hostId, name: i.name, connectVia: i.hostId };
    });
  }
  let reports = await applyConfig({ ...input, targets });
  let failed = reports.filter((r) => !r.ok);
  // §3.4: remediate automatically where possible. Configuration is idempotent,
  // so one bounded full re-run is a safe repair attempt (package locks, service
  // start ordering, transient DNS inside the lab). It is not an infinite retry:
  // a second failure is reported with the failing hosts and the env is destroyed
  // by the workflow, exactly as before.
  let remediated = 0;
  if (failed.length) {
    const first = failed.map((f) => f.instance);
    await audit({
      orgId: input.orgId, actor: "configurator", action: "CONFIG_REMEDIATION",
      subjectType: "deployment", subjectId: input.deploymentId,
      detail: { attempt: 1, failed: first, details: failed.map((f) => ({ instance: f.instance, detail: f.detail })) },
    });
    reports = await applyConfig({ ...input, targets });
    failed = reports.filter((r) => !r.ok);
    remediated = first.length - failed.length;
    await audit({
      orgId: input.orgId, actor: "configurator", action: "CONFIG_REMEDIATION",
      subjectType: "deployment", subjectId: input.deploymentId,
      detail: { attempt: 2, failed: failed.map((f) => f.instance), details: failed.map((f) => ({ instance: f.instance, detail: f.detail })), recovered: remediated },
    });
  }
  if (failed.length) throw new Error(`configuration failed for: ${failed.map((f) => `${f.instance} (${f.detail})`).join(", ")}`);
  return remediated > 0 ? `configured:${reports.length} remediated:${remediated}` : `configured:${reports.length}`;
}

/**
 * Readiness gate (T-16b): every VM host must answer its declared service
 * protocols over the run's SSH endpoint before proof/exercise may run. A
 * failed or unanswerable probe fails the gate — installation is not proof.
 */
export async function readinessActivity(input: { deploymentId: string; orgId: string; runId: string; spec: EnvironmentSpec }): Promise<string> {
  await markDeployment(input.deploymentId, { status: "verifying" });
  const hasVm = input.spec.instances.some((i) => i.runtime === "vm");
  const hasContainer = input.spec.instances.some((i) => i.runtime === "container");
  if (!hasVm && !hasContainer) return "readiness:skipped";
  const { checkSpecReadiness } = await import("../configurator/readiness.js");
  const results = [];
  if (hasVm) {
    const { vmLifecycleFor } = await import("../provisioner/deploy.js");
    const { readVmRunState } = await import("../provisioner/vm-lifecycle.js");
    const { execInGuest } = await import("../configurator/vm-ssh.js");
    const state = await readVmRunState(vmLifecycleFor({ runId: input.runId }));
    if (!state) throw new Error(`no VM registry for ${input.runId}; cannot verify readiness`);
    results.push(...await checkSpecReadiness({
      spec: input.spec,
      runId: input.runId,
      sshUserOf: (hostId) => state.instances[hostId]?.ssh?.user ?? "arena",
      exec: async (hostId, command, timeoutMs) => {
        const inst = state.instances[hostId];
        if (!inst) throw new Error(`no VM ${hostId} in the run registry`);
        return (await execInGuest(inst, command, { timeoutMs })).stdout;
      },
    }));
  }
  if (hasContainer) {
    const { execInContainerShell } = await import("../configurator/docker-executors.js");
    const { containerName } = await import("../provisioner/names.js");
    results.push(...await checkSpecReadiness({
      spec: input.spec,
      runId: input.runId,
      runtime: "container",
      sshUserOf: () => "root",
      exec: async (hostId, command, timeoutMs) => execInContainerShell(containerName(input.runId, hostId), command, { timeoutMs }),
    }));
  }
  const failed = results.filter((r) => !r.ok);
  const pass = failed.length === 0;
  await audit({
    orgId: input.orgId, actor: "configurator", action: "PROOF_GATE_DECISION", subjectType: "run",
    subjectId: input.runId,
    detail: { gate: "readiness", pass, hosts: results.map((r) => ({ host: r.hostId, ok: r.ok, checks: r.checks })) },
  });
  incr("arena_readiness_decisions_total", { pass: String(pass) });
  if (!pass) {
    throw new Error(`readiness failed: ${failed.map((h) => `${h.hostId}: ${h.checks.filter((c) => !c.ok).map((c) => c.detail).join("; ")}`).join(" | ")}`);
  }
  return `readiness:ok:${results.length}`;
}

/** Gate executors: real Docker executors when every instance runs as a container; local harness executors only with MUSEARENA_LOCAL_GATES=1; otherwise none (fail closed). */
export function gatesFor(spec: EnvironmentSpec, env: NodeJS.ProcessEnv = process.env, runId?: string): GateOptions & { executor: string } {
  if (spec.instances.length > 0 && spec.instances.every((i) => i.runtime === "container")) return { ...dockerGateOptions(spec), executor: "docker" };
  if (runId && spec.instances.length > 0 && spec.instances.every((i) => i.runtime === "vm")) return { ...vmGateOptions(spec, { runId }), executor: "vm" };
  const local = gateOptionsFromEnv(env);
  return { ...local, executor: local.executeCanary ? "local-harness" : "none" };
}

/**
 * Gate activity (Req §12.3, §3.3): canary on every host, live proof per
 * planted vuln. The gate never passes itself; the decision and the executor
 * used are audited either way.
 */
export async function proofActivity(input: { deploymentId: string; orgId: string; runId: string; spec: EnvironmentSpec }, gates: GateOptions & { executor?: string } = gatesFor(input.spec, process.env, input.runId)): Promise<string> {
  await markDeployment(input.deploymentId, { status: "verifying" });
  const canaries = [];
  for (const i of input.spec.instances) canaries.push(await sensorCanary(input.runId, i.hostId, gates));
  const canary = { pass: canaries.length > 0 && canaries.every((c) => c.pass), details: canaries.flatMap((c) => c.details) };
  const proof = await proofGate({ runId: input.runId, spec: input.spec }, gates);
  await audit({
    orgId: input.orgId, actor: "configurator", action: "PROOF_GATE_DECISION", subjectType: "run",
    subjectId: input.runId, detail: { executor: gates.executor ?? "injected", canary: canary.details, proof: proof.details, pass: canary.pass && proof.pass },
  });
  incr("arena_gate_decisions_total", { executor: gates.executor ?? "injected", pass: String(canary.pass && proof.pass) });
  if (!canary.pass) throw new Error(`sensor canary failed: ${canary.details.join("; ")}`);
  if (!proof.pass) throw new Error(`proof gate failed: ${proof.details.join("; ")}`);
  return "proof:ok";
}

/**
 * Exercise (Req §5): container envs run the LIVE exercise (red acts on the
 * env, blue detects via promoted Sigma over collected telemetry). Other
 * runtimes have no live red/blue yet and use the deterministic harness,
 * stamped as such in the audit so the two are never confused.
 */
/**
 * Exercise-start deployment pinning (F-11): active aliases decide the served
 * model for this run, subject to their traffic percentage, and the tuple is
 * written onto the run record before any agent acts. An unapplied learning
 * schema degrades to the existing registry/base resolution with a warning —
 * the core exercise path must not brick on an additive migration.
 */
async function deploymentClients(run: Run, surface: "meta" | "meta-modal"): Promise<{ red?: AgentClient; blue?: AgentClient }> {
  try {
    const fallbackModelIds: Partial<Record<"red" | "blue", string>> = {};
    for (const role of ["red", "blue"] as const) {
      try {
        fallbackModelIds[role] = (await resolveServedModel(run.orgId, role, { surface })).modelId;
      } catch {
        fallbackModelIds[role] = baseModelFor(role, process.env, surface).modelId;
      }
    }
    const pins = await pinDeploymentsForRun(
      { orgId: run.orgId, roles: ["red", "blue"], fallbackModelIds },
      supabaseDeploymentStore(),
    );
    if (Object.keys(pins).length === 0) {
      if (surface !== "meta") return {};
      // Fill an explicit Meta run here so downstream generic resolution can
      // never drift onto Modal just because no deployment alias is active.
      const clients: { red?: AgentClient; blue?: AgentClient } = {};
      for (const role of ["red", "blue"] as const) {
        const modelId = fallbackModelIds[role]!;
        run.modelIds = { ...run.modelIds, [role]: modelId };
        clients[role] = await resolveModel(role, run.orgId, modelId, { surface });
      }
      return clients;
    }
    run.deployments = pins;
    const clients: { red?: AgentClient; blue?: AgentClient } = {};
    for (const role of ["red", "blue"] as const) {
      const pin = pins[role];
      if (!pin) continue;
      run.modelIds = { ...run.modelIds, [role]: pin.modelId };
      clients[role] = await resolveModel(role, run.orgId, pin.modelId, { surface });
    }
    return clients;
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (/PGRST205|model_deployments|does not exist|Could not find/i.test(message)) {
      console.warn(`[deployments] alias pinning unavailable (${message}); resolving models without deployments`);
      return {};
    }
    throw err;
  }
}

export async function exerciseActivity(input: { spec: EnvironmentSpec; run: Run }): Promise<string> {
  await markDeployment(input.run.deploymentId, { status: "exercising" });
  // `ready` is written only here: the environment has been configured,
  // probe-verified, gate-verified and scored. Everything before this is a
  // claim; this is the first point where the row may say the run works.
  const done = async (result: string): Promise<string> => {
    await markDeployment(input.run.deploymentId, { status: "ready" });
    return result;
  };
  const platform = input.spec.platform;
  const useAgents = platform?.exerciseEngine
    ? platform.exerciseEngine === "agents"
    : (process.env.MUSEARENA_AGENT_RUNTIME ?? "") === "maas";
  // Modal is the default agent surface when configured: Spark plays the
  // primary red/blue roles and Glimmer plays the small persona agents. An
  // explicit Meta surface instead resolves through registry/deployments on
  // Meta and is never silently substituted.
  const agentClients = async (): Promise<{ red?: AgentClient; blue?: AgentClient; personas?: AgentClient }> => {
    const surface = effectiveAgentSurface(platform?.modelSurface);
    const deployed = await deploymentClients(input.run, surface);
    if (surface !== "meta-modal") return deployed;
    const sparkFallback = deployed.red ?? deployed.blue ?? modalAgentClient("red");
    return { ...deployed, personas: await personaClientOrFallback(sparkFallback) };
  };
  const allVm = input.spec.instances.length > 0 && input.spec.instances.every((i) => i.runtime === "vm");
  if (allVm) {
    const store = new EventStore();
    const pack = await livePack();
    if (useAgents) {
      // Model agents act from the attacker guest over the lab segment; a spec
      // without one cannot host them and fails with that reason.
      const clients = await agentClients();
      const res = await runVmAgentExercise(input, { detections: pack.store, store, ...clients });
      await recordRunScore(res.run, { mode: "agents-maas-vm", platform, transport: "lab-attacker-guest", modelIds: res.run.modelIds, deployments: res.run.deployments, promotedRules: pack.promoted, alerts: res.alerts.length, falsePositives: res.falsePositives, benignEvents: res.benignEvents, falsePositiveDetail: res.falsePositiveDetail, langfuseEvents: res.langfuseEvents, agentStates: res.agentStates, blueProposals: res.blueProposals, enforcement: res.enforcement, guardrails: res.guardrails, shiftReport: res.shiftReport, redCampaign: res.redCampaign, blueMonitoring: res.blueMonitoring });
      const ds = await publishRunDataset(res.run, { store, spec: input.spec });
      return done(`score:${res.scorecard.objectivesAchieved}/${res.scorecard.objectivesTotal}|dataset:${ds.contentHash}|mode:agents-vm`);
    }
    const res = await runVmExercise(input, { detections: pack.store, store });
    await recordRunScore(res.run, { mode: "live-vm", platform, promotedRules: pack.promoted, alerts: res.alerts.length, falsePositives: res.falsePositives, benignEvents: res.benignEvents, falsePositiveDetail: res.falsePositiveDetail, langfuseEvents: res.langfuseEvents, enforcement: res.enforcement });
    const ds = await publishRunDataset(res.run, { store, spec: input.spec });
    return done(`score:${res.scorecard.objectivesAchieved}/${res.scorecard.objectivesTotal}|dataset:${ds.contentHash}|mode:live-vm`);
  }
  const live = input.spec.instances.length > 0 && input.spec.instances.every((i) => i.runtime === "container");
  if (live) {
    // Per-run store: the export below must contain this run's rows only, and
    // exercise + export share one activity so they share one process/store.
    const store = new EventStore();
    const pack = await livePack();
    if (useAgents) {
      const { personas: _personas, ...clients } = await agentClients();
      const res = await runAgentExercise(input, { detections: pack.store, store, ...clients });
      await recordRunScore(res.run, { mode: "agents-maas", platform, modelIds: res.run.modelIds, deployments: res.run.deployments, promotedRules: pack.promoted, alerts: res.alerts.length, falsePositives: res.falsePositives, benignEvents: res.benignEvents, falsePositiveDetail: res.falsePositiveDetail, langfuseEvents: res.langfuseEvents, agentStates: res.agentStates, blueProposals: res.blueProposals, enforcement: res.enforcement, guardrails: res.guardrails, redCampaign: res.redCampaign, blueMonitoring: res.blueMonitoring });
      const ds = await publishRunDataset(res.run, { store, spec: input.spec });
      return done(`score:${res.scorecard.objectivesAchieved}/${res.scorecard.objectivesTotal}|dataset:${ds.contentHash}|mode:agents`);
    }
    const res = await runLiveExercise(input, { detections: pack.store, store });
    await recordRunScore(res.run, { mode: "live-docker", platform, promotedRules: pack.promoted, alerts: res.alerts.length, falsePositives: res.falsePositives, benignEvents: res.benignEvents, falsePositiveDetail: res.falsePositiveDetail, langfuseEvents: res.langfuseEvents });
    const ds = await publishRunDataset(res.run, { store, spec: input.spec });
    return done(`score:${res.scorecard.objectivesAchieved}/${res.scorecard.objectivesTotal}|dataset:${ds.contentHash}`);
  }
  const res = await runExercise(input);
  await recordRunScore(res.run, { mode: "deterministic-harness", platform });
  return done(`score:${res.scorecard.objectivesAchieved}/${res.scorecard.objectivesTotal}`);
}

export async function teardownActivity(input: {
  deploymentId: string; orgId: string; stackName: string; spec: EnvironmentSpec; runId: string;
  outcome?: { status: "destroyed" | "failed"; failure?: { stage: string; error: string; at?: string } };
}): Promise<string> {
  await teardownEnvironment(input);
  return input.outcome?.status ?? "destroyed";
}

export async function maintenanceActivity(): Promise<string> {
  const { maintenancePass } = await import("../ops/maintenance.js");
  const routing = workerRoutingConfig();
  const r = await maintenancePass({ routing });
  return JSON.stringify({ workerId: routing.workerId, orphans: r.sweep.orphans.length, vmOrphans: r.vmOrphans.removed.length, ttl: r.ttl.length, drift: r.drift, errors: r.errors });
}

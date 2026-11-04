import type { Budget as BudgetT, EnvironmentSpec as SpecT } from "@musearena/shared";
import type { ModelClient } from "../lib/model.js";
import {
  emitDesignEvent, throwIfDesignAborted, type DesignRunOptions,
} from "./events.js";
import { checkBudget, designEnvironment, digestOf, refineEnvironment, validateDesign, type DesignResult } from "./pipeline.js";
import { digestOfSpec } from "../lib/digest.js";
import { topologyFor, type TopologyMap } from "./topology.js";
import { estimateCost } from "./cost.js";
import { deployability } from "../provisioner/capability.js";
import { planDeployment, type DeploymentPlan } from "../configurator/plan.js";

export interface DesignPackage extends DesignResult {
  topology: TopologyMap;
  /** What will be installed, configured, wired and run — the reviewable plan. */
  plan: DeploymentPlan;
  /** Content digest of `plan`; stored at approval and re-checked before deploy. */
  planDigest: string;
  cost: { perHour: number; ttlTotal: number };
  /** Provisioning is blocked when this is false (Req §1.5). */
  canProvision: boolean;
  blockReasons: string[];
}

/** Orchestrator: prompt → designer → budget/validation gate → topology + cost package. */
export async function orchestrateDesign(
  client: ModelClient,
  prompt: string,
  budget: BudgetT,
  opts?: DesignRunOptions,
): Promise<DesignPackage> {
  const result = await designEnvironment(client, prompt, budget, opts);
  return toPackage(result, opts);
}

export async function orchestrateRefine(
  client: ModelClient,
  current: SpecT,
  instruction: string,
  budget: BudgetT,
  opts?: DesignRunOptions,
): Promise<DesignPackage> {
  const result = await refineEnvironment(client, current, instruction, budget, opts);
  return toPackage(result, opts);
}

/**
 * Package a spec that did not come from the model (imported JSON, a stored
 * template). It runs the same budget, design and plan gates as a generated
 * design without spending a model call — an imported spec must not be
 * "approvable" on weaker evidence than a designed one.
 */
export function orchestrateSpec(spec: SpecT, budget: BudgetT, opts?: DesignRunOptions): DesignPackage {
  emitDesignEvent(opts, {
    type: "step.started", phase: "validation", stepId: "validation-1",
    title: "Validating imported specification",
    detail: "Imported JSON passes through the same budget and coherence gates as a generated design.",
    data: { hosts: spec.instances.length, personas: spec.personas.length, objectives: spec.objectives.length },
  });
  const violations = checkBudget(spec, budget);
  const designErrors = validateDesign(spec);
  const passed = violations.length === 0 && designErrors.length === 0;
  emitDesignEvent(opts, {
    type: passed ? "step.completed" : "step.blocked", phase: "validation", stepId: "validation-1",
    title: passed ? "Imported design gates passed" : "Imported design gates refused the spec",
    detail: passed ? "Budget and coherence gates passed." : `${violations.length + designErrors.length} issue${violations.length + designErrors.length === 1 ? "" : "s"} block this imported design.`,
    data: { passed, violations, designErrors },
  });
  return toPackage({
    spec,
    digest: digestOf(spec),
    withinBudget: violations.length === 0,
    violations,
    designErrors,
  }, opts);
}

function toPackage(result: DesignResult, opts?: DesignRunOptions): DesignPackage {
  throwIfDesignAborted(opts?.signal);
  emitDesignEvent(opts, {
    type: "step.started", phase: "packaging", stepId: "package-topology",
    title: "Building topology graph",
    detail: "Placing hosts into network segments and deriving the environment domain.",
  });
  const topology = topologyFor(result.spec);
  emitDesignEvent(opts, {
    type: "step.completed", phase: "packaging", stepId: "package-topology",
    title: "Topology graph built",
    detail: `${topology.subnets.length} network segment${topology.subnets.length === 1 ? "" : "s"} · ${topology.domain}.`,
    data: { subnets: topology.subnets.length, hosts: topology.subnets.reduce((n, s) => n + s.nodes.length, 0), domain: topology.domain, cidr: topology.cidr },
  });

  emitDesignEvent(opts, {
    type: "step.started", phase: "packaging", stepId: "package-plan",
    title: "Compiling deployment plan",
    detail: "Resolving packages, configuration, seeds, wiring, readiness probes, and task order for every host.",
  });
  const plan = planDeployment(result.spec);
  const planDigest = digestOfSpec(plan);
  emitDesignEvent(opts, {
    type: plan.gaps.length ? "step.blocked" : "step.completed", phase: "packaging", stepId: "package-plan",
    title: plan.gaps.length ? "Deployment plan has gaps" : "Deployment plan compiled",
    detail: plan.gaps.length ? `${plan.gaps.length} planning gap${plan.gaps.length === 1 ? "" : "s"} block provisioning.` : `${plan.hosts.length} host build sheets, ${plan.edges.length} service edges, ${plan.steps.length} execution steps.`,
    data: {
      hosts: plan.hosts.length,
      edges: plan.edges.length,
      probes: plan.labProbes.length,
      steps: plan.steps.length,
      gaps: plan.gaps,
      planDigest,
      versions: plan.versions,
    },
  });

  emitDesignEvent(opts, {
    type: "step.started", phase: "packaging", stepId: "package-cost",
    title: "Estimating operating cost",
    detail: "Applying the platform cost model to the approved design shape.",
  });
  const cost = estimateCost(result.spec);
  emitDesignEvent(opts, {
    type: "step.completed", phase: "packaging", stepId: "package-cost",
    title: "Cost estimated",
    detail: `$${cost.perHour}/hr · $${cost.ttlTotal} over the declared TTL.`,
    data: { ...cost },
  });

  emitDesignEvent(opts, {
    type: "step.started", phase: "packaging", stepId: "package-deployability",
    title: "Checking deployability",
    detail: "Verifying that this worker can build, configure, and prove every declared service and objective.",
  });
  const deployabilityReasons = deployability(result.spec);
  const blockReasons = [...result.violations, ...result.designErrors, ...deployabilityReasons, ...plan.gaps];
  const canProvision = blockReasons.length === 0;
  emitDesignEvent(opts, {
    type: canProvision ? "step.completed" : "step.blocked", phase: "packaging", stepId: "package-deployability",
    title: canProvision ? "Design is deployable" : "Deployment blocked",
    detail: canProvision ? "Every platform gate passed. The artifact is ready for operator approval." : `${blockReasons.length} blocking reason${blockReasons.length === 1 ? "" : "s"} remain.`,
    data: { canProvision, blockReasons, deployabilityReasons, specDigest: result.digest, planDigest },
  });

  throwIfDesignAborted(opts?.signal);
  return {
    ...result,
    topology,
    plan,
    planDigest,
    cost,
    canProvision,
    blockReasons,
  };
}

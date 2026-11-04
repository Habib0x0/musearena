import { zodToJsonSchema } from "zod-to-json-schema";
import type { z } from "zod";
import { digestOfSpec } from "../lib/digest.js";
import { validateDesign } from "./coherence.js";
import { archetypeCatalogText } from "./archetypes.js";
import { vulnTargetCatalogText } from "../configurator/vuln-targets.js";
import { Budget, EnvironmentSpec, type Budget as BudgetT, type EnvironmentSpec as SpecT, type PlatformSelection } from "@musearena/shared";
import type { ModelClient, ModelStreamDelta } from "../lib/model.js";
import {
  emitDesignEvent, isDesignAbort, throwIfDesignAborted,
  type DesignEventInput, type DesignRunOptions,
} from "./events.js";
import { capabilityCatalog, deployability, normalizeSpec } from "../provisioner/capability.js";
import { planDeployment } from "../configurator/plan.js";
import { hostBrief, hostCapabilities } from "../provisioner/host-capabilities.js";
import { estimateCostPerHour } from "./cost.js";

import { readFileSync } from "node:fs";
import path from "node:path";

/** Agent prompts live as files (AnomalyLab prompts/ pattern); inline fallback. */
function loadPromptFile(name: string): string {
  const candidates = [
    path.join(process.cwd(), "src/agents/prompts", `${name}.md`),
    path.join(process.cwd(), "backend/src/agents/prompts", `${name}.md`),
    path.join(path.dirname(new URL(import.meta.url).pathname), `../agents/prompts/${name}.md`),
  ];
  for (const c of candidates) { try { return readFileSync(c, "utf8").trim(); } catch { /* next */ } }
  throw new Error(`agent prompt ${name}.md not found`);
}

export function designerSystemPrompt(catalog: string = capabilityCatalog()): string {
  let base: string;
  try {
    base = loadPromptFile("designer");
  } catch {
    base = [
      "# Designer Agent",
      "You are the MuseArena designer agent. Return ONLY a JSON object matching the EnvironmentSpec schema.",
      "Design a complete virtual organization; hard-reference integrity rules apply:",
      "every persona.workstation, plantedVuln.targetHostId and objective.asset MUST be an instance hostId;",
      "every objective needs a non-empty successSignal and techniqueId; nothing outside the capability catalog is emitted.",
    ].join("\n");
  }
  return `${base}\n\n## Capability catalog (checked)\n${catalog}\n\n## Org archetypes (versioned)\n${archetypeCatalogText()}\n\n## CVE targets (planted vulns with gate-verified exploits; use type "cve" and these ids as plantedVuln.id)\n${vulnTargetCatalogText()}`;
}

export function designerRefinePrompt(): string {
  try {
    return loadPromptFile("designer-refine");
  } catch {
    return [
      "You are the MuseArena designer agent refining an existing EnvironmentSpec.",
      "Return ONLY the full updated JSON object matching the EnvironmentSpec schema.",
      "Preserve every instance, persona, objective and vuln the instruction does not mention; keep hostIds stable.",
    ].join(" ");
  }
}

/**
 * The system prompt is built per design, not at module load: the worker the
 * designer runs on decides whether a VM org lab is buildable at all.
 */
function platformConstraint(platform?: PlatformSelection): string {
  if (!platform) return "";
  return [
    "",
    "## Operator platform selection (non-negotiable)",
    `Every instance runtime MUST be "${platform.runtimeTarget}". Do not emit the other runtime anywhere in this design.`,
    platform.runtimeTarget === "vm"
      ? "Design the full VM organization lab using the VM service declarations and role-exact exercise placements in the catalog."
      : "Design only the container-provable web/db lab in the catalog; do not emit VM-only organization services, workstations, or an attacker instance.",
    platform.exerciseEngine === "agents" && platform.runtimeTarget === "vm"
      ? "Model agents are selected: include exactly one VM attacker guest (role \"attacker\") in the spec."
      : "The scripted exercise engine is selected; do not add an attacker guest solely for model agents.",
    `Set the top-level platform field exactly to ${JSON.stringify(platform)}.`,
  ].join("\n");
}

function systemForWorker(platform?: PlatformSelection): string {
  return designerSystemPrompt(capabilityCatalog(hostBrief(hostCapabilities()))) + platformConstraint(platform);
}

function workerBrief(): string {
  return hostBrief(hostCapabilities());
}

export interface DesignResult { spec: SpecT; digest: string; withinBudget: boolean; violations: string[]; designErrors: string[]; /** A semantic repair attempt produced the accepted design. */ repaired?: boolean }

function designStep(opts: DesignRunOptions | undefined, event: DesignEventInput): void {
  emitDesignEvent(opts, event);
}

function specCounts(spec: SpecT): Record<string, number> {
  return {
    hosts: spec.instances.length,
    personas: spec.personas.length,
    objectives: spec.objectives.length,
    weaknesses: spec.plantedVulns.length,
    subnets: spec.topology.subnets.length,
  };
}

function modelDeltaSink(opts: DesignRunOptions | undefined, stepId: string, attempt: number) {
  return (delta: ModelStreamDelta) => {
    designStep(opts, {
      type: delta.kind === "reasoning" ? "model.reasoning" : "model.progress",
      phase: "model",
      stepId,
      title: delta.kind === "reasoning" ? "Model reasoning" : "Structured output",
      data: {
        attempt,
        text: delta.text,
        reasoningChars: delta.reasoningChars,
        contentChars: delta.contentChars,
      },
    });
  };
}

function normalizeWithEvent(spec: SpecT, opts: DesignRunOptions | undefined, stepId = "normalize"): SpecT {
  designStep(opts, {
    type: "step.started", phase: "normalize", stepId,
    title: "Normalizing specification",
    detail: "Canonicalizing host roles against the runtime vocabulary.",
  });
  const normalized = normalizeSpec(spec);
  const normalizedRoles = spec.instances.flatMap((instance, index) => {
    const next = normalized.instances[index];
    return next && next.role !== instance.role ? [`${instance.hostId}: ${instance.role} → ${next.role}`] : [];
  });
  designStep(opts, {
    type: "step.completed", phase: "normalize", stepId,
    title: "Specification normalized",
    detail: normalizedRoles.length ? `${normalizedRoles.length} role${normalizedRoles.length === 1 ? "" : "s"} canonicalized.` : "All host roles were already canonical.",
    data: { ...specCounts(normalized), normalizedRoles },
  });
  return normalized;
}

export function digestOf(spec: SpecT): string {
  return digestOfSpec(spec);
}

// `validateDesign` now lives beside `validateCoherence` so the deployment
// trigger can run it without loading designer prompts. Re-exported here for
// the existing designer callers.
export { validateDesign };

/**
 * Budget gate (Req §1.5). Cost is the platform's own estimate — never the
 * $/hr the model declares in spec.budgets, which it can understate.
 */
export function checkBudget(spec: SpecT, budget: BudgetT): string[] {
  const v: string[] = [];
  const perHour = estimateCostPerHour(spec);
  if (perHour > budget.maxDollarsPerHour)
    v.push(`estimated $${perHour}/hr > cap $${budget.maxDollarsPerHour}/hr`);
  if (spec.instances.length > budget.maxInstances)
    v.push(`instances ${spec.instances.length} > cap ${budget.maxInstances}`);
  if (spec.budgets.maxDollarsPerHour > budget.maxDollarsPerHour)
    v.push(`$/hr ${spec.budgets.maxDollarsPerHour} > cap ${budget.maxDollarsPerHour}`);
  if (spec.budgets.ttlHours > budget.ttlHours)
    v.push(`ttl ${spec.budgets.ttlHours}h > cap ${budget.ttlHours}h`);
  return v;
}

/**
 * Model output is untrusted: one repair attempt on invalid JSON or a schema
 * violation, quoting the rejection back. Bounded — a model that fails twice
 * fails the design rather than looping.
 */
async function generateObjectRepairing<T>(
  client: ModelClient,
  args: { system: string; prompt: string; schema: z.ZodTypeAny; maxTokens?: number },
  opts?: DesignRunOptions,
  stepPrefix = "model",
): Promise<T> {
  let prompt = args.prompt;
  let lastError = "";
  for (let attempt = 1; attempt <= 2; attempt++) {
    throwIfDesignAborted(opts?.signal);
    const stepId = `${stepPrefix}-attempt-${attempt}`;
    designStep(opts, {
      type: "step.started", phase: "model", stepId,
      title: attempt === 1 ? "Generating structured design" : "Repairing rejected model output",
      detail: attempt === 1
        ? `${client.modelId} is producing the EnvironmentSpec under the checked schema.`
        : `Previous output was rejected: ${lastError}`,
      data: { attempt, modelId: client.modelId, maxTokens: args.maxTokens ?? 32768 },
    });
    try {
      const result = await client.generateObject<T>({
        ...args,
        prompt,
        signal: opts?.signal,
        onDelta: modelDeltaSink(opts, stepId, attempt),
      });
      throwIfDesignAborted(opts?.signal);
      designStep(opts, {
        type: "step.completed", phase: "model", stepId,
        title: "Model output accepted",
        detail: "The response parsed as JSON and passed the EnvironmentSpec schema gate.",
        data: { attempt, modelId: client.modelId },
      });
      return result;
    } catch (err) {
      if (isDesignAbort(err, opts?.signal)) throw err;
      lastError = (err instanceof Error ? err.message : String(err)).slice(0, 600);
      designStep(opts, {
        type: "step.failed", phase: "model", stepId,
        title: attempt === 1 ? "Model output rejected" : "Model repair failed",
        detail: lastError,
        data: { attempt, modelId: client.modelId, error: lastError },
      });
      if (attempt === 2) throw err;
      prompt = `${args.prompt}\n\nYour previous reply was rejected (${lastError.slice(0, 300)}). Return ONLY one JSON object that matches the schema.`;
    }
  }
  throw new Error("designer model attempts exhausted");
}

/**
 * Semantic gate after the JSON gate. A design can parse, match the schema and
 * still be refused (coherence, budget, an unprovisionable service). The model
 * never sees those reasons otherwise, so the same bounded rule applies: quote
 * the violations back once and accept the result either way. A failed or
 * malformed repair keeps the original refusal rather than losing it.
 */
async function finishDesign(
  client: ModelClient,
  input: { spec: SpecT; system: string; prompt: string; budget: BudgetT },
  opts?: DesignRunOptions,
): Promise<DesignResult> {
  const selection = opts?.platform ?? input.spec.platform;
  const pinPlatform = (spec: SpecT): SpecT => selection ? { ...spec, platform: selection } : spec;
  const firstSpec = pinPlatform(input.spec);
  const validate = (spec: SpecT, attempt: number) => {
    const stepId = `validation-${attempt}`;
    designStep(opts, {
      type: "step.started", phase: "validation", stepId,
      title: "Running design gates",
      detail: "Checking budget, references, coherence, telemetry, topology, and provable objectives.",
      data: { attempt, ...specCounts(spec) },
    });
    let planGaps: string[];
    try {
      planGaps = planDeployment(spec).gaps;
    } catch (err) {
      planGaps = [`cannot be planned: ${String(err instanceof Error ? err.message : err).split("\n")[0]}`];
    }
    const gates = {
      violations: checkBudget(spec, input.budget),
      designErrors: validateDesign(spec),
      provisioningReasons: [...new Set([...deployability(spec), ...planGaps])],
    };
    const issueCount = gates.violations.length + gates.designErrors.length + gates.provisioningReasons.length;
    const passed = issueCount === 0;
    designStep(opts, {
      type: passed ? "step.completed" : "step.blocked", phase: "validation", stepId,
      title: passed ? "Design gates passed" : "Design gates refused the draft",
      detail: passed
        ? "Budget, coherence, deployability, and wiring-plan gates passed."
        : `${issueCount} issue${issueCount === 1 ? "" : "s"} must be repaired or accepted as blocked.`,
      data: { attempt, passed, violations: gates.violations, designErrors: gates.designErrors, provisioningReasons: gates.provisioningReasons, ...specCounts(spec) },
    });
    return gates;
  };

  const first = validate(firstSpec, 1);
  const firstDesignAccepted = first.violations.length === 0 && first.designErrors.length === 0;
  if (firstDesignAccepted && first.provisioningReasons.length === 0) {
    return {
      spec: firstSpec, digest: digestOf(firstSpec), withinBudget: true,
      violations: first.violations, designErrors: first.designErrors,
    };
  }
  const why = [...new Set([...first.violations, ...first.designErrors, ...first.provisioningReasons])];
  const repairStepId = "semantic-repair";
  try {
    throwIfDesignAborted(opts?.signal);
    designStep(opts, {
      type: "step.started", phase: "repair", stepId: repairStepId,
      title: "Repairing semantic gate failures",
      detail: `${client.modelId} is revising only the refused parts of the design.`,
      data: { attempt: 1, modelId: client.modelId, issues: why },
    });
    const rawRepaired = await client.generateObject<SpecT>({
      system: input.system,
      prompt: `${input.prompt}\n\nYour previous reply was valid JSON but the platform refused the design:\n- ${why.join("\n- ")}\nReturn ONLY one JSON object matching the schema with exactly those problems fixed and everything else unchanged.`,
      schema: EnvironmentSpec,
      maxTokens: 32768,
      signal: opts?.signal,
      onDelta: modelDeltaSink(opts, repairStepId, 1),
    });
    throwIfDesignAborted(opts?.signal);
    designStep(opts, {
      type: "step.completed", phase: "repair", stepId: repairStepId,
      title: "Semantic repair returned",
      detail: "The repaired draft will now pass through normalization and every gate again.",
      data: { attempt: 1, modelId: client.modelId },
    });
    const repaired = pinPlatform(normalizeWithEvent(rawRepaired, opts, "normalize-repair"));
    const second = validate(repaired, 2);
    if (second.violations.length === 0 && second.designErrors.length === 0 && second.provisioningReasons.length === 0) {
      return {
        spec: repaired, digest: digestOf(repaired), withinBudget: true,
        violations: second.violations, designErrors: second.designErrors, repaired: true,
      };
    }
    return {
      spec: firstSpec, digest: digestOf(firstSpec), withinBudget: firstDesignAccepted,
      violations: first.violations, designErrors: first.designErrors,
    };
  } catch (err) {
    if (isDesignAbort(err, opts?.signal)) throw err;
    const message = (err instanceof Error ? err.message : String(err)).slice(0, 600);
    designStep(opts, {
      type: "step.failed", phase: "repair", stepId: repairStepId,
      title: "Semantic repair failed",
      detail: message,
      data: { attempt: 1, modelId: client.modelId, error: message },
    });
    // The repair attempt itself failed (malformed/transport): the first
    // design's named violations are the honest outcome.
    return {
      spec: firstSpec, digest: digestOf(firstSpec), withinBudget: firstDesignAccepted,
      violations: first.violations, designErrors: first.designErrors,
    };
  }
}

export async function designEnvironment(
  client: ModelClient,
  prompt: string,
  budget: BudgetT,
  opts?: DesignRunOptions,
): Promise<DesignResult> {
  Budget.parse(budget);
  throwIfDesignAborted(opts?.signal);
  designStep(opts, {
    type: "step.started", phase: "context", stepId: "context",
    title: "Assembling designer context",
    detail: "Loading the designer prompt, checked capability catalog, org archetypes, worker capabilities, and output schema.",
    data: { operation: "design", budget, requestChars: prompt.length },
  });
  const schemaJson = JSON.stringify(zodToJsonSchema(EnvironmentSpec, { target: "openApi3" }));
  const system = systemForWorker(opts?.platform);
  const basePrompt = `Design this environment within budget ${JSON.stringify(budget)}. Return JSON matching EXACTLY this JSON Schema (all required fields, exact enum values):\n${schemaJson}\n\nUser request:\n${prompt}`;
  designStep(opts, {
    type: "step.completed", phase: "context", stepId: "context",
    title: "Designer context ready",
    detail: "The model is constrained to deployable services, exact telemetry names, provable objectives, and the worker's real capabilities.",
    data: { operation: "design", budget, requestChars: prompt.length, systemChars: system.length, schemaChars: schemaJson.length },
  });
  const rawSpec = await generateObjectRepairing<SpecT>(client, {
    system,
    prompt: basePrompt,
    schema: EnvironmentSpec,
    // The API counts reasoning tokens against this budget; at 8192 the model
    // spent the whole budget thinking and returned no message (observed live
    // 2026-10-29). Keep headroom for reasoning plus the JSON body.
    maxTokens: 32768,
  }, opts);
  const spec = normalizeWithEvent(rawSpec, opts);
  return finishDesign(client, { spec, system, prompt: basePrompt, budget }, opts);
}

const REFINE_SYSTEM = designerRefinePrompt();

export async function refineEnvironment(
  client: ModelClient,
  current: SpecT,
  instruction: string,
  budget: BudgetT,
  opts?: DesignRunOptions,
): Promise<DesignResult> {
  Budget.parse(budget);
  throwIfDesignAborted(opts?.signal);
  const currentDigest = digestOf(current);
  designStep(opts, {
    type: "step.started", phase: "context", stepId: "context",
    title: "Assembling refinement context",
    detail: "Loading the current specification, preservation rules, checked capability catalog, worker capabilities, and output schema.",
    data: { operation: "refine", budget, instructionChars: instruction.length, currentDigest, ...specCounts(current) },
  });
  const schemaJson = JSON.stringify(zodToJsonSchema(EnvironmentSpec, { target: "openApi3" }));
  // Same checked catalog as a fresh design: a refinement that adds a host
  // needs the closed service/telemetry vocabulary, not just the worker brief.
  const selection = opts?.platform ?? current.platform;
  const system = `${REFINE_SYSTEM}\n\n## Capability catalog (checked)\n${capabilityCatalog(workerBrief())}${platformConstraint(selection)}`;
  const basePrompt = `Current EnvironmentSpec:\n${JSON.stringify(current)}\n\nRefinement (apply only this change, preserve the rest):\n${instruction}\n\nBudget: ${JSON.stringify(budget)}. Return JSON matching EXACTLY this JSON Schema:\n${schemaJson}`;
  designStep(opts, {
    type: "step.completed", phase: "context", stepId: "context",
    title: "Refinement context ready",
    detail: "Unaffected hosts, personas, objectives, weaknesses, and identifiers must be preserved.",
    data: { operation: "refine", budget, instructionChars: instruction.length, currentDigest, systemChars: system.length, schemaChars: schemaJson.length, ...specCounts(current) },
  });
  const rawSpec = await generateObjectRepairing<SpecT>(client, {
    system,
    prompt: basePrompt,
    schema: EnvironmentSpec,
    maxTokens: 32768,
  }, opts);
  const spec = normalizeWithEvent(rawSpec, opts);
  return finishDesign(client, { spec, system, prompt: basePrompt, budget }, opts);
}

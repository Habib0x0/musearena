import type { EnvironmentSpec, ServiceKind } from "@musearena/shared";
import { resolveProfile } from "../configurator/profiles.js";
import { catalogEntry } from "../configurator/catalog.js";
import { validateOrgTopology } from "./org-topology.js";

/** Telemetry the base profile installs on every VM guest (never declared as a service). */
export const BASE_TELEMETRY = new Set(["auditd", "audit.log", "osquery", "rsyslog", "syslog", "chrony", "auth.log"]);

/**
 * Org-coherence validation (T-17). A spec can be schema-valid, within budget
 * and deployable and still describe an org that cannot be scored: an objective
 * pointed at a host with no service that can emit its signal, a dependency
 * cycle, a persona sitting on a machine with no client tools, or instances
 * left unplaced in a multi-subnet topology.
 *
 * Gated to org specs — anything that declares a structured service — so
 * container specs keep their existing validation exactly.
 */

/**
 * Objective technique → the service kinds that can realize it. The model names
 * signals freely (`exec-marker:web-01:pwned`), so the technique decides whether
 * the asset can host the proof path; an unknown technique fails closed.
 */
const TECHNIQUE_SERVICES: Record<string, ServiceKind[]> = {
  T1059: ["http"], // command injection against the intranet app
  T1078: ["db"], // weak database credential
  T1110: [], // failed SSH auth — sshd is in the base profile of every guest
};

export function isOrgSpec(spec: EnvironmentSpec): boolean {
  return spec.instances.some((i) => (i.serviceDecls ?? []).length > 0);
}

export function validateCoherence(spec: EnvironmentSpec): string[] {
  if (!isOrgSpec(spec)) return [];
  const errors: string[] = [];
  const byHost = new Map(spec.instances.map((i) => [i.hostId, i]));
  const kindsOf = (hostId: string) => new Set((byHost.get(hostId)?.serviceDecls ?? []).map((d) => d.kind));

  // 1. Every objective needs an asset whose services can emit its signal.
  for (const o of spec.objectives) {
    if (!byHost.has(o.asset)) {
      errors.push(`objective ${o.id}: asset "${o.asset}" is not an instance`);
      continue;
    }
    const needs = TECHNIQUE_SERVICES[o.techniqueId];
    if (!needs) {
      errors.push(`objective ${o.id}: technique "${o.techniqueId}" has no known proof path in org specs`);
      continue;
    }
    const kinds = kindsOf(o.asset);
    if (needs.length > 0 && !needs.some((k) => kinds.has(k))) {
      errors.push(`objective ${o.id}: asset "${o.asset}" declares ${[...kinds].join("/") || "no services"}, which cannot realize ${o.techniqueId} (needs ${needs.join(" or ")})`);
    }
  }

  // 2. dependsOn is a DAG.
  const state = new Map<string, "visiting" | "done">();
  const visit = (hostId: string, path: string[]): void => {
    if (state.get(hostId) === "done") return;
    if (state.get(hostId) === "visiting") {
      errors.push(`dependency cycle: ${[...path, hostId].join(" → ")}`);
      return;
    }
    state.set(hostId, "visiting");
    for (const dep of byHost.get(hostId)?.dependsOn ?? []) if (byHost.has(dep)) visit(dep, [...path, hostId]);
    state.set(hostId, "done");
  };
  for (const i of spec.instances) visit(i.hostId, []);

  // 3. A persona's workstation must be able to reach something: client tools
  //    come from dependsOn edges, so an isolated host has none.
  for (const p of spec.personas) {
    if (!byHost.has(p.workstation)) {
      errors.push(`persona ${p.id}: workstation "${p.workstation}" is not an instance`);
      continue;
    }
    let tools: string[];
    try {
      tools = resolveProfile(spec, p.workstation).clientTools;
    } catch {
      continue; // unknown catalog service — deployability reports it
    }
    if (tools.length === 0) errors.push(`persona ${p.id}: workstation "${p.workstation}" has no client tools (no dependsOn edge to a service host)`);
  }

  // 4. Placement must be explicit once the topology offers a choice.
  if (spec.topology.subnets.length > 1) {
    for (const i of spec.instances) {
      if (!i.subnet) errors.push(`instance ${i.hostId}: no subnet placed in a ${spec.topology.subnets.length}-subnet topology`);
    }
  }
  return errors;
}

/**
 * Design validation beyond schema: every objective needs a verifiable signal
 * (Req §8), every reference points at a real host, and an org must be
 * coherent. This lives beside `validateCoherence` (not in `pipeline.ts`) so
 * the deployment trigger can run it without loading model prompts.
 */
export function validateDesign(spec: EnvironmentSpec): string[] {
  const errors: string[] = [];
  const hostIds = new Set<string>();
  for (const i of spec.instances) {
    const id = i.hostId?.trim();
    if (!id) errors.push("instance hostId must not be empty");
    else if (hostIds.has(id)) errors.push(`instance hostId "${id}" is duplicated`);
    else hostIds.add(id);
  }
  for (const o of spec.objectives) {
    if (!o.successSignal?.trim()) errors.push(`objective ${o.id} has no verifiable successSignal`);
    if (!o.techniqueId?.trim()) errors.push(`objective ${o.id} has no techniqueId`);
  }
  if (spec.objectives.length === 0) errors.push("at least one objective is required");
  if (spec.requiredTelemetry.length === 0) errors.push("requiredTelemetry must not be empty");
  if (isOrgSpec(spec)) {
    // Honesty gate: a required telemetry source must be something the base
    // profile or a declared service actually produces. Otherwise the design
    // promises visibility that nothing in the lab can supply.
    const emitted = new Set(BASE_TELEMETRY);
    for (const i of spec.instances) for (const d of i.serviceDecls ?? []) for (const t of catalogEntry(d)?.telemetry ?? []) emitted.add(t);
    for (const t of spec.requiredTelemetry) {
      if (!emitted.has(t)) errors.push(`requiredTelemetry "${t}" is not emitted by the base profile or a declared service`);
    }
  }
  for (const v of spec.plantedVulns) {
    if (!hostIds.has(v.targetHostId)) errors.push(`planted vuln ${v.id} targets unknown host ${v.targetHostId}`);
  }
  for (const p of spec.personas) {
    if (!hostIds.has(p.workstation)) errors.push(`persona ${p.id} workstation ${p.workstation} is not an instance`);
  }
  // Org specs get the extra coherence checks (no-op for container specs).
  errors.push(...validateCoherence(spec));
  // Site/zone/policy validation is no-op for v1 flat labs.
  errors.push(...validateOrgTopology(spec));
  return errors;
}

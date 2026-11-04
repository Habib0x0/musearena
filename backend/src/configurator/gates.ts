import { randomBytes } from "node:crypto";
import type { EnvironmentSpec, PlantedVuln } from "@musearena/shared";
import { localStore, type EventStore, type GroundTruthEvent } from "../observability/events.js";

/**
 * Gates verify INDEPENDENT telemetry in the event store (Req §12.3, §3.3).
 * The gate never writes the marker it then looks for: a separate executor
 * performs the canary/proof action inside the environment, and the sensor
 * plane is expected to record it out-of-band. With no executor configured,
 * or no telemetry observed, the gate FAILS — it cannot pass itself.
 */
export interface GateResult { gate: "proof" | "canary"; pass: boolean; details: string[] }

export type CanaryExecutor = (runId: string, hostId: string, marker: string) => Promise<void>;
export type ProofExecutor = (vuln: PlantedVuln, runId: string) => Promise<void>;

export interface GateOptions {
  store?: EventStore;
  executeCanary?: CanaryExecutor;
  executeProof?: ProofExecutor;
}

export function canaryMarker(runId: string, hostId: string, nonce?: string): string {
  return nonce ? `canary-${runId}-${hostId}-${nonce}` : `canary-${runId}-${hostId}`;
}

function canarySeen(store: EventStore, runId: string, hostId: string, marker: string): boolean {
  return store.groundTruth(runId).some((e) => e.hostId === hostId && e.kind === marker);
}

/** Sensor canary: execute one known action; it must appear in telemetry before scoring unlocks. */
export async function sensorCanary(runId: string, hostId: string, opts: GateOptions = {}): Promise<GateResult> {
  const store = opts.store ?? localStore;
  // Fresh nonce per execution: an earlier observation (e.g. a log line from a
  // previous canary, before the sensor was switched off) can never satisfy
  // this one. Found live: a deterministic marker passed with the sensor off.
  const marker = canaryMarker(runId, hostId, randomBytes(6).toString("hex"));
  if (!opts.executeCanary) {
    return { gate: "canary", pass: false, details: [`canary ${marker} NOT executed — no canary executor configured; sensor unverified`] };
  }
  try {
    await opts.executeCanary(runId, hostId, marker);
  } catch (err) {
    return { gate: "canary", pass: false, details: [`canary ${marker} execution failed: ${err instanceof Error ? err.message : String(err)}`] };
  }
  const seen = canarySeen(store, runId, hostId, marker);
  return { gate: "canary", pass: seen, details: [seen ? `canary ${marker} observed in telemetry` : `canary ${marker} MISSING from telemetry — sensor blind`] };
}

function proofSeen(e: GroundTruthEvent, runId: string, v: PlantedVuln): boolean {
  if (e.runId !== runId || e.hostId !== v.targetHostId || e.actor !== "proof") return false;
  if (e.outcome !== undefined && e.outcome !== "succeeded") return false;
  if (e.techniqueId !== undefined && e.techniqueId !== v.techniqueId) return false;
  return e.stepId === v.proofAtomicGuid || e.kind === `proof-${v.proofAtomicGuid}`;
}

/** Live Atomic-style proof per planted vuln, verified in telemetry (never by exit code alone). */
export async function proofGate(input: { runId: string; spec: EnvironmentSpec }, opts: GateOptions = {}): Promise<GateResult> {
  const store = opts.store ?? localStore;
  const details: string[] = [];
  let pass = true;
  if (!opts.executeProof && input.spec.plantedVulns.length > 0) {
    return { gate: "proof", pass: false, details: ["no live proof executor configured — planted vulns unverified"] };
  }
  for (const v of input.spec.plantedVulns) {
    try {
      await opts.executeProof!(v, input.runId);
    } catch (err) {
      details.push(`${v.id} proof execution failed: ${err instanceof Error ? err.message : String(err)}`);
      pass = false;
      continue;
    }
    const seen = store.groundTruth(input.runId).some((e) => proofSeen(e, input.runId, v));
    details.push(seen ? `${v.id} (${v.techniqueId}) live proof seen in telemetry` : `${v.id} proof NOT seen — unsolvable or sensor gap`);
    if (!seen) pass = false;
  }
  if (input.spec.plantedVulns.length === 0) details.push("no planted vulns to prove");
  return { gate: "proof", pass, details };
}

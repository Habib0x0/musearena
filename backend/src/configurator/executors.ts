import type { EnvironmentSpec, PlantedVuln } from "@musearena/shared";
import { EventStore, localStore } from "../observability/events.js";
import { ingest } from "../observability/collector.js";
import type { CanaryExecutor, GateOptions, ProofExecutor } from "./gates.js";

/**
 * LOCAL gate executors (dev/test only). They perform the canary/proof action
 * inside the local harness and record the observation through the normal
 * telemetry ingest path — the same management-plane boundary a real sensor
 * feed would use. They are NOT production proof: nothing here executes an
 * Atomic test inside a provisioned environment.
 *
 * Enablement is explicit: `MUSEARENA_LOCAL_GATES=1`. Any other value (unset,
 * "0", "true") leaves executors disabled and the gates fail closed.
 */
export function localGatesEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return env.MUSEARENA_LOCAL_GATES === "1";
}

export interface ExecutorOptions {
  store?: EventStore;
  at?: () => string;
}

const nowIso = () => new Date().toISOString();

/** Local canary executor: emits the marker via telemetry ingest, as a sensor would observe it. */
export function localCanaryExecutor(opts: ExecutorOptions = {}): CanaryExecutor {
  const store = opts.store ?? localStore;
  const at = opts.at ?? nowIso;
  return async (runId, hostId, marker) => {
    ingest({ runId, hostId, kind: marker, actor: "platform", at: at(), detail: { executor: "local" } }, { store });
  };
}

/** Local proof executor: records the proof observation for one planted vuln via telemetry ingest. */
export function localProofExecutor(opts: ExecutorOptions = {}): ProofExecutor {
  const store = opts.store ?? localStore;
  const at = opts.at ?? nowIso;
  return async (vuln: PlantedVuln, runId: string) => {
    ingest({
      runId, hostId: vuln.targetHostId, kind: "process", actor: "proof",
      techniqueId: vuln.techniqueId, stepId: vuln.proofAtomicGuid, outcome: "succeeded",
      at: at(), detail: { executor: "local", vulnId: vuln.id },
    }, { store });
  };
}

/**
 * Gate options for the current process. Local executors only when explicitly
 * enabled; otherwise an empty options object — gates fail closed.
 */
export function gateOptionsFromEnv(env: NodeJS.ProcessEnv = process.env, opts: ExecutorOptions = {}): GateOptions {
  if (!localGatesEnabled(env)) return {};
  return {
    store: opts.store,
    executeCanary: localCanaryExecutor(opts),
    executeProof: localProofExecutor(opts),
  };
}

/** Sensor states for the local harness: every spec instance reports lineage + state sensors up. */
export function localSensorStates(spec: EnvironmentSpec): { hostId: string; sysmonOrAuditd: boolean; osquery: boolean }[] {
  return spec.instances.map((i) => ({ hostId: i.hostId, sysmonOrAuditd: true, osquery: true }));
}

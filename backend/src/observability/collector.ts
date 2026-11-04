import { localStore, EventStore, type GroundTruthEvent } from "./events.js";

/**
 * Out-of-band collector (Req §4, NFR isolation): telemetry arrives only on
 * the management plane. Ingest from an attacker-reachable source is refused —
 * a foothold inside the environment must never write ground truth.
 */
export type IngestSource = "management-plane" | "environment";

const TECHNIQUE_BY_KIND: Record<string, string> = {
  "process.powershell": "T1059.001",
  "process.exec": "T1059",
  "network.exfil": "T1048",
  "network.c2": "T1071.001",
  "auth.bruteforce": "T1110.001",
  "auth.logon": "T1078",
  "file.canary": "T1003.001",
};

/** MITRE labeling at ingest (§4.5): explicit technique wins, else kind map. */
export function labelTechnique(e: GroundTruthEvent): string | undefined {
  if (e.techniqueId) return e.techniqueId;
  const hint = typeof e.detail?.signal === "string" ? e.detail.signal : "";
  return TECHNIQUE_BY_KIND[hint] ?? TECHNIQUE_BY_KIND[`${e.kind}.${hint}`];
}

export interface IngestOptions { source?: IngestSource; store?: EventStore }

export function ingest(e: GroundTruthEvent, opts: IngestOptions = {}): GroundTruthEvent {
  if ((opts.source ?? "management-plane") !== "management-plane") {
    throw new Error("collector unreachable from environment: telemetry must arrive out-of-band");
  }
  if (!e.runId?.trim()) throw new Error("ground-truth event missing runId");
  if (!e.hostId?.trim()) throw new Error("ground-truth event missing hostId");
  return (opts.store ?? localStore).appendGroundTruth({ ...e, techniqueId: labelTechnique(e) });
}

import type { EnvironmentSpec } from "@musearena/shared";

/** Mandatory prerequisites (Req §12, §8; T-14). A run that fails the gate is not scored. */
export interface SensorState { hostId: string; sysmonOrAuditd: boolean; osquery: boolean }

export interface GateOutcome { pass: boolean; failures: string[] }

export function checkSensors(states: SensorState[]): GateOutcome {
  const failures: string[] = [];
  for (const s of states) {
    // osquery alone never satisfies the gate (§12.1): process lineage is mandatory.
    if (!s.sysmonOrAuditd) failures.push(`${s.hostId}: Sysmon/auditd missing — sensor gate fails`);
    if (!s.osquery) failures.push(`${s.hostId}: osquery missing`);
  }
  return { pass: failures.length === 0, failures };
}

export function validateSpecForRun(spec: EnvironmentSpec): GateOutcome {
  const failures: string[] = [];
  for (const o of spec.objectives) {
    if (!o.successSignal?.trim()) failures.push(`objective ${o.id} has no verifiable signal — design rejected`);
  }
  if (!spec.seed?.trim()) failures.push("seed missing");
  if (spec.requiredTelemetry.length === 0) failures.push("requiredTelemetry empty");
  return { pass: failures.length === 0, failures };
}

export interface NoiseEvent { runId: string; hostId: string; actor: "noise"; personaId: string; kind: string; at: string }

/** Benign background activity, labelled actor=noise and hidden from blue as truth (§12.2). */
export function generateNoise(spec: EnvironmentSpec, runId: string, startAt: number): NoiseEvent[] {
  const kinds = ["logon", "file-share-read", "browse", "admin-script"];
  return spec.personas.map((p, i) => ({
    runId, hostId: p.workstation, actor: "noise" as const, personaId: p.id,
    kind: kinds[i % kinds.length], at: new Date(startAt + (i + 1) * 60_000).toISOString(),
  }));
}

export interface SinkholeHit { runId: string; hostId: string; bytes: number; at: string }

/** Platform sinkhole: the only definition of exfil success (§8, design defaults). */
export class Sinkhole {
  private hits: SinkholeHit[] = [];
  record(h: SinkholeHit): void { this.hits.push(h); } // bytes counted, never forwarded
  exfilBytes(runId: string): number { return this.hits.filter((h) => h.runId === runId).reduce((a, h) => a + h.bytes, 0); }
}

import type { EnvironmentSpec } from "@musearena/shared";

/** Drift detection (Req §6.4, T-10): desired spec vs observed instance state. */
export interface ObservedInstance { hostId: string; services: string[]; packages: string[] }

export interface DriftReport { hostId: string; drifted: boolean; missingServices: string[]; extraServices: string[] }

export function detectDrift(spec: EnvironmentSpec, observed: ObservedInstance[]): DriftReport[] {
  return spec.instances.map((inst) => {
    const obs = observed.find((o) => o.hostId === inst.hostId);
    if (!obs) return { hostId: inst.hostId, drifted: true, missingServices: [...inst.services], extraServices: [] };
    const missing = inst.services.filter((s) => !obs.services.includes(s));
    const extra = obs.services.filter((s) => !inst.services.includes(s));
    return { hostId: inst.hostId, drifted: missing.length + extra.length > 0, missingServices: missing, extraServices: extra };
  });
}

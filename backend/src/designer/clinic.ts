import type { EnvironmentSpec } from "@musearena/shared";
import { CLINIC_ARCHETYPE, materializeArchetype } from "./archetypes.js";

/**
 * The fixed-seed 12-person clinic (T-20), materialised from the versioned
 * `clinic@1` archetype. Kept as a named function because the demo, the
 * workflow run and the tests all ask for "the clinic".
 */
export const CLINIC_PROMPT = CLINIC_ARCHETYPE.prompt;

export function clinicOrgSpec(opts: { ttlHours?: number } = {}): EnvironmentSpec {
  return materializeArchetype(CLINIC_ARCHETYPE, opts);
}

/**
 * The clinic plus an attacker guest on the lab segment (T-15). Opt-in: the
 * default clinic stays six hosts, so its pinned digest does not move. With a
 * real attacker host, red acts from another guest and blue's `block IP`
 * responses have a peer address to enforce.
 */
export function clinicOrgSpecWithAttacker(opts: { ttlHours?: number } = {}): EnvironmentSpec {
  const base = clinicOrgSpec(opts);
  return {
    ...base,
    instances: [...base.instances, {
      hostId: "atk-01", name: "atk-01", role: "attacker", runtime: "vm", os: "Debian 12",
      stack: [], services: ["ssh"], databases: [],
      serviceDecls: [{ kind: "ssh", impl: "openssh", port: 22, readyWhen: "ssh-login" }],
      dependsOn: [], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 },
    }],
  };
}

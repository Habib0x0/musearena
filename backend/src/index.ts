import { EnvironmentSpec } from "@musearena/shared";

// T-1 scaffold: proves backend compiles against shared contracts.
// Real workers (orchestrator/designer/provisioner/configurator/evaluator)
// arrive in T-2 and T-4+.
export function validateSpec(input: unknown): EnvironmentSpec {
  return EnvironmentSpec.parse(input);
}

console.log("musearena backend scaffold ok");

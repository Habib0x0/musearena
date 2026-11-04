import type { EnvironmentSpec } from "@musearena/shared";
import { serviceClient } from "../lib/supabase.js";
import { detectDrift, type ObservedInstance } from "./drift.js";

/**
 * Ops jobs (Req §6.4, T-10): persist a drift report per deployment. Observed
 * state must come from a real sensor/inventory source; when none is supplied
 * the job records "unobserved" instead of inventing a clean bill of health.
 */
export async function runDriftJob(input: { deploymentId: string; orgId: string; spec: EnvironmentSpec; observed?: ObservedInstance[] }): Promise<string> {
  const sb = serviceClient();
  if (!input.observed) {
    await sb.from("deployments").update({ drift_status: "unobserved" }).eq("id", input.deploymentId).eq("org_id", input.orgId);
    return "unobserved";
  }
  const reports = detectDrift(input.spec, input.observed);
  const drifted = reports.filter((r) => r.drifted);
  const status = drifted.length ? `drifted:${drifted.map((r) => r.hostId).join(",")}` : "in-sync";
  await sb.from("deployments").update({ drift_status: status }).eq("id", input.deploymentId).eq("org_id", input.orgId);
  return status;
}

import { serviceClient } from "../lib/supabase.js";
import { sendJson, type ApiRoute } from "./server.js";

/**
 * Learning overview counts (F-13, design §9). Every number is a live count
 * from the org's rows; a missing learning table is an error with the table
 * named, never a decorative zero.
 */
async function count(table: string, orgId: string, filters: Record<string, string> = {}): Promise<number> {
  let query = serviceClient().from(table).select("id", { count: "exact", head: true }).eq("org_id", orgId);
  for (const [column, value] of Object.entries(filters)) query = query.eq(column, value);
  const { count: n, error } = await query;
  if (error) throw new Error(`${table} unreadable: ${error.message}`);
  return n ?? 0;
}

async function overview(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  const sb = serviceClient();
  const [traces, corrections, openDisputes, datasets, trainingRuns, proposals] = await Promise.all([
    count("traces", orgId),
    count("corrections", orgId),
    count("label_disputes", orgId, { status: "pending" }),
    count("datasets", orgId),
    count("training_runs", orgId),
    count("training_proposals", orgId, { status: "proposed" }),
  ]);
  const { data: models, error: modelError } = await sb.from("models")
    .select("id, name, version, served_model, status, role")
    .eq("org_id", orgId).eq("status", "ready");
  if (modelError) throw new Error(`models unreadable: ${modelError.message}`);
  const { data: latestEvaluation, error: evalError } = await sb.from("evaluations")
    .select("id, model_id, baseline_model_id, role, status, comparison, created_at")
    .eq("org_id", orgId).order("created_at", { ascending: false }).limit(1).maybeSingle();
  if (evalError) throw new Error(`evaluations unreadable: ${evalError.message}`);
  const { data: deployments, error: deploymentError } = await sb.from("model_deployments")
    .select("id, model_id, role, alias, environment, traffic_pct")
    .eq("org_id", orgId).eq("status", "active");
  if (deploymentError) throw new Error(`model_deployments unreadable: ${deploymentError.message}`);

  const activeModelsByRole: Record<string, unknown[]> = {};
  for (const model of models ?? []) {
    for (const role of (model as { role?: string[] }).role ?? []) {
      activeModelsByRole[role] = [...(activeModelsByRole[role] ?? []), model];
    }
  }
  sendJson(ctx.res, 200, {
    traces, corrections, openDisputes, datasets, trainingRuns, openProposals: proposals,
    activeModelsByRole,
    lastEvaluation: latestEvaluation ?? null,
    productionDeployments: (deployments ?? []).filter(
      (d) => (d as { environment?: string }).environment === "production",
    ),
  });
}

export function overviewRoutes(): ApiRoute[] {
  return [
    { method: "GET", path: "/overview", auth: "session", role: "reviewer", handler: overview },
  ];
}

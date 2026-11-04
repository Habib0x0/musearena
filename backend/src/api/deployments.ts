// SPDX-License-Identifier: Apache-2.0
import { serviceClient } from "../lib/supabase.js";
import { audit } from "../lib/audit.js";
import { ApiError } from "./auth.js";
import { workflowCanceller, type WorkflowCanceller } from "./admin.js";
import { sendJson, type ApiRoute } from "./server.js";
import {
  DeploymentConflict, DeploymentNotFound, listDeployments, PromoteModel,
  promoteModel, PromotionRefused, rollbackDeployment, supabaseDeploymentStore,
  type DeploymentStore,
} from "../learning/deployments.js";

/**
 * Deployment routes (F-11). Promotion is an operator action: the session
 * subject becomes the approver in the audit chain. A refused promotion is a
 * client error with the production target left untouched.
 *
 * `DELETE /deployments/:id` is the environment registry delete: a live lab is
 * torn down through its own workflow first (cancellation runs the same
 * teardown path as TTL), then the row is marked `destroyed` with who deleted
 * it and when. Runs, traces, and datasets are keyed independently and stay
 * as the record of what happened.
 */
const DeployBody = PromoteModel.omit({ modelId: true });

const LAB_LIVE_STATUSES = ["pending", "provisioning", "configuring", "verifying", "ready", "exercising", "destroying"];

export interface DeploymentRouteDeps {
  store?: DeploymentStore;
  /** Cancels the environment's workflow; teardown runs as its cancellation handler. */
  cancelWorkflow?: (workflowId: string) => Promise<void>;
}

export function deploymentRoutes(deps: DeploymentRouteDeps = {}): ApiRoute[] {
  const store = () => deps.store ?? supabaseDeploymentStore();

  async function deploy(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const parsed = DeployBody.safeParse(ctx.body);
    if (!parsed.success) {
      sendJson(ctx.res, 400, {
        error: "invalid deployment",
        issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })),
      });
      return;
    }
    try {
      const row = await promoteModel(
        { ...parsed.data, modelId: ctx.params.id, orgId: ctx.session!.orgId, approvedBy: ctx.session!.subject },
        store(),
      );
      sendJson(ctx.res, 201, row);
    } catch (err) {
      if (err instanceof PromotionRefused) { sendJson(ctx.res, 409, { error: err.message }); return; }
      if (err instanceof DeploymentNotFound) { sendJson(ctx.res, 404, { error: err.message }); return; }
      throw err;
    }
  }

  async function list(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const rows = deps.store
      ? await deps.store.listDeployments(ctx.session!.orgId)
      : await listDeployments(ctx.session!.orgId);
    sendJson(ctx.res, 200, { deployments: rows });
  }

  async function rollback(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    try {
      const row = await rollbackDeployment(
        { orgId: ctx.session!.orgId, id: ctx.params.id, actor: ctx.session!.subject },
        store(),
      );
      sendJson(ctx.res, 200, row);
    } catch (err) {
      if (err instanceof DeploymentNotFound) { sendJson(ctx.res, 404, { error: err.message }); return; }
      if (err instanceof DeploymentConflict) { sendJson(ctx.res, 409, { error: err.message }); return; }
      throw err;
    }
  }

  /** Registry delete: tear down if live, mark destroyed, keep the evidence. */
  async function deleteEnvironment(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
    const orgId = ctx.session!.orgId;
    const id = ctx.params.id;
    const sb = serviceClient();
    const { data, error } = await sb.from("deployments")
      .select("id, status, access_info").eq("id", id).eq("org_id", orgId).maybeSingle();
    if (error) throw new Error(`deployment unreadable: ${error.message}`);
    if (!data) throw new ApiError(404, "no such environment in this organization");
    const row = data as { status: string; access_info: Record<string, unknown> | null };

    const deletedAt = new Date().toISOString();
    let how: string;
    if (LAB_LIVE_STATUSES.includes(row.status)) {
      if (row.status === "pending") {
        // Not claimed by a worker: no resources exist. The status guard loses
        // cleanly to a worker claiming it in the same instant.
        const { data: upd, error: e } = await sb.from("deployments")
          .update({ status: "destroyed", access_info: { ...(row.access_info ?? {}), deletedAt, deletedBy: ctx.session!.subject } })
          .eq("id", id).eq("status", "pending").select("id");
        if (e) throw new Error(`delete failed: ${e.message}`);
        if (!upd?.length) throw new ApiError(409, "a worker claimed this environment just now; delete it again");
        how = "deleted before provisioning";
      } else {
        // A claimed lab tears down through its own workflow; the row moves to
        // destroying and the workflow's teardown completes it as destroyed.
        if (!deps.cancelWorkflow && !workflowCanceller()) throw new ApiError(502, "the workflow service is not wired to this host");
        try {
          await (deps.cancelWorkflow ?? workflowCanceller())(`deployment-${id}`);
        } catch (err) {
          throw new ApiError(502, `could not reach the workflow service: ${err instanceof Error ? err.message : String(err)}`);
        }
        const { error: e } = await sb.from("deployments")
          .update({ status: "destroying", access_info: { ...(row.access_info ?? {}), deletedAt, deletedBy: ctx.session!.subject, deletedVia: "operator-delete" } })
          .eq("id", id);
        if (e) throw new Error(`delete failed: ${e.message}`);
        how = "teardown requested from its workflow";
      }
    } else {
      // Already terminal: mark destroyed with the deletion stamp.
      const { error: e } = await sb.from("deployments")
        .update({ status: "destroyed", access_info: { ...(row.access_info ?? {}), deletedAt, deletedBy: ctx.session!.subject } })
        .eq("id", id);
      if (e) throw new Error(`delete failed: ${e.message}`);
      how = `removed from registry (was ${row.status})`;
    }

    await audit({
      orgId, actor: ctx.session!.subject, action: "DEPLOYMENT_DESTROY", subjectType: "deployment", subjectId: id,
      detail: { previousStatus: row.status, how },
    });
    sendJson(ctx.res, 200, { id, deleted: true, how });
  }

  return [
    { method: "POST", path: "/models/:id/deploy", auth: "session", role: "operator", handler: deploy },
    { method: "GET", path: "/model-deployments", auth: "session", role: "reviewer", handler: list },
    { method: "POST", path: "/model-deployments/:id/rollback", auth: "session", role: "operator", handler: rollback },
    { method: "DELETE", path: "/deployments/:id", auth: "session", role: "operator", handler: deleteEnvironment },
  ];
}

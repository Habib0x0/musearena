import { z } from "zod";
import { sendJson, type ApiRoute } from "./server.js";
import {
  archiveDataset, buildDataset, DatasetNotArchived, DatasetNotFound, DatasetSelection,
  EmptyDataset, FamilySplitCollision, InsufficientRealShare, listDatasets, renameDataset, restoreDataset,
} from "../learning/datasets.js";

/**
 * Dataset builder routes (F-7). Building is a trainer action; reading snapshots,
 * their hashes and leakage status is reviewer. Renaming and archiving are
 * trainer metadata actions on an immutable snapshot.
 */
async function postDataset(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = DatasetSelection.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid dataset selection", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    return;
  }
  try {
    const result = await buildDataset({ orgId: ctx.session!.orgId, selection: parsed.data });
    sendJson(ctx.res, 201, result);
  } catch (err) {
    if (err instanceof FamilySplitCollision) {
      sendJson(ctx.res, 409, { error: err.message });
      return;
    }
    if (err instanceof EmptyDataset || err instanceof InsufficientRealShare) {
      sendJson(ctx.res, 422, { error: err.message });
      return;
    }
    throw err;
  }
}

async function getDatasets(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const includeArchived = ctx.url.searchParams.get("archived") === "1";
  sendJson(ctx.res, 200, { datasets: await listDatasets(ctx.session!.orgId, { includeArchived }) });
}

const RenameDataset = z.object({ name: z.string().trim().min(1).max(120) }).strict();

async function patchDataset(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const action = ctx.url.searchParams.get("action");
  try {
    if (action === "archive") {
      sendJson(ctx.res, 200, await archiveDataset(ctx.session!.orgId, ctx.params.id, ctx.session!.subject));
      return;
    }
    if (action === "restore") {
      sendJson(ctx.res, 200, await restoreDataset(ctx.session!.orgId, ctx.params.id, ctx.session!.subject));
      return;
    }
    const parsed = RenameDataset.safeParse(ctx.body);
    if (!parsed.success) {
      sendJson(ctx.res, 400, { error: "invalid rename", issues: parsed.error.issues.map((i) => i.message) });
      return;
    }
    sendJson(ctx.res, 200, await renameDataset(ctx.session!.orgId, ctx.params.id, parsed.data.name, ctx.session!.subject));
  } catch (err) {
    if (err instanceof DatasetNotFound) {
      sendJson(ctx.res, 404, { error: err.message });
      return;
    }
    if (err instanceof DatasetNotArchived) {
      sendJson(ctx.res, 409, { error: err.message });
      return;
    }
    throw err;
  }
}

export function datasetRoutes(): ApiRoute[] {
  return [
    { method: "POST", path: "/datasets", auth: "session", role: "trainer", handler: postDataset },
    { method: "GET", path: "/datasets", auth: "session", role: "reviewer", handler: getDatasets },
    { method: "PATCH", path: "/datasets/:id", auth: "session", role: "trainer", handler: patchDataset },
  ];
}

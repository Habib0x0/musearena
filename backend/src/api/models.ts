import { sendJson, type ApiRoute } from "./server.js";
import {
  listModels, ModelInUse, ModelNotFound, registerModel, RegisterModel, REGISTRY_ROLES, resolveServedModel,
  StatusNotEditable, UnapprovedModel, updateModel, UpdateModel, type RegistryRole,
} from "../learning/models.js";

/**
 * Model registry routes (F-8). Registration is an operator action: it names the
 * exact Meta ID an agent will later call. Reading and resolving are reviewer.
 * Editing metadata (or deprecating) is operator too — readiness is earned by a
 * training run, never set by hand.
 */
function roleParam(raw: string | null): RegistryRole | null | "invalid" {
  if (raw === null) return null;
  return (REGISTRY_ROLES as readonly string[]).includes(raw) ? (raw as RegistryRole) : "invalid";
}

async function getModels(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const role = roleParam(ctx.url.searchParams.get("role"));
  if (role === "invalid") {
    sendJson(ctx.res, 400, { error: `role must be one of ${REGISTRY_ROLES.join(", ")}` });
    return;
  }
  const models = await listModels(ctx.session!.orgId, role ?? undefined);
  sendJson(ctx.res, 200, { models });
}

async function resolve(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const role = roleParam(ctx.url.searchParams.get("role"));
  if (!role || role === "invalid") {
    sendJson(ctx.res, 400, { error: `role must be one of ${REGISTRY_ROLES.join(", ")}` });
    return;
  }
  const resolved = await resolveServedModel(ctx.session!.orgId, role);
  sendJson(ctx.res, 200, resolved);
}

async function postModel(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = RegisterModel.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid model", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    return;
  }
  try {
    const model = await registerModel({ orgId: ctx.session!.orgId, ...parsed.data });
    sendJson(ctx.res, 201, model);
  } catch (err) {
    if (err instanceof UnapprovedModel) {
      sendJson(ctx.res, 400, { error: err.message });
      return;
    }
    throw err;
  }
}

async function patchModel(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = UpdateModel.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid model update", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    return;
  }
  try {
    const model = await updateModel(ctx.session!.orgId, ctx.params.id, parsed.data, ctx.session!.subject);
    sendJson(ctx.res, 200, model);
  } catch (err) {
    if (err instanceof ModelNotFound) {
      sendJson(ctx.res, 404, { error: err.message });
      return;
    }
    if (err instanceof ModelInUse || err instanceof StatusNotEditable) {
      sendJson(ctx.res, 409, { error: err.message });
      return;
    }
    throw err;
  }
}

export function modelRoutes(): ApiRoute[] {
  return [
    { method: "GET", path: "/models", auth: "session", role: "reviewer", handler: getModels },
    { method: "GET", path: "/models/resolve", auth: "session", role: "reviewer", handler: resolve },
    { method: "POST", path: "/models", auth: "session", role: "operator", handler: postModel },
    { method: "PATCH", path: "/models/:id", auth: "session", role: "operator", handler: patchModel },
  ];
}

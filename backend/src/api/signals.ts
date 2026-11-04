import { z } from "zod";
import { sendJson, type ApiRoute } from "./server.js";
import {
  createSignal, deleteSignal, listSignals, ModelDefinition, RuleDefinition, runSignal,
  SignalDisabled, SignalNotFound, signalHitCounts, UnsupportedSignalKind, updateSignal,
} from "../learning/signals.js";

/**
 * Signal and grader definitions (F-6). Definition is a trainer action; reading
 * is reviewer. Hitting is a worker action with an explicit manual trigger; a
 * signal marked `continual` is also applied when new traces arrive.
 */
const CreateSignal = z.object({
  name: z.string().trim().min(1).max(80),
  kind: z.enum(["rule", "model", "human"]),
  definition: z.record(z.unknown()),
  enabled: z.boolean().optional(),
  continual: z.boolean().optional(),
}).strict();

const UpdateSignal = z.object({
  definition: z.record(z.unknown()).optional(),
  enabled: z.boolean().optional(),
  continual: z.boolean().optional(),
}).strict();

const RunSignal = z.object({
  runId: z.string().min(1).optional(),
  limit: z.number().int().positive().max(5000).optional(),
}).strict();

async function getSignals(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const orgId = ctx.session!.orgId;
  const [signals, counts] = await Promise.all([listSignals(orgId), signalHitCounts(orgId)]);
  sendJson(ctx.res, 200, { signals: signals.map((signal) => ({ ...signal, hits: counts[signal.id] ?? 0 })) });
}

async function postSignal(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = CreateSignal.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid signal", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    return;
  }
  if (parsed.data.kind === "rule") {
    const rule = RuleDefinition.safeParse(parsed.data.definition);
    if (!rule.success) {
      sendJson(ctx.res, 400, { error: "invalid rule definition", issues: rule.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
      return;
    }
  }
  if (parsed.data.kind === "model") {
    const model = ModelDefinition.safeParse(parsed.data.definition);
    if (!model.success) {
      sendJson(ctx.res, 400, { error: "invalid model definition", issues: model.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
      return;
    }
  }
  const signal = await createSignal({ orgId: ctx.session!.orgId, ...parsed.data });
  sendJson(ctx.res, 201, signal);
}

async function runSignalRoute(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = RunSignal.safeParse(ctx.body ?? {});
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid run request", issues: parsed.error.issues.map((i) => i.message) });
    return;
  }
  try {
    const result = await runSignal({ orgId: ctx.session!.orgId, signalId: ctx.params.id, ...parsed.data });
    sendJson(ctx.res, 200, result);
  } catch (err) {
    if (err instanceof SignalNotFound) {
      sendJson(ctx.res, 404, { error: "signal not found" });
      return;
    }
    if (err instanceof SignalDisabled) {
      sendJson(ctx.res, 409, { error: err.message });
      return;
    }
    if (err instanceof UnsupportedSignalKind) {
      sendJson(ctx.res, 409, { error: err.message });
      return;
    }
    throw err;
  }
}

async function patchSignal(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  const parsed = UpdateSignal.safeParse(ctx.body);
  if (!parsed.success) {
    sendJson(ctx.res, 400, { error: "invalid signal update", issues: parsed.error.issues.map((i) => ({ path: i.path.join("."), message: i.message })) });
    return;
  }
  try {
    const signal = await updateSignal({ orgId: ctx.session!.orgId, signalId: ctx.params.id, ...parsed.data });
    sendJson(ctx.res, 200, signal);
  } catch (err) {
    if (err instanceof SignalNotFound) {
      sendJson(ctx.res, 404, { error: "signal not found" });
      return;
    }
    if (err instanceof z.ZodError) {
      sendJson(ctx.res, 400, { error: "invalid definition", issues: err.issues.map((i) => i.message) });
      return;
    }
    throw err;
  }
}

async function deleteSignalRoute(ctx: Parameters<ApiRoute["handler"]>[0]): Promise<void> {
  try {
    await deleteSignal(ctx.session!.orgId, ctx.params.id);
    sendJson(ctx.res, 200, { ok: true, id: ctx.params.id });
  } catch (err) {
    if (err instanceof SignalNotFound) {
      sendJson(ctx.res, 404, { error: "signal not found" });
      return;
    }
    throw err;
  }
}

export function signalRoutes(): ApiRoute[] {
  return [
    { method: "GET", path: "/signals", auth: "session", role: "reviewer", handler: getSignals },
    { method: "POST", path: "/signals", auth: "session", role: "trainer", handler: postSignal },
    { method: "POST", path: "/signals/:id/run", auth: "session", role: "trainer", handler: runSignalRoute },
    { method: "PATCH", path: "/signals/:id", auth: "session", role: "trainer", handler: patchSignal },
    { method: "DELETE", path: "/signals/:id", auth: "session", role: "trainer", handler: deleteSignalRoute },
  ];
}

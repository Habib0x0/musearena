// SPDX-License-Identifier: Apache-2.0
import { createServer, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { Budget, EnvironmentSpec, PlatformSelection, type Budget as BudgetT, type EnvironmentSpec as SpecT, type PlatformSelection as PlatformSelectionT } from "@musearena/shared";
import { configuredDesignerSurfaces, designerModelClient, designerModelClientForSurface } from "../lib/model.js";
import { hostCapabilities } from "../provisioner/host-capabilities.js";
import { orchestrateDesign, orchestrateRefine, orchestrateSpec, type DesignPackage } from "./orchestrator.js";
import {
  isDesignAbort, type DesignEventInput, type DesignEventSink, type DesignRunEvent, type DesignRunOptions,
} from "./events.js";
import { clerkIssuer, verifyClerkToken } from "../lib/clerk-jwt.js";
import { assertEmailAllowed, EmailNotAllowed } from "../lib/email-allowlist.js";

const MAX_BODY = 256 * 1024;
const STREAM_MIN_INTERVAL_MS = 50;

export function formatDesignSseEvent(event: DesignRunEvent): string {
  return `id: ${event.seq}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`;
}

/**
 * Paced SSE sink: the first event is immediate, later events are delivered at
 * roughly 20/second even when the model produces token batches faster.
 */
export function createPacedDesignEventSink(
  write: (chunk: string) => void,
  runId: string,
  minIntervalMs = STREAM_MIN_INTERVAL_MS,
): { emit: DesignEventSink; flush: () => Promise<void>; close: () => void } {
  let seq = 0;
  let lastSentAt = 0;
  let closed = false;
  let chain = Promise.resolve();

  const emit: DesignEventSink = (input) => {
    if (closed) return;
    const event: DesignRunEvent = { ...input, runId, seq: ++seq, at: new Date().toISOString() };
    chain = chain.then(async () => {
      if (closed) return;
      const wait = lastSentAt ? minIntervalMs - (Date.now() - lastSentAt) : 0;
      if (wait > 0) await new Promise((resolve) => setTimeout(resolve, wait));
      if (closed) return;
      write(formatDesignSseEvent(event));
      lastSentAt = Date.now();
    });
  };

  return {
    emit,
    flush: async () => { await chain; },
    close: () => { closed = true; },
  };
}

/**
 * Dev/edge design endpoint.
 *
 * POST /design remains the one-shot JSON contract. POST /design/stream runs
 * the same pipeline while streaming its real lifecycle as SSE: context,
 * model reasoning/output, validation and repair attempts, packaging, and the
 * final artifact. Requires a Clerk session token.
 */
export function designServer(port = Number(process.env.DESIGN_PORT ?? 8787), host = process.env.DESIGN_HOST ?? "127.0.0.1") {
  // No silent mock: with no designer model configured the endpoint says so
  // (501) instead of serving a MockModelClient({}) that can only fail schema
  // validation. Modal (MODAL_PROXY_TOKEN_*) wins over Meta (META_API_KEY).
  const client = designerModelClient();
  // Every model call costs money: callers must hold a valid Clerk session.
  const issuer = clerkIssuer();
  const allowed = new Set((process.env.DESIGN_ALLOWED_ORIGINS ?? "http://localhost:5173,http://127.0.0.1:5173").split(",").map((o) => o.trim()).filter(Boolean));

  const server = createServer(async (req, res) => {
    const origin = req.headers.origin;
    if (origin && allowed.has(origin)) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
      res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    }
    const json = (code: number, body: unknown) => res.writeHead(code, { "Content-Type": "application/json" }).end(JSON.stringify(body));
    const pathname = (() => { try { return new URL(req.url ?? "/", "http://localhost").pathname; } catch { return ""; } })();
    const isStream = pathname === "/design/stream";
    if (pathname !== "/design" && !isStream) { res.writeHead(404).end(); return; }
    if (req.method === "OPTIONS") { res.writeHead(origin && allowed.has(origin) ? 204 : 403).end(); return; }
    if (req.method !== "POST") { res.writeHead(405).end(); return; }
    if (!issuer) { json(503, { error: "Clerk issuer not configured (CLERK_ISSUER or CLERK_PUBLISHABLE_KEY)" }); return; }
    const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
    if (!token) { json(401, { error: "missing Bearer [REDACTED]" }); return; }
    let subject: string;
    try { subject = (await verifyClerkToken(token, issuer)).sub; } catch (err) { json(401, { error: `invalid session: ${err instanceof Error ? err.message : String(err)}` }); return; }
    try { await assertEmailAllowed(subject); } catch (err) {
      json(err instanceof EmailNotAllowed ? 403 : 503, { error: err instanceof EmailNotAllowed ? err.message : `account check unavailable: ${err instanceof Error ? err.message : String(err)}` });
      return;
    }

    let body = "";
    let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > MAX_BODY) { json(413, { error: "request too large" }); req.destroy(); return; }
      body += c;
    });

    req.on("end", async () => {
      let input: Record<string, unknown>;
      let budget: BudgetT;
      let importedSpec: SpecT | undefined;
      let platform: PlatformSelectionT | undefined;
      try {
        input = JSON.parse(body) as Record<string, unknown>;
        budget = Budget.parse(input.budget) as BudgetT;
        if (input.spec) importedSpec = EnvironmentSpec.parse(input.spec);
        if (input.platform) platform = PlatformSelection.parse(input.platform);
      } catch (err) {
        json(400, { error: String(err) });
        return;
      }

      const operation = importedSpec ? "validate" : typeof input.instruction === "string" && input.current ? "refine" : "design";
      let requestClient = client;
      const platformsEqual = (a?: PlatformSelectionT, b?: PlatformSelectionT) =>
        a?.runtimeTarget === b?.runtimeTarget && a?.modelSurface === b?.modelSurface && a?.exerciseEngine === b?.exerciseEngine;
      if (importedSpec && platform && importedSpec.platform && !platformsEqual(platform, importedSpec.platform)) {
        json(409, {
          error: "Imported spec carries a different platform selection than the request",
          code: "platform_unavailable",
          field: "platform",
          requested: platform,
          alternatives: [importedSpec.platform],
        });
        return;
      }
      if (importedSpec && platform && !importedSpec.platform) importedSpec = { ...importedSpec, platform };
      const effectivePlatform = platform ?? importedSpec?.platform;
      // Refuse unavailable combinations before any designer model call. The
      // user chose "ask each time": alternatives are offered, never substituted.
      if (effectivePlatform) {
        const caps = hostCapabilities();
        const runtimeAvailable = effectivePlatform.runtimeTarget === "vm" ? caps.vmRuns : caps.container;
        if (!runtimeAvailable) {
          const other = effectivePlatform.runtimeTarget === "vm" ? "container" : "vm";
          const otherAvailable = other === "vm" ? caps.vmRuns : caps.container;
          json(409, {
            error: `Selected runtime "${effectivePlatform.runtimeTarget}" is not available on this worker`,
            code: "platform_unavailable",
            field: "runtimeTarget",
            requested: effectivePlatform,
            alternatives: otherAvailable ? [{ ...effectivePlatform, runtimeTarget: other }] : [],
          });
          return;
        }
      }
      if (!importedSpec && effectivePlatform) {
        try {
          requestClient = designerModelClientForSurface(effectivePlatform.modelSurface);
        } catch {
          requestClient = null;
        }
        if (!requestClient) {
          json(409, {
            error: `Selected model surface "${effectivePlatform.modelSurface}" is not configured on this worker`,
            code: "platform_unavailable",
            field: "modelSurface",
            requested: effectivePlatform,
            alternatives: configuredDesignerSurfaces()
              .filter((surface) => surface !== effectivePlatform.modelSurface)
              .map((modelSurface) => ({ ...effectivePlatform, modelSurface })),
          });
          return;
        }
      }
      platform = effectivePlatform;
      if (!importedSpec && !requestClient) {
        json(501, { error: "no designer model configured — set MODAL_PROXY_TOKEN_ID/MODAL_PROXY_TOKEN_SECRET (Modal) or META_API_KEY (Meta)" });
        return;
      }

      const execute = async (opts?: DesignRunOptions): Promise<DesignPackage> => {
        const runOpts = platform ? { ...opts, platform } : opts;
        if (importedSpec) return orchestrateSpec(importedSpec, budget, runOpts);
        if (!requestClient) throw new Error("no designer model configured");
        return operation === "refine"
          ? orchestrateRefine(requestClient, input.current as SpecT, input.instruction as string, budget, runOpts)
          : orchestrateDesign(requestClient, typeof input.prompt === "string" ? input.prompt : "", budget, runOpts);
      };

      if (!isStream) {
        try {
          const pkg = await execute();
          res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify(pkg));
        } catch (err) {
          if (!res.headersSent) json(400, { error: String(err) });
        }
        return;
      }

      await streamDesign(res, { budget, operation, modelId: importedSpec ? "none" : requestClient?.modelId ?? "none", execute });
    });
  });

  server.listen(port, host, () => console.log(`design endpoint on ${host}:${port} (model: ${client?.modelId ?? "unconfigured"}, issuer: ${issuer ?? "unset"})`));
  return server;
}

async function streamDesign(res: ServerResponse, input: {
  budget: BudgetT;
  operation: string;
  modelId: string;
  execute: (opts: DesignRunOptions) => Promise<DesignPackage>;
}): Promise<void> {
  const runId = randomUUID();
  const abort = new AbortController();
  const sender = createPacedDesignEventSink((chunk) => { if (!res.writableEnded) res.write(chunk); }, runId);
  const emit = sender.emit;

  res.writeHead(200, {
    "Content-Type": "text/event-stream; charset=utf-8",
    "Cache-Control": "no-cache, no-transform",
    Connection: "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.flushHeaders?.();

  const heartbeat = setInterval(() => {
    if (!res.writableEnded) res.write(": keep-alive\n\n");
  }, 15_000);
  heartbeat.unref?.();

  res.on("close", () => {
    if (res.writableEnded) return;
    sender.close();
    const error = new Error("design run cancelled by client");
    error.name = "AbortError";
    abort.abort(error);
  });

  emit({
    type: "run.started", phase: "run", stepId: "run",
    title: "Designer run started",
    detail: input.operation === "validate" ? "Validating the imported specification." : `${input.modelId} is handling this ${input.operation} request.`,
    data: { operation: input.operation, modelId: input.modelId, budget: input.budget },
  });

  try {
    const pkg = await input.execute({ onEvent: emit, signal: abort.signal });
    emit({
      type: "artifact.ready", phase: "artifact", stepId: "artifact",
      title: pkg.canProvision ? "Design artifact ready" : "Design artifact ready with blocks",
      detail: `${pkg.spec.instances.length} hosts · ${pkg.spec.personas.length} personas · ${pkg.spec.objectives.length} objectives · $${pkg.cost.perHour}/hr.`,
      data: {
        package: pkg,
        canProvision: pkg.canProvision,
        specDigest: pkg.digest,
        planDigest: pkg.planDigest,
        blockReasons: pkg.blockReasons,
      },
    });
    emit({
      type: "run.completed", phase: "run", stepId: "run",
      title: pkg.canProvision ? "Designer run completed" : "Designer run completed with blocks",
      detail: pkg.canProvision ? "The checked artifact is ready for review and approval." : "The artifact was produced, but provisioning remains blocked.",
      data: { operation: input.operation, canProvision: pkg.canProvision, specDigest: pkg.digest, planDigest: pkg.planDigest },
    });
  } catch (err) {
    if (isDesignAbort(err, abort.signal)) {
      emit({
        type: "run.cancelled", phase: "run", stepId: "run",
        title: "Designer run cancelled",
        detail: "The operator stopped this run before an artifact was completed.",
        data: { operation: input.operation },
      });
    } else {
      const message = err instanceof Error ? err.message : String(err);
      emit({
        type: "run.failed", phase: "run", stepId: "run",
        title: "Designer run failed",
        detail: message,
        data: { operation: input.operation, error: message },
      });
    }
  } finally {
    clearInterval(heartbeat);
    await sender.flush().catch(() => undefined);
    if (!res.writableEnded) res.end();
  }
}

if (import.meta.url === `file://${process.argv[1]}`) designServer();

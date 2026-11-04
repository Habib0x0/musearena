import { assertEmailAllowed, EmailNotAllowed } from "../lib/email-allowlist.js";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { clerkIssuer, verifyClerkToken, type ClerkClaims } from "../lib/clerk-jwt.js";
import { audit } from "../lib/audit.js";
import { ApiError, bearerToken, requireRole, sessionFromClaims, type OrgRole, type Session } from "./auth.js";
import { supabaseCaptureKeyStore, verifyCaptureKey, type CaptureKeyStore, type RejectionAudit } from "./keys.js";

/**
 * The learning API host (design §4.1).
 *
 * One process owns every learning-platform route. Design stays on
 * `designer/server.ts`; this server never holds the designer's model
 * credentials and never serves a design route.
 *
 * Request order is deliberate: match the route, then authenticate, then read
 * the body. A caller who fails authentication never gets a handler, a body
 * parse, or a database read.
 */
const MAX_BODY = 256 * 1024;
export const DEFAULT_API_PORT = 8788;
const DEFAULT_ORIGINS = "http://localhost:5173,http://127.0.0.1:5173";

export interface ApiContext {
  req: IncomingMessage;
  res: ServerResponse;
  url: URL;
  params: Record<string, string>;
  /** Present on `session` routes. */
  session?: Session;
  /** Present on `capture` routes: the org the key belongs to. */
  orgId?: string;
  body?: unknown;
}

export interface ApiRoute {
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE";
  path: string;
  auth: "public" | "session" | "capture";
  /** Minimum org role for `session` routes. */
  role?: OrgRole;
  handler: (ctx: ApiContext) => Promise<void> | void;
}

export interface ApiServerOptions {
  host?: string;
  issuer?: string | null;
  routes?: ApiRoute[];
  verifySession?: (token: string) => Promise<ClerkClaims>;
  captureKeys?: CaptureKeyStore;
  allowedOrigins?: string[];
  onCaptureKeyRejected?: (input: RejectionAudit) => Promise<void>;
}

const HEALTH: ApiRoute = {
  method: "GET",
  path: "/health",
  auth: "public",
  handler: ({ res }) => sendJson(res, 200, { ok: true, service: "musearena-learning-api" }),
};

export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  if (res.headersSent) return;
  res.writeHead(status, { "Content-Type": "application/json" }).end(JSON.stringify(body));
}

function matchPath(pattern: string, pathname: string): Record<string, string> | null {
  const want = pattern.split("/");
  const got = pathname.split("/");
  if (want.length !== got.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < want.length; i++) {
    if (want[i].startsWith(":")) {
      if (!got[i]) return null;
      params[want[i].slice(1)] = decodeURIComponent(got[i]);
    } else if (want[i] !== got[i]) {
      return null;
    }
  }
  return params;
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buf = chunk as Buffer;
    size += buf.length;
    if (size > MAX_BODY) throw new ApiError(413, "request too large");
    chunks.push(buf);
  }
  if (size === 0) return undefined;
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new ApiError(400, "body is not valid JSON");
  }
}

function hasBody(method: string): boolean {
  return method === "POST" || method === "PUT" || method === "PATCH";
}

function originAllowed(origin: string | undefined, allowed: Set<string>): boolean {
  return Boolean(origin && allowed.has(origin));
}

/** A rejection is logged always and audited only when the owning org is known. */
async function defaultRejectionAudit(input: RejectionAudit): Promise<void> {
  console.warn(`capture key rejected: ${input.reason}${input.orgId ? ` (org ${input.orgId})` : ""}`);
  if (!input.orgId) return;
  await audit({
    orgId: input.orgId,
    actor: "capture-key",
    action: "CAPTURE_KEY_REJECTED",
    subjectType: "capture_key",
    subjectId: input.reason,
    detail: { reason: input.reason },
  });
}

const lazySupabaseStore: CaptureKeyStore = {
  find: (hash) => supabaseCaptureKeyStore().find(hash),
  touch: (id) => supabaseCaptureKeyStore().touch(id),
};

export function createApiServer(opts: ApiServerOptions = {}): Server {
  const routes = [HEALTH, ...(opts.routes ?? [])];
  const issuer = opts.issuer === undefined ? clerkIssuer() : opts.issuer;
  const allowed = new Set((opts.allowedOrigins ?? (process.env.API_ALLOWED_ORIGINS ?? DEFAULT_ORIGINS).split(",")).map((o) => o.trim()).filter(Boolean));
  const captureKeys = opts.captureKeys ?? lazySupabaseStore;
  const onCaptureKeyRejected = opts.onCaptureKeyRejected ?? defaultRejectionAudit;
  const verifySession = opts.verifySession ?? (async (token: string) => {
    if (!issuer) throw new ApiError(503, "Clerk issuer not configured (CLERK_ISSUER or CLERK_PUBLISHABLE_KEY)");
    return verifyClerkToken(token, issuer);
  });

  return createServer(async (req, res) => {
    const origin = req.headers.origin;
    if (originAllowed(origin, allowed)) {
      res.setHeader("Access-Control-Allow-Origin", origin as string);
      res.setHeader("Vary", "Origin");
      res.setHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
    }

    try {
      if (req.method === "OPTIONS") {
        res.writeHead(originAllowed(origin, allowed) ? 204 : 403).end();
        return;
      }

      const url = new URL(req.url ?? "/", "http://localhost");
      const candidates = routes
        .map((route) => ({ route, params: matchPath(route.path, url.pathname) }))
        .filter((c): c is { route: ApiRoute; params: Record<string, string> } => c.params !== null);
      if (!candidates.length) {
        sendJson(res, 404, { error: "not found" });
        return;
      }
      const matched = candidates.find((c) => c.route.method === req.method);
      if (!matched) {
        sendJson(res, 405, { error: `method ${req.method ?? "unknown"} not allowed` });
        return;
      }

      const ctx: ApiContext = { req, res, url, params: matched.params };
      if (matched.route.auth === "session") {
        const token = bearerToken(req.headers.authorization);
        if (!token) throw new ApiError(401, "missing Bearer token");
        let claims: ClerkClaims;
        try {
          claims = await verifySession(token);
        } catch (err) {
          if (err instanceof ApiError) throw err;
          throw new ApiError(401, `invalid session: ${err instanceof Error ? err.message : String(err)}`);
        }
        try {
          await assertEmailAllowed(claims.sub);
        } catch (err) {
          if (err instanceof EmailNotAllowed) throw new ApiError(403, err.message);
          throw new ApiError(503, `account check unavailable: ${err instanceof Error ? err.message : String(err)}`);
        }
        ctx.session = sessionFromClaims(claims);
        if (matched.route.role) requireRole(ctx.session, matched.route.role, `${req.method} ${url.pathname}`);
      } else if (matched.route.auth === "capture") {
        const token = bearerToken(req.headers.authorization);
        if (!token) {
          await onCaptureKeyRejected({ reason: "malformed" });
          throw new ApiError(401, "missing capture key");
        }
        ctx.orgId = await verifyCaptureKey(token, captureKeys, onCaptureKeyRejected);
      }

      if (hasBody(req.method ?? "GET")) ctx.body = await readJson(req);
      await matched.route.handler(ctx);
    } catch (err) {
      if (err instanceof ApiError) {
        sendJson(res, err.status, {
          error: err.message,
          ...(err.requiredRole ? { required_role: err.requiredRole } : {}),
        });
        return;
      }
      console.error("learning API request failed", err);
      sendJson(res, 500, { error: "internal error" });
    }
  });
}

export function startApiServer(opts: ApiServerOptions & { port?: number } = {}): Server {
  const port = opts.port ?? Number(process.env.MUSEARENA_API_PORT ?? DEFAULT_API_PORT);
  const host = opts.host ?? process.env.MUSEARENA_API_HOST ?? "127.0.0.1";
  const server = createApiServer(opts);
  server.listen(port, host, () => {
    console.log(`learning API on http://${host}:${port}`);
  });
  return server;
}

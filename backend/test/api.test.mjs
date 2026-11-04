import test from "node:test";
import assert from "node:assert/strict";
import { createApiServer } from "../dist/api/server.js";
import { hashCaptureKey, newCaptureKey } from "../dist/api/keys.js";

const ISSUER = "https://clerk.test";

const claims = (role, org = "org-1") => ({ sub: "user-1", iss: ISSUER, exp: 9_999_999_999, o: { id: org, rol: role } });

function setup({ captureKeys, rejected = [] } = {}) {
  const server = createApiServer({
    issuer: ISSUER,
    verifySession: async (token) => {
      const known = {
        reviewer: claims("reviewer"),
        trainer: claims("trainer"),
        operator: claims("operator"),
        "no-role": { sub: "user-1", iss: ISSUER, exp: 9_999_999_999, o: { id: "org-1" } },
      };
      if (!known[token]) throw new Error("bad token");
      return known[token];
    },
    captureKeys: captureKeys ?? { find: async () => null, touch: async () => {} },
    onCaptureKeyRejected: async (input) => { rejected.push(input); },
    routes: [
      {
        method: "GET", path: "/echo", auth: "session", role: "trainer",
        handler: ({ res, session }) => res.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ org: session.orgId, role: session.role })),
      },
      {
        method: "POST", path: "/echo", auth: "session", role: "reviewer",
        handler: ({ res, session, body }) => res.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ org: session.orgId, body })),
      },
      {
        method: "POST", path: "/capture/echo", auth: "capture",
        handler: ({ res, orgId }) => res.writeHead(200, { "Content-Type": "application/json" })
          .end(JSON.stringify({ org: orgId })),
      },
    ],
  });
  return { server, rejected };
}

async function listen(server) {
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  return `http://127.0.0.1:${address.port}`;
}

async function close(server) {
  await new Promise((resolve) => server.close(resolve));
}

test("learning API: health, unknown routes, and no designer route", async () => {
  const { server } = setup();
  const base = await listen(server);
  try {
    const health = await fetch(`${base}/health`);
    assert.equal(health.status, 200);
    assert.deepEqual(await health.json(), { ok: true, service: "musearena-learning-api" });
    assert.equal((await fetch(`${base}/nope`)).status, 404);
    assert.equal((await fetch(`${base}/design`)).status, 404, "the designer endpoint is not served here");
    assert.equal((await fetch(`${base}/health`, { method: "POST" })).status, 405);
  } finally {
    await close(server);
  }
});

test("learning API: missing, invalid and under-privileged sessions are refused before any handler", async () => {
  const { server } = setup();
  const base = await listen(server);
  try {
    assert.equal((await fetch(`${base}/echo`)).status, 401);
    assert.equal((await fetch(`${base}/echo`, { headers: { authorization: "Bearer bad" } })).status, 401);
    const noRole = await fetch(`${base}/echo`, { headers: { authorization: "Bearer no-role" } });
    assert.equal(noRole.status, 403, "a token without a recognized org role is refused");

    const forbidden = await fetch(`${base}/echo`, { headers: { authorization: "Bearer reviewer" } });
    assert.equal(forbidden.status, 403);
    assert.equal((await forbidden.json()).required_role, "trainer");

    const allowed = await fetch(`${base}/echo`, { headers: { authorization: "Bearer operator" } });
    assert.equal(allowed.status, 200, "operator implies trainer");
    assert.deepEqual(await allowed.json(), { org: "org-1", role: "operator" });
  } finally {
    await close(server);
  }
});

test("learning API: org comes from the verified token, never from the body", async () => {
  const { server } = setup();
  const base = await listen(server);
  try {
    const res = await fetch(`${base}/echo`, {
      method: "POST",
      headers: { authorization: "Bearer reviewer", "content-type": "application/json" },
      body: JSON.stringify({ org_id: "org-foreign" }),
    });
    assert.equal(res.status, 200);
    const out = await res.json();
    assert.equal(out.org, "org-1", "a body org_id cannot switch tenants");
    assert.equal(out.body.org_id, "org-foreign", "the body is passed through but not trusted");
  } finally {
    await close(server);
  }
});

test("learning API: capture keys resolve their org; unknown and revoked keys are refused", async () => {
  const good = newCaptureKey();
  const revoked = newCaptureKey();
  const store = {
    find: async (hash) => {
      if (hash === hashCaptureKey(good.raw)) return { id: "k1", orgId: "org-9", revokedAt: null };
      if (hash === hashCaptureKey(revoked.raw)) return { id: "k2", orgId: "org-7", revokedAt: new Date().toISOString() };
      return null;
    },
    touch: async () => {},
  };
  const rejected = [];
  const { server } = setup({ captureKeys: store, rejected });
  const base = await listen(server);
  const post = (key) => fetch(`${base}/capture/echo`, { method: "POST", headers: key ? { authorization: `Bearer ${key}` } : {} });
  try {
    assert.equal((await post()).status, 401, "missing key");
    assert.equal((await post("not-a-key")).status, 401, "malformed key");
    assert.equal((await post(newCaptureKey().raw)).status, 401, "unknown key");

    const denied = await post(revoked.raw);
    assert.equal(denied.status, 401, "revoked key");
    assert.equal((await denied.json()).error, "revoked capture key");
    assert.equal(rejected.at(-1).reason, "revoked");
    assert.equal(rejected.at(-1).orgId, "org-7", "the rejection is attributed to the owning org");

    const ok = await post(good.raw);
    assert.equal(ok.status, 200);
    assert.deepEqual(await ok.json(), { org: "org-9" });
  } finally {
    await close(server);
  }
});

test("capture key format: prefix is display-only and the hash is sha256", () => {
  const key = newCaptureKey();
  assert.match(key.raw, /^muse_ck_[A-Za-z0-9_-]{43}$/);
  assert.equal(key.prefix.length, 12);
  assert.ok(key.raw.startsWith(key.prefix));
  assert.equal(key.hash, hashCaptureKey(key.raw));
  assert.notEqual(key.hash, key.raw);
});

test("learning API: Clerk's built-in org roles map to operator/reviewer; unknown roles are refused", async () => {
  const { sessionFromClaims } = await import("../dist/api/auth.js");
  const c = (rol) => ({ sub: "u", iss: ISSUER, exp: 9_999_999_999, o: { id: "org-1", rol } });
  assert.equal(sessionFromClaims(c("admin")).role, "operator");
  assert.equal(sessionFromClaims(c("org:admin")).role, "operator");
  assert.equal(sessionFromClaims(c("member")).role, "reviewer");
  assert.equal(sessionFromClaims(c("org:trainer")).role, "trainer");
  assert.throws(() => sessionFromClaims(c("guest")), /no recognized organization role/);
  assert.throws(() => sessionFromClaims(c(undefined)), /no recognized organization role/);
});

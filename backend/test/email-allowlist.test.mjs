import test from "node:test";
import assert from "node:assert/strict";
import { allowedDomains, assertEmailAllowed, emailAllowed, resetEmailAllowlistCache } from "../dist/lib/email-allowlist.js";
import { createApiServer } from "../dist/api/server.js";

const DOMAINS = "meta.com,@baseten.co, modal.com,cerebralvalley.ai,fireworks.ai";

test("email allowlist: off when unset, exact domains when set", () => {
  assert.equal(allowedDomains({}), null);
  assert.deepEqual(allowedDomains({ MUSEARENA_ALLOWED_EMAIL_DOMAINS: DOMAINS }), ["meta.com", "baseten.co", "modal.com", "cerebralvalley.ai", "fireworks.ai"]);
  const d = allowedDomains({ MUSEARENA_ALLOWED_EMAIL_DOMAINS: DOMAINS });
  assert.ok(emailAllowed("Jane@Meta.com", d));
  assert.ok(emailAllowed("x@fireworks.ai", d));
  assert.ok(!emailAllowed("x@gmail.com", d));
  assert.ok(!emailAllowed("x@evilmeta.com", d), "suffix match is not enough");
  assert.ok(!emailAllowed("x@meta.com.evil.io", d));
  assert.ok(!emailAllowed("x@sub.meta.com", d), "subdomains are not implied");
  assert.ok(!emailAllowed("meta.com", d));
});

test("email allowlist: only a verified address counts", async () => {
  resetEmailAllowlistCache();
  const env = { MUSEARENA_ALLOWED_EMAIL_DOMAINS: DOMAINS };
  const user = (addrs) => async () => ({ email_addresses: addrs });
  await assert.doesNotReject(assertEmailAllowed("u1", { env, fetchUser: user([{ email_address: "a@meta.com", verification: { status: "verified" } }]) }));
  await assert.rejects(assertEmailAllowed("u2", { env, fetchUser: user([{ email_address: "a@meta.com", verification: { status: "unverified" } }]) }), /limited to/);
  await assert.rejects(assertEmailAllowed("u3", { env, fetchUser: user([{ email_address: "a@gmail.com", verification: { status: "verified" } }]) }), /@meta\.com/);
  await assert.doesNotReject(assertEmailAllowed("u4", { env: {}, fetchUser: async () => { throw new Error("must not be called"); } }), "off in dev");
});

test("email allowlist: the API refuses a valid session from another domain with 403", async () => {
  resetEmailAllowlistCache();
  const prev = process.env.MUSEARENA_ALLOWED_EMAIL_DOMAINS;
  const prevFetch = globalThis.fetch;
  process.env.MUSEARENA_ALLOWED_EMAIL_DOMAINS = DOMAINS;
  process.env.CLERK_SECRET_KEY ??= "sk_test_x";
  const users = { "user-meta": "a@meta.com", "user-gmail": "a@gmail.com" };
  const server = createApiServer({
    issuer: "x",
    verifySession: async (t) => ({ sub: t, iss: "x", exp: 9e9, o: { id: "org-1", rol: "reviewer" } }),
    routes: [{ method: "GET", path: "/ping", auth: "session", role: "reviewer", handler: ({ res }) => res.writeHead(200).end("{}") }],
    captureKeys: { find: async () => null, touch: async () => {} },
  });
  globalThis.fetch = async (url, init) => {
    const m = /\/v1\/users\/([^/?]+)/.exec(String(url));
    if (m) return new Response(JSON.stringify({ email_addresses: [{ email_address: users[decodeURIComponent(m[1])], verification: { status: "verified" } }] }));
    return prevFetch(url, init);
  };
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await prevFetch(`${base}/ping`, { headers: { Authorization: "Bearer user-meta" } })).status, 200);
    const denied = await prevFetch(`${base}/ping`, { headers: { Authorization: "Bearer user-gmail" } });
    assert.equal(denied.status, 403);
    assert.match((await denied.json()).error, /limited to @meta\.com/);
  } finally {
    globalThis.fetch = prevFetch;
    await new Promise((r) => server.close(r));
    if (prev === undefined) delete process.env.MUSEARENA_ALLOWED_EMAIL_DOMAINS; else process.env.MUSEARENA_ALLOWED_EMAIL_DOMAINS = prev;
  }
});

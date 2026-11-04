import test from "node:test";
import assert from "node:assert/strict";
import {
  auditCsv, limitViolations, parseLimitsPatch, tokensByModel, usageFor, NO_LIMITS, fromClerkRole, toClerkRole,
} from "../dist/admin/core.js";
import { adminRoutes, integrationStatus } from "../dist/api/admin.js";
import { createApiServer } from "../dist/api/server.js";
import { estimateCostPerHour } from "../dist/designer/cost.js";

const vm = (hostId, role = "web") => ({ hostId, name: hostId, role, runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [] });
const spec = (n = 3, ttlHours = 2) => ({ name: "lab", instances: Array.from({ length: n }, (_, i) => vm(`h${i}`)), budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours } });

test("admin: audit CSV quotes every cell and neutralises spreadsheet formulas", () => {
  const csv = auditCsv([{ id: 1, created_at: "2026-11-04T00:00:00Z", actor: "=cmd()", action: "RUN_START", subject_type: "run", subject_id: 'a"b', detail: { k: 1 }, prev_hash: null, entry_hash: "h1" }]);
  const [head, row] = csv.trim().split("\n");
  assert.equal(head, "id,created_at,actor,action,subject_type,subject_id,detail,prev_hash,entry_hash");
  assert.match(row, /"'=cmd\(\)"/, "a leading = is prefixed so it is never evaluated");
  assert.match(row, /"a""b"/, "quotes are doubled");
  assert.match(row, /"\{""k"":1\}"/, "detail is JSON");
});

test("admin: usage counts only the overlap of each lab with the window", () => {
  const now = new Date("2026-11-04T12:00:00Z");
  const s = spec(2);
  const deps = [
    // ran 10:00–11:00, inside the window
    { id: "a", status: "destroyed", created_at: "2026-11-04T10:00:00Z", access_info: { destroyedAt: "2026-11-04T11:00:00Z" }, spec: s },
    // still running since 11:30
    { id: "b", status: "ready", created_at: "2026-11-04T11:30:00Z", access_info: {}, spec: s },
    // ended before the window
    { id: "c", status: "destroyed", created_at: "2026-11-03T01:00:00Z", access_info: { destroyedAt: "2026-11-03T02:00:00Z" }, spec: s },
  ];
  const u = usageFor(deps, new Date("2026-11-04T00:00:00Z"), now, now);
  assert.equal(u.labs, 2);
  assert.equal(u.vmHours, 3, "1h×2 VMs + 0.5h×2 VMs");
  assert.equal(u.estimatedUsd, Math.round(1.5 * estimateCostPerHour(s) * 100) / 100);
});

test("admin: limits name every violation; none configured means none", () => {
  const s = spec(5, 4);
  assert.deepEqual(limitViolations(NO_LIMITS, s, 10, 1000), []);
  const v = limitViolations({ ...NO_LIMITS, paused: true, max_concurrent_labs: 2, max_vms_per_lab: 4, max_dollars_per_hour: 1, max_ttl_hours: 2, monthly_budget_usd: 5 }, s, 2, 4);
  assert.equal(v.length, 6, v.join(" | "));
  assert.ok(v.some((x) => /paused/.test(x)));
  assert.ok(v.some((x) => /concurrent labs: 2 running, limit 2/.test(x)));
  assert.ok(v.some((x) => /VMs per lab: 5, limit 4/.test(x)));
  assert.ok(v.some((x) => /TTL 4h, limit 2h/.test(x)));
  assert.ok(v.some((x) => /monthly budget/.test(x)));
  assert.deepEqual(limitViolations({ ...NO_LIMITS, max_concurrent_labs: 3 }, s, 2, 0), [], "under the limit starts");
});

test("admin: limits updates are validated", () => {
  assert.deepEqual(parseLimitsPatch({ max_vms_per_lab: 8, monthly_budget_usd: null, paused: true }), { max_vms_per_lab: 8, monthly_budget_usd: null, paused: true });
  assert.throws(() => parseLimitsPatch({ max_vms_per_lab: -1 }), /non-negative/);
  assert.throws(() => parseLimitsPatch({ max_vms_per_lab: 2.5 }), /whole number/);
  assert.throws(() => parseLimitsPatch({ max_ttl_hours: 0 }), /greater than 0/);
  assert.throws(() => parseLimitsPatch({ paused: "yes" }), /true or false/);
  assert.throws(() => parseLimitsPatch({ org_id: "other" }), /unknown field/);
  assert.throws(() => parseLimitsPatch([1]), /object/);
});

test("admin: tokens are summed per model from scored runs", () => {
  const t = tokensByModel([
    { detail: { agentStates: { red: { modelId: "spark", inputTokens: 100, outputTokens: 10 }, blue: { modelId: "spark", inputTokens: 50, outputTokens: 5 }, "persona:p1": { modelId: "glimmer", inputTokens: 7, outputTokens: 1 } } } },
    { detail: { agentStates: { red: { modelId: "spark", inputTokens: 1, outputTokens: 1 } } } },
    { detail: { mode: "live-vm" } },
  ]);
  assert.deepEqual(t, { spark: { input: 151, output: 16, runs: 2 }, glimmer: { input: 7, output: 1, runs: 1 } });
});

test("admin: Clerk role keys map both ways; unknown roles are not trusted", () => {
  assert.equal(toClerkRole("operator"), "org:operator");
  assert.equal(fromClerkRole("org:trainer"), "trainer");
  assert.equal(fromClerkRole("org:admin"), null);
});

test("admin: integration status reports whether a secret is set, never its value", () => {
  const prev = process.env.META_API_KEY;
  process.env.META_API_KEY = "secret-value-123";
  try {
    const text = JSON.stringify(integrationStatus());
    assert.ok(!text.includes("secret-value-123"));
    assert.equal(integrationStatus().find((i) => i.name === "Meta Model API").configured, true);
  } finally {
    if (prev === undefined) delete process.env.META_API_KEY; else process.env.META_API_KEY = prev;
  }
});

test("admin: reads need a session, changes need operator", async () => {
  const ISSUER = "https://clerk.test";
  const claims = (role) => ({ sub: "user-1", iss: ISSUER, exp: 9_999_999_999, o: { id: "org-1", rol: role } });
  const server = createApiServer({ issuer: ISSUER, verifySession: async (t) => claims(t), routes: adminRoutes(), captureKeys: { find: async () => null, touch: async () => {} } });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(`${base}/admin/fleet`)).status, 401, "no token");
    for (const [method, path] of [["PUT", "/admin/limits"], ["POST", "/admin/fleet/x/stop"], ["GET", "/admin/audit/export"], ["GET", "/admin/members"], ["POST", "/admin/members/invite"], ["GET", "/admin/integrations"]]) {
      const r = await fetch(`${base}${path}`, { method, headers: { Authorization: "Bearer trainer", "Content-Type": "application/json" }, body: method === "GET" ? undefined : "{}" });
      assert.equal(r.status, 403, `${method} ${path} must need operator`);
    }
    const bad = await fetch(`${base}/admin/limits`, { method: "PUT", headers: { Authorization: "Bearer operator", "Content-Type": "application/json" }, body: JSON.stringify({ max_vms_per_lab: -3 }) });
    assert.equal(bad.status, 400, "invalid limits are refused before any write");
  } finally {
    await new Promise((r) => server.close(r));
  }
});

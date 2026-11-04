import { test } from "node:test";
import assert from "node:assert/strict";
import { generateKeyPairSync, createSign } from "node:crypto";
import { verifyClerkToken, clerkIssuer, resetJwksCache } from "../dist/lib/clerk-jwt.js";
import { checkBudget } from "../dist/designer/pipeline.js";

const ISS = "https://example.clerk.accounts.dev";
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: "jwk" }), kid: "k1" };
const fetchJwks = async () => ({ keys: [jwk] });
const sign = (claims, kid = "k1", key = privateKey) => {
  const h = Buffer.from(JSON.stringify({ alg: "RS256", kid })).toString("base64url");
  const p = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const s = createSign("RSA-SHA256").update(`${h}.${p}`).sign(key).toString("base64url");
  return `${h}.${p}.${s}`;
};
const now = Math.floor(Date.now() / 1000);

test("valid Clerk token verifies; tampered, expired, wrong issuer, foreign key rejected", async () => {
  resetJwksCache();
  const ok = await verifyClerkToken(sign({ sub: "u1", iss: ISS, exp: now + 60, o: { id: "org_1" } }), ISS, { fetchJwks });
  assert.equal(ok.o.id, "org_1");
  const good = sign({ sub: "u1", iss: ISS, exp: now + 60 });
  const [h, , s] = good.split(".");
  const forged = `${h}.${Buffer.from(JSON.stringify({ sub: "admin", iss: ISS, exp: now + 60 })).toString("base64url")}.${s}`;
  await assert.rejects(verifyClerkToken(forged, ISS, { fetchJwks }), /bad signature/);
  await assert.rejects(verifyClerkToken(sign({ sub: "u1", iss: ISS, exp: now - 120 }), ISS, { fetchJwks }), /expired/);
  await assert.rejects(verifyClerkToken(sign({ sub: "u1", iss: "https://evil", exp: now + 60 }), ISS, { fetchJwks }), /wrong issuer/);
  const other = generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
  await assert.rejects(verifyClerkToken(sign({ sub: "u1", iss: ISS, exp: now + 60 }, "k1", other), ISS, { fetchJwks }), /bad signature/);
  const none = `${Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url")}.${Buffer.from("{}").toString("base64url")}.`;
  await assert.rejects(verifyClerkToken(none, ISS, { fetchJwks }), /unsupported alg/);
});

test("issuer derives from the publishable key", () => {
  const pk = `pk_test_${Buffer.from("integral-hare-7828.clerk.accounts.dev$").toString("base64")}`;
  assert.equal(clerkIssuer({ CLERK_PUBLISHABLE_KEY: pk }), "https://integral-hare-7828.clerk.accounts.dev");
  assert.equal(clerkIssuer({}), null);
});

test("budget gate uses the platform estimate, not the model-declared $/hr", () => {
  const spec = { instances: Array.from({ length: 4 }, (_, i) => ({ hostId: `h${i}`, runtime: "vm", databases: [] })), budgets: { maxDollarsPerHour: 0.1, ttlHours: 1 } };
  const v = checkBudget(spec, { maxInstances: 8, maxDollarsPerHour: 1, ttlHours: 8 });
  assert.ok(v.some((x) => /estimated \$.*> cap \$1\/hr/.test(x)), v.join("; "));
});

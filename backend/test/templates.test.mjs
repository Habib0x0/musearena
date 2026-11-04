import { test } from "node:test";
import assert from "node:assert/strict";

import { digestOfSpec } from "../dist/lib/digest.js";
import { TemplateRegistry, templateFromRow } from "../dist/templates/registry.js";

const ORG = "org-1";
const AT = "2026-01-01T00:00:00.000Z";

function spec(seed = "s1", name = "clinic-template") {
  return {
    version: 1, name, provider: "kvm", seed, difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
    instances: [
      { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: ["php"], services: ["http"], databases: [] },
      { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: ["postgres"], databases: ["app"] },
    ],
    personas: [],
    objectives: [{ id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 10 }],
    requiredTelemetry: ["auditd"],
    plantedVulns: [],
    budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 1 },
  };
}

function row({ name = "clinic-template", family = "clinic", version = 1, seed = "s1", orgId = ORG, digest } = {}) {
  const value = spec(seed, name);
  return {
    id: `00000000-0000-4000-8000-${String(version).padStart(12, "0")}`,
    org_id: orgId,
    name,
    family,
    version,
    spec: value,
    digest: digest ?? digestOfSpec(value),
    shared: false,
    share_token: null,
    created_at: AT,
  };
}

function uniqueError() {
  return Object.assign(new Error("duplicate key value violates unique constraint templates_org_name_version_key"), { code: "23505" });
}

class FakeTemplateStore {
  rows = [];
  nextId = 100;
  failNextInsert = false;

  async list(orgId) {
    return this.rows.filter((r) => r.org_id === orgId).map((r) => structuredClone(r));
  }

  async insert(input) {
    if (this.failNextInsert) {
      this.failNextInsert = false;
      const concurrent = {
        ...structuredClone(input),
        id: `00000000-0000-4000-8000-${String(this.nextId++).padStart(12, "0")}`,
        shared: false,
        share_token: null,
        created_at: AT,
      };
      this.rows.push(concurrent);
      throw uniqueError();
    }
    if (this.rows.some((r) => r.org_id === input.org_id && r.name === input.name && r.version === input.version)) {
      throw uniqueError();
    }
    const saved = {
      ...structuredClone(input),
      id: `00000000-0000-4000-8000-${String(this.nextId++).padStart(12, "0")}`,
      shared: false,
      share_token: null,
      created_at: AT,
    };
    this.rows.push(saved);
    return structuredClone(saved);
  }
}

test("template rows are parsed and their pinned digest is verified", () => {
  const tpl = templateFromRow(row({ version: 3, seed: "s3" }));
  assert.equal(tpl.id, "clinic-template");
  assert.equal(tpl.version, 3);
  assert.equal(tpl.rowId, "00000000-0000-4000-8000-000000000003");
  assert.equal(tpl.orgId, ORG);
  assert.throws(
    () => templateFromRow(row({ digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000" })),
    /digest mismatch/,
  );
});

test("persistent template registry loads the highest version and filters by family", async () => {
  const store = new FakeTemplateStore();
  store.rows.push(
    row({ version: 3, seed: "s3" }),
    row({ version: 1, seed: "s1" }),
    row({ name: "phishing-template", family: "phishing", version: 1, seed: "p1" }),
  );

  const loaded = await TemplateRegistry.load(ORG, store);
  assert.equal(loaded.get("clinic-template")?.version, 3);
  assert.equal(loaded.get("clinic-template", 1)?.digest, digestOfSpec(spec("s1")));
  assert.deepEqual(loaded.byFamily("clinic").map((t) => t.version), [1, 3]);
  assert.deepEqual(loaded.byFamily("phishing").map((t) => t.id), ["phishing-template"]);
});

test("persistent registration uses max persisted version, not a visible-row count", async () => {
  const store = new FakeTemplateStore();
  store.rows.push(row({ version: 3, seed: "s3" }));
  const registry = new TemplateRegistry();

  const saved = await registry.registerPersistent(ORG, "clinic-template", "clinic", spec("s4"), store);
  assert.equal(saved.version, 4);
  assert.equal(saved.digest, digestOfSpec(spec("s4")));
  assert.equal(registry.get("clinic-template")?.version, 4);
  assert.equal(store.rows.find((r) => r.version === 4)?.digest, saved.digest);
});

test("persistent registration reloads and retries once after a concurrent version claim", async () => {
  const store = new FakeTemplateStore();
  store.rows.push(row({ version: 1, seed: "s1" }));
  store.failNextInsert = true;
  const registry = new TemplateRegistry();

  const saved = await registry.registerPersistent(ORG, "clinic-template", "clinic", spec("s4"), store);
  assert.equal(saved.version, 3, "the concurrent writer claimed v2, so the retry must claim v3");
  assert.deepEqual(store.rows.map((r) => r.version).sort((a, b) => a - b), [1, 2, 3]);
  assert.equal(registry.get("clinic-template")?.version, 3);
});

test("persistent registration refuses to mix orgs in one loaded registry", async () => {
  const store = new FakeTemplateStore();
  store.rows.push(row({ version: 1, seed: "s1" }));
  const registry = await TemplateRegistry.load(ORG, store);
  await assert.rejects(
    registry.registerPersistent("org-2", "clinic-template", "clinic", spec("other"), store),
    /different org/,
  );
});

import test from "node:test";
import assert from "node:assert/strict";
import { AGENT_MODELS, modelForRole } from "../dist/lib/model.js";
import { assertApprovedModel, RegisterModel, REGISTRY_ROLES } from "../dist/learning/models.js";

test("registry: only verified Meta tool-use IDs are approvable", () => {
  assert.doesNotThrow(() => assertApprovedModel("meta", "muse-spark-1.3"));
  assert.throws(() => assertApprovedModel("meta", "unapproved-model-id"), /not a verified Meta/i);
  assert.throws(() => assertApprovedModel("meta", "muse-glimmer-1.0"), /not a verified Meta/i);
  assert.doesNotThrow(() => assertApprovedModel("meta-modal", "meta-models/Muse-Spark-Open-816B-A42B"));
  assert.doesNotThrow(() => assertApprovedModel("meta-modal", "glimmer"), "the ep-glimmer served model name is approvable");
  assert.doesNotThrow(() => assertApprovedModel("meta-modal", "meta-models/Muse-Glimmer-30B"), "the Glimmer repository ID is approvable");
  assert.throws(() => assertApprovedModel("meta-modal", "meta-models/Some-Other"), /Muse Spark Open|Muse Glimmer/i);
});

test("registry: roles are the four training roles, and judge resolves to a verified model", () => {
  assert.deepEqual([...REGISTRY_ROLES], ["red", "blue", "persona", "judge"]);
  assert.ok(AGENT_MODELS.includes(modelForRole("judge")), "the judge role has a verified base model");
});

test("registry: registration input is strict about roles and unknown fields", () => {
  const base = {
    name: "red-sft-v1", baseModel: "muse-spark-1.3", servedModel: "muse-spark-1.3",
    provider: "meta", role: ["red"],
  };
  const parsed = RegisterModel.parse(base);
  assert.equal(parsed.status, "available", "status defaults to available");
  assert.deepEqual(parsed.metrics, {});
  assert.throws(() => RegisterModel.parse({ ...base, role: [] }), /at least 1|too_small/i);
  assert.throws(() => RegisterModel.parse({ ...base, role: ["designer"] }), /invalid/i, "designer is not a training role");
  assert.throws(() => RegisterModel.parse({ ...base, orgId: "org-other" }), /unrecognized key/i);
});

test("agents default to the Modal surface when it is configured; explicit Meta still wins", async () => {
  const { baseModelFor } = await import("../dist/learning/models.js");
  const { effectiveAgentSurface, MODAL_DEFAULT_MODEL, MODAL_GLIMMER_MODEL, modalBaseUrlForModel, MODAL_GLIMMER_API_BASE } = await import("../dist/lib/model.js");
  const modalEnv = { MODAL_PROXY_TOKEN_ID: "id", MODAL_PROXY_TOKEN_SECRET: "secret", META_API_KEY: "k" };
  assert.deepEqual(baseModelFor("red", modalEnv), { provider: "meta-modal", modelId: MODAL_DEFAULT_MODEL },
    "with Modal configured, the agent base model is the Modal-hosted Muse Spark");
  assert.deepEqual(baseModelFor("blue", { ...modalEnv, MODAL_MODEL_ID: "meta-models/Muse-Spark-Open-816B-A42B" }),
    { provider: "meta-modal", modelId: "meta-models/Muse-Spark-Open-816B-A42B" });
  assert.deepEqual(baseModelFor("persona", modalEnv), { provider: "meta-modal", modelId: MODAL_GLIMMER_MODEL },
    "small, high-volume persona agents default to Muse Glimmer on Modal");
  assert.deepEqual(baseModelFor("persona", { ...modalEnv, MODAL_GLIMMER_MODEL_ID: "meta-models/Muse-Glimmer-30B" }),
    { provider: "meta-modal", modelId: MODAL_GLIMMER_MODEL },
    "the Glimmer repository ID canonicalizes to the endpoint's served model name");
  assert.equal(modalBaseUrlForModel("meta-models/Muse-Glimmer-30B", {}), MODAL_GLIMMER_API_BASE,
    "Glimmer IDs route to ep-glimmer rather than the Spark endpoint");
  assert.equal(baseModelFor("persona", { META_API_KEY: "k" }).modelId, "muse-spark-1.1", "without Modal, personas keep the lighter Meta default");
  assert.equal(baseModelFor("red", { META_API_KEY: "k" }).provider, "meta", "no Modal tokens -> Meta base");
  assert.equal(baseModelFor("red", { META_API_KEY: "k" }).modelId, modelForRole("red", {}));
  assert.deepEqual(baseModelFor("red", modalEnv, "meta"), { provider: "meta", modelId: modelForRole("red", {}) },
    "an explicit Meta surface overrides the Modal default");
  assert.deepEqual(baseModelFor("persona", { META_API_KEY: "k" }, "meta-modal"), { provider: "meta-modal", modelId: MODAL_GLIMMER_MODEL },
    "an explicit Modal surface chooses Glimmer for personas even before client construction validates tokens");
  assert.throws(() => baseModelFor("red", { ...modalEnv, MODAL_MODEL_ID: "meta-models/Some-Other" }), /Muse Spark|Muse Glimmer/,
    "an unverified Modal model id fails closed");
  assert.equal(effectiveAgentSurface(undefined, modalEnv), "meta-modal", "unset surface defaults to Modal when configured");
  assert.equal(effectiveAgentSurface("meta", modalEnv), "meta", "an explicit Meta selection is never silently substituted");
  assert.equal(effectiveAgentSurface("meta-modal", { META_API_KEY: "k" }), "meta-modal", "an explicit Modal selection stands (construction fails loud if unconfigured)");
  assert.equal(effectiveAgentSurface(undefined, { META_API_KEY: "k" }), "meta");
  assert.equal(effectiveAgentSurface(undefined, { MODAL_PROXY_TOKEN_ID: "id" }), "meta-modal", "a half-set Modal pair surfaces as Modal so construction fails loud, not a silent Meta fallback");
});

test("registry: a pinned Modal Muse Spark Open ID resolves to a Modal agent client; Meta IDs stay on Meta", async () => {
  const { resolveModel } = await import("../dist/learning/models.js");
  const { ModalModelClient, MetaModelClient } = await import("../dist/lib/model.js");
  const env = { MODAL_PROXY_TOKEN_ID: process.env.MODAL_PROXY_TOKEN_ID, MODAL_PROXY_TOKEN_SECRET: process.env.MODAL_PROXY_TOKEN_SECRET, META_API_KEY: process.env.META_API_KEY, MODAL_BASE_URL: process.env.MODAL_BASE_URL, MODAL_GLIMMER_BASE_URL: process.env.MODAL_GLIMMER_BASE_URL };
  Object.assign(process.env, { MODAL_PROXY_TOKEN_ID: "id", MODAL_PROXY_TOKEN_SECRET: "secret", META_API_KEY: "k", MODAL_BASE_URL: "https://example--ep-muse-spark-open-server.example/v1", MODAL_GLIMMER_BASE_URL: "https://example--ep-glimmer-server.example/v1" });
  try {
    const modal = await resolveModel("red", "org", "meta-models/Muse-Spark-Open-816B-A42B");
    assert.ok(modal instanceof ModalModelClient);
    assert.equal(typeof modal.generateTurn, "function");
    assert.ok(await resolveModel("blue", "org", "muse-spark-1.3") instanceof MetaModelClient);
    const glimmer = await resolveModel("persona", "org", "meta-models/Muse-Glimmer-30B");
    assert.ok(glimmer instanceof ModalModelClient);
    assert.equal(glimmer.modelId, "glimmer", "the Glimmer repository ID uses ep-glimmer's served model name");
    assert.match(glimmer.baseUrl, /ep-glimmer-server/, "Glimmer resolves to its own Modal endpoint, not Spark");
    await assert.rejects(resolveModel("persona", "org", "glimmer", { surface: "meta" }), /surface|Meta/i,
      "an explicit Meta surface rejects a Modal pin instead of substituting it");
    await assert.rejects(resolveModel("red", "org", "meta-models/Some-Other"), /Muse Spark Open|Muse Glimmer/);
  } finally {
    for (const [k, v] of Object.entries(env)) if (v === undefined) delete process.env[k]; else process.env[k] = v;
  }
});

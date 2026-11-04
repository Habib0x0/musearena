import test from "node:test";
import assert from "node:assert/strict";
import { CaptureTrace } from "@musearena/shared";

import { EventStore } from "../dist/observability/events.js";
import { ingest } from "../dist/observability/collector.js";
import { LocalTrajectoryRecorder } from "../dist/observability/trajectory.js";
import { exportDataset } from "../dist/observability/export.js";
import { assertNoProofRows } from "../dist/traces/integrity.js";
import { captureRow } from "../dist/api/traces.js";
import { roeCheck, checkProposal } from "../dist/exercise/agents.js";
import { scoreExercise } from "../dist/exercise/evaluator.js";
import { computeRubric } from "../dist/evaluator/rubric.js";
import { DetectionStore } from "../dist/detections/sigma.js";
import { deployability } from "../dist/provisioner/capability.js";
import { clinicOrgSpec } from "../dist/designer/clinic.js";

const T0 = Date.parse("2026-01-01T00:00:00.000Z");
const iso = (ms) => new Date(T0 + ms).toISOString();

function run() {
  return {
    runId: "run-conformance", orgId: "org-1", deploymentId: "dep-1", mode: "blind",
    specDigest: "sha256:x", techniquePackVersion: "attack-15.1", modelIds: {},
    truthLayer: "mirror-only", backend: "kvm",
  };
}

function spec() {
  return {
    version: 1, name: "conformance", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.2.0.0/16", subnets: [], firewallRules: [] },
    instances: [
      { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: ["http"], databases: [] },
      { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: ["db"], databases: ["app"] },
    ],
    personas: [], requiredTelemetry: ["auditd"], plantedVulns: [],
    objectives: [
      { id: "o-db", asset: "db-01", techniqueId: "T1110", successSignal: "auth-failures", points: 10 },
      { id: "o-web", asset: "web-01", techniqueId: "T1110", successSignal: "auth-failures", points: 10 },
    ],
    budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
  };
}

function joinedStep(hostId, actor, outcome, at, detail = {}) {
  return {
    at, hostId, techniqueId: "T1110", matched: true,
    groundTruth: { runId: "run-conformance", hostId, kind: "auth", actor, techniqueId: "T1110", outcome, at, detail },
  };
}

test("conformance: dataset export deep-redacts every field and excludes platform rows", () => {
  const store = EventStore.fresh();
  const r = run();
  new LocalTrajectoryRecorder(store).record({
    runId: r.runId, hostId: "db-01", actor: "red",
    observation: "token=obs-secret-value", reasoning: "api_key: reasoning-secret-value",
    toolCall: "PGPASSWORD=tool-secret-value psql", action: "curl token=action-secret-value",
    techniqueId: "T1078", at: iso(60_000),
    detail: { argv: ["sh", "-c", "echo MUSE-PROOF-abcdef0123456789"], credential: "detail-secret-value" },
  });
  ingest({
    runId: r.runId, hostId: "db-01", kind: "db", actor: "red", techniqueId: "T1078",
    outcome: "succeeded", at: iso(60_500),
    detail: { objectiveId: "o-db", credential: "gt-secret-value", line: "returned MUSE-PROOF-0123456789abcdef" },
  }, { store });
  ingest({ runId: r.runId, hostId: "web-01", kind: "platform", actor: "platform", at: iso(61_000), detail: {} }, { store });

  const exp = exportDataset(r, "train", { store });
  const json = JSON.stringify(exp);
  for (const secret of ["obs-secret-value", "reasoning-secret-value", "tool-secret-value", "action-secret-value", "detail-secret-value", "gt-secret-value", "MUSE-PROOF-abcdef0123456789", "MUSE-PROOF-0123456789abcdef"]) {
    assert.ok(!json.includes(secret), `export leaked ${secret}`);
  }
  assert.equal(assertNoProofRows(exp), true);
  assert.ok(exp.join.steps.every((s) => s.groundTruth?.actor !== "platform"), "platform rows are excluded from training exports");
});

test("conformance: capture rows deep-redact and preserve the caller-pinned split", () => {
  const parsed = CaptureTrace.parse({
    runId: "run-capture", stepIndex: 0, at: iso(0), hostId: "db-01", actor: "red", split: "test",
    observation: "PGPASSWORD=capture-secret-value", action: "token=capture-action-secret",
    toolCall: "sk-live-capture-tool-secret", detail: { nested: { apiKey: "capture-detail-secret" } },
  });
  const row = captureRow(parsed, "org-1");
  assert.equal(row.split, "test");
  const json = JSON.stringify(row);
  for (const secret of ["capture-secret-value", "capture-action-secret", "sk-live-capture-tool-secret", "capture-detail-secret"]) {
    assert.ok(!json.includes(secret), `capture row leaked ${secret}`);
  }
});

test("conformance: ROE blocks shell, absolute-path, URI and external-target bypasses", () => {
  const s = spec();
  assert.notEqual(roeCheck(["sh", "-c", "docker ps"], s), null);
  assert.notEqual(roeCheck(["/usr/bin/docker", "ps"], s), null);
  assert.notEqual(roeCheck(["curl", "http://203.0.113.9/x"], s), null);
  assert.notEqual(roeCheck(["psql", "postgresql://u@evil-host/app"], s), null);
  assert.equal(roeCheck(["psql", "-h", "db-01", "-U", "app", "-d", "app"], s), null);
});

test("conformance: blue proposals reject localhost blocks and missing why", () => {
  const shown = new Map([
    ["E1", { id: "E1", hostId: "db-01", src: "localhost", count: 1, line: "" }],
    ["E2", { id: "E2", hostId: "db-01", src: "10.0.0.9", count: 1, line: "" }],
  ]);
  const ctx = { hosts: ["db-01", "web-01"], shown };
  assert.equal(checkProposal({ hostId: "db-01", techniqueId: "T1110", response: "block IP", ip: "localhost", evidence: ["E1"], why: "local" }, ctx).reject?.kind, "ip");
  assert.equal(checkProposal({ hostId: "db-01", techniqueId: "T1110", response: "block IP", ip: "10.0.0.9", evidence: ["E2"], why: "" }, ctx).reject?.kind, "schema");
});

test("conformance: scoring is host-scoped for MTTD, exact coverage and false positives", () => {
  const join = {
    runId: "run-conformance", matched: 2, trajectoryOnly: 0, groundTruthOnly: 0, dropped: 0,
    steps: [
      joinedStep("db-01", "red", "succeeded", iso(60_000), { objectiveId: "o-db" }),
      joinedStep("web-01", "blue", "detected", iso(660_000), {}),
    ],
  };
  const oneObjective = { ...spec(), objectives: [spec().objectives[0]] };
  const score = scoreExercise(oneObjective, join);
  assert.equal(score.objectivesAchieved, 1);
  assert.equal(score.exactTechniqueCoverage, 0, "a same-technique detection on another host is not exact coverage");
  assert.equal(score.mttdMinutesP50, undefined, "no MTTD is fabricated across hosts");

  const rubric = computeRubric(oneObjective, join, run());
  assert.equal(rubric.falsePositiveRate, 1, "the wrong-host detection is a false positive");
  assert.equal(rubric.mttdMinutesP50, undefined);
});

test("conformance: Sigma promotion requires replay evidence for the rule technique", () => {
  const store = new DetectionStore();
  store.add({ id: "sig-conformance", version: 1, title: "brute force", techniqueId: "T1110", field: "signal", contains: "x", status: "draft" });
  const wrongTechnique = [{ runId: "seed", hostId: "db-01", kind: "auth", actor: "red", techniqueId: "T1078", outcome: "succeeded", at: iso(0), detail: { signal: "x" } }];
  assert.throws(() => store.promote("sig-conformance", 1, wrongTechnique), /technique|no alerts/i);
});

test("conformance: platform/provider/FreeIPA/vuln/objective gates fail closed before provisioning", () => {
  const caps = { vmRuns: true, container: true, accel: "kvm", maxVmInstances: 8 };
  const reasons = (s) => deployability(s, { caps }).join(" | ");

  const aws = clinicOrgSpec();
  aws.provider = "aws";
  assert.match(reasons(aws), /provider.*kvm|aws.*not.*local|only.*kvm/i);

  const mixed = clinicOrgSpec();
  delete mixed.platform;
  mixed.instances = mixed.instances.map((i, idx) => idx === 0 ? { ...i, runtime: "container", serviceDecls: [] } : i);
  assert.match(reasons(mixed), /mixed.*runtime|platform.*required|one runtime/i);

  const rocky8 = clinicOrgSpec();
  rocky8.instances = rocky8.instances.map((i) => i.hostId === "dc-01"
    ? { ...i, role: "web", os: "Rocky Linux 8", resources: { vcpu: 2, memoryMb: 4096, diskGb: 20 }, serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }] }
    : i);
  assert.match(reasons(rocky8), /Rocky Linux 9/);
  assert.match(reasons(rocky8), /role "dc"|role.*dc/i);

  const noDbDecl = clinicOrgSpec();
  noDbDecl.instances = noDbDecl.instances.map((i) => i.hostId === "db-01" ? { ...i, services: [], serviceDecls: [] } : i);
  assert.match(reasons(noDbDecl), /weak-cred.*db service|declaring db/i);

  const wrongObjectiveRole = clinicOrgSpec();
  wrongObjectiveRole.instances = wrongObjectiveRole.instances.map((i) => i.hostId === "web-01"
    ? { ...i, services: ["http", "db"], serviceDecls: [...i.serviceDecls, { kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }] }
    : i);
  wrongObjectiveRole.objectives = wrongObjectiveRole.objectives.map((o) => o.id === "o2" ? { ...o, asset: "web-01" } : o);
  assert.match(reasons(wrongObjectiveRole), /T1078.*role "db"|objective.*db/i);
});

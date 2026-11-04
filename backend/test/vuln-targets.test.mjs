import test from "node:test";
import assert from "node:assert/strict";
import { bindStep, VULN_TARGETS, vulnTargetFor } from "../dist/configurator/vuln-targets.js";
import { parseSigmaYaml, replay } from "../dist/detections/sigma.js";
import { EventStore } from "../dist/observability/events.js";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

const vuln = (over = {}) => ({
  id: "cve-web-php-diag-rce", type: "cve", techniqueId: "T1059",
  targetHostId: "web-01", pinnedVersion: "diag-1.0", proofAtomicGuid: "g1", difficulty: "standard",
  ...over,
});

test("registry: the CVE target resolves by id and by pinnedVersion", () => {
  const byId = vulnTargetFor(vuln());
  assert.ok(byId, "resolves by PlantedVuln.id");
  assert.equal(byId?.cveId, "CLASS-PHP-PARAM-RCE");
  const byPin = vulnTargetFor(vuln({ id: "designer-minted-id" }));
  assert.ok(byPin, "resolves by pinnedVersion when the designer mints its own id");
  assert.equal(byPin?.id, "cve-web-php-diag-rce");
});

test("registry: unknown CVE targets do not resolve (fail closed upstream)", () => {
  assert.equal(vulnTargetFor(vuln({ id: "cve-not-in-registry", pinnedVersion: "unknown-9.9" })), undefined);
});

test("registry: the exploit binds the proof marker into the payload", () => {
  const target = VULN_TARGETS[0];
  const step = target.exploitSteps[0];
  const bound = bindStep(step, "127.0.0.1", "arena-proof-g1-abcd1234");
  assert.ok(bound.includes("127.0.0.1"), "host bound");
  assert.ok(bound.includes("arena-proof-g1-abcd1234"), "marker bound");
});

test("sigma: the CVE rule loads and matches the exploit request telemetry", async () => {
  const yaml = await readFile(path.join(ROOT, "detections", "cve_web_php_diag_rce.yml"), "utf8");
  const rule = parseSigmaYaml(yaml);
  assert.equal(rule.id, "cve-web-php-diag-rce");
  assert.equal(rule.techniqueId, "T1059");

  const store = EventStore.fresh();
  store.appendGroundTruth({
    runId: "run-1", hostId: "web-01", kind: "apache-access", actor: "red",
    techniqueId: "T1059", stepId: "s1", at: "2026-01-01T00:00:00Z",
    detail: { message: 'GET /diag.php?host=x%3Becho+arena-proof-g1-ab 1>&2 HTTP/1.1' },
  });
  const alerts = replay(rule, store.groundTruth("run-1"));
  assert.equal(alerts.length, 1, "the injection request raises the alert");
  assert.equal(alerts[0].ruleId, "cve-web-php-diag-rce");
  assert.equal(alerts[0].techniqueId, "T1059");
});

test("sigma: the CVE rule matches the executed-command telemetry, not only the request", async () => {
  const yaml = await readFile(path.join(ROOT, "detections", "cve_web_php_diag_rce.yml"), "utf8");
  const rule = parseSigmaYaml(yaml);
  const store = EventStore.fresh();
  store.appendGroundTruth({
    runId: "run-1", hostId: "web-01", kind: "apache-error", actor: "red",
    at: "2026-01-01T00:00:01Z",
    detail: { message: "arena-proof-g1-abcd1234" },
  });
  const alerts = replay(rule, store.groundTruth("run-1"));
  assert.equal(alerts.length, 1, "the shell output in the service log raises the alert");
});

test("sigma: benign diag.php use without metacharacters does not alert on execution", async () => {
  const yaml = await readFile(path.join(ROOT, "detections", "cve_web_php_diag_rce.yml"), "utf8");
  const rule = parseSigmaYaml(yaml);
  const store = EventStore.fresh();
  store.appendGroundTruth({
    runId: "run-1", hostId: "web-01", kind: "apache-access", actor: "persona",
    at: "2026-01-01T00:00:02Z",
    detail: { message: "GET /diag.php?host=intranet.local HTTP/1.1" },
  });
  const alerts = replay(rule, store.groundTruth("run-1"));
  assert.equal(alerts.length, 0, "a plain hostname lookup is not an alert");
});

test("plantable: the web role accepts the cve type on the docker runtime surface", async () => {
  const { PLANTABLE } = await import("../dist/provisioner/roles.js");
  assert.ok(PLANTABLE.web.includes("cve"), "web accepts cve");
  assert.ok(!PLANTABLE.db.includes("cve"), "db does not");
});

test("registry: CVE-2018-9205 target exists with a multi-step upload→execute exploit", () => {
  const t = vulnTargetFor({ id: "cve-2018-9205-jquery-file-upload", pinnedVersion: "" });
  assert.ok(t, "resolves by registry id");
  assert.equal(t.cveId, "CVE-2018-9205");
  assert.equal(t.techniqueId, "T1190");
  assert.ok(t.files.some((f) => f.path.endsWith("upload.php")), "plants the vulnerable upload endpoint");
  assert.ok(t.exploitSteps.length >= 3, "exploit is multi-step (create → upload → execute)");
  const byPin = vulnTargetFor({ id: "designer-x", pinnedVersion: "upload-9.22.0" });
  assert.equal(byPin?.id, t.id, "resolves by pinnedVersion too");
});

test("sigma: CVE-2018-9205 alerts on the upload and on the webshell execution", async () => {
  const yaml = await readFile(path.join(ROOT, "detections", "cve_2018_9205_upload.yml"), "utf8");
  const rule = parseSigmaYaml(yaml);
  assert.equal(rule.id, "cve-2018-9205-jquery-file-upload");
  assert.equal(rule.techniqueId, "T1190");

  const store = EventStore.fresh();
  store.appendGroundTruth({
    runId: "run-1", hostId: "web-01", kind: "apache-access", actor: "red",
    techniqueId: "T1190", stepId: "s1", at: "2026-01-01T00:00:00Z",
    detail: { message: "POST /upload.php HTTP/1.1" },
  });
  store.appendGroundTruth({
    runId: "run-1", hostId: "web-01", kind: "apache-access", actor: "red",
    at: "2026-01-01T00:00:02Z",
    detail: { message: "GET /uploads/x.php HTTP/1.1" },
  });
  const alerts = replay(rule, store.groundTruth("run-1"));
  assert.equal(alerts.length, 2, "both the upload POST and the uploads/*.php GET raise");

  const benign = EventStore.fresh();
  benign.appendGroundTruth({
    runId: "run-1", hostId: "web-01", kind: "apache-access", actor: "persona",
    at: "2026-01-01T00:00:03Z",
    detail: { message: "GET /index.php HTTP/1.1" },
  });
  benign.appendGroundTruth({
    runId: "run-1", hostId: "web-01", kind: "apache-access", actor: "persona",
    at: "2026-01-01T00:00:04Z",
    detail: { message: "POST /login.php HTTP/1.1" },
  });
  assert.equal(replay(rule, benign.groundTruth("run-1")).length, 0, "normal intranet use does not alert");
});

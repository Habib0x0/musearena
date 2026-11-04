import { test } from "node:test";
import assert from "node:assert/strict";
import { parseSigmaYaml, compileRule, DetectionStore, loadSigmaDir } from "../dist/detections/sigma.js";
import { parseLine } from "../dist/observability/docker-telemetry.js";
import { livePack, promoteAgainst } from "../dist/exercise/live.js";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

const ev = (kind, detail, extra = {}) => ({ runId: "r", hostId: "db-01", kind, actor: "noise", at: "2026-01-01T00:00:00.000Z", detail, ...extra });

const RULE = `
title: t
id: abc
tags: [attack.t1078]
level: high
detection:
  selection:
    kind: auth.logon
    user: app
  filter_local:
    src: ['127.0.0.1', '[local]']
  condition: selection and not filter_local
`;

test("SigmaHQ YAML compiles: selections, list OR, modifiers, and/not, 1 of", () => {
  const r = parseSigmaYaml(RULE);
  assert.equal(r.techniqueId, "T1078");
  const m = compileRule(r);
  assert.equal(m(ev("auth.logon", { user: "app", src: "10.0.0.5" })), true);
  assert.equal(m(ev("auth.logon", { user: "app", src: "[local]" })), false);
  assert.equal(m(ev("auth.logon", { user: "bob", src: "10.0.0.5" })), false);
  const r2 = parseSigmaYaml(`id: x\ntags: [attack.t1059]\ndetection:\n  a:\n    path|contains: ['%3B', '%7C']\n  b:\n    kind: process.stderr\n  condition: 1 of a* or b\n`);
  const m2 = compileRule(r2);
  assert.equal(m2(ev("http.request", { path: "/diag.php?host=x%3Bid" })), true);
  assert.equal(m2(ev("process.stderr", {})), true);
  assert.equal(m2(ev("http.request", { path: "/" })), false);
});

test("unsupported Sigma constructs fail at load, never silently match", () => {
  assert.throws(() => parseSigmaYaml(`id: x\ntags: [attack.t1059]\ndetection:\n  a:\n    path|re: '.*'\n  condition: a\n`), /unsupported Sigma modifier/);
  assert.throws(() => parseSigmaYaml(`id: x\ntags: [attack.t1059]\ndetection:\n  a: {kind: x}\n  condition: a and missing\n`), /unknown selection/);
  assert.throws(() => parseSigmaYaml(`id: x\ndetection:\n  a: {kind: x}\n  condition: a\n`), /attack.tNNNN/);
});

test("edited rule body is a new version; same id+version with different body is refused", () => {
  const a = parseSigmaYaml(RULE);
  const b = parseSigmaYaml(RULE.replace("user: app", "user: admin"));
  assert.notEqual(a.version, b.version);
  const store = new DetectionStore();
  store.add(a);
  assert.throws(() => store.add({ ...b, version: a.version }), /immutable/);
});

test("collector parses real Apache and Postgres lines", () => {
  const web = parseLine("web-01", "web", { at: "2026-01-01T00:00:00Z", text: '10.2.32.3 - - [27/Oct/2026:06:29:39 +0000] "GET /diag.php?host=x%3Bid HTTP/1.1" 200 47 "-" "Wget"' });
  assert.deepEqual([web.kind, web.src, web.detail.path], ["http.request", "10.2.32.3", "/diag.php?host=x%3Bid"]);
  assert.equal(parseLine("web-01", "web", { at: "x", text: "[Tue Oct 27] [core:notice] AH00094: Command line" }), null);
  assert.equal(parseLine("web-01", "web", { at: "x", text: "uid=33(www-data)" }).kind, "process.stderr");
  const pg = parseLine("db-01", "db", { at: "x", text: "2026-10-27 07:00:02.284 UTC [67] user=app db=app client=10.2.32.3 LOG:  statement: SELECT value FROM secrets" });
  assert.deepEqual([pg.kind, pg.src, pg.user, pg.detail.statement], ["db.statement", "10.2.32.3", "app", "SELECT value FROM secrets"]);
  const fail = parseLine("db-01", "db", { at: "x", text: '2026-10-27 16:23:01.100 UTC [80] user=app db=app client=10.2.32.5 FATAL:  password authentication failed for user "app"' });
  assert.deepEqual([fail.kind, fail.src, fail.user], ["auth.failure", "10.2.32.5", "app"]);
});

test("checked-in pack: promotion needs replay hits; zero FPs on benign calibration traffic", async () => {
  const rules = await loadSigmaDir(new URL("../detections", import.meta.url).pathname);
  assert.ok(rules.length >= 4);
  // Mirror livePack(): every replay corpus in the directory, not just v1.
  const replayDir = new URL("../detections/replay/", import.meta.url).pathname;
  const replayEvents = readdirSync(replayDir).filter((f) => f.endsWith(".jsonl"))
    .flatMap((f) => readFileSync(path.join(replayDir, f), "utf8").trim().split("\n").filter(Boolean).map(JSON.parse));
  const { store, promoted, draft } = promoteAgainst(rules, replayEvents);
  assert.ok(promoted.length >= 3);
  assert.ok(draft.length >= 1, "a rule with no replay evidence must stay draft");
  assert.equal(store.liveAlerts(replayEvents.filter((e) => e.actor !== "red")).length, 0);
  assert.ok(store.liveAlerts(replayEvents.filter((e) => e.actor === "red")).length >= 3);
  const pack = await livePack(new URL("../detections", import.meta.url).pathname);
  assert.deepEqual(pack.promoted.sort(), promoted.sort());
  assert.ok(pack.store.liveAlerts(replayEvents).every((a) => a.confidence > 0 && a.ruleVersion > 0));
});

test("live exercise writes red, blue detection and containment into the RUN's store (not the global one)", async () => {
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { runLiveExercise, livePack } = await import("../dist/exercise/live.js");
  const { EventStore, localStore } = await import("../dist/observability/events.js");
  const { canaryValue } = await import("../dist/configurator/ansible.js");
  const runId = "run-abcdef12-0000";
  const dir = mkdtempSync(`${tmpdir()}/fd-`);
  const state = `${dir}/state.json`;
  writeFileSync(state, JSON.stringify({ clock: Date.now() + 60_000, logs: {}, web: "ma-abcdef12-web-01", db: "ma-abcdef12-db-01", canary: canaryValue(runId, "o1") }));
  process.env.FAKE_DOCKER_STATE = state;
  const spec = {
    version: 1, name: "t", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.9.0.0/16", subnets: [], firewallRules: [] },
    instances: [
      { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu", stack: [], services: ["http"], databases: [] },
      { hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: [], databases: [] },
    ],
    personas: [{ id: "p1", role: "clerk", workstation: "web-01", access: [], credentialsProfile: "x", riskProfile: "low", routine: "", relationships: [] }],
    objectives: [
      { id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10 },
      { id: "o2", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 5 },
    ],
    requiredTelemetry: ["x"], plantedVulns: [], budgets: { maxInstances: 4, maxDollarsPerHour: 1, ttlHours: 1 },
  };
  const run = { runId, orgId: "o", deploymentId: "d", mode: "blind", specDigest: "x", techniquePackVersion: "attack-15.1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm" };
  const before = localStore.counts().groundTruth;
  const store = new EventStore();
  const pack = await livePack(new URL("../detections", import.meta.url).pathname);
  const res = await runLiveExercise({ spec, run }, { store, detections: pack.store, langfuse: null, docker: new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname });
  assert.equal(localStore.counts().groundTruth, before, "live exercise leaked events into the global store");
  const gt = store.groundTruth(runId);
  assert.ok(gt.some((e) => e.actor === "blue" && e.outcome === "detected"));
  assert.ok(gt.some((e) => e.actor === "blue" && e.outcome === "contained" && e.detail.enforced === true));
  assert.equal(res.scorecard.objectivesAchieved, 2);
  assert.equal(res.scorecard.containmentCorrectness, 1);
  assert.equal(res.falsePositives, 0);
  assert.ok(res.benignEvents >= 2);
});

test("Navigator tactics come from the pinned STIX bundle (all tactics, no guessing)", async () => {
  const { tacticsForTechnique, attackIndex, navigatorLayer } = await import("../dist/evaluator/rubric.js");
  assert.deepEqual(tacticsForTechnique("T1078").sort(), ["defense-evasion", "initial-access", "persistence", "privilege-escalation"]);
  assert.deepEqual(tacticsForTechnique("T1059"), ["execution"]);
  assert.throws(() => tacticsForTechnique("T9999"), /not in ATT&CK/);
  assert.throws(() => attackIndex("attack-0.1"), /not pinned/);
  assert.match(attackIndex("attack-15.1").bundleSha256, /^[0-9a-f]{64}$/);
  const spec = { objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "s", points: 1 }] };
  const run = { runId: "r", mode: "blind", backend: "kvm", truthLayer: "mirror-only", techniquePackVersion: "attack-15.1" };
  const layer = navigatorLayer(spec, run, { steps: [] });
  assert.equal(layer.techniques.length, 4, "one Navigator cell per tactic");
  assert.equal(layer.versions.attack, "15.1");
  assert.match(layer.techniques[0].comment, /^Valid Accounts/);
});

test("benign-only control run: red never acts; FP baseline over persona traffic", async () => {
  const { writeFileSync, mkdtempSync, readFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { runLiveExercise, livePack } = await import("../dist/exercise/live.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const runId = "run-c0c0c0c0-0000";
  const dir = mkdtempSync(`${tmpdir()}/fd-`);
  const state = `${dir}/state.json`;
  writeFileSync(state, JSON.stringify({ clock: Date.now() + 60_000, logs: {}, web: "ma-c0c0c0c0-web-01", db: "ma-c0c0c0c0-db-01", canary: "x" }));
  process.env.FAKE_DOCKER_STATE = state;
  const spec = {
    version: 1, name: "t", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.9.0.0/16", subnets: [], firewallRules: [] },
    instances: [
      { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu", stack: [], services: ["http"], databases: [] },
      { hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: [], databases: [] },
    ],
    personas: [{ id: "p1", role: "clerk", workstation: "web-01", access: [], credentialsProfile: "x", riskProfile: "low", routine: "", relationships: [] }],
    objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10 }],
    requiredTelemetry: ["x"], plantedVulns: [], budgets: { maxInstances: 4, maxDollarsPerHour: 1, ttlHours: 1 },
  };
  const run = { runId, orgId: "o", deploymentId: "d", mode: "blind", specDigest: "x", techniquePackVersion: "attack-15.1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm" };
  const pack = await livePack(new URL("../detections", import.meta.url).pathname);
  const res = await runLiveExercise({ spec, run }, { store: new EventStore(), detections: pack.store, langfuse: null, control: true, noiseRounds: 5, docker: new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname });
  assert.equal(res.redSteps, 0);
  assert.equal(res.scorecard.objectivesAchieved, 0);
  assert.ok(res.benignEvents >= 10, `benign events ${res.benignEvents}`);
  assert.equal(res.falsePositives, 0);
  const st = JSON.parse(readFileSync(state, "utf8"));
  assert.ok(!st.disconnected, "blue must not respond when nothing fired");
});

test("canary with sensor switched off fails even when an earlier canary line is in the log", async () => {
  const { writeFileSync, readFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { sensorCanary } = await import("../dist/configurator/gates.js");
  const { dockerGateOptions } = await import("../dist/configurator/docker-executors.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const runId = "run-5e5e5e5e-0000";
  const state = `${mkdtempSync(`${tmpdir()}/fd-`)}/state.json`;
  writeFileSync(state, JSON.stringify({ clock: Date.now(), logs: {}, web: "ma-5e5e5e5e-web-01", db: "ma-5e5e5e5e-db-01", canary: "x" }));
  process.env.FAKE_DOCKER_STATE = state;
  const spec = { instances: [{ hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: [], databases: [] }], plantedVulns: [] };
  const docker = new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname;
  const on = await sensorCanary(runId, "db-01", dockerGateOptions(spec, { store: new EventStore(), docker, settleMs: 1 }));
  assert.equal(on.pass, true);
  const st = JSON.parse(readFileSync(state, "utf8")); st.sensorOff = true; writeFileSync(state, JSON.stringify(st));
  const off = await sensorCanary(runId, "db-01", dockerGateOptions(spec, { store: new EventStore(), docker, settleMs: 1 }));
  assert.equal(off.pass, false, "stale canary line from before the sensor went off satisfied the gate");
});

test("agent red: ROE refuses boundary tools and unknown hosts; success only on the planted proof; caps stop runaways", async () => {
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { redObjective, roeCheck } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const spec = { instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu", stack: [], services: ["http"], databases: [] },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: ["postgres"], databases: ["app"] },
  ], personas: [], plantedVulns: [] };
  assert.notEqual(roeCheck(["docker", "ps"], spec), null);
  assert.notEqual(roeCheck(["psql", "-h", "host.docker.internal"], spec), null);
  assert.notEqual(roeCheck(["sh", "-c", "wget -qO- http://169.254.169.254/"], spec), null);
  assert.notEqual(roeCheck(["psql", "-h", "other-host"], spec), null);
  assert.equal(roeCheck(["sh", "-c", "id"], spec), null);
  assert.equal(roeCheck(["psql", "-h", "db-01", "-U", "app"], spec), null);
  const runId = "run-abcdef12-0000";
  const proof = "MUSE-PROOF-0123456789abcdef01234567";
  const state = `${mkdtempSync(`${tmpdir()}/fd-`)}/state.json`;
  writeFileSync(state, JSON.stringify({ clock: Date.now() + 60_000, logs: {}, web: "ma-abcdef12-web-01", db: "ma-abcdef12-db-01", canary: proof }));
  process.env.FAKE_DOCKER_STATE = state;
  const docker = new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname;
  const objective = { id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 1 };
  const caps = { maxSteps: 6, maxInputTokens: 10000, maxOutputTokens: 1000, maxWallMinutes: 1 };
  const turn = (calls, text = "") => ({ text, toolCalls: calls.map((c) => ({ callId: c[0], name: "exec", argumentsJson: JSON.stringify({ argv: c[1], reason: c[2] ?? "" }) })), usage: { inputTokens: 100, outputTokens: 10 } });
  const recorder = new LocalTrajectoryRecorder(new EventStore());
  const steal = ["psql", "-h", "db-01", "-U", "app", "-d", "app", "-tAc", "SELECT value FROM secrets WHERE objective_id='o1'"];

  const ok = await redObjective(new ScriptedAgentClient([turn([["c1", steal, "go"]])]), { spec, runId, objective, proof, caps, recorder, docker });
  assert.equal(ok.retrieved, true);
  assert.equal(ok.attempts.length, 1);
  assert.deepEqual([ok.state.steps, ok.state.inputTokens, ok.state.outputTokens], [1, 100, 10]);

  // Self-report is worthless: the model claims the proof in text, never retrieves it.
  const liar = await redObjective(new ScriptedAgentClient([turn([], `Done. The secret is ${proof}`)]), { spec, runId, objective, proof, caps, recorder, docker });
  assert.equal(liar.retrieved, false);
  // ROE-refused calls never reach docker and never count.
  const refused = await redObjective(new ScriptedAgentClient([turn([["c1", ["docker", "exec", "ma-abcdef12-db-01", "cat", "/x"]]]), turn([])]), { spec, runId, objective, proof, caps, recorder, docker });
  assert.equal(refused.retrieved, false);
  assert.equal(refused.attempts.length, 0);
  // Without a planted proof the objective is unachievable, whatever comes back.
  const noProof = await redObjective(new ScriptedAgentClient([turn([["c1", steal]]), turn([])]), { spec, runId, objective, caps, recorder, docker });
  assert.equal(noProof.retrieved, false);

  const loop = await redObjective(new ScriptedAgentClient(Array.from({ length: 20 }, (_, i) => turn([[`c${i}`, ["whoami"]]]))), { spec, runId, objective, proof, caps: { ...caps, maxSteps: 2 }, recorder, docker });
  assert.equal(loop.retrieved, false);
  assert.equal(loop.state.steps, 2);
  assert.equal(loop.state.stoppedByCap, "maxSteps 2");
  const tokens = await redObjective(new ScriptedAgentClient(Array.from({ length: 20 }, (_, i) => turn([[`c${i}`, ["whoami"]]]))), { spec, runId, objective, proof, caps: { ...caps, maxInputTokens: 250 }, recorder, docker });
  assert.equal(tokens.state.stoppedByCap, "token cap");
  assert.equal(tokens.state.steps, 3);
});

test("agent exercise: blue proposals outside the allowlist are rejected; alerts only when a promoted rule confirms; scores from ground truth", async () => {
  const { writeFileSync, mkdtempSync, readFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { runAgentExercise } = await import("../dist/exercise/agents-live.js");
  const { livePack } = await import("../dist/exercise/live.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const runId = "run-abcdef12-0000";
  const state = `${mkdtempSync(`${tmpdir()}/fd-`)}/state.json`;
  writeFileSync(state, JSON.stringify({ clock: Date.now() + 60_000, logs: {}, web: "ma-abcdef12-web-01", db: "ma-abcdef12-db-01", canary: "stale" }));
  process.env.FAKE_DOCKER_STATE = state;
  const docker = new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname;
  const spec = {
    version: 1, name: "t", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.9.0.0/16", subnets: [], firewallRules: [] },
    instances: [
      { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu", stack: [], services: ["http"], databases: [] },
      { hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: [], databases: [] },
    ],
    personas: [{ id: "p1", role: "clerk", workstation: "web-01", access: [], credentialsProfile: "x", riskProfile: "low", routine: "", relationships: [] }],
    objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10 }],
    requiredTelemetry: ["x"], plantedVulns: [], budgets: { maxInstances: 4, maxDollarsPerHour: 1, ttlHours: 1 },
  };
  const run = { runId, orgId: "o", deploymentId: "d", mode: "blind", specDigest: "x", techniquePackVersion: "attack-15.1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm" };
  const call = (id, name, args) => ({ callId: id, name, argumentsJson: JSON.stringify(args) });
  const t = (toolCalls, text = "") => ({ text, toolCalls, usage: { inputTokens: 50, outputTokens: 5 } });
  const agent = new ScriptedAgentClient([
    // red o1
    t([call("r1", "exec", { argv: ["psql", "-h", "db-01", "-U", "app", "-d", "app", "-tAc", "SELECT value FROM secrets WHERE objective_id='o1'"] })]),
    // blue: page, one invalid response, one off-allowlist host, one valid
    t([call("b1", "fetch_telemetry", {})]),
    t([call("b2", "respond", { hostId: "db-01", techniqueId: "T1078", response: "wipe disk", why: "x" }),
       call("b3", "respond", { hostId: "attacker", techniqueId: "T1078", response: "block IP", why: "x" }),
       call("b4", "respond", { hostId: "db-01", techniqueId: "T1078", response: "block IP", ip: "10.9.0.9", evidence: ["E2", "E3", "E4"], why: "app login from attacker ip" })]),
  ]);
  const pack = await livePack(new URL("../detections", import.meta.url).pathname);
  const store = new EventStore();
  const res = await runAgentExercise({ spec, run }, { store, detections: pack.store, langfuse: null, docker, agent, traceEnabled: false });
  const planted = JSON.parse(readFileSync(state, "utf8"));
  assert.match(planted.canary, /^MUSE-PROOF-[0-9a-f]{24}$/, "a fresh proof was planted before red ran");
  assert.equal(res.scorecard.objectivesAchieved, 1);
  assert.equal(res.alerts.length, 1, "only the allowlisted, rule-confirmed proposal became an alert");
  assert.ok(store.groundTruth(runId).some((e) => e.actor === "blue" && e.outcome === "contained" && e.detail.response === "block IP"));
  assert.ok(planted.disconnected, "block IP was enforced on the runtime");
  assert.equal(res.agentStates["red:o1"].steps, 1);
  assert.equal(res.agentStates.blue.steps, 2, "blue stops once telemetry is exhausted and it has proposed");
  assert.equal(res.falsePositives, 0);
  assert.equal(res.enforcement.target, "attacker", "block IP cut off the container that owns the cited IP");
  assert.equal(res.guardrails.rejected, 2, "off-allowlist response and non-defended host are both refused");
  assert.deepEqual(res.run.modelIds, { red: "scripted-1", blue: "scripted-1" });
});

test("agent blue: a turn with neither a proposal nor \"clean\" is re-prompted once for a verdict, then a valid proposal is kept", async () => {
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { blueInvestigate } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const state = `${mkdtempSync(`${tmpdir()}/fd-`)}/state.json`;
  writeFileSync(state, JSON.stringify({ clock: Date.now(), logs: { "ma-abcdef12-db-01": [{ at: new Date(Date.now() + 1000).toISOString(), text: "x user=app db=app client=10.9.0.9 LOG:  connection authorized: user=app database=app" }] } }));
  process.env.FAKE_DOCKER_STATE = state;
  const spec = { instances: [{ hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: [], databases: [] }], personas: [], plantedVulns: [] };
  const t = (toolCalls, text = "") => ({ text, toolCalls, usage: { inputTokens: 10, outputTokens: 1 } });
  const agent = new ScriptedAgentClient([
    t([], "Submitting containment now."), // announced but never called respond
    t([{ callId: "b1", name: "fetch_telemetry", argumentsJson: "{}" }]),
    t([{ callId: "b2", name: "respond", argumentsJson: JSON.stringify({ hostId: "db-01", techniqueId: "T1078", response: "block IP", ip: "10.9.0.9", evidence: ["E1"], why: "remote app logon" }) }]),
  ]);
  const res = await blueInvestigate(agent, { spec, runId: "run-abcdef12-0000", since: new Date(Date.now() - 1000).toISOString(), caps: { maxSteps: 6, maxInputTokens: 1e4, maxOutputTokens: 1e3, maxWallMinutes: 1 }, recorder: new LocalTrajectoryRecorder(new EventStore()), docker: new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname });
  assert.equal(res.proposals.length, 1);
  assert.equal(res.examined, 1);
  assert.equal(res.state.steps, 3);
});

test("agent blue: an explicit clean verdict ends the investigation without a re-prompt", async () => {
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { blueInvestigate } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const spec = { instances: [{ hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: [], databases: [] }], personas: [], plantedVulns: [] };
  const agent = new ScriptedAgentClient([{ text: "clean", toolCalls: [], usage: { inputTokens: 1, outputTokens: 1 } }]);
  const res = await blueInvestigate(agent, { spec, runId: "run-abcdef12-0000", since: new Date().toISOString(), caps: { maxSteps: 6, maxInputTokens: 1e4, maxOutputTokens: 1e3, maxWallMinutes: 1 }, recorder: new LocalTrajectoryRecorder(new EventStore()), docker: new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname });
  assert.equal(res.state.steps, 1);
  assert.equal(res.proposals.length, 0);
});

test("agent blue: a brute-force burst collapses to one counted row; pages stay under the tool-result cap", async () => {
  const { collapseTelemetry, PAGE_CHARS } = await import("../dist/exercise/agents.js");
  const fail = (i) => ({ hostId: "db-01", ev: { hostId: "db-01", at: `2026-10-27T16:00:${String(i).padStart(2, "0")}Z`, kind: "auth.failure", src: "10.2.32.5", user: "app", detail: { db: "app", reason: 'password authentication failed for user "app"' } } });
  const rows = collapseTelemetry([...Array.from({ length: 50 }, (_, i) => fail(i)), { hostId: "db-01", ev: { hostId: "db-01", at: "2026-10-27T16:01:00Z", kind: "auth.logon", src: "10.2.32.5", user: "app", detail: { db: "app" } } }]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].count, 50);
  assert.match(rows[0].line, /^\[E1\] 2026-10-27T16:00:00Z\.\.2026-10-27T16:00:49Z x50 db-01 auth\.failure src=10\.2\.32\.5 user=app/);
  assert.deepEqual([rows[1].id, rows[1].hostId, rows[1].src], ["E2", "db-01", "10.2.32.5"]);
  assert.ok(PAGE_CHARS < 8000);
});

test("agent blue: the last allowed step is reserved for a verdict (respond only), so paging cannot exhaust the budget", async () => {
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { blueInvestigate } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const base = Date.now() + 1000;
  // 400 distinct statements: far more than fits in the pages blue can fetch.
  const logs = { "ma-abcdef12-db-01": Array.from({ length: 400 }, (_, i) => ({ at: new Date(base + i).toISOString(), text: `x user=app db=app client=10.9.0.9 LOG:  statement: SELECT ${i} ${"x".repeat(150)}` })) };
  const state = `${mkdtempSync(`${tmpdir()}/fd-`)}/state.json`;
  writeFileSync(state, JSON.stringify({ clock: Date.now(), logs }));
  process.env.FAKE_DOCKER_STATE = state;
  const spec = { instances: [{ hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: [], databases: [] }], personas: [], plantedVulns: [] };
  const seen = [];
  const agent = {
    modelId: "probe",
    async generateObject() { throw new Error("unused"); },
    async generateTurn({ tools, transcript }) {
      const names = tools.map((t) => t.name);
      seen.push(names);
      for (const item of transcript) if (item.type === "function_call_output") assert.ok(item.output.length <= 8000);
      const call = names.includes("fetch_telemetry")
        ? { callId: `f${seen.length}`, name: "fetch_telemetry", argumentsJson: "{}" }
        : { callId: "r", name: "respond", argumentsJson: JSON.stringify({ hostId: "db-01", techniqueId: "T1078", response: "block IP", ip: "10.9.0.9", evidence: ["E1"], why: "remote statements" }) };
      return { text: "", toolCalls: [call], usage: { inputTokens: 1, outputTokens: 1 } };
    },
  };
  const res = await blueInvestigate(agent, { spec, runId: "run-abcdef12-0000", since: new Date(base - 1000).toISOString(), caps: { maxSteps: 4, maxInputTokens: 1e6, maxOutputTokens: 1e6, maxWallMinutes: 1 }, recorder: new LocalTrajectoryRecorder(new EventStore()), docker: new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname });
  assert.deepEqual(seen.at(-1), ["respond"], "final step offers respond only");
  assert.ok(seen.slice(0, -1).every((n) => n.includes("fetch_telemetry")));
  assert.equal(res.proposals.length, 1);
  assert.equal(res.state.steps, 4);
  assert.ok(res.examined > 40 && res.examined < 400, `examined ${res.examined}`);
});

test("red campaign: orchestrator delegates objectives in its chosen order and adapts from verified outcomes", async () => {
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { runRedCampaign, newGuardrailLog } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const spec = {
    instances: [
      { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["postgresql"], databases: ["app"] },
      { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["http"], databases: [] },
    ],
    objectives: [
      { id: "o-db", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10 },
      { id: "o-web", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 10 },
    ],
    plantedVulns: [{ id: "vuln-web", type: "code-flaw", targetHostId: "web-01", service: "http" }],
    personas: [],
  };
  const call = (id, name, args) => ({ callId: id, name, argumentsJson: JSON.stringify(args) });
  const turn = (toolCalls) => ({ text: "", toolCalls, usage: { inputTokens: 10, outputTokens: 2 } });
  const orchestrator = new ScriptedAgentClient([
    turn([call("p0", "delegate_attack", { objectiveId: "missing", directive: "try anything", reason: "bad" })]),
    turn([call("p1", "delegate_attack", { objectiveId: "o-web", directive: "Establish the web foothold first; keep commands small.", reason: "reported web weakness is the best initial access" })]),
    turn([call("p2", "delegate_attack", { objectiveId: "o-db", directive: "The web path failed; retry the database path with the brief intel only.", reason: "pivot after the verified web miss" })]),
    turn([call("p3", "finish_campaign", { summary: "both objectives attempted" })]),
  ]);
  const executed = [];
  const result = await runRedCampaign(orchestrator, {
    spec, runId: "run-abcdef12-0000",
    caps: { maxSteps: 6, maxInputTokens: 1000, maxOutputTokens: 100, maxWallMinutes: 1 },
    recorder: new LocalTrajectoryRecorder(new EventStore()),
    executeObjective: async (objective, directive) => {
      executed.push([objective.id, directive]);
      return {
        objectiveId: objective.id, attempts: [{ argv: ["probe"], text: "", stdout: "", stderr: "" }], elapsedMs: 1,
        retrieved: objective.id === "o-db", state: { steps: 1, inputTokens: 1, outputTokens: 1, modelId: "operator" }, guardrails: newGuardrailLog(),
      };
    },
  });
  assert.deepEqual(result.order, ["o-web", "o-db"], "the orchestrator, not spec order, coordinates the attacks");
  assert.deepEqual(executed.map((x) => x[0]), ["o-web", "o-db"]);
  assert.match(executed[1][1], /web path failed/, "the second directive reflects the first verified outcome");
  assert.deepEqual(result.decisions.map((d) => [d.objectiveId, d.outcome]), [["o-web", "not retrieved"], ["o-db", "retrieved"]]);
  assert.equal(result.guardrails.rejected.length, 1, "a delegation to a non-existent objective is refused before it can run");
  assert.equal(result.state.steps, 4);
});

test("blue monitor: deterministic anomaly candidates are separated from benign rows, and the monitoring loop can cite their evidence", async () => {
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { blueInvestigate, collapseTelemetry, detectTelemetryAnomalies } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const ev = (at, kind, src, detail, user = "app") => ({ hostId: "db-01", at, kind, src, user, detail });
  const telemetry = [
    ...Array.from({ length: 5 }, (_, i) => ev("2026-01-01T00:00:0" + i + "Z", "auth.failure", "10.9.0.9", { db: "app", reason: "password authentication failed" })),
    ev("2026-01-01T00:00:06Z", "db.statement", "10.9.0.9", { db: "app", statement: "SELECT value FROM secrets" }),
    ev("2026-01-01T00:00:07Z", "db.query", "[local]", { db: "app", statement: "SELECT count(*) FROM employees" }, "alice"),
  ];
  const rows = collapseTelemetry(telemetry.map((x) => ({ hostId: x.hostId, ev: x })));
  const anomalies = detectTelemetryAnomalies(rows);
  assert.ok(anomalies.some((a) => a.signal === "auth-burst" && a.hostId === "db-01" && a.src === "10.9.0.9" && a.count === 5), "repeated remote auth failures become a monitor candidate");
  assert.ok(anomalies.some((a) => a.signal === "remote-db-access" && a.evidence.includes("E2")), "remote database access becomes a monitor candidate");
  assert.ok(!anomalies.some((a) => a.src === "[local]"), "ordinary local work is not promoted to an anomaly solely because it is in the logs");
  const spec = { instances: [{ hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Rocky Linux 9", stack: [], services: [], databases: [] }], personas: [], plantedVulns: [] };
  const call = (id, name, args) => ({ callId: id, name, argumentsJson: JSON.stringify(args) });
  const turn = (toolCalls) => ({ text: "", toolCalls, usage: { inputTokens: 10, outputTokens: 2 } });
  const agent = new ScriptedAgentClient([
    turn([call("m1", "monitor_anomalies", {})]),
    turn([call("m2", "fetch_telemetry", {})]),
    turn([call("m3", "respond", { hostId: "db-01", techniqueId: "T1078", response: "block IP", ip: "10.9.0.9", evidence: ["E1", "E2"], why: "remote auth burst followed by database access" })]),
  ]);
  const res = await blueInvestigate(agent, {
    spec, runId: "run-abcdef12-0000", since: "2026-01-01T00:00:00Z", telemetry,
    caps: { maxSteps: 5, maxInputTokens: 1000, maxOutputTokens: 100, maxWallMinutes: 1 },
    recorder: new LocalTrajectoryRecorder(new EventStore()),
  });
  assert.equal(res.proposals.length, 1);
  assert.ok(res.monitoring.anomalies.length >= 2, "the loop returns monitor candidates alongside the proposal");
  assert.equal(res.monitoring.rows, 3);
  assert.ok(res.monitoring.pages >= 1, "the loop reports telemetry monitoring batches");
  assert.equal(res.examined, 7, "row counts are counted once even when monitor and paging return the same evidence");
});

test("guardrails: blue respond is refused for unseen/foreign evidence, fake techniques and an IP not in the cited rows", async () => {
  const { checkProposal, knownTechnique } = await import("../dist/exercise/agents.js");
  const row = (id, hostId, src) => [id, { id, hostId, src, count: 1, line: "" }];
  const ctx = { hosts: ["web-01", "db-01"], shown: new Map([row("E1", "web-01", "10.2.32.5"), row("E2", "db-01", "10.2.32.5"), row("E3", "db-01", "[local]")]) };
  const base = { hostId: "db-01", techniqueId: "T1110", response: "block IP", ip: "10.2.32.5", evidence: ["E2"], why: "x" };
  const kind = (args) => checkProposal(args, ctx).reject?.kind;
  assert.equal(checkProposal(base, ctx).ok.ip, "10.2.32.5");
  assert.equal(checkProposal({ ...base, techniqueId: "t1110.003" }, ctx).ok.techniqueId, "T1110.003", "sub-techniques accepted, normalised");
  assert.equal(kind({ ...base, techniqueId: "T1999" }), "technique");
  assert.equal(kind({ ...base, techniqueId: "SQL injection" }), "technique");
  assert.equal(kind({ ...base, evidence: [] }), "citation");
  assert.equal(kind({ ...base, evidence: ["E99"] }), "citation", "row never shown");
  assert.equal(kind({ ...base, evidence: ["E1"] }), "citation", "evidence is from another host");
  assert.equal(kind({ ...base, ip: "10.2.32.99" }), "ip", "IP not in cited rows");
  assert.equal(kind({ ...base, ip: "[local]", evidence: ["E3"] }), "ip", "local source cannot be blocked");
  assert.equal(kind({ ...base, response: "wipe disk" }), "schema");
  assert.equal(checkProposal({ ...base, response: "disable account", ip: undefined }, ctx).ok.response, "disable account", "ip only required for block IP");
  assert.ok(knownTechnique("T1595.002") && !knownTechnique("T0000"));
});

test("guardrails: red stating a proof it never retrieved is logged as an unverified claim and scores nothing", async () => {
  const { writeFileSync, mkdtempSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { redObjective } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const state = `${mkdtempSync(`${tmpdir()}/fd-`)}/state.json`;
  writeFileSync(state, JSON.stringify({ clock: Date.now(), logs: {}, web: "ma-abcdef12-web-01", db: "ma-abcdef12-db-01", canary: "MUSE-PROOF-aaaa" }));
  process.env.FAKE_DOCKER_STATE = state;
  const spec = { instances: [{ hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: [], databases: [] }], personas: [], plantedVulns: [] };
  const turn = (text) => ({ text, toolCalls: [], usage: { inputTokens: 1, outputTokens: 1 } });
  const run = (text) => redObjective(new ScriptedAgentClient([turn(text)]), { spec, runId: "run-abcdef12-0000", objective: { id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 1 }, proof: "MUSE-PROOF-aaaa", caps: { maxSteps: 3, maxInputTokens: 1e4, maxOutputTokens: 1e3, maxWallMinutes: 1 }, recorder: new LocalTrajectoryRecorder(new EventStore()), docker: new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname });
  for (const claim of ["The value is MUSE-PROOF-aaaa", "Got it: MUSE-PROOF-deadbeef"]) {
    const r = await run(claim);
    assert.equal(r.retrieved, false);
    assert.equal(r.guardrails.unverifiedClaims.length, 1, claim);
  }
  assert.equal((await run("No access yet.")).guardrails.unverifiedClaims.length, 0);
});

test("guardrails: blue announcing containment without calling respond is an unverified claim", async () => {
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { blueInvestigate } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const spec = { instances: [{ hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu", stack: [], services: [], databases: [] }], personas: [], plantedVulns: [] };
  const t = (text) => ({ text, toolCalls: [], usage: { inputTokens: 1, outputTokens: 1 } });
  const res = await blueInvestigate(new ScriptedAgentClient([t("Both hosts compromised, submitting containment."), t("clean")]), { spec, runId: "run-abcdef12-0000", since: new Date().toISOString(), caps: { maxSteps: 6, maxInputTokens: 1e4, maxOutputTokens: 1e3, maxWallMinutes: 1 }, recorder: new LocalTrajectoryRecorder(new EventStore()), docker: new URL("./fixtures/fake-docker.mjs", import.meta.url).pathname });
  assert.equal(res.guardrails.unverifiedClaims.length, 1);
  assert.equal(res.proposals.length, 0);
});

test("org labs: shared spec accepts structured services; legacy container specs validate + digest unchanged", async () => {
  const { EnvironmentSpec } = await import("../../shared/dist/index.js");
  const { digestOfSpec } = await import("../dist/lib/digest.js");
  const legacy = {
    version: 1, name: "t", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
    instances: [{ hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu 24.04", stack: [], services: ["http"], databases: [] }],
    personas: [], objectives: [{ id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 5 }],
    requiredTelemetry: ["auditd"], plantedVulns: [],
    budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
  };
  const parsed = EnvironmentSpec.parse(legacy);
  assert.equal(parsed.instances[0].serviceDecls, undefined, "no org-lab fields invented for legacy specs");
  assert.equal(digestOfSpec(parsed), digestOfSpec(legacy), "digest is stable across the schema extension");
  const org = EnvironmentSpec.parse({
    ...legacy,
    instances: [{ hostId: "gw-01", name: "gw-01", role: "gateway", runtime: "vm", os: "Debian 12", stack: [], services: ["dns"], databases: [],
      subnet: "private-a", serviceDecls: [{ kind: "dns", impl: "dnsmasq", port: 53, readyWhen: "dns-query" }], dependsOn: [], resources: { vcpu: 1, memoryMb: 512, diskGb: 4 } }],
    objectives: [{ id: "o1", asset: "gw-01", techniqueId: "T1078", successSignal: "canary-hash", points: 5 }],
  });
  assert.equal(org.instances[0].serviceDecls[0].impl, "dnsmasq");
  assert.throws(() => EnvironmentSpec.parse({ ...legacy, instances: [{ ...legacy.instances[0], serviceDecls: [{ kind: "gopher", impl: "x", port: 70, readyWhen: "tcp" }] }] }), /kind|ServiceKind/, "unknown service kinds fail schema validation");
});

test("org labs: catalog + profile resolver — declared tools/packages, unknown services fail closed", async () => {
  const { catalogEntry, CATALOG_VERSION } = await import("../dist/configurator/catalog.js");
  const { resolveProfile, resolveProfiles } = await import("../dist/configurator/profiles.js");
  const { deployability } = await import("../dist/provisioner/capability.js");
  assert.ok(CATALOG_VERSION.length > 0);
  assert.equal(catalogEntry({ kind: "dns", impl: "dnsmasq" }).defaultPort, 53);
  assert.equal(catalogEntry({ kind: "http", impl: "nginx" }), null, "impls outside the catalog are not provisionable");
  const spec = {
    version: 1, name: "clinic", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
    instances: [
      { hostId: "gw-01", name: "gw-01", role: "gateway", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [], subnet: "private-a",
        serviceDecls: [{ kind: "dns", impl: "dnsmasq", port: 53, readyWhen: "dns-query" }, { kind: "dhcp", impl: "dnsmasq", port: 67, readyWhen: "dhcp-lease" }] },
      { hostId: "mail-01", name: "mail-01", role: "mail", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [], subnet: "private-a", dependsOn: ["gw-01"],
        serviceDecls: [{ kind: "smtp", impl: "postfix", port: 25, readyWhen: "smtp-imap-roundtrip" }, { kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" }] },
      { hostId: "attacker", name: "attacker", role: "attacker", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [], subnet: "private-a" },
    ],
    personas: [], objectives: [{ id: "o1", asset: "mail-01", techniqueId: "T1078", successSignal: "canary-hash", points: 5 }],
    requiredTelemetry: ["auditd"], plantedVulns: [], budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
  };
  const gw = resolveProfile(spec, "gw-01");
  assert.ok(gw.packages.includes("dnsmasq") && gw.packages.includes("auditd") && gw.packages.includes("osquery"), "base sensors + declared service packages");
  assert.ok(gw.groups.some((g) => g.name === "dns-configure"));
  const mail = resolveProfile(spec, "mail-01");
  assert.ok(mail.packages.includes("postfix") && mail.packages.includes("dovecot-imapd"));
  assert.ok(mail.clientTools.includes("dnsutils"), "dependencies pull client tools (DNS via gateway)");
  const atk = resolveProfile(spec, "attacker");
  assert.ok(atk.clientTools.includes("nmap") && atk.clientTools.includes("swaks"), "attacker gets the declared red toolbox");
  assert.throws(() => resolveProfile({ ...spec, instances: [{ ...spec.instances[0], serviceDecls: [{ kind: "http", impl: "nginx", port: 80, readyWhen: "http-2xx" }] }, ...spec.instances.slice(1)] }, "gw-01"), /not in the runtime catalog/);
  const blocked = deployability(spec);
  assert.ok(!blocked.some((r) => /dhcp/i.test(r)), `VM dhcp is deployable now, got: ${blocked.join("; ")}`);
  assert.ok(deployability({ ...spec, instances: [{ ...spec.instances[0], serviceDecls: [{ kind: "http", impl: "nginx", port: 80, readyWhen: "http-2xx" }] }, ...spec.instances.slice(1)] }).some((r) => /not in the runtime catalog/.test(r)));
  void resolveProfiles;
});

test("model registry: per-role Muse models, fail closed on ids not verified for tool use", async () => {
  const { modelForRole, AGENT_MODELS, DEFAULT_MODEL } = await import("../dist/lib/model.js");
  assert.equal(modelForRole("red", {}), DEFAULT_MODEL);
  assert.equal(modelForRole("red", { META_MODEL_ID: "muse-spark-1.2" }), "muse-spark-1.2");
  assert.equal(modelForRole("blue", { META_MODEL_ID: "muse-spark-1.2", MUSEARENA_MODEL_BLUE: "muse-wonder-1.0" }), "muse-wonder-1.0");
  assert.throws(() => modelForRole("red", { MUSEARENA_MODEL_RED: "muse-image-1.0" }), /not a verified tool-use Muse model/);
  assert.throws(() => modelForRole("red", { MUSEARENA_MODEL_RED: "muse-latest" }), /not a verified/);
  assert.ok(AGENT_MODELS.every((m) => m.startsWith("muse-")));
  // Persona role: cheaper verified default, per-persona override wins, and an
  // unverified glimmer id fails closed instead of reaching the API.
  assert.equal(modelForRole("persona", {}), "muse-spark-1.1", "persona defaults to the lighter verified Muse");
  assert.equal(modelForRole("persona", { MUSEARENA_MODEL_PERSONA: "muse-wonder-1.0" }), "muse-wonder-1.0");
  assert.throws(() => modelForRole("persona", { MUSEARENA_MODEL_PERSONA: "muse-glimmer-1.0" }), /not a verified tool-use Muse model/);
});

test("designer client: Modal wins over Meta, Meta is the fallback, a half-set Modal pair fails loud", async () => {
  const { configuredDesignerSurfaces, designerModelClient, designerModelClientForSurface, MODAL_DEFAULT_MODEL } = await import("../dist/lib/model.js");
  const both = { MODAL_PROXY_TOKEN_ID: "wk-id", MODAL_PROXY_TOKEN_SECRET: "ws-secret", META_API_KEY: "meta-key" };
  assert.deepEqual(configuredDesignerSurfaces(both), ["meta", "meta-modal"]);
  assert.equal(designerModelClientForSurface("meta", both).modelId, "muse-spark-1.3", "an explicit Meta selection is not overridden by Modal");
  assert.equal(designerModelClientForSurface("meta-modal", { META_API_KEY: "meta-key" }), null, "an unconfigured explicit surface never falls back silently");
  const modal = designerModelClient(both);
  assert.equal(modal.modelId, MODAL_DEFAULT_MODEL, "Modal is the designer default when its token pair is set");
  assert.equal(typeof modal.generateTurn, "function", "Modal client also serves agent tool turns (verified live 2026-11-03)");
  assert.equal(designerModelClient({ ...both, MODAL_MODEL_ID: "org/other-model" }).modelId, "org/other-model");
  const meta = designerModelClient({ META_API_KEY: "meta-key" });
  assert.equal(meta.modelId, "muse-spark-1.3", "Meta fallback keeps the verified designer model");
  assert.equal(typeof meta.generateTurn, "function");
  assert.equal(designerModelClient({}), null, "no keys -> no client (endpoint answers 501)");
  assert.throws(() => designerModelClient({ MODAL_PROXY_TOKEN_ID: "wk-id" }), /must both be set/);
  assert.throws(() => designerModelClient({ MODAL_PROXY_TOKEN_SECRET: "ws-secret" }), /must both be set/);
});

test("Modal designer client: streamed chat completion with proxy-token auth and json_schema, Zod-validated", async () => {
  const { ModalModelClient } = await import("../dist/lib/model.js");
  const { Budget, EnvironmentSpec } = await import("@musearena/shared");
  const prevFetch = globalThis.fetch;
  const client = new ModalModelClient({ baseUrl: "http://modal.test/v1/", tokenId: "wk-id", tokenSecret: "ws-secret", affinityKey: "replica-1" });
  const sse = (chunks) => new Response(new ReadableStream({
    start(controller) {
      const enc = new TextEncoder();
      for (const c of chunks) controller.enqueue(enc.encode(c));
      controller.close();
    },
  }), { headers: { "Content-Type": "text/event-stream" } });
  try {
    let seen;
    // A data line split mid-chunk; a reasoning delta must not leak into content.
    globalThis.fetch = async (url, opts) => {
      seen = { url, opts };
      const body = '{"maxInstances":8,"maxDollarsPerHour":5,"ttlHours":2}';
      const half = Math.ceil(body.length / 2);
      const line = (content, extra = {}) => `data: ${JSON.stringify({ choices: [{ delta: { content }, ...extra }] })}\n\n`;
      return sse([
        `data: ${JSON.stringify({ choices: [{ delta: { reasoning_content: "thinking {not json" } }] })}\n\n${line(body.slice(0, half)).slice(0, 30)}`,
        `${line(body.slice(0, half)).slice(30)}${line(body.slice(half), { finish_reason: "stop" })}data: [DONE]\n\n`,
      ]);
    };
    const deltas = [];
    const budget = await client.generateObject({ system: "sys", prompt: "p", schema: Budget, maxTokens: 1234, onDelta: (d) => deltas.push(d) });
    assert.deepEqual(budget, { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 2 });
    // Reasoning is forwarded to observers as its own stream; content stays clean JSON.
    assert.equal(deltas.filter((d) => d.kind === "reasoning").map((d) => d.text).join(""), "thinking {not json");
    assert.equal(deltas.filter((d) => d.kind === "content").map((d) => d.text).join(""), '{"maxInstances":8,"maxDollarsPerHour":5,"ttlHours":2}');
    const lastDelta = deltas.at(-1);
    assert.equal(lastDelta.reasoningChars, "thinking {not json".length);
    assert.equal(lastDelta.contentChars, 53);
    assert.equal(seen.url, "http://modal.test/v1/chat/completions");
    assert.equal(seen.opts.headers.Authorization, "Bearer wk-id.ws-secret");
    assert.equal(seen.opts.headers["Modal-Routing-Affinity-Key"], "replica-1");
    const sent = JSON.parse(seen.opts.body);
    assert.equal(sent.model, "meta-models/Muse-Spark-Open-816B-A42B");
    assert.equal(sent.stream, true);
    assert.equal(sent.max_tokens, 1234);
    assert.equal(sent.reasoning_effort, "medium");
    assert.equal(sent.messages[0].role, "system");
    assert.equal(sent.response_format.type, "json_schema");
    assert.equal(sent.response_format.json_schema.strict, true);
    assert.ok(sent.response_format.json_schema.schema.properties.maxInstances, "Zod schema is sent for guided decoding");
    assert.ok(!("$schema" in sent.response_format.json_schema.schema));

    // The real designer schema survives conversion (no $ref for guided decoding)
    // and a streamed EnvironmentSpec comes back Zod-validated with defaults filled.
    const spec = {
      version: 1, name: "t", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
      topology: { cidr: "10.9.0.0/16", subnets: [], firewallRules: [] },
      instances: [{ hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: ["http"] }],
      objectives: [{ id: "o1", asset: "web-01", techniqueId: "T1190", successSignal: "canary", points: 10 }],
      requiredTelemetry: ["x"], budgets: { maxInstances: 4, maxDollarsPerHour: 1, ttlHours: 1 },
    };
    globalThis.fetch = async (url, opts) => {
      seen = { url, opts };
      return sse([`data: ${JSON.stringify({ choices: [{ delta: { content: JSON.stringify(spec) } }] })}\n\ndata: [DONE]\n\n`]);
    };
    const designed = await client.generateObject({ system: "sys", prompt: "p", schema: EnvironmentSpec, maxTokens: 32768 });
    assert.equal(designed.instances[0].hostId, "web-01");
    assert.deepEqual(designed.personas, [], "Zod defaults fill omitted arrays");
    const sentSchema = JSON.parse(seen.opts.body).response_format.json_schema.schema;
    assert.ok(sentSchema.properties.instances, "EnvironmentSpec sent as json_schema");
    assert.ok(!JSON.stringify(sentSchema).includes('"$ref"'), "guided-decoding schema is fully inlined");
  } finally {
    globalThis.fetch = prevFetch;
  }
});

test("Modal designer client: a schema rejection retries once unstructured; a 401 is permanent and does not retry", async () => {
  const { ModalModelClient, PermanentModelError } = await import("../dist/lib/model.js");
  const { Budget } = await import("@musearena/shared");
  const prevFetch = globalThis.fetch;
  const client = new ModalModelClient({ baseUrl: "http://modal.test/v1", tokenId: "wk-id", tokenSecret: "ws-secret" });
  try {
    let calls = 0;
    let secondBody;
    globalThis.fetch = async (url, opts) => {
      calls++;
      if (calls === 1) return new Response('{"error":"response_format json_schema unsupported"}', { status: 400 });
      secondBody = JSON.parse(opts.body);
      return new Response(JSON.stringify({ choices: [{ message: { content: '{"maxInstances":3,"maxDollarsPerHour":2,"ttlHours":1}' } }] }), { headers: { "Content-Type": "application/json" } });
    };
    assert.deepEqual(await client.generateObject({ system: "s", prompt: "p", schema: Budget }), { maxInstances: 3, maxDollarsPerHour: 2, ttlHours: 1 });
    assert.equal(calls, 2, "exactly one unstructured retry (also covers a non-streamed JSON reply)");
    assert.ok(!("response_format" in secondBody));

    calls = 0;
    globalThis.fetch = async () => { calls++; return new Response('{"error":"proxy auth required"}', { status: 401 }); };
    await assert.rejects(
      client.generateObject({ system: "s", prompt: "p", schema: Budget }),
      (e) => e instanceof PermanentModelError && /401/.test(e.message),
    );
    assert.equal(calls, 1, "auth failures keep their error; no unstructured retry");
  } finally {
    globalThis.fetch = prevFetch;
  }
});

test("persona agents: the shift tool allows only declared routine actions; off-list and off-target calls are refused and counted", async () => {
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { personaShift, SHIFT_ACTIONS } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const spec = {
    version: 1, name: "t", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.9.0.0/16", subnets: [], firewallRules: [] },
    instances: [
      { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: ["http"], databases: [], serviceDecls: [{ kind: "http", impl: "apache-php", port: 80, readyWhen: "http-2xx" }] },
    ],
    personas: [{ id: "p1", role: "clerk", workstation: "web-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
    objectives: [], requiredTelemetry: ["x"], plantedVulns: [], budgets: { maxInstances: 4, maxDollarsPerHour: 1, ttlHours: 1 },
  };
  const executed = [];
  const execute = async (command) => { executed.push(command); return "ok"; };
  const call = (id, args) => ({ callId: id, name: "shift", argumentsJson: JSON.stringify(args) });
  const t = (toolCalls, text = "") => ({ text, toolCalls, usage: { inputTokens: 50, outputTokens: 5 } });
  const agent = new ScriptedAgentClient([
    t([
      call("s1", { action: "whoami", reason: "start shift" }),
      call("s2", { action: "shell", args: "rm -rf /" }),
      call("s3", { action: "web_fetch", url: "https://evil.example/" }),
      call("s4", { action: "lookup_host", name: "db-01" }),
      call("s5", { action: "web_fetch", url: "http://web-01.local/" }),
    ]),
    t([], "shift done"),
  ]);
  const res = await personaShift(agent, {
    spec, runId: "run-p1", persona: spec.personas[0],
    caps: { maxSteps: 4, maxInputTokens: 10_000, maxOutputTokens: 1000, maxWallMinutes: 1 },
    recorder: new LocalTrajectoryRecorder(new EventStore()),
    execute,
  });
  assert.equal(res.mode, "agent");
  assert.deepEqual(res.performed.map((p) => p.action), ["whoami", "web_fetch"], "only the two in-bounds actions ran");
  assert.equal(res.refused.length, 3, "shell, off-target fetch, and unknown host are refused");
  assert.ok(res.refused.every((r) => /not a declared routine action|not in your access list|not a host in this environment/.test(r.detail)), res.refused.map((r) => r.detail).join(" | "));
  assert.equal(res.guardrails.rejected.length, 3, "refusals are guardrail-counted");
  assert.equal(executed.length, 2, "refused actions never reach the guest");
  assert.ok(SHIFT_ACTIONS.includes("web_fetch") && !SHIFT_ACTIONS.some((a) => /shell|exec|run/.test(a)), "the allowlist has no shell-shaped action");
});

test("persona Kerberos: a FreeIPA member gets a per-persona ccache and every shift command runs as the directory user", async () => {
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { personaShift } = await import("../dist/exercise/agents.js");
  const { personaKerberosFor } = await import("../dist/exercise/persona-auth.js");
  const { ipaUserSecret } = await import("../dist/configurator/lab.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const spec = {
    version: 1, name: "ipa-shift", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.9.0.0/16", subnets: [], firewallRules: [] },
    instances: [
      { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
        serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }] },
      { hostId: "ws-01", name: "ws-01", role: "workstation", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
        serviceDecls: [], dependsOn: ["dc-01"] },
    ],
    personas: [{ id: "p1", role: "nurse", workstation: "ws-01", access: [], credentialsProfile: "standard", riskProfile: "low", routine: "", relationships: [] }],
    objectives: [], requiredTelemetry: [], plantedVulns: [], budgets: { maxInstances: 4, maxDollarsPerHour: 1, ttlHours: 1 },
  };
  const ctx = personaKerberosFor(spec, "run-shift", spec.personas[0]);
  assert.ok(ctx, "member workstation yields a Kerberos context");
  assert.equal(ctx.user, "p1");
  assert.equal(ctx.ccache, "/tmp/arena-krb5-run-shift-p1.ccache");
  assert.match(ctx.setupCommand, /sudo -n -u 'p1' env KRB5CCNAME='FILE:\/tmp\/arena-krb5-run-shift-p1\.ccache' python3/);
  assert.match(ctx.setupCommand, /ldapwhoami -Y GSSAPI -H 'ldap:\/\/dc-01\.ipa\./);
  assert.ok(!ctx.setupCommand.includes(ipaUserSecret("run-shift", "p1")), "the password is not in argv");
  assert.equal(personaKerberosFor({ ...spec, instances: [spec.instances[0], { ...spec.instances[1], dependsOn: [] }] }, "run-shift", spec.personas[0]), null, "non-member stays local");

  const executed = [];
  const t = (toolCalls) => ({ text: "", toolCalls, usage: { inputTokens: 10, outputTokens: 2 } });
  const agent = new ScriptedAgentClient([
    t([{ callId: "k1", name: "shift", argumentsJson: JSON.stringify({ action: "whoami" }) }]),
    t([]),
  ]);
  const res = await personaShift(agent, {
    spec, runId: "run-shift", persona: spec.personas[0],
    caps: { maxSteps: 2, maxInputTokens: 1000, maxOutputTokens: 100, maxWallMinutes: 1 },
    recorder: new LocalTrajectoryRecorder(new EventStore()),
    execute: async (command) => { executed.push(command); return "p1"; },
    kerberos: { user: ctx.user, ccache: ctx.ccache },
  });
  assert.equal(res.auth, "kerberos");
  assert.deepEqual(executed, [`sudo -n -u 'p1' env KRB5CCNAME='FILE:${ctx.ccache}' id -un`]);

  // Setup is fail-closed: a member whose kinit/GSSAPI proof does not complete
  // never reaches the model as the SSH user.
  const { personaShifts } = await import("../dist/exercise/vm-agents.js");
  await assert.rejects(
    personaShifts(spec, "run-shift", async () => "", async (hostId) => ({ hostId }), {
      agent: new ScriptedAgentClient([]),
      caps: { maxSteps: 2, maxInputTokens: 100, maxOutputTokens: 10, maxWallMinutes: 1 },
      recorder: new LocalTrajectoryRecorder(new EventStore()),
      traceEnabled: false,
    }),
    /kinit did not produce a usable ticket/,
  );
});

test("persona agents: a persona with no VM workstation gets the scripted baseline, never a faked model shift", async () => {
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { personaShift } = await import("../dist/exercise/agents.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const spec = {
    version: 1, name: "t", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.9.0.0/16", subnets: [], firewallRules: [] },
    instances: [
      { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu", stack: [], services: ["http"], databases: [] },
    ],
    personas: [{ id: "p1", role: "clerk", workstation: "web-01", access: [], credentialsProfile: "x", riskProfile: "low", routine: "", relationships: [] }],
    objectives: [], requiredTelemetry: ["x"], plantedVulns: [], budgets: { maxInstances: 4, maxDollarsPerHour: 1, ttlHours: 1 },
  };
  const res = await personaShift(new ScriptedAgentClient([]), {
    spec, runId: "run-p1", persona: spec.personas[0],
    caps: { maxSteps: 2, maxInputTokens: 1000, maxOutputTokens: 100, maxWallMinutes: 1 },
    recorder: new LocalTrajectoryRecorder(new EventStore()),
    execute: async () => { throw new Error("must not execute for a container workstation"); },
  });
  assert.equal(res.mode, "scripted", "container workstation → scripted baseline");
  assert.equal(res.performed.length, 0);
  assert.equal(res.state.steps, 0);
});

test("dataset objects: gzip round-trip is lossless (hash-stable) and legacy plain objects still decode", async () => {
  const { encodeObject, decodeObject } = await import("../dist/observability/dataset-object.js");
  const { verifyExportHash } = await import("../dist/traces/integrity.js");
  // The kind of content the storage gateway's filter rejected as plain text.
  const body = JSON.stringify({ steps: [{ toolCall: "wget -qO- http://web-01/../../etc/passwd" }, { toolCall: "psql -c \"SELECT value FROM secrets WHERE 1=1--\"" }] });
  const gz = encodeObject(body);
  assert.deepEqual([gz[0], gz[1]], [0x1f, 0x8b]);
  assert.ok(!gz.toString("latin1").includes("../"), "attack strings are not visible on the wire");
  assert.equal(await decodeObject(new Blob([gz])), body);
  assert.equal(await decodeObject(new Blob([body])), body, "pre-compression objects decode unchanged");
  void verifyExportHash;
});

test("metrics endpoint: a port already in use is reported, not thrown (worker keeps running)", async () => {
  const { createServer } = await import("node:net");
  const { metricsServer } = await import("../dist/observability/metrics.js");
  const holder = createServer().listen(0, "127.0.0.1");
  await new Promise((r) => holder.once("listening", r));
  const port = holder.address().port;
  const s = metricsServer(port, "127.0.0.1");
  const err = await new Promise((r) => s.once("error", r));
  assert.equal(err.code, "EADDRINUSE");
  holder.close();
});

test("Modal agent turn: Responses-style transcript becomes chat messages; tool calls come back as ToolCalls", async () => {
  const { ModalModelClient, chatMessages, userText, assistantItems, toolResult } = await import("../dist/lib/model.js");
  const turn = { text: "checking", toolCalls: [{ callId: "c1", name: "exec", argumentsJson: '{"cmd":"id"}' }, { callId: "c2", name: "exec", argumentsJson: "{}" }], usage: { inputTokens: 0, outputTokens: 0 } };
  const transcript = [userText("go"), ...assistantItems(turn), toolResult("c1", "uid=0"), toolResult("c2", "ok")];
  assert.deepEqual(chatMessages(transcript), [
    { role: "user", content: "go" },
    { role: "assistant", content: "checking", tool_calls: [
      { id: "c1", type: "function", function: { name: "exec", arguments: '{"cmd":"id"}' } },
      { id: "c2", type: "function", function: { name: "exec", arguments: "{}" } }] },
    { role: "tool", tool_call_id: "c1", content: "uid=0" },
    { role: "tool", tool_call_id: "c2", content: "ok" },
  ]);
  const prevFetch = globalThis.fetch;
  let body;
  globalThis.fetch = async (_url, opts) => {
    body = JSON.parse(opts.body);
    return new Response(JSON.stringify({ choices: [{ message: { content: "", tool_calls: [{ id: "x", function: { name: "exec", arguments: '{"cmd":"ls"}' } }] } }], usage: { prompt_tokens: 7, completion_tokens: 3 } }));
  };
  try {
    const client = new ModalModelClient({ baseUrl: "http://modal.test/v1", tokenId: "a", tokenSecret: "b" });
    const out = await client.generateTurn({ system: "sys", transcript: [userText("hi")], tools: [{ name: "exec", description: "d", parameters: { type: "object" } }] });
    assert.deepEqual(out, { text: "", toolCalls: [{ callId: "x", name: "exec", argumentsJson: '{"cmd":"ls"}' }], usage: { inputTokens: 7, outputTokens: 3 } });
    assert.equal(body.messages[0].role, "system");
    assert.equal(body.tools[0].function.name, "exec");
  } finally {
    globalThis.fetch = prevFetch;
  }
});

test("ROE: ordinary recon shell is not refused; off-lab targets still are", async () => {
  const { roeCheck } = await import("../dist/exercise/agents.js");
  const { clinicOrgSpecWithAttacker } = await import("../dist/designer/clinic.js");
  const { labDomainFor } = await import("../dist/configurator/dns.js");
  const spec = clinicOrgSpecWithAttacker();
  const d = labDomainFor(spec);
  // Each of these was refused in a live Muse Spark run (2026-11-03) as "unknown host echo/nc/ss/filter".
  for (const cmd of [
    "cat /etc/hosts; echo ---; ping -c1 -W2 web-01; echo ping_exit:$?",
    "nc -vz db-01 5432 2>&1; ss -tulpn 2>&1 | head -n 50",
    `wget -qO- "http://web-01/index.php?view=php://filter/convert.base64-encode/resource=index.php" 2>&1 | head`,
    `nmap -p 389,636 dc-01.${d} 2>&1 | head -n 100`,
    "which dig host nslookup 2>&1; ldapsearch -h 2>&1 | head",
    "for u in admin root; do ssh -o BatchMode=yes -o ConnectTimeout=3 $u@dc-01 true 2>&1; done",
  ]) assert.equal(roeCheck(["sh", "-c", cmd], spec, ["10.2.32.12"]), null, cmd);
  for (const cmd of ["curl http://evil.example.com/x", "ssh root@evil.example.com id",
    "sudo -n apt-get install -y sshpass", "apt-get update", "pip3 install impacket", "git clone https://example.org/x", "su -", "ping -c1 8.8.8.8; echo hi", "nmap 2>&1 evil.example.com",
    "wget -qO- https://example.org 2>&1", "nc evil.example.com 4444", "psql -h attacker.net", "docker ps"]) {
    assert.notEqual(roeCheck(["sh", "-c", cmd], spec, ["10.2.32.12"]), null, cmd);
  }
});

test("red brief names the exact lab targets before any DNS mining", async () => {
  const { redObjective } = await import("../dist/exercise/agents.js");
  const { clinicOrgSpecWithAttacker } = await import("../dist/designer/clinic.js");
  const { labDomainFor } = await import("../dist/configurator/dns.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const spec = clinicOrgSpecWithAttacker();
  const domain = labDomainFor(spec);
  let inventory = "";
  const client = { modelId: "test-model", async generateTurn(input) { inventory = input.tools[0].description; return { text: "", toolCalls: [], usage: { inputTokens: 1, outputTokens: 1 } }; } };
  await redObjective(client, {
    spec, runId: "run-abcdef12-0000",
    objective: { id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "code-proof", points: 1 },
    proof: "MUSE-PROOF-test", caps: { maxSteps: 1, maxInputTokens: 1000, maxOutputTokens: 100, maxWallMinutes: 1 },
    recorder: new LocalTrajectoryRecorder(new EventStore()), execute: async () => ({ stdout: "", stderr: "" }),
  });
  assert.match(inventory, /web-01/);
  assert.match(inventory, new RegExp(`web-01\\.${domain.replaceAll(".", "\\.")}`), "the exact FQDN is in the tool inventory, not left for DNS discovery");
  assert.match(inventory, /exact target names before scanning or IP mining/i);
});

test("red brief names the reported web weakness route before broad crawling", async () => {
  const { redObjective } = await import("../dist/exercise/agents.js");
  const { clinicOrgSpecWithAttacker } = await import("../dist/designer/clinic.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const spec = clinicOrgSpecWithAttacker();
  let brief = "";
  const client = { modelId: "test-model", async generateTurn(input) {
    brief = input.transcript.map((m) => ("content" in m ? String(m.content) : "")).join("\n");
    return { text: "", toolCalls: [], usage: { inputTokens: 1, outputTokens: 1 } };
  } };
  await redObjective(client, {
    spec, runId: "run-abcdef12-0000",
    objective: { id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "code-proof", points: 1 },
    vuln: spec.plantedVulns.find((v) => v.targetHostId === "web-01" && v.type === "code-flaw"),
    proof: "MUSE-PROOF-test", caps: { maxSteps: 1, maxInputTokens: 1000, maxOutputTokens: 100, maxWallMinutes: 1 },
    recorder: new LocalTrajectoryRecorder(new EventStore()), execute: async () => ({ stdout: "", stderr: "" }),
  });
  assert.match(brief, /\/diag\.php\?host=/, "the reported code-flaw route is named directly instead of leaving endpoint discovery to the model");
});

test("persona model: Glimmer wakes through 503s, real errors fail fast, and a cold Glimmer falls back", async () => {
  const { ModalModelClient, modalPersonaClient, personaClientOrFallback, MODAL_GLIMMER_MODEL } = await import("../dist/lib/model.js");
  const prevFetch = globalThis.fetch;
  const prevEnv = { id: process.env.MODAL_PROXY_TOKEN_ID, secret: process.env.MODAL_PROXY_TOKEN_SECRET, glimmer: process.env.MODAL_GLIMMER_BASE_URL };
  process.env.MODAL_PROXY_TOKEN_ID = "a"; process.env.MODAL_PROXY_TOKEN_SECRET = "b";
  process.env.MODAL_GLIMMER_BASE_URL = "https://example--ep-glimmer-server.example/v1";
  try {
    assert.equal(modalPersonaClient().modelId, MODAL_GLIMMER_MODEL);
    let calls = 0;
    globalThis.fetch = async () => (++calls < 3 ? new Response("no upstreams available", { status: 503 }) : new Response("{}"));
    await modalPersonaClient().wake({ pollMs: 1, timeoutMs: 1000 });
    assert.equal(calls, 3, "503 while starting is retried until it serves");

    globalThis.fetch = async () => new Response("bad", { status: 401 });
    await assert.rejects(modalPersonaClient().wake({ pollMs: 1, timeoutMs: 1000 }), /Modal API 401/);

    let glimmerUrl, glimmerBody;
    globalThis.fetch = async (url, opts) => {
      glimmerUrl = String(url); glimmerBody = JSON.parse(opts.body);
      return new Response(JSON.stringify({ choices: [{ message: { content: "", tool_calls: [{ id: "g1", function: { name: "get_weather", arguments: '{"city":"London"}' } }] } }], usage: { prompt_tokens: 11, completion_tokens: 5 } }));
    };
    const { userText } = await import("../dist/lib/model.js");
    const turn = await modalPersonaClient().generateTurn({
      system: "sys", transcript: [userText("weather in London")],
      tools: [{ name: "get_weather", description: "weather", parameters: { type: "object", properties: { city: { type: "string" } }, required: ["city"] } }],
    });
    assert.match(glimmerUrl, /ep-glimmer-server.*\/chat\/completions$/);
    assert.equal(glimmerBody.model, "glimmer");
    assert.deepEqual(glimmerBody.reasoning, { enabled: true }, "Glimmer/SGLang receives the reasoning object from its deployment contract");
    assert.equal(glimmerBody.reasoning_effort, undefined);
    assert.equal(glimmerBody.tool_choice, "auto");
    assert.equal(turn.toolCalls[0].name, "get_weather");

    globalThis.fetch = async () => new Response("no upstreams available", { status: 503 });
    const fallback = new ModalModelClient({ baseUrl: "http://spark.test/v1" });
    assert.equal(await personaClientOrFallback(fallback, 5), fallback, "a cold Glimmer never stalls the exercise");
  } finally {
    globalThis.fetch = prevFetch;
    process.env.MODAL_PROXY_TOKEN_ID = prevEnv.id; process.env.MODAL_PROXY_TOKEN_SECRET = prevEnv.secret;
    if (prevEnv.glimmer === undefined) delete process.env.MODAL_GLIMMER_BASE_URL; else process.env.MODAL_GLIMMER_BASE_URL = prevEnv.glimmer;
  }
});

test("persona agents: shift actions reach the lab's real services by FQDN, with a least-privilege DB role", async () => {
  const { ScriptedAgentClient } = await import("../dist/lib/model.js");
  const { personaShift } = await import("../dist/exercise/agents.js");
  const { clinicOrgSpecWithAttacker } = await import("../dist/designer/clinic.js");
  const { labDomainFor } = await import("../dist/configurator/dns.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { LocalTrajectoryRecorder } = await import("../dist/observability/trajectory.js");
  const spec = clinicOrgSpecWithAttacker();
  const d = labDomainFor(spec);
  const call = (id, args) => ({ callId: id, name: "shift", argumentsJson: JSON.stringify(args) });
  const agent = new ScriptedAgentClient([
    { text: "", usage: { inputTokens: 1, outputTokens: 1 }, toolCalls: [
      call("a", { action: "web_fetch", url: "http://web-01/" }),
      call("b", { action: "lookup_host", name: "db-01" }),
      call("c", { action: "db_query", query: "SELECT count(*) FROM employees" }),
      call("d", { action: "send_probe_mail" }),
      call("e", { action: "lookup_host", name: "atk-01" }),
    ] },
    { text: "done", toolCalls: [], usage: { inputTokens: 1, outputTokens: 1 } },
  ]);
  const ran = [];
  const res = await personaShift(agent, {
    spec, runId: "run-x", persona: spec.personas[0],
    caps: { maxSteps: 3, maxInputTokens: 10_000, maxOutputTokens: 1000, maxWallMinutes: 1 },
    recorder: new LocalTrajectoryRecorder(new EventStore()), execute: async (c) => { ran.push(c); return "ok"; },
  });
  assert.match(ran[0], new RegExp(`curl .*'http://web-01\\.${d.replace(/\./g, "\\.")}/'`));
  assert.match(ran[1], new RegExp(`getent ahostsv4 'db-01\\.${d.replace(/\./g, "\\.")}'`));
  assert.match(ran[2], /psql -h 'db-01\..*' -U arena_staff -d app/, "employees use their own read-only role, never the shared app account");
  assert.ok(!ran[2].includes("-U app "), "the app account is the planted weak credential and stays red's");
  assert.match(ran[3], new RegExp(`swaks --to 'probe@${d.replace(/\./g, "\\.")}' --server 'mail-01\\.`));
  assert.ok(!ran.some((c) => c.includes(".local")), "no .local names: they do not resolve on the lab segment");
  assert.equal(res.refused.length, 1, "the attacker guest is not an employee destination");
  assert.ok(res.performed.every((p) => !/Arena-/.test(p.detail)), "the staff password never appears in the recorded detail");
});

test("LFI/path-traversal rule: matches red's recorded probes, not ordinary intranet requests", async () => {
  const { loadSigmaDir, compileRule } = await import("../dist/detections/sigma.js");
  const rule = (await loadSigmaDir(new URL("../detections", import.meta.url).pathname)).find((r) => r.id === "40f81152-ba0f-4f69-ae50-e4b3d36f22a7");
  assert.ok(rule, "rule loads");
  assert.equal(rule.techniqueId, "T1190");
  const m = compileRule(rule);
  const req = (path) => ({ runId: "r", hostId: "web-01", kind: "http.request", actor: "red", at: "2026-11-04T00:00:00Z", detail: { path } });
  for (const p of ["/index.php?page=php%3A%2F%2Ffilter%2Fconvert.base64-encode%2Fresource%3Dindex.php", "/index.php?file=%2Fetc%2Fpasswd",
    "/index.php?cmd=cat%20/etc/passwd", "/view?f=../../etc/hosts", "/view?f=%2e%2e%2fconfig.php", "/x?f=..%2F..%2Fsecret"]) {
    assert.ok(m(req(p)), `should match ${p}`);
  }
  for (const p of ["/", "/index.php", "/index.php?page=p1", "/api/patients?id=12", "/static/app.js", "/diag.php?host=localhost"]) {
    assert.ok(!m(req(p)), `should not match ${p}`);
  }
  assert.ok(!m({ ...req("/etc/passwd"), kind: "db.statement" }), "only web requests");
});

test("brute-force objectives are recognised by technique even when the model parameterises the signal", async () => {
  const { isAuthFailureObjective } = await import("../dist/exercise/agents.js");
  assert.ok(isAuthFailureObjective({ techniqueId: "T1110", successSignal: "auth-failures" }));
  assert.ok(isAuthFailureObjective({ techniqueId: "T1110", successSignal: "auth-fail-t1110-mail-01" }));
  assert.ok(isAuthFailureObjective({ techniqueId: "T1110.003", successSignal: "anything" }));
  assert.ok(!isAuthFailureObjective({ techniqueId: "T1078", successSignal: "canary-hash-db-01-t1078" }));
  assert.ok(!isAuthFailureObjective({ techniqueId: "T1059", successSignal: "exec-marker" }));
});

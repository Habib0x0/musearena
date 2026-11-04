/**
 * Org-lab demo (T-20): the 12-person clinic, end to end on real guests.
 *
 *   node scripts/org-demo.mjs                          # fixed-seed design (default)
 *   node scripts/org-demo.mjs --prompt "12-person ..." # model design (needs Modal or Meta designer keys)
 *   node scripts/org-demo.mjs --agents                 # Muse Spark Open plays red/blue, Muse Glimmer 30B the personas (Modal)
 *
 * design → deploy → configure → readiness → gates → scripted red/blue →
 * verified dataset → teardown. One exit code. Writes the recorded run to
 * captures/org-demo/<runId>/ (run.json, dataset.json, index.html) so
 * `scripts/org-demo-replay.mjs` can verify it offline.
 *
 * Honest scope: six unbridged user-mode guests on one host. DHCP and
 * cross-host traffic are not exercised (T-15); red acts same-host and is
 * attributed by per-objective markers, not source address.
 */
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, writeFile, rm } from "node:fs/promises";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { promisify } from "node:util";
import { detectHost } from "../dist/provisioner/kvm.js";
import { resolveGoldenImage } from "../dist/provisioner/images.js";
import { destroyRunVms, startRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { execInGuest, probeGuestIdentity, vmTargetsFromState } from "../dist/configurator/vm-ssh.js";
import { inventoryFor, parseRecap, playbookFor } from "../dist/configurator/ansible.js";
import { checkSpecReadiness } from "../dist/configurator/readiness.js";
import { sensorCanary, proofGate } from "../dist/configurator/gates.js";
import { vmGateOptions } from "../dist/configurator/vm-executors.js";
import { runVmExercise } from "../dist/exercise/vm-live.js";
import { runVmAgentExercise } from "../dist/exercise/vm-agents.js";
import { livePack } from "../dist/exercise/live.js";
import { exportDataset } from "../dist/observability/export.js";
import { assertExportIntegrity } from "../dist/traces/integrity.js";
import { EventStore } from "../dist/observability/events.js";
import { deployability } from "../dist/provisioner/capability.js";
import { checkBudget, digestOf, validateDesign } from "../dist/designer/pipeline.js";
import { topologyFor } from "../dist/designer/topology.js";
import { CLINIC_PROMPT, clinicOrgSpec, clinicOrgSpecWithAttacker } from "../dist/designer/clinic.js";
import { CLINIC_ARCHETYPE, designPin, pinnedDesignDigest } from "../dist/designer/archetypes.js";
import { planDeployment } from "../dist/configurator/plan.js";

// Same env loading as the workflow/integration scripts: `--prompt` needs
// META_API_KEY, and the fixed-seed path must not depend on the caller's shell.
const repoRoot = new URL("../../", import.meta.url).pathname;
for (const f of ["deployment/.platform.env", ".env"]) {
  if (!existsSync(repoRoot + f)) continue;
  for (const l of readFileSync(repoRoot + f, "utf8").split("\n").filter((x) => x.includes("="))) {
    const i = l.indexOf("=");
    process.env[l.slice(0, i).trim()] ??= l.slice(i + 1).trim();
  }
}

const run = promisify(execFile);
const host = detectHost();
const BUDGET = { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 };
// --agents: model agents act from an attacker guest on the lab segment.
const AGENTS = process.argv.includes("--agents");
// Persona agents run on Muse Glimmer (scales to zero): warm it during the build.
let glimmerWarm = null;
if (AGENTS) {
  const { modalPersonaClient } = await import("../dist/lib/model.js");
  glimmerWarm = modalPersonaClient().wake().catch((e) => console.warn(`[personas] warm-up: ${e.message}`));
}
const runId = `run-org-demo-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_DIR ?? path.join(process.cwd(), ".disposable");
process.env.VM_STATE_DIR = stateRoot;
const lifecycle = { stateRoot, runId };
const outDir = path.join(process.cwd(), "captures", "org-demo", runId);

/** Model design when asked; otherwise the recorded fixed-seed design. */
async function design() {
  // --spec <file>: build an exact spec (e.g. one the console designed) to verify it deploys.
  const si = process.argv.indexOf("--spec");
  if (si !== -1) {
    const spec = JSON.parse(readFileSync(process.argv[si + 1], "utf8"));
    return { spec, mode: "spec-file", prompt: spec.name, archetype: null, plan: planDeployment(spec) };
  }
  const i = process.argv.indexOf("--prompt");
  if (i === -1) {
    const spec = AGENTS ? clinicOrgSpecWithAttacker() : clinicOrgSpec();
    return { spec, mode: "fixed-seed", prompt: CLINIC_PROMPT, archetype: CLINIC_ARCHETYPE, plan: planDeployment(spec) };
  }
  const prompt = process.argv[i + 1];
  if (!prompt) throw new Error("--prompt needs a value");
  const { designerModelClient } = await import("../dist/lib/model.js");
  const designer = designerModelClient();
  if (!designer) throw new Error("--prompt needs a designer model (MODAL_PROXY_TOKEN_ID/MODAL_PROXY_TOKEN_SECRET or META_API_KEY); omit the flag to use the fixed-seed design");
  const { orchestrateDesign } = await import("../dist/designer/orchestrator.js");
  const pkg = await orchestrateDesign(designer, prompt, BUDGET);
  if (!pkg.canProvision) throw new Error(`design not deployable: ${pkg.blockReasons.join("; ")}`);
  return { spec: pkg.spec, mode: "model-prompt", prompt, archetype: null, plan: pkg.plan };
}

const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

function page(a) {
  const card = (label, value) => `<div class="card"><span class="k">${esc(label)}</span><strong>${esc(value)}</strong></div>`;
  const subnet = (s) => `<h3>${esc(s.name)} <span class="dim">${esc(s.cidr)} · zone ${esc(s.zone)}</span></h3>
    <table><tr><th>host</th><th>role</th><th>os</th><th>services</th><th>weaknesses</th></tr>
    ${s.nodes.map((n) => `<tr><td>${esc(n.hostId)}</td><td>${esc(n.role)}</td><td>${esc(n.os)}</td><td>${esc(n.services.join(", "))}</td><td>${n.vulnCount}</td></tr>`).join("\n")}</table>`;
  const ready = a.readiness.flatMap((h) => h.checks.map((c) => `<tr><td>${esc(h.hostId)}</td><td>${esc(c.kind)}/${esc(c.probe)}</td><td class="${c.ok ? "ok" : "bad"}">${c.ok ? "PASS" : "FAIL"}</td><td class="dim">${esc(c.detail)}</td></tr>`)).join("\n");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Org-lab demo — ${esc(a.runId)}</title>
<style>
:root{color-scheme:light dark}body{font:14px/1.45 ui-sans-serif,system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem}
h1{margin:0 0 .2rem}.sub,.dim{opacity:.65;font-size:.85em}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(11rem,1fr));gap:.6rem;margin:1.2rem 0}
.card{border:1px solid #8884;border-radius:.5rem;padding:.6rem .75rem;display:flex;flex-direction:column;gap:.25rem}
.card .k{opacity:.6;font-size:.75em;text-transform:uppercase;letter-spacing:.04em}
table{border-collapse:collapse;width:100%;margin:.4rem 0 1.2rem}
th,td{border-bottom:1px solid #8883;padding:.3rem .5rem;text-align:left}
th{font-size:.75em;text-transform:uppercase;letter-spacing:.04em;opacity:.6}
.ok{color:#12805c}.bad{color:#b42318;font-weight:600}
code{font-size:.85em}footer{margin-top:2rem;opacity:.6;font-size:.8em}
</style></head><body>
<h1>12-person clinic — org lab</h1>
<p class="sub"><code>${esc(a.runId)}</code> · ${esc(a.backend)} · ${esc(a.design.mode)} design · ${esc(a.image.name)}</p>
<p class="sub">pin: ${esc(a.design.pin.archetype)} · catalog ${esc(a.design.pin.catalog)} · profile ${esc(a.design.pin.profile)} · image ${esc(a.design.pin.image)}</p>
<section class="cards">
${card("Objectives", `${a.score.objectivesAchieved}/${a.score.objectivesTotal}`)}
${card("Points", `${a.score.pointsEarned}/${a.score.pointsTotal}`)}
${card("Alerts", `${a.exercise.alerts} · ${a.exercise.falsePositives} FP`)}
${card("Benign events", a.exercise.benignEvents)}
${card("Dataset", a.dataset.contentHash.slice(0, 23) + "…")}
${card("Run time", `${(a.durationMs / 1000).toFixed(0)}s`)}
</section>
<h2>Topology</h2>${a.topology.subnets.map(subnet).join("\n")}
<h2>Readiness</h2><table><tr><th>host</th><th>probe</th><th>result</th><th>detail</th></tr>${ready}</table>
<h2>Gates</h2><table><tr><th>host</th><th>canary</th></tr>
${a.gates.canaries.map((c) => `<tr><td>${esc(c.hostId)}</td><td class="${c.pass ? "ok" : "bad"}">${c.pass ? "PASS" : "FAIL"}</td></tr>`).join("\n")}
<tr><td>proof</td><td class="${a.gates.proof.pass ? "ok" : "bad"}">${a.gates.proof.pass ? "PASS" : "FAIL"}</td></tr></table>
<h2>Timeline</h2><ol>${a.timeline.map((t) => `<li>${esc(t)}</li>`).join("")}</ol>
<footer>${a.exercise.mode === "agents" ? `Model agents (${esc(Object.values(a.agents.modelIds).join(", "))}) acting from an attacker guest` : "Scripted red/blue"} on unbridged user-mode guests: red acts same-host and is labelled by per-objective marker. Not exercised: DHCP, cross-host requests (T-15), and log forwarding — log-01 accepts syslog on 514 but hosts do not ship to it yet. Dataset <code>${esc(a.dataset.contentHash)}</code>, ${a.dataset.steps} steps.</footer>
</body></html>
`;
}

let primaryError = null;
const t0 = Date.now();
const timeline = [];
const lap = (s) => { timeline.push(`${((Date.now() - t0) / 1000).toFixed(1)}s — ${s}`); console.log(`[${((Date.now() - t0) / 1000).toFixed(1)}s] ${s}`); };
await mkdir(outDir, { recursive: true });
const artifact = { runId, backend: "kvm", host, timeline, design: null, plan: null, image: null, topology: null, readiness: [], gates: null, score: null, exercise: null, dataset: null, durationMs: 0 };

try {
  const designed = await design();
  const spec = designed.spec;
  const violations = validateDesign(spec);
  const budget = checkBudget(spec, BUDGET);
  const undeployable = deployability(spec);
  assert.deepEqual([...violations, ...budget, ...undeployable], [], `design rejected: ${[...violations, ...budget, ...undeployable].join("; ")}`);
  assert.deepEqual(designed.plan.gaps, [], `plan gaps: ${designed.plan.gaps.join("; ")}`);
  artifact.plan = designed.plan;
  await writeFile(path.join(outDir, "plan.json"), JSON.stringify(designed.plan, null, 2));
  lap(`plan: ${designed.plan.hosts.length} hosts, ${new Set(designed.plan.hosts.flatMap((h) => h.packages)).size} packages, ${designed.plan.edges.length} edges, ${designed.plan.steps.length} steps, $${designed.plan.totals.dollarsPerHour}/hr, dns ${designed.plan.topology.domain}`);
  // Pin the versions that produced this design alongside its bare spec digest.
  const pin = designPin(designed.archetype);
  artifact.design = { mode: designed.mode, prompt: designed.prompt, digest: digestOf(spec), pin, pinnedDigest: pinnedDesignDigest(spec, pin) };
  artifact.spec = spec; // replay re-scores from this + the recorded dataset, offline
  artifact.topology = topologyFor(spec);
  lap(`design: ${designed.mode}, ${spec.instances.length} hosts, ${pin.archetype}, pinned ${artifact.design.pinnedDigest.slice(0, 19)}…`);

  const golden = await resolveGoldenImage(host.hostArch);
  artifact.image = { name: golden.image.name, digest: golden.image.digest };
  lap(`image: ${golden.image.name}`);

  const res = await startRunVms(spec, { ...lifecycle, golden }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const state = res.state;
  for (const inst of Object.values(state.instances)) {
    const id = await probeGuestIdentity(inst, { runId }, { attempts: 45, delayMs: 2000, timeoutMs: 15000 });
    lap(`${inst.hostId}: ssh-ready as ${id.user}`);
  }

  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 15 * 60_000, maxBuffer: 16 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [h, r] of recap) lap(`configure ${h}: ok=${r.ok}`);
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed: ${stdout.slice(-2500)}`);

  artifact.readiness = await checkSpecReadiness({
    spec, runId,
    sshUserOf: (hostId) => state.instances[hostId]?.ssh?.user ?? "arena",
    exec: async (hostId, command, timeoutMs) => {
      const inst = state.instances[hostId];
      if (!inst) throw new Error(`no VM ${hostId}`);
      return (await execInGuest(inst, command, { timeoutMs })).stdout;
    },
  });
  for (const h of artifact.readiness) lap(`readiness ${h.hostId}: ${h.checks.map((c) => `${c.probe}=${c.ok ? "PASS" : "FAIL"}`).join(" ")}`);
  if (artifact.readiness.some((h) => !h.ok)) throw new Error(`readiness failed: ${JSON.stringify(artifact.readiness.filter((h) => !h.ok))}`);

  const gateStore = new EventStore();
  const gates = vmGateOptions(spec, { runId, store: gateStore });
  const canaries = [];
  for (const inst of spec.instances.filter((i) => i.runtime === "vm")) {
    const c = await sensorCanary(runId, inst.hostId, gates);
    canaries.push({ hostId: inst.hostId, pass: c.pass, details: c.details });
    if (!c.pass) throw new Error(`canary failed on ${inst.hostId}: ${c.details.join("; ")}`);
  }
  const proof = await proofGate({ runId, spec }, gates);
  artifact.gates = { canaries, proof: { pass: proof.pass, details: proof.details } };
  lap(`gates: ${canaries.length}/${canaries.length} canaries, proof ${proof.pass ? "PASS" : "FAIL"}`);
  if (!proof.pass) throw new Error(`proof gate failed: ${proof.details.join("; ")}`);

  const store = new EventStore();
  const pack = await livePack();
  const runRec = { runId, orgId: "demo-org", deploymentId: "demo-deployment", mode: "blind", specDigest: artifact.design.pinnedDigest, techniquePackVersion: "v1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm" };
  let ex;
  if (AGENTS) {
    const { ModalModelClient, personaClientOrFallback } = await import("../dist/lib/model.js");
    const agent = new ModalModelClient();
    await glimmerWarm;
    const personas = await personaClientOrFallback(agent);
    lap(`exercise: model agents — red/blue ${agent.modelId}, personas ${personas.modelId}`);
    ex = await runVmAgentExercise({ spec, run: runRec }, { store, detections: pack.store, state, agent, personas,
      // Trajectories are recorded locally into the dataset; external trace export is opt-in.
      langfuse: process.env.ORG_DEMO_LANGFUSE ? undefined : null });
    ex.enforcement = ex.enforcement ? [ex.enforcement] : [];
    artifact.agents = {
      modelIds: ex.run.modelIds, shiftReport: ex.shiftReport, guardrails: ex.guardrails, redCampaign: ex.redCampaign,
      blueProposals: ex.blueProposals,
      states: Object.fromEntries(Object.entries(ex.agentStates).map(([k, v]) => [k, { steps: v.steps, inputTokens: v.inputTokens, outputTokens: v.outputTokens, stoppedByCap: v.stoppedByCap ?? null }])),
    };
  } else {
    ex = await runVmExercise({ spec, run: runRec }, { store, detections: pack.store, state });
  }
  artifact.score = ex.scorecard;
  artifact.exercise = { mode: AGENTS ? "agents" : "scripted", alerts: ex.alerts.length, falsePositives: ex.falsePositives, benignEvents: ex.benignEvents, redSteps: ex.redSteps, falsePositiveDetail: ex.falsePositiveDetail };
  lap(`exercise: ${ex.scorecard.objectivesAchieved}/${ex.scorecard.objectivesTotal} objectives, ${ex.scorecard.pointsEarned}/${ex.scorecard.pointsTotal} points, ${ex.alerts.length} alerts, ${ex.falsePositives} FP`);
  for (const e of ex.enforcement) lap(`response ${e.response} on ${e.hostId}${e.target ? ` -> ${e.target}` : ""} enforced=${e.enforced}${e.verifiedBlocked !== undefined ? ` verified_blocked=${e.verifiedBlocked}` : ""} (${e.detail ?? e.reason ?? e.verifyDetail ?? ""})`);
  if (!AGENTS && ex.enforcement.length > 0 && !ex.enforcement.some((e) => e.enforced)) {
    throw new Error(`no response was enforced: ${JSON.stringify(ex.enforcement)}`);
  }
  // The scripted baseline must clear every objective (it defines solvability);
  // a model run is evidence of the loop, and its score is reported as is.
  if (!AGENTS && ex.scorecard.objectivesAchieved !== spec.objectives.length) throw new Error(`objectives ${ex.scorecard.objectivesAchieved}/${spec.objectives.length}`);
  if (ex.falsePositives !== 0) throw new Error(`false positives: ${ex.falsePositives} (${JSON.stringify(ex.falsePositiveDetail)})`);

  const exp = exportDataset(ex.run, "train", { store });
  assertExportIntegrity(exp);
  const datasetPath = path.join(outDir, "dataset.json");
  await writeFile(datasetPath, JSON.stringify(exp));
  artifact.dataset = { contentHash: exp.meta.contentHash, steps: exp.join.steps.length, path: path.relative(process.cwd(), datasetPath) };
  lap(`dataset: ${exp.meta.contentHash.slice(0, 20)}… (${exp.join.steps.length} steps)`);

  artifact.durationMs = Date.now() - t0;
  await writeFile(path.join(outDir, "run.json"), JSON.stringify(artifact, null, 2));
  await writeFile(path.join(outDir, "index.html"), page(artifact));
  lap(`recorded: ${path.relative(process.cwd(), outDir)}`);
  console.log("ORG DEMO OK");
} catch (err) {
  primaryError = err;
  console.error("ORG DEMO FAILURE:", err instanceof Error ? err.message : err);
  artifact.error = err instanceof Error ? err.message : String(err);
  artifact.durationMs = Date.now() - t0;
  await writeFile(path.join(outDir, "run.json"), JSON.stringify(artifact, null, 2)).catch(() => undefined);
} finally {
  await destroyRunVms(lifecycle).catch((e) => { primaryError ??= e; });
  const leaked = await new Promise((resolve) => {
    try {
      execFile("pgrep", ["-f", `musearena-${runId}-`], (e, out) => resolve(!e && out.trim().length > 0));
    } catch { resolve(false); }
  });
  if (leaked) primaryError ??= new Error(`leaked QEMU processes for ${runId}`);
  console.log(leaked ? "LEAKED QEMU" : "destroyed: no leaked QEMU");
  if (!primaryError) await rm(path.join(stateRoot, "ansible", runId), { recursive: true, force: true });
}
if (primaryError) process.exit(1);

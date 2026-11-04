/**
 * Benign-only control run (T-14 acceptance: "benign-only control run produces
 * FP-rate baseline"). Deploys a real env with the real Pulumi program and
 * Ansible tasks, runs the live exercise in control mode (personas act, red
 * does not) with the promoted pack, prints the FP baseline, destroys the env.
 *     node scripts/control-run.mjs [noiseRounds]
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import path from "node:path";
import { LocalWorkspace } from "@pulumi/pulumi/automation/index.js";
import { program } from "../dist/provisioner/generate.js";
import { playbookFor, inventoryFor } from "../dist/configurator/ansible.js";
import { containerName } from "../dist/provisioner/names.js";
import { runLiveExercise, livePack } from "../dist/exercise/live.js";
import { EventStore } from "../dist/observability/events.js";

const rounds = Number(process.argv[2] ?? 10);
const runId = `run-ctl${randomBytes(3).toString("hex")}-${Date.now()}`;
const spec = {
  version: 1, name: "control-org", provider: "kvm", seed: "c1", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.249.0.0/16", subnets: [], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu 24.04", stack: ["php"], services: ["http"], databases: [] },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu 24.04", stack: [], services: ["postgres"], databases: ["app"] },
  ],
  personas: [
    { id: "ceo", role: "ceo", workstation: "web-01", access: [], credentialsProfile: "strong", riskProfile: "medium", routine: "", relationships: [] },
    { id: "intern", role: "intern", workstation: "web-01", access: [], credentialsProfile: "weak", riskProfile: "high", routine: "", relationships: [] },
  ],
  objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 1 }],
  requiredTelemetry: ["auditd"],
  plantedVulns: [{ id: "v1", type: "weak-cred", techniqueId: "T1078", targetHostId: "db-01", pinnedVersion: "16", proofAtomicGuid: "g1", difficulty: "standard" }],
  budgets: { maxInstances: 4, maxDollarsPerHour: 1, ttlHours: 1 },
};
const passFile = "/tmp/musearena-smoke-passphrase";
if (!existsSync(passFile)) writeFileSync(passFile, randomBytes(24).toString("hex"), { mode: 0o600 });
const stateDir = path.join(process.cwd(), ".pulumi-state", "control");
mkdirSync(stateDir, { recursive: true });
const stack = await LocalWorkspace.createOrSelectStack(
  { stackName: "control", projectName: "musearena-control", program: async () => program({ spec, orgId: "control", runId, cidrOctet: 249 }) },
  { envVars: { PULUMI_BACKEND_URL: `file://${stateDir}`, PULUMI_CONFIG_PASSPHRASE: readFileSync(passFile, "utf8").trim() } },
);
try {
  await stack.up();
  const dir = `/tmp/control-${runId}`; mkdirSync(dir, { recursive: true });
  writeFileSync(`${dir}/inv.json`, inventoryFor(spec, spec.instances.map((i) => ({ hostId: i.hostId, name: i.name, connectVia: containerName(runId, i.hostId) }))));
  writeFileSync(`${dir}/pb.yml`, playbookFor(spec, runId));
  execFileSync("ansible-playbook", [`${dir}/pb.yml`, "-i", `${dir}/inv.json`], { stdio: "ignore" });
  await new Promise((r) => setTimeout(r, 1500));
  const pack = await livePack();
  const run = { runId, orgId: "control", deploymentId: "control", mode: "blind", specDigest: "control", techniquePackVersion: "attack-15.1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm" };
  const res = await runLiveExercise({ spec, run }, { store: new EventStore(), detections: pack.store, langfuse: null, control: true, noiseRounds: rounds });
  console.log(JSON.stringify({ control: true, rounds, promotedRules: pack.promoted.length, redSteps: res.redSteps, benignEvents: res.benignEvents, alerts: res.alerts.length, falsePositives: res.falsePositives, falsePositiveRate: res.scorecard.falsePositiveRate, objectivesAchieved: res.scorecard.objectivesAchieved, fpDetail: res.falsePositiveDetail }, null, 1));
} finally {
  await stack.destroy();
  await stack.workspace.removeStack("control");
  const left = execFileSync("docker", ["ps", "-aq", "--filter", `label=arena.run_id=${runId}`], { encoding: "utf8" }).trim();
  console.log(left ? `LEAKED: ${left}` : "control env destroyed, nothing left");
}

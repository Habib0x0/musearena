/**
 * Record a calibration replay for Sigma promotion (T-12). Deploys a throwaway
 * env via the real Pulumi program, configures it with the real Ansible tasks,
 * performs benign traffic and the planted attacks from the attacker container,
 * then writes the COLLECTED telemetry (out-of-band docker logs, normalized and
 * attributed by the real collector) to detections/replay/<name>.jsonl.
 * The env is destroyed afterwards. No Supabase/Temporal needed.
 */
import { writeFileSync, mkdirSync, readFileSync, existsSync } from "node:fs";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { LocalWorkspace } from "@pulumi/pulumi/automation/index.js";
import { program } from "../dist/provisioner/generate.js";
import { playbookFor, inventoryFor } from "../dist/configurator/ansible.js";
import { containerName } from "../dist/provisioner/names.js";
import { collectTelemetry, windowStart } from "../dist/observability/docker-telemetry.js";
import { WEAK_DB_PASSWORD } from "../dist/provisioner/roles.js";

const name = process.argv[2] ?? "calibration-v1";
const runId = `run-replay${randomBytes(2).toString("hex")}-${Date.now()}`;
const spec = {
  version: 1, name: "replay-org", provider: "kvm", seed: "r1", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.250.0.0/16", subnets: [], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu 24.04", stack: ["php"], services: ["http"], databases: [] },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu 24.04", stack: [], services: ["postgres"], databases: ["app"] },
  ],
  personas: [{ id: "p1", role: "clerk", workstation: "web-01", access: [], credentialsProfile: "weak", riskProfile: "low", routine: "", relationships: [] }],
  objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 1 }],
  requiredTelemetry: ["auditd"],
  plantedVulns: [
    { id: "v1", type: "weak-cred", techniqueId: "T1078", targetHostId: "db-01", pinnedVersion: "16", proofAtomicGuid: "g1", difficulty: "standard" },
    { id: "v2", type: "code-flaw", techniqueId: "T1059", targetHostId: "web-01", pinnedVersion: "8.2", proofAtomicGuid: "g2", difficulty: "standard" },
  ],
  budgets: { maxInstances: 4, maxDollarsPerHour: 1, ttlHours: 1 },
};
const passFile = "/tmp/musearena-smoke-passphrase";
if (!existsSync(passFile)) writeFileSync(passFile, randomBytes(24).toString("hex"), { mode: 0o600 });
const stateDir = path.join(process.cwd(), ".pulumi-state", "replay");
mkdirSync(stateDir, { recursive: true });
const stack = await LocalWorkspace.createOrSelectStack(
  { stackName: "replay", projectName: "musearena-replay", program: async () => program({ spec, orgId: "replay", runId, cidrOctet: 250 }) },
  { envVars: { PULUMI_BACKEND_URL: `file://${stateDir}`, PULUMI_CONFIG_PASSPHRASE: readFileSync(passFile, "utf8").trim() } },
);
const sh = (args) => { try { return execFileSync("docker", args, { encoding: "utf8", timeout: 30_000 }); } catch (e) { return e.stdout ?? ""; } };
try {
  await stack.up();
  const dir = `/tmp/replay-${runId}`; mkdirSync(dir, { recursive: true });
  const targets = spec.instances.map((i) => ({ hostId: i.hostId, name: i.name, connectVia: containerName(runId, i.hostId) }));
  writeFileSync(`${dir}/inv.json`, inventoryFor(spec, targets));
  writeFileSync(`${dir}/pb.yml`, playbookFor(spec, runId));
  execFileSync("ansible-playbook", [`${dir}/pb.yml`, "-i", `${dir}/inv.json`], { stdio: "inherit" });
  await new Promise((r) => setTimeout(r, 1000));
  const startedAt = await windowStart(spec, runId);
  const since = new Date(startedAt - 5000).toISOString();
  const web = containerName(runId, "web-01"), db = containerName(runId, "db-01"), atk = containerName(runId, "attacker");
  // benign
  for (let i = 0; i < 5; i++) { sh(["exec", web, "curl", "-s", "-o", "/dev/null", "http://127.0.0.1/"]); sh(["exec", db, "psql", "-U", "app", "-d", "app", "-tAc", "SELECT count(*) FROM employees"]); }
  // attacks
  sh(["exec", atk, "wget", "-q", "-T", "5", "-O", "-", `http://web-01/diag.php?host=${encodeURIComponent("x;id")}`]);
  sh(["exec", "-e", `PGPASSWORD=${WEAK_DB_PASSWORD}`, atk, "psql", "-h", "db-01", "-U", "app", "-d", "app", "-tAc", "SELECT value FROM secrets"]);
  await new Promise((r) => setTimeout(r, 1500));
  const events = (await collectTelemetry(spec, runId, { since, localActor: "noise" })).filter((e) => Date.parse(e.at) > startedAt);
  const out = path.join(process.cwd(), "detections", "replay", `${name}.jsonl`);
  // Strip the throwaway run id so the corpus is env-independent.
  writeFileSync(out, events.map((e) => JSON.stringify({ ...e, runId: "calibration" })).join("\n") + "\n");
  const by = events.reduce((a, e) => ((a[`${e.actor}:${e.kind}`] = (a[`${e.actor}:${e.kind}`] ?? 0) + 1), a), {});
  console.log(`wrote ${events.length} events to ${out}`, by);
} finally {
  await stack.destroy();
  await stack.workspace.removeStack("replay");
  const left = sh(["ps", "-aq", "--filter", `label=arena.run_id=${runId}`]).trim();
  console.log(left ? `LEAKED containers: ${left}` : "replay env destroyed, nothing left");
}

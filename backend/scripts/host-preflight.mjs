/**
 * Host preflight for MuseArena org labs (T-15) — not a test.
 *   node scripts/host-preflight.mjs          # human report
 *   node scripts/host-preflight.mjs --json   # machine report (HostVirt + blockers)
 *   node scripts/host-preflight.mjs --require-kvm
 *     exit 1 unless this host can run SCORED VM labs (native KVM + tools).
 *
 * Honest by construction: an HVF/TCG host reports dev-only; nothing here
 * upgrades a host it cannot verify.
 */
import { existsSync, accessSync, constants } from "node:fs";
import { execFileSync } from "node:child_process";
import { detectHost, scoredVmAccel } from "../dist/provisioner/kvm.js";

const host = detectHost();
const bin = (name) => {
  try { return execFileSync("which", [name], { encoding: "utf8" }).trim() || null; } catch { return null; }
};
const version = (cmd, args) => {
  try { return execFileSync(cmd, args, { encoding: "utf8", timeout: 10_000 }).split("\n")[0].trim(); } catch { return null; }
};
const writable = (p) => { try { accessSync(p, constants.W_OK); return true; } catch { return false; } };

const tools = {
  docker: bin("docker"), ansible: bin("ansible-playbook"), pulumi: bin("pulumi"),
  qemuX86: host.qemuX86, qemuArm: host.qemuArm,
};
const versions = {
  node: process.version,
  docker: tools.docker ? version("docker", ["--version"]) : null,
  ansible: tools.ansible ? version("ansible-playbook", ["--version"]) : null,
  pulumi: tools.pulumi ? version("pulumi", ["version"]) : null,
  qemuNative: (host.hostArch === "aarch64" ? host.qemuArm : host.qemuX86)
    ? version(host.hostArch === "aarch64" ? host.qemuArm : host.qemuX86, ["--version"]) : null,
};
const kvmDevice = process.platform === "linux" && existsSync("/dev/kvm");
const kvmWritable = kvmDevice && writable("/dev/kvm");
const scoredAccel = scoredVmAccel(host);
const dockerDaemon = tools.docker ? version("docker", ["info", "--format", "{{.ServerVersion}}"]) : null;
const policyDeps = existsSync(new URL("../policy/node_modules/@pulumi/policy/package.json", import.meta.url));

const blockers = [];
if (!scoredAccel) blockers.push(`no native acceleration for scored VM runs (${host.reason})`);
if (process.platform === "linux" && kvmDevice && !kvmWritable) blockers.push("/dev/kvm exists but is not writable by this user (kvm group?)");
if (process.platform !== "linux") blockers.push(`platform ${process.platform}: VM labs are dev-only here (scored labs need Linux/KVM)`);
if (!tools.docker) blockers.push("docker not found (container runtime + platform plane)");
if (tools.docker && !dockerDaemon) blockers.push("docker daemon is not reachable by this user (docker group?)");
if (!tools.ansible) blockers.push("ansible-playbook not found (configurator)");
if (!tools.pulumi) blockers.push("pulumi not found (provisioner/platform Automation API)");
if (!policyDeps) blockers.push("backend/policy dependencies are not installed (run npm ci in backend/policy)");

const report = {
  platform: host.platform, arch: host.arch, hostArch: host.hostArch,
  accel: host.accel, scoredAccel, canKvmVmiClaim: host.canKvmVmi,
  truthLayerCap: "mirror-only", // KVM alone never justifies a kvm-vmi claim
  kvmDevice, kvmWritable, dockerDaemon, policyDeps, tools, versions, blockers,
  verdict: blockers.length === 0 ? "scored-vm-labs-ok" : process.platform === "linux" ? "blocked" : "dev-only",
};

if (process.argv.includes("--json")) {
  console.log(JSON.stringify(report, null, 2));
} else {
  console.log(`host: ${report.platform}/${report.arch} (guest arch ${report.hostArch})`);
  console.log(`accel: ${report.accel}${scoredAccel ? ` (scored runs: ${scoredAccel})` : " (scored VM runs: REFUSED)"} — ${host.reason}`);
  console.log(`/dev/kvm: ${kvmDevice ? (kvmWritable ? "present, writable" : "present, NOT writable") : "absent"}`);
  console.log(`tools: docker=${tools.docker ?? "MISSING"} daemon=${dockerDaemon ?? "UNREACHABLE"} ansible=${tools.ansible ?? "MISSING"} pulumi=${versions.pulumi ?? "MISSING"} policy=${policyDeps ? "installed" : "MISSING"} qemu-native=${versions.qemuNative ?? "MISSING"}`);
  console.log(`truth cap: mirror-only (KVM is not VMI)`);
  for (const b of blockers) console.log(`BLOCKER: ${b}`);
  console.log(`verdict: ${report.verdict}`);
}
if (process.argv.includes("--require-kvm") && report.verdict !== "scored-vm-labs-ok") process.exit(1);

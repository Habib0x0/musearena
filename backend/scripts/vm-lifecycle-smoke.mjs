/**
 * Live VM lifecycle smoke (T-15b) — real QEMU, Debian golden image.
 *   node scripts/vm-lifecycle-smoke.mjs          # arm64 host: HVF (dev-only)
 *   node scripts/vm-lifecycle-smoke.mjs --with-network-fetch
 * Proves: golden image hash-verified → CoW overlay → seed ISO → persistent
 * guest starts (pidfile, registry) → destroy cleans everything.
 * On Linux/KVM the same script with accel=kvm is the scored-host variant;
 * HVF success proves lifecycle + seed + boot-to-userspace only.
 */
import { existsSync, readFileSync, rmSync } from "node:fs";
import path from "node:path";
import { detectHost } from "../dist/provisioner/kvm.js";
import { resolveGoldenImage } from "../dist/provisioner/images.js";
import { startRunVms, destroyRunVms, vmStateDir } from "../dist/provisioner/vm-lifecycle.js";
import { probeGuestIdentity } from "../dist/configurator/vm-ssh.js";

const host = detectHost();
const spec = {
  version: 1, name: "lifecycle-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: ["http"], databases: [], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: ["postgres"], databases: ["app"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
  ],
  personas: [], objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary", points: 10 }],
  requiredTelemetry: ["auditd"], plantedVulns: [], budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const runId = `run-vm-smoke-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const isoTool = process.env.ISO_TOOL || undefined;
const lifecycle = { stateRoot, runId, isoTool };
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

const bootWaitMs = Number(process.env.VM_BOOT_WAIT_MS ?? 120000);

let primaryError = null;
try {
  const golden = await resolveGoldenImage(host.hostArch);
  lifecycle.golden = golden;
  console.log("image:", golden.image.name, golden.image.digest);
  const res = await startRunVms(spec, lifecycle, (hostId, pubKey) => ({ hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId } }));
  const dir = vmStateDir(lifecycle);
  for (const [hostId, inst] of Object.entries(res.state.instances)) {
    console.log(`${hostId}: image=${inst.imageName} pid ${inst.pid} overlay=${inst.overlay} mode=${inst.netMode}`);
    assert(existsSync(inst.overlay), `${hostId} overlay missing`);
    const alive = (() => { try { process.kill(inst.pid, 0); return true; } catch { return false; } })();
    assert(alive, `${hostId} QEMU pid ${inst.pid} not alive after start`);
    // Wait for the guest's serial log to show real userspace (UEFI/kernel/init).
    // With EDK2 wired, a Debian cloud guest reaches init in seconds under HVF;
    // zero bytes within the wait means the guest never booted — that fails.
    const serial = path.join(dir, `${hostId}-serial.log`);
    const deadline = Date.now() + bootWaitMs;
    let log = "";
    while (Date.now() < deadline) {
      log = existsSync(serial) ? readFileSync(serial, "utf8") : "";
      if (/login:|systemd|cloud-init|Linux.*Debian|Debian GNU\/Linux/.test(log)) break;
      await new Promise((r) => setTimeout(r, 2000));
    }
    const sawUserspace = /login:|cloud-init|Debian GNU\/Linux|Linux version|init/.test(log);
    console.log(`${hostId}: serial ${log.length} bytes, userspace seen: ${sawUserspace}`);
    assert(sawUserspace, `${hostId} produced no Debian userspace on serial within ${bootWaitMs}ms (head: ${JSON.stringify(log.slice(0, 160))})`);
    assert(inst.ssh, `${hostId} has no SSH endpoint in the registry`);
    const identity = await probeGuestIdentity(inst, { runId }, { attempts: 45, delayMs: 2000, timeoutMs: 15000 });
    console.log(`${hostId}: SSH ready — hostname=${identity.hostname} user=${identity.user} RUN_ID/HOST_ID match seed`);
  }
  console.log("registry:", JSON.stringify(Object.keys(res.state.instances)));
  console.log("VM LIFECYCLE LIVE-START OK (guests on the run lab segment)");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message : err);
} finally {
  const r = await destroyRunVms(lifecycle);
  assert(r.removed || !primaryError, "destroy did not remove state dir");
  // No leaked QEMU for this run name.
  const leaked = await new Promise((resolve) => {
    import("node:child_process").then(({ execFileSync }) => {
      try { resolve(execFileSync("pgrep", ["-f", `musearena-${runId}-`], { encoding: "utf8" }).trim().length > 0); } catch { resolve(false); }
    }).catch(() => resolve(false));
  });
  assert(!leaked, `leaked QEMU processes for ${runId}`);
  console.log("destroyed: state removed, no leaked QEMU for run");
  try { rmSync(stateRoot, { recursive: true, force: true }); } catch { /* disposable root */ }
}
if (primaryError) process.exit(1);
console.log("VM LIFECYCLE SMOKE OK");

function assert(cond, msg) { if (!cond) { console.error("ASSERTION FAILED:", msg); process.exit(1); } }

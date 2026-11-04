/**
 * Live lab-L2 smoke (T-15): real QEMU, Debian golden image, two guests that
 * can only talk to each other over the run's lab segment.
 *
 *   node scripts/vm-l2-smoke.mjs
 *
 * Proves the primitive the whole org-lab contract rests on: guests on one
 * run share an L2 segment (`socket,mcast=` on the dev host), each has a
 * static lab address from the spec's subnet, and a TCP connection crosses
 * the segment guest-to-guest. The management NIC keeps its user-net DHCP
 * address, so configuration and SSH hostfwd are unaffected.
 *
 * Not claimed here: DHCP on the lab segment, DNS/LDAP/mail/web→DB service
 * proofs, egress control or enforcement. Those are the next T-15/T-16 steps.
 */
import path from "node:path";
import { detectHost } from "../dist/provisioner/kvm.js";
import { resolveGoldenImage } from "../dist/provisioner/images.js";
import { startRunVms, destroyRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { probeGuestIdentity, execInGuest, waitForLabAddress } from "../dist/configurator/vm-ssh.js";

const host = detectHost();
const runId = `run-vm-l2-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId, isoTool: process.env.ISO_TOOL || undefined };

const spec = {
  version: 1, name: "l2-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "clinic-lan", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "gw-01", name: "gw-01", role: "gateway", runtime: "vm", os: "Debian 12", stack: [], services: ["dns"], databases: [], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
    { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: ["http"], databases: [], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: ["postgres"], databases: ["app"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
  ],
  personas: [], objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary", points: 10 }],
  requiredTelemetry: ["auditd"], plantedVulns: [], budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

let primaryError = null;
try {
  const golden = await resolveGoldenImage(host.hostArch);
  lifecycle.golden = golden;
  console.log("image:", golden.image.name, golden.image.digest);

  const res = await startRunVms(spec, lifecycle, (hostId, pubKey) => ({ hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId } }));
  const vms = Object.values(res.state.instances);
  for (const inst of vms) {
    assert(inst.netMode === "lab", `${inst.hostId} is not on the lab segment (${inst.netMode})`);
    assert(inst.lab?.address, `${inst.hostId} has no lab address in the registry`);
    console.log(`${inst.hostId}: ssh 127.0.0.1:${inst.ssh.port} lab ${inst.lab.address}/${inst.lab.prefix}`);
    const identity = await probeGuestIdentity(inst, { runId }, { attempts: 60, delayMs: 2000, timeoutMs: 15000 });
    assert(identity.user === "arena", `${inst.hostId} SSH user is ${identity.user}`);
    await waitForLabAddress(inst);
    console.log(`${inst.hostId}: lab address applied by cloud-init`);
  }

  const byId = Object.fromEntries(vms.map((i) => [i.hostId, i]));
  assert(byId["gw-01"].lab.address.endsWith(".1"), `gateway address is ${byId["gw-01"].lab.address}, expected .1`);

  // Every guest still has its management address: the lab NIC must be additive.
  for (const inst of vms) {
    const out = await guest(inst, "ip -4 -o addr show | awk '{print $4}' | tr '\\n' ' '");
    console.log(`${inst.hostId}: addresses ${out.trim()}`);
    assert(out.includes("10.0.2."), `${inst.hostId} lost its management DHCP address (${out.trim()})`);
    assert(out.includes(`${inst.lab.address}/${inst.lab.prefix}`), `${inst.hostId} has no ${inst.lab.address} on any interface`);
  }

  // The point of the segment: each guest reaches every other guest's TCP stack.
  for (const from of vms) {
    for (const to of vms) {
      if (to.hostId === from.hostId) continue;
      const out = await guest(from, `timeout 5 bash -c 'exec 3<>/dev/tcp/${to.lab.address}/22 && echo connected' 2>&1 || echo failed`);
      assert(out.includes("connected"), `${from.hostId} could not reach ${to.hostId} (${to.lab.address}:22): ${out.trim()}`);
      console.log(`l2: ${from.hostId} -> ${to.hostId} (${to.lab.address}:22) connected`);
    }
  }
  console.log("VM LAB L2 OK — guest-to-guest TCP over the run.s L2 hub");
} catch (err) {
  primaryError = err;
  console.error("L2 SMOKE FAILURE:", err instanceof Error ? err.message : err);
} finally {
  const r = await destroyRunVms(lifecycle);
  assert(r.removed || !primaryError, "destroy did not remove state dir");
  const leaked = await new Promise((resolve) => {
    import("node:child_process").then(({ execFileSync }) => {
      try { resolve(execFileSync("pgrep", ["-f", `musearena-${runId}-`], { encoding: "utf8" }).trim().length > 0); } catch { resolve(false); }
    }).catch(() => resolve(false));
  });
  assert(!leaked, `leaked QEMU processes for ${runId}`);
  console.log("destroyed: state removed, no leaked QEMU for run");
}
if (primaryError) process.exit(1);
console.log("VM L2 SMOKE OK");

function guest(inst, command) {
  return execInGuest(inst, command, { timeoutMs: 30_000 }).then((r) => r.stdout + r.stderr);
}

function assert(cond, msg) { if (!cond) throw new Error(`assertion failed: ${msg}`); }

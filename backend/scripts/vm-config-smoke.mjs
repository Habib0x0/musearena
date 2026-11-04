/**
 * Live VM configure + readiness smoke (T-16b) — baked image, real Ansible
 * over SSH, protocol probes.
 *
 *   node scripts/vm-config-smoke.mjs [--negative]
 *
 * --negative adds the T-16 acceptance leg: after the positive readiness
 * pass, one declared service at a time is stopped and readiness must fail
 * naming that host and service; restarting it must go green again.
 *
 * Deploy-side prerequisites are the same as vm-lifecycle-smoke.mjs. Proves:
 * the baked catalog image boots, the generated playbook installs/enables the
 * profile over the run's SSH endpoint, and the readiness gate's HTTP and SQL
 * probes answer from inside the guests. No Pulumi/Supabase/worker involved.
 */
import { execFile } from "node:child_process";
import { mkdir, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { detectHost } from "../dist/provisioner/kvm.js";
import { resolveGoldenImage } from "../dist/provisioner/images.js";
import { destroyRunVms, startRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { execInGuest, probeGuestIdentity, vmTargetsFromState } from "../dist/configurator/vm-ssh.js";
import { inventoryFor, parseRecap, playbookFor } from "../dist/configurator/ansible.js";
import { checkSpecReadiness } from "../dist/configurator/readiness.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-config-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

const spec = {
  version: 1, name: "config-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "http", impl: "apache-php" }], dependsOn: ["gw-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 8 } },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: ["app"],
      serviceDecls: [{ kind: "db", impl: "postgres" }], dependsOn: ["gw-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 8 } },
    { hostId: "gw-01", name: "gw-01", role: "sensor", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "dns", impl: "dnsmasq" }, { kind: "dhcp", impl: "dnsmasq" }], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "openldap" }], dependsOn: ["gw-01"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
    { hostId: "mail-01", name: "mail-01", role: "sensor", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "smtp", impl: "postfix" }, { kind: "imap", impl: "dovecot" }], dependsOn: ["gw-01", "dc-01"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
    { hostId: "log-01", name: "log-01", role: "sensor", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "log", impl: "rsyslog-collector" }], dependsOn: ["gw-01"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } },
  ],
  personas: [], objectives: [], requiredTelemetry: ["auditd"], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

let primaryError = null;
try {
  const golden = await resolveGoldenImage(host.hostArch);
  console.log("image:", golden.image.name, golden.image.digest);
  const res = await startRunVms(spec, { ...lifecycle, golden }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const state = res.state;
  for (const inst of Object.values(state.instances)) {
    const id = await probeGuestIdentity(inst, { runId }, { attempts: 45, delayMs: 2000, timeoutMs: 15000 });
    console.log(`${inst.hostId}: image=${inst.imageName} ssh-ready hostname=${id.hostname} user=${id.user}`);
  }

  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  console.log("configure: ansible-playbook over SSH…");
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 15 * 60_000, maxBuffer: 16 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [hostId, r] of recap) console.log(`${hostId}: ${r.line}`);
  const failed = [...recap].filter(([, r]) => !r.ok);
  if (failed.length) throw new Error(`configure failed: ${stdout.slice(-2000)}`);

  const guestExec = async (hostId, command, timeoutMs) => {
    const inst = state.instances[hostId];
    if (!inst) throw new Error(`no VM ${hostId} in registry`);
    return (await execInGuest(inst, command, { timeoutMs })).stdout;
  };
  const runReadiness = async () => {
    const results = await checkSpecReadiness({
      spec, runId,
      sshUserOf: (hostId) => state.instances[hostId]?.ssh?.user ?? "arena",
      exec: guestExec,
    });
    for (const h of results) for (const c of h.checks) console.log(`${h.hostId}: ${c.ok ? "PASS" : "FAIL"} ${c.kind}/${c.probe} — ${c.detail}`);
    return results;
  };
  const readiness = await runReadiness();
  const failedChecks = readiness.filter((h) => !h.ok);
  if (failedChecks.length) throw new Error(`readiness failed: ${JSON.stringify(failedChecks)}`);
  console.log("VM CONFIG + READINESS SMOKE OK");

  if (process.argv.includes("--negative")) {
    // T-16 acceptance: disabling any declared service fails readiness with
    // the host and service named — the gate that keeps the env unscored.
    const cases = [
      { hostId: "web-01", unit: "apache2", kind: "http/apache-php" },
      { hostId: "db-01", unit: "postgresql", kind: "db/postgres" },
    ];
    for (const c of cases) {
      console.log(`negative: stopping ${c.unit} on ${c.hostId}…`);
      await guestExec(c.hostId, `sudo -n systemctl stop ${c.unit}`, 30_000);
      try {
        const down = await runReadiness();
        const host = down.find((h) => h.hostId === c.hostId);
        if (!host || host.ok) throw new Error(`READINESS NEGATIVE: ${c.hostId} still ready with ${c.unit} stopped`);
        const named = host.checks.filter((x) => !x.ok && x.kind === c.kind);
        if (!named.length) throw new Error(`READINESS NEGATIVE: ${c.hostId} failed without naming ${c.kind}: ${JSON.stringify(host.checks)}`);
        console.log(`negative: readiness correctly failed ${c.hostId} on ${c.kind} (${named[0].detail})`);
      } finally {
        await guestExec(c.hostId, `sudo -n systemctl start ${c.unit}`, 30_000).catch(() => undefined);
      }
      let green = null;
      for (let i = 0; i < 6 && !green; i++) {
        const again = await runReadiness().catch(() => null);
        if (again && again.every((h) => h.ok)) green = again;
        else await new Promise((r) => setTimeout(r, 5000));
      }
      if (!green) throw new Error(`READINESS NEGATIVE: readiness did not recover after restarting ${c.unit} on ${c.hostId}`);
      console.log(`negative: readiness green again after restarting ${c.unit} on ${c.hostId}`);
    }
    console.log("VM READINESS NEGATIVE SMOKE OK");
  }
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message : err);
} finally {
  await destroyRunVms(lifecycle);
  const leaked = await new Promise((resolve) => {
    import("node:child_process").then(({ execFileSync }) => {
      try { resolve(execFileSync("pgrep", ["-f", `musearena-${runId}-`], { encoding: "utf8" }).trim().length > 0); } catch { resolve(false); }
    }).catch(() => resolve(false));
  });
  if (leaked) primaryError ??= new Error(`leaked QEMU processes for ${runId}`);
  if (!primaryError) {
    await rm(path.join(stateRoot, "ansible", runId), { recursive: true, force: true });
    // The default root is disposable; a caller-provided VM_STATE_ROOT is shared.
    if (!process.env.VM_STATE_ROOT) await rm(stateRoot, { recursive: true, force: true }).catch(() => undefined);
  }
  console.log(leaked ? "LEAKED QEMU" : "destroyed: state removed, no leaked QEMU");
}
if (primaryError) process.exit(1);

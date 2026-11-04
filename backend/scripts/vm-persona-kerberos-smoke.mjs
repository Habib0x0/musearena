/**
 * Live persona-shift smoke (P4 follow-up): Kerberos-authenticated shifts.
 *
 *   node scripts/vm-persona-kerberos-smoke.mjs
 *
 * Boots dc-01 (Rocky 9, FreeIPA) and ws-01 (Debian member, dependsOn dc-01),
 * configures them with the generated playbook, then runs the production
 * `personaShifts` path with a deterministic shift agent. The member path must:
 *   - kinit as the seeded persona without a tty prompt,
 *   - prove a GSSAPI bind as that user before the model gets a turn,
 *   - run every rendered shift command through `sudo -u <uid>` with the
 *     persona's FILE ccache,
 *   - still hold a usable ticket after the shift (klist + ldapwhoami).
 * A container/non-member workstation keeps the local path; that is a named
 * non-claim, not a silent downgrade.
 */
import { execFile } from "node:child_process";
import { mkdir, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { detectHost } from "../dist/provisioner/kvm.js";
import { ensureGoldenImage, ensureRockyGoldenImage } from "../dist/provisioner/images.js";
import { destroyRunVms, startRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { execInGuest, probeGuestIdentity, waitForLabAddress, vmTargetsFromState } from "../dist/configurator/vm-ssh.js";
import { inventoryFor, parseRecap, playbookFor } from "../dist/configurator/ansible.js";
import { labSecret } from "../dist/configurator/lab.js";
import { labDomainFor, ipaDomainFor } from "../dist/configurator/dns.js";
import { labPlanFor } from "../dist/provisioner/lab-network.js";
import { personaKerberosFor } from "../dist/exercise/persona-auth.js";
import { personaShifts } from "../dist/exercise/vm-agents.js";
import { ScriptedAgentClient } from "../dist/lib/model.js";
import { EventStore } from "../dist/observability/events.js";
import { LocalTrajectoryRecorder } from "../dist/observability/trajectory.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-persona-kerberos-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

const spec = {
  version: 1, name: "persona-kerberos-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "ws-01", name: "ws-01", role: "workstation", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [], dependsOn: ["dc-01"],
      resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "ws-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [], requiredTelemetry: [], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const domain = labDomainFor(spec);
const ipaDomain = ipaDomainFor(spec);
const dcAddr = labPlanFor(spec, runId).find((e) => e.hostId === "dc-01").address;
const adminPw = labSecret(runId, "ipa-admin");
const persona = spec.personas[0];

let primaryError = null;
const proof = async (label, fn) => {
  try { const out = await fn(); console.log(`PROOF PASS ${label}${out ? `: ${String(out).trim().slice(0, 180)}` : ""}`); return out; }
  catch (err) { throw new Error(`PROOF FAIL ${label}: ${err instanceof Error ? err.message.slice(0, 400) : err}`); }
};

try {
  const [rocky, debian] = await Promise.all([ensureRockyGoldenImage(host.hostArch), ensureGoldenImage(host.hostArch)]);
  console.log("images:", rocky.image.name, rocky.image.digest, "|", debian.image.name, debian.image.digest);
  const res = await startRunVms(spec, { ...lifecycle, goldenByFamily: { rocky, debian } }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const state = res.state;
  for (const inst of Object.values(state.instances)) {
    const id = await probeGuestIdentity(inst, { runId }, { attempts: 60, delayMs: 2000, timeoutMs: 15000 });
    console.log(`${inst.hostId}: image=${inst.imageName} ssh-ready hostname=${id.hostname}`);
    await waitForLabAddress(inst);
  }

  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  console.log("configure: ansible-playbook over SSH (FreeIPA install can take several minutes)…");
  let stdout = "";
  let recap = new Map();
  // The Rocky installer/daemon start occasionally drops the management SSH
  // session under HVF. The playbook is idempotent; one retry distinguishes a
  // transient transport loss from a real configure failure.
  for (let attempt = 1; attempt <= 2; attempt++) {
    console.log(`configure attempt ${attempt}…`);
    stdout = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
      timeout: 45 * 60_000, maxBuffer: 32 * 1024 * 1024,
    }).then((r) => r.stdout).catch((e) => `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}`);
    await writeFile(path.join(dir, `ansible-${attempt}.log`), stdout);
    recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
    for (const [hostId, r] of recap) console.log(`${hostId}: ${r.line}`);
    if (recap.size > 0 && [...recap.values()].every((r) => r.ok)) break;
    if (attempt === 1) {
      console.log("configure attempt 1 did not finish cleanly; retrying once…");
      await new Promise((r) => setTimeout(r, 5_000));
    }
  }
  if (recap.size === 0 || [...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed:\n${stdout.slice(-12_000)}`);

  const dc = state.instances["dc-01"], ws = state.instances["ws-01"];
  const exec = (inst, cmd, timeoutMs = 120_000) => execInGuest(inst, cmd, { timeoutMs }).then((r) => r.stdout);

  await proof("dc-01 kinit admin", () => exec(dc, `printf '%s\\n' '${adminPw}' | kinit admin >/dev/null && klist | head -2 && kdestroy`));
  await proof("ws-01 joined + SSSD resolves persona", () => exec(ws, "test -f /etc/ipa/default.conf && systemctl is-active sssd && id p1"));
  await proof("ws-01 DNS SRV via dc-01", () => exec(ws, `dig +short @${dcAddr} _kerberos._udp.${ipaDomain} SRV | head -2`));

  const ctx = personaKerberosFor(spec, runId, persona);
  if (!ctx) throw new Error("personaKerberosFor returned null for a FreeIPA member");
  console.log(`kerberos context: user=${ctx.user} ccache=${ctx.ccache} ldap=${ctx.ldapUri}`);

  // Run the production shift path: setup (kinit + GSSAPI proof) happens
  // before the agent's first turn; every rendered command is then wrapped.
  const executed = [];
  const execute = async (inst, cmd, timeoutMs) => {
    const out = await exec(inst, cmd, timeoutMs);
    executed.push({ cmd, out });
    return out;
  };
  const instOf = async (hostId) => state.instances[hostId];
  const turn = (toolCalls) => ({ text: "", toolCalls, usage: { inputTokens: 20, outputTokens: 5 } });
  const agent = new ScriptedAgentClient([
    turn([
      { callId: "s1", name: "shift", argumentsJson: JSON.stringify({ action: "whoami" }) },
      { callId: "s2", name: "shift", argumentsJson: JSON.stringify({ action: "hostname" }) },
    ]),
    turn([]),
  ]);
  const shifts = await personaShifts(spec, runId, execute, instOf, {
    agent, traceEnabled: true,
    caps: { maxSteps: 4, maxInputTokens: 2000, maxOutputTokens: 200, maxWallMinutes: 2 },
    recorder: new LocalTrajectoryRecorder(new EventStore()),
  });
  const shift = shifts.shifts[0];
  if (!shift) throw new Error("no persona shift recorded");
  if (shift.mode !== "agent") throw new Error(`expected the agent path, got ${shift.mode}`);
  if (shift.auth !== "kerberos") throw new Error(`expected Kerberos auth, got ${shift.auth}`);
  const who = executed.find((e) => e.cmd.includes("id -un"));
  const hostCmd = executed.find((e) => e.cmd.includes("hostname"));
  if (!who || who.out.trim() !== shift.personaId) throw new Error(`whoami did not run as the persona: ${who?.out?.trim() ?? "(missing)"}`);
  if (!hostCmd) throw new Error("hostname action did not reach the guest");
  for (const e of executed.filter((e) => e.cmd.startsWith("sudo "))) {
    if (!e.cmd.includes(`sudo -n -u '${ctx.user}' env KRB5CCNAME='FILE:${ctx.ccache}'`)) {
      throw new Error(`shift command was not wrapped with the persona ccache: ${e.cmd}`);
    }
  }
  console.log(`shift: ${shift.mode}/${shift.auth}, ${shift.performed.length} performed, ${shift.refused.length} refused`);
  console.log(`  whoami -> ${who.out.trim()}`);

  const runAs = (command) => `sudo -n -u '${ctx.user}' env KRB5CCNAME='FILE:${ctx.ccache}' ${command}`;
  const klist = await proof("persona ticket survives the shift", () => exec(ws, runAs("klist")));
  if (!klist.includes(`${ctx.user}@`)) throw new Error("klist does not show the persona principal");
  const whoami = await proof("persona GSSAPI bind after the shift", () => exec(ws, runAs(`ldapwhoami -Y GSSAPI -H '${ctx.ldapUri}'`)));
  if (!whoami.includes(`dn: uid=${ctx.user},`)) throw new Error("GSSAPI bind did not return the persona DN");

  console.log("VM PERSONA KERBEROS SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message : err);
} finally {
  if (process.env.PERSONA_KERBEROS_KEEP === "1" && primaryError) {
    console.log(`kept for diagnosis: ${path.join(stateRoot, "kvm", runId)} (rerun destroy manually)`);
    process.exit(1);
  }
  await destroyRunVms(lifecycle).catch(() => undefined);
  const leaked = await run("pgrep", ["-f", `musearena-${runId}-`]).then(() => true).catch(() => false);
  if (leaked && !primaryError) primaryError = new Error(`leaked QEMU processes for ${runId}`);
  if (!primaryError && !process.env.VM_STATE_ROOT) await rm(stateRoot, { recursive: true, force: true }).catch(() => undefined);
  console.log(leaked ? "LEAKED QEMU" : "destroyed: state removed, no leaked QEMU");
}
if (primaryError) process.exit(1);

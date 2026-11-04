/**
 * Live P3/P4 combined org smoke: one FreeIPA realm, four services, one member.
 *
 *   node scripts/vm-org-multi-service-smoke.mjs
 *
 * Boots Rocky dc-01 (baked FreeIPA tier) + Debian mail-01, db-01, git-01 and
 * ws-01 (all members, dependsOn dc-01), configures them in one generated
 * playbook, then proves on one run:
 *   - per-host readiness: ldap-bind, smtp-imap-roundtrip, sql-select,
 *     git-ldap-login, ssh-login and lab-ldap;
 *   - cross-host L2 probes from the readiness plan (DNS/LDAP/SMTP/DB);
 *   - p1 authenticates to mail, Postgres and Gitea with the same realm
 *     password, and each service refuses a wrong password;
 *   - the ws-01 persona shift runs as p1 with a real Kerberos ccache.
 *
 * This is the combined-service claim: the services are not tested in
 * isolation, they share one directory, one realm and one run.
 */
import { execFile } from "node:child_process";
import { mkdir, writeFile, rm } from "node:fs/promises";
import path from "node:path";
import { promisify } from "node:util";
import { detectHost } from "../dist/provisioner/kvm.js";
import { ensureRockyFreeipaImage, ensureRockyGoldenImage, resolveGoldenImage } from "../dist/provisioner/images.js";
import { destroyRunVms, startRunVms } from "../dist/provisioner/vm-lifecycle.js";
import { execInGuest, probeGuestIdentity, waitForLabAddress, vmTargetsFromState } from "../dist/configurator/vm-ssh.js";
import { inventoryFor, parseRecap, playbookFor } from "../dist/configurator/ansible.js";
import { checkSpecReadiness, labProbesFor } from "../dist/configurator/readiness.js";
import { labSecret, ipaUserIdFor, ipaUserSecret } from "../dist/configurator/lab.js";
import { labDomainFor, ipaDomainFor } from "../dist/configurator/dns.js";
import { personaShifts } from "../dist/exercise/vm-agents.js";
import { ScriptedAgentClient } from "../dist/lib/model.js";
import { EventStore } from "../dist/observability/events.js";
import { LocalTrajectoryRecorder } from "../dist/observability/trajectory.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-org-multi-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

const spec = {
  version: 1, name: "org-multi-service-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "mail-01", name: "mail-01", role: "mail", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "smtp", impl: "postfix", port: 25, readyWhen: "smtp-imap-roundtrip" },
                      { kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 10 } },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: ["app"],
      serviceDecls: [{ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 10 } },
    { hostId: "git-01", name: "git-01", role: "git", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 2048, diskGb: 10 } },
    { hostId: "ws-01", name: "ws-01", role: "workstation", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [], dependsOn: ["dc-01"], resources: { vcpu: 1, memoryMb: 1024, diskGb: 8 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "ws-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [], requiredTelemetry: [], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const domain = labDomainFor(spec);
const ipaDomain = ipaDomainFor(spec);
const uid = ipaUserIdFor("p1");
const userPw = ipaUserSecret(runId, "p1");
const adminPw = labSecret(runId, "ipa-admin");

let primaryError = null;
const proof = async (label, fn) => {
  try { const out = await fn(); console.log(`PROOF PASS ${label}${out ? `: ${String(out).trim().slice(0, 180)}` : ""}`); return out; }
  catch (err) { throw new Error(`PROOF FAIL ${label}: ${err instanceof Error ? err.message.slice(0, 400) : err}`); }
};

try {
  const [rockyBaked, debian] = await Promise.all([ensureRockyFreeipaImage(host.hostArch), resolveGoldenImage(host.hostArch)]);
  const rocky = rockyBaked ?? await ensureRockyGoldenImage(host.hostArch);
  console.log("images:", rocky.image.name, rocky.image.digest, "|", debian.image.name, debian.image.digest);
  if (!rockyBaked) console.log("WARNING: baked Rocky tier missing; configure will install FreeIPA over mgmt");
  const res = await startRunVms(spec, { ...lifecycle, goldenByFamily: { rocky, debian } }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const state = res.state;
  for (const inst of Object.values(state.instances)) {
    await probeGuestIdentity(inst, { runId }, { attempts: 90, delayMs: 2000, timeoutMs: 15000 });
    await waitForLabAddress(inst);
    console.log(`${inst.hostId}: ready lab=${inst.lab?.address} image=${inst.imageName}`);
  }

  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  console.log("configure: one playbook for dc-01, mail-01, db-01, git-01, ws-01…");
  let stdout = "";
  let recap = new Map();
  for (let attempt = 1; attempt <= 2; attempt++) {
    stdout = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
      timeout: 45 * 60_000, maxBuffer: 32 * 1024 * 1024,
    }).then((r) => r.stdout).catch((e) => `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}`);
    recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
    for (const [hostId, r] of recap) console.log(`${hostId}: ${r.line}`);
    if (recap.size > 0 && [...recap.values()].every((r) => r.ok)) break;
    if (attempt === 1) { console.log("configure attempt 1 did not finish cleanly; retrying once…"); await new Promise((r) => setTimeout(r, 5000)); }
  }
  if (recap.size === 0 || [...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed:\n${stdout.slice(-12_000)}`);

  const execHost = (hostId, command, timeoutMs = 90_000) =>
    execInGuest(state.instances[hostId], command, { timeoutMs }).then((r) => r.stdout);

  // Per-host readiness, including each service's negative leg.
  const readiness = await checkSpecReadiness({
    spec, runId,
    sshUserOf: (hostId) => state.instances[hostId]?.ssh?.user ?? "arena",
    exec: async (hostId, command, timeoutMs) => execHost(hostId, command, timeoutMs),
  });
  for (const h of readiness) for (const c of h.checks) console.log(`${h.hostId}: ${c.ok ? "PASS" : "FAIL"} ${c.kind}/${c.probe}`);
  if (readiness.some((h) => !h.ok)) throw new Error(`readiness failed: ${JSON.stringify(readiness)}`);

  // Cross-host L2 proofs: the services are reachable from other guests, not
  // only from themselves.
  for (const p of labProbesFor(spec, runId)) {
    const out = await execHost(p.from, p.command, p.timeoutMs);
    const ok = p.expect ? out.includes(p.expect) : true;
    console.log(`cross-host ${p.from}->${p.to} ${p.probe}: ${ok ? "PASS" : "FAIL"}`);
    if (!ok) throw new Error(`cross-host probe ${p.probe} ${p.from}->${p.to} failed: ${out.slice(0, 200)}`);
  }

  await proof("dc-01 admin kinit + seeded persona", () =>
    execHost("dc-01", `printf '%s\\n' '${adminPw}' | kinit admin >/dev/null && ipa user-show ${uid} --raw | grep -E '^(uid|uidnumber):' ; kdestroy`));

  const mailAddr = state.instances["mail-01"].lab.address;
  const dbAddr = state.instances["db-01"].lab.address;
  const gitAddr = state.instances["git-01"].lab.address;

  await proof("cross-host mail: ws-01 → mail-01 as the domain user", async () => {
    const out = await execHost("ws-01", `curl -fsS --max-time 10 -u '${uid}:${userPw}' imap://${mailAddr}:143/INBOX >/dev/null 2>&1 && echo DOMAIN-OK || echo DOMAIN-FAIL`);
    if (!out.includes("DOMAIN-OK")) throw new Error(out.trim());
    return "IMAP login over the lab segment";
  });
  await proof("cross-host DB: mail-01 → db-01 as the domain user", async () => {
    const out = await execHost("mail-01", `PGPASSWORD='${userPw}' psql -h ${dbAddr} -U ${uid} -d app -tAc 'select 1' 2>&1`);
    if (out.trim() !== "1") throw new Error(out.trim());
    return "SQL select over the lab segment";
  });
  await proof("cross-host git: ws-01 → git-01 as the domain user", async () => {
    const out = await execHost("ws-01", `curl -fsS --max-time 10 -u '${uid}:${userPw}' http://${gitAddr}:3000/api/v1/user`);
    if (JSON.parse(out).login !== uid) throw new Error(out.slice(0, 200));
    return "Gitea API login over the lab segment";
  });

  await proof("mail-01 domain-user SMTP→IMAP", async () => {
    const out = await execHost("mail-01", `swaks --to ${uid}@${domain} --server 127.0.0.1 --port 25 --silent 3 >/dev/null 2>&1; curl -fsS --max-time 10 -u '${uid}:${userPw}' imap://127.0.0.1:143/INBOX >/dev/null 2>&1 && echo DOMAIN-OK || echo DOMAIN-FAIL`);
    if (!out.includes("DOMAIN-OK")) throw new Error(out.trim() || "IMAP login failed");
    const bad = await execHost("mail-01", `curl -sS --max-time 10 -u '${uid}:definitely-wrong' imap://127.0.0.1:143/INBOX >/dev/null 2>&1 && echo WRONG-ACCEPTED || echo WRONG-REFUSED`);
    if (!bad.includes("WRONG-REFUSED")) throw new Error("mail accepted a wrong domain password");
    return "DOMAIN-OK + wrong password refused";
  });

  await proof("db-01 domain-user SQL", async () => {
    const out = await execHost("db-01", `PGPASSWORD='${userPw}' psql -h 127.0.0.1 -U ${uid} -d app -tAc 'select 1' 2>&1`);
    if (out.trim() !== "1") throw new Error(out.trim() || "SQL login failed");
    const bad = await execHost("db-01", `PGPASSWORD='definitely-wrong' psql -h 127.0.0.1 -U ${uid} -d app -tAc 'select 1' >/dev/null 2>&1 && echo WRONG-ACCEPTED || echo WRONG-REFUSED`);
    if (!bad.includes("WRONG-REFUSED")) throw new Error("Postgres accepted a wrong domain password");
    return "select 1 + wrong password refused";
  });

  await proof("git-01 domain-user API login", async () => {
    const out = await execHost("git-01", `curl -fsS --max-time 10 -u '${uid}:${userPw}' http://127.0.0.1:3000/api/v1/user`);
    const login = JSON.parse(out).login;
    if (login !== uid) throw new Error(`API login returned ${login}`);
    const code = await execHost("git-01", `curl -sS -o /dev/null -w '%{http_code}' --max-time 10 -u '${uid}:definitely-wrong' http://127.0.0.1:3000/api/v1/user`);
    if (code.trim() !== "401") throw new Error(`wrong password returned HTTP ${code.trim()}`);
    return `login=${login} + wrong password 401`;
  });

  await proof("ws-01 persona shift runs as the Kerberos user", async () => {
    const executed = [];
    const execute = async (inst, command, timeoutMs) => {
      const out = await execInGuest(inst, command, { timeoutMs }).then((r) => r.stdout);
      executed.push({ command, out });
      return out;
    };
    const turn = (toolCalls) => ({ text: "", toolCalls, usage: { inputTokens: 20, outputTokens: 5 } });
    const agent = new ScriptedAgentClient([
      turn([{ callId: "s1", name: "shift", argumentsJson: JSON.stringify({ action: "whoami" }) }]),
      turn([]),
    ]);
    const shifts = await personaShifts(spec, runId, execute, async (hostId) => state.instances[hostId], {
      agent, traceEnabled: false,
      caps: { maxSteps: 2, maxInputTokens: 1000, maxOutputTokens: 100, maxWallMinutes: 2 },
      recorder: new LocalTrajectoryRecorder(new EventStore()),
    });
    const shift = shifts.shifts[0];
    if (!shift || shift.auth !== "kerberos") throw new Error(`expected Kerberos shift, got ${shift?.auth ?? "none"}`);
    const who = executed.find((e) => e.command.includes("id -un"));
    if (!who || who.out.trim() !== uid) throw new Error(`whoami did not run as ${uid}: ${who?.out?.trim() ?? "(missing)"}`);
    return `${shift.mode}/${shift.auth}, whoami=${who.out.trim()}`;
  });

  console.log("VM ORG MULTI-SERVICE SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message : err);
} finally {
  if (process.env.ORG_MULTI_KEEP === "1" && primaryError) {
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

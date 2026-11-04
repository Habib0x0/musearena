/**
 * Live T-40 smoke: service keytabs + GSSAPI on FreeIPA members.
 *
 *   node scripts/vm-gssapi-smoke.mjs
 *
 * Boots Rocky dc-01 (baked FreeIPA tier) + Debian db-01, web-01 and mail-01
 * (all members), configures them in one generated playbook, then proves:
 *   - the member got a service keytab for each Kerberized service;
 *   - Postgres authenticates p1 by GSSAPI against `gssdb` and refuses a
 *     keytab-less connection;
 *   - Apache authenticates p1 by SPNEGO on /gssapi and returns 401 without a
 *     ticket;
 *   - Dovecot offers GSSAPI and accepts p1's ticket, refusing without one;
 *   - the existing password/LDAP paths are still green (app DB, IMAP, HTTP).
 *
 * The negative leg is the point: a configured keytab that is never exercised
 * would not be a GSSAPI claim.
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
import { checkSpecReadiness } from "../dist/configurator/readiness.js";
import { labSecret, ipaUserIdFor, ipaUserSecret } from "../dist/configurator/lab.js";
import { labDomainFor } from "../dist/configurator/dns.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-gssapi-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel, host.reason);

const spec = {
  version: 1, name: "gssapi-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: ["app"],
      serviceDecls: [{ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 10 } },
    { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "http", impl: "apache-php", port: 80, readyWhen: "http-2xx" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 10 } },
    { hostId: "mail-01", name: "mail-01", role: "mail", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "smtp", impl: "postfix", port: 25, readyWhen: "smtp-imap-roundtrip" },
                      { kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 1536, diskGb: 10 } },
  ],
  personas: [{ id: "p1", role: "nurse", workstation: "web-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] }],
  objectives: [], requiredTelemetry: [], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const domain = labDomainFor(spec);
const uid = ipaUserIdFor("p1");
const userPw = ipaUserSecret(runId, "p1");
const adminPw = labSecret(runId, "ipa-admin");
const CC = "/tmp/arena-gssapi.cc";
const fqdnOf = (id) => `${id}.${domain}`;

let primaryError = null;
const proof = async (label, fn) => {
  try { const out = await fn(); console.log(`PROOF PASS ${label}${out ? `: ${String(out).trim().slice(0, 180)}` : ""}`); return out; }
  catch (err) { throw new Error(`PROOF FAIL ${label}: ${err instanceof Error ? err.message.slice(0, 400) : err}`); }
};

const kinit = `printf '%s\\n' '${userPw}' | KRB5CCNAME=${CC} kinit ${uid} >/dev/null 2>&1`;
const kdestroy = `KRB5CCNAME=${CC} kdestroy >/dev/null 2>&1 || true`;

try {
  const [rockyBaked, debian] = await Promise.all([ensureRockyFreeipaImage(host.hostArch), resolveGoldenImage(host.hostArch)]);
  const rocky = rockyBaked ?? await ensureRockyGoldenImage(host.hostArch);
  console.log("images:", rocky.image.name, rocky.image.digest, "|", debian.image.name, debian.image.digest);
  if (!rockyBaked) throw new Error("baked Rocky tier missing; this smoke requires the baked FreeIPA image");
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
  console.log("configure: one playbook for dc-01, db-01, web-01, mail-01…");
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

  const readiness = await checkSpecReadiness({
    spec, runId,
    sshUserOf: (hostId) => state.instances[hostId]?.ssh?.user ?? "arena",
    exec: async (hostId, command, timeoutMs) => execHost(hostId, command, timeoutMs),
  });
  for (const h of readiness) for (const c of h.checks) console.log(`${h.hostId}: ${c.ok ? "PASS" : "FAIL"} ${c.kind}/${c.probe}`);
  if (readiness.some((h) => !h.ok)) throw new Error(`readiness failed: ${JSON.stringify(readiness)}`);
  for (const [hostId, probe] of [["db-01", "gssapi-sql"], ["web-01", "gssapi-http"], ["mail-01", "gssapi-imap"]]) {
    const check = readiness.find((h) => h.hostId === hostId)?.checks.find((c) => c.probe === probe);
    if (!check?.ok) throw new Error(`${hostId}: readiness did not prove ${probe}`);
  }

  await proof("dc-01 admin kinit + seeded persona", () =>
    execHost("dc-01", `printf '%s\\n' '${adminPw}' | kinit admin >/dev/null && ipa user-show ${uid} --raw | grep -E '^(uid|uidnumber):' ; kdestroy`));

  await proof("db-01 keytab and GSSAPI SQL as the persona", async () => {
    const keytab = await execHost("db-01", "sudo -n klist -k /etc/postgresql/postgres.keytab 2>&1 | tail -n +2");
    if (!keytab.includes(`postgres/`)) throw new Error(`keytab missing or unreadable: ${keytab.trim()}`);
    const out = await execHost("db-01", `${kinit} && KRB5CCNAME=${CC} psql -h ${fqdnOf("db-01")} -U ${uid} -d gssdb -tAc 'select 1' 2>&1`);
    if (out.trim() !== "1") throw new Error(out.trim() || "GSSAPI SQL login failed");
    const noTicket = await execHost("db-01", `${kdestroy}; KRB5CCNAME=${CC} psql -h ${fqdnOf("db-01")} -U ${uid} -d gssdb -tAc 'select 1' >/dev/null 2>&1 && echo ACCEPTED || echo REFUSED`);
    if (!noTicket.includes("REFUSED")) throw new Error("Postgres accepted a keytab-less connection");
    // Wrong principal: a valid Kerberos identity with no database role must be
    // refused. `admin` has a ticket but no Postgres role, so this is not a
    // password or keytab problem.
    const wrongPrincipal = await execHost("db-01", `printf '%s\\n' '${adminPw}' | KRB5CCNAME=${CC} kinit admin >/dev/null 2>&1 && KRB5CCNAME=${CC} psql -h ${fqdnOf("db-01")} -U admin -d gssdb -tAc 'select 1' >/dev/null 2>&1 && echo ACCEPTED || echo REFUSED; ${kdestroy}`);
    if (!wrongPrincipal.includes("REFUSED")) throw new Error("Postgres accepted a principal with no database role");
    return `select 1 as ${uid}; no-ticket refused; wrong-principal refused; ${keytab.trim().split("\n")[0]}`;
  });

  await proof("web-01 Apache SPNEGO as the persona", async () => {
    const out = await execHost("web-01", `${kinit} && KRB5CCNAME=${CC} curl -fsS --max-time 10 --negotiate -u : http://${fqdnOf("web-01")}/gssapi/ 2>&1`);
    if (out.trim() !== uid) throw new Error(`SPNEGO returned ${JSON.stringify(out.trim())}, expected ${uid}`);
    const code = await execHost("web-01", `${kdestroy}; KRB5CCNAME=${CC} curl -sS -o /dev/null -w '%{http_code}' --max-time 10 --negotiate -u : http://${fqdnOf("web-01")}/gssapi/ 2>/dev/null`);
    if (code.trim() !== "401") throw new Error(`keytab-less request returned HTTP ${code.trim()}`);
    const plain = await execHost("web-01", "curl -fsS --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1/");
    if (plain.trim() !== "200") throw new Error(`the existing HTTP path returned ${plain.trim()}`);
    return `REMOTE_USER=${uid}; no-ticket 401; plain HTTP 200`;
  });

  await proof("mail-01 Dovecot GSSAPI as the persona", async () => {
    const caps = await execHost("mail-01", "bash -c 'exec 3<>/dev/tcp/127.0.0.1/143; printf \"a1 CAPABILITY\\r\\n\" >&3; timeout 2 cat <&3' 2>&1 | head -c 600");
    if (!/AUTH=GSSAPI/i.test(caps)) throw new Error(`GSSAPI not advertised: ${caps.trim()}`);
    const out = await execHost("mail-01", `${kinit} && KRB5CCNAME=${CC} curl -fsS --max-time 10 --negotiate -u : imap://${fqdnOf("mail-01")}:143/INBOX >/dev/null 2>&1 && echo GSS-OK || echo GSS-FAIL`);
    if (!out.includes("GSS-OK")) throw new Error("Dovecot refused the persona ticket");
    const noTicket = await execHost("mail-01", `${kdestroy}; KRB5CCNAME=${CC} curl -sS --max-time 10 --negotiate -u : imap://${fqdnOf("mail-01")}:143/INBOX >/dev/null 2>&1 && echo ACCEPTED || echo REFUSED`);
    if (!noTicket.includes("REFUSED")) throw new Error("Dovecot accepted a ticket-less GSSAPI login");
    const password = await execHost("mail-01", `curl -fsS --max-time 10 -u '${uid}:${userPw}' imap://127.0.0.1:143/INBOX >/dev/null 2>&1 && echo PASSWORD-OK || echo PASSWORD-FAIL`);
    if (!password.includes("PASSWORD-OK")) throw new Error("the existing LDAP password path regressed");
    return "AUTH=GSSAPI advertised; ticket accepted; no-ticket refused; password path still green";
  });

  await proof("db-01 password/LDAP path still green", async () => {
    const out = await execHost("db-01", `PGPASSWORD='${userPw}' psql -h 127.0.0.1 -U ${uid} -d app -tAc 'select 1' 2>&1`);
    if (out.trim() !== "1") throw new Error(out.trim() || "LDAP SQL login failed");
    const bad = await execHost("db-01", `PGPASSWORD='definitely-wrong' psql -h 127.0.0.1 -U ${uid} -d app -tAc 'select 1' >/dev/null 2>&1 && echo ACCEPTED || echo REFUSED`);
    if (!bad.includes("REFUSED")) throw new Error("Postgres accepted a wrong domain password");
    return "select 1 via LDAP; wrong password refused";
  });

  console.log("VM GSSAPI SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message : err);
} finally {
  if (process.env.GSSAPI_KEEP === "1" && primaryError) {
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

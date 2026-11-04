import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import { tasksFor, playbookFor, parseRecap, failedAnsibleTasks, inventoryFor, canaryValue } from "../dist/configurator/ansible.js";
import { gatesFor } from "../dist/activities/index.js";
import { roleImage, PLANTABLE } from "../dist/provisioner/roles.js";
import { containerName, networkName } from "../dist/provisioner/names.js";
import { proofGate } from "../dist/configurator/gates.js";
import { EventStore } from "../dist/observability/events.js";
import { dockerGateOptions } from "../dist/configurator/docker-executors.js";

const RUN = "run-0123abcd-ffff";
const spec = (vulns, instances) => ({
  version: 1, name: "rt-org", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [], firewallRules: [] },
  instances: instances ?? [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu 24.04", stack: ["php"], services: ["http"], databases: [] },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "container", os: "Ubuntu 24.04", stack: [], services: ["postgres"], databases: ["app", "hr; DROP"] },
  ],
  personas: [{ id: "o'brien", role: "intern<script>", workstation: "web-01", access: [], credentialsProfile: "weak", riskProfile: "high", routine: "", relationships: [] }],
  objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10 }],
  requiredTelemetry: ["auditd"],
  plantedVulns: vulns,
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
});
const WEAK = { id: "v1", type: "weak-cred", techniqueId: "T1078", targetHostId: "db-01", pinnedVersion: "16", proofAtomicGuid: "g1", difficulty: "standard" };
const FLAW = { id: "v2", type: "code-flaw", techniqueId: "T1059", targetHostId: "web-01", pinnedVersion: "8.2", proofAtomicGuid: "g2", difficulty: "standard" };
const decode = (raw) => Buffer.from(/'([A-Za-z0-9+/=]+)'/.exec(raw)[1], "base64").toString();

test("roles map to real services, unknown roles to a generic host with no telemetry", () => {
  assert.equal(roleImage("web").image, "php:8.2-apache");
  assert.equal(roleImage("db").image, "postgres:16-alpine");
  assert.equal(roleImage("dc").telemetry, undefined);
  assert.deepEqual(PLANTABLE.db, ["weak-cred"]);
});

test("code flaw is planted only when the spec plants it", () => {
  const planted = tasksFor(spec([FLAW]), RUN, "web-01").map((t) => t.name);
  assert.ok(planted.includes("plant_code_flaw"));
  const clean = tasksFor(spec([]), RUN, "web-01").map((t) => t.name);
  assert.ok(!clean.includes("plant_code_flaw"));
  assert.ok(clean.includes("ensure_no_code_flaw"));
});

test("weak DB credential survives only when planted; otherwise rotated", () => {
  assert.ok(!tasksFor(spec([WEAK]), RUN, "db-01").some((t) => t.name === "rotate_credentials"));
  assert.ok(tasksFor(spec([]), RUN, "db-01").some((t) => t.name === "rotate_credentials"));
});

test("spec-derived strings never reach the shell raw; SQL/HTML are escaped", () => {
  const tasks = tasksFor(spec([WEAK]), RUN, "db-01");
  for (const t of tasks) assert.ok(!t.raw.includes("o'brien"), `raw shell contains spec string: ${t.name}`);
  const createDb = tasks.find((t) => t.name.startsWith("create_db_"));
  assert.equal(createDb.name, "create_db_hrDROP");
  assert.ok(!createDb.raw.includes(";"), "db name not sanitized");
  const seed = decode(tasks.find((t) => t.name === "write_seed").raw);
  assert.match(seed, /'o''brien'/);
  assert.match(seed, new RegExp(canaryValue(RUN, "o1")));
  const page = decode(tasksFor(spec([]), RUN, "web-01").find((t) => t.name === "deploy_app").raw);
  assert.ok(!page.includes("<script>") && page.includes("&lt;script&gt;"));
});

test("playbook is valid JSON/YAML with raw tasks; inventory uses the docker connection", () => {
  const pb = JSON.parse(playbookFor(spec([WEAK, FLAW]), RUN));
  assert.equal(pb.length, 2);
  assert.ok(pb.every((p) => p.tasks.every((t) => typeof t["ansible.builtin.raw"] === "string")));
  const inv = JSON.parse(inventoryFor(spec([]), [{ hostId: "web-01", name: "web-01", connectVia: containerName(RUN, "web-01") }]));
  assert.equal(inv.all.hosts["web-01"].ansible_connection, "community.docker.docker");
  assert.equal(inv.all.hosts["web-01"].ansible_host, "ma-0123abcd-web-01");
});

test("recap is parsed per host: one failure does not fail the others", () => {
  const out = "PLAY RECAP\nweb-01  : ok=3 changed=1 unreachable=0 failed=0 skipped=0\ndb-01   : ok=1 changed=0 unreachable=0 failed=1 skipped=0\n";
  const r = parseRecap(out, ["web-01", "db-01", "dc-01"]);
  assert.equal(r.get("web-01").ok, true);
  assert.equal(r.get("db-01").ok, false);
  assert.equal(r.get("dc-01").ok, false);
  const failed = failedAnsibleTasks([
    "TASK [profile-install] *****",
    "changed: [web-01]",
    "TASK [log-configure] *****",
    "fatal: [log-01]: FAILED! => {\"changed\": false, \"msg\": \"non-zero return code\"}",
    "TASK [profile-enable] *****",
    "fatal: [db-01]: UNREACHABLE! => {\"changed\": false}",
  ].join("\n"));
  assert.equal(failed.get("log-01"), "log-configure");
  assert.equal(failed.get("db-01"), "profile-enable");
  assert.equal(failed.has("web-01"), false);
});

test("names are run-scoped and docker-safe", () => {
  assert.equal(containerName(RUN, "DB 01"), "ma-0123abcd-db-01");
  assert.equal(networkName(RUN), "ma-0123abcd-net");
});

test("gate executor selection: docker for container envs, fail-closed otherwise", () => {
  assert.equal(gatesFor(spec([])).executor, "docker");
  const vmSpec = spec([], [{ hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Ubuntu 24.04", stack: [], services: [], databases: [] }]);
  assert.equal(gatesFor(vmSpec, {}).executor, "none");
  assert.equal(gatesFor(vmSpec, { MUSEARENA_LOCAL_GATES: "1" }).executor, "local-harness");
});

test("docker proof refuses vulns the runtime cannot plant (no false pass)", async () => {
  const store = new EventStore();
  const s = spec([{ ...WEAK, type: "cve" }]);
  const res = await proofGate({ runId: RUN, spec: s }, dockerGateOptions(s, { store, docker: "/usr/bin/false", settleMs: 1 }));
  assert.equal(res.pass, false);
  assert.match(res.details.join(" "), /not plantable/);
});

test("docker proof with no observable telemetry fails closed", async () => {
  const store = new EventStore();
  const s = spec([WEAK]);
  const res = await proofGate({ runId: RUN, spec: s }, dockerGateOptions(s, { store, docker: "/usr/bin/false", settleMs: 1 }));
  assert.equal(res.pass, false);
  assert.match(res.details.join(" "), /NOT seen/);
});

test("designer roles normalize to runtime roles; undeployable designs are blocked with reasons", async () => {
  const { normalizeRole, deployability } = await import("../dist/provisioner/capability.js");
  assert.equal(normalizeRole("database"), "db");
  assert.equal(normalizeRole("domain-controller"), "dc");
  assert.equal(normalizeRole("Web Server"), "web");
  assert.deepEqual(deployability(spec([WEAK, FLAW])), []);
  const win = spec([], [{ hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Windows Server 2022", stack: [], services: [], databases: [] }]);
  assert.ok(deployability(win).some((r) => /KVM_WINDOWS_IMAGE/.test(r)));
  assert.ok(deployability(spec([{ ...WEAK, type: "cve" }])).some((r) => /cannot be planted/.test(r)));
});

test("trigger rejects undeployable specs with the reason instead of failing at the gate", async () => {
  const { validatePendingSpec } = await import("../dist/workflows/trigger.js");
  const res = validatePendingSpec(spec([{ ...WEAK, type: "cve" }]));
  assert.equal(res.ok, false);
  assert.match(res.reason, /not deployable/);
});

const vmSpec = (declsByHost) => ({
  version: 1, name: "vm-org", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: declsByHost["web-01"] ?? [{ kind: "http", impl: "apache-php" }] },
    { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: ["app"],
      serviceDecls: declsByHost["db-01"] ?? [{ kind: "db", impl: "postgres" }] },
  ],
  personas: [], objectives: [], requiredTelemetry: [], plantedVulns: [], budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
});

test("vm profile tasks: packages/units/seed run as root; container task shape unchanged", async () => {
  const { tasksFor, vmProfileTasks } = await import("../dist/configurator/ansible.js");
  const { allProvisionablePackages } = await import("../dist/configurator/profiles.js");
  const { labSecret } = await import("../dist/configurator/lab.js");
  const baked = allProvisionablePackages();
  for (const p of ["osquery", "apache2", "postgresql", "slapd", "dovecot-imapd", "swaks", "nmap"]) assert.ok(baked.includes(p), `bake covers ${p}`);
  // The FreeIPA stack and the zone router must be in the bake, or config
  // would fall back to apt over the management NIC (the offline claim).
  for (const p of ["freeipa-client", "sssd", "nftables"]) assert.ok(baked.includes(p), `bake covers ${p}`);
  assert.ok(!baked.includes("ipa-server"), "Debian bake must not name Rocky-only ipa-server");
  const s = vmSpec({});
  const web = tasksFor(s, RUN, "web-01");
  const names = web.map((t) => t.name);
  assert.ok(names.includes("profile-install") && names.includes("profile-enable"), names.join(","));
  assert.ok(!names.includes("db-configure"), "web host must not get db bootstrap");
  assert.ok(web.some((t) => t.name === "deploy_app" && t.raw.includes("sudo -n sh")), "VM role tasks run as root");
  const db = tasksFor(s, RUN, "db-01");
  assert.ok(db.some((t) => t.name === "db-configure"), "db host bootstraps postgres auth");
  assert.ok(db.some((t) => t.name === "db-seed-access"), "db host seeds the app role/db");
  assert.ok(vmProfileTasks(s, RUN, "web-01").every((t) => t.raw.includes("sudo -n sh")));
  const container = tasksFor(spec([]), RUN, "web-01");
  assert.ok(container.some((t) => t.name === "deploy_app" && !t.raw.includes("sudo -n sh")), "container tasks stay as before");

  const all = vmSpec({
    "web-01": [{ kind: "dns", impl: "dnsmasq" }, { kind: "ldap", impl: "openldap" }],
    "db-01": [{ kind: "smtp", impl: "postfix" }, { kind: "imap", impl: "dovecot" }, { kind: "log", impl: "rsyslog-collector" }],
  });
  const decode = (t) => Buffer.from(/'([A-Za-z0-9+/=]+)'/.exec(t.raw)[1], "base64").toString();
  const gw = tasksFor(all, RUN, "web-01");
  const gwNames = gw.map((t) => t.name);
  assert.ok(gwNames.includes("dns-configure") && gwNames.includes("ldap-configure") && gwNames.includes("ldap-seed"), gwNames.join(","));
  assert.match(decode(gw.find((t) => t.name === "ldap-configure")), new RegExp(labSecret(RUN, "ldap-admin")));
  const mail = tasksFor(all, RUN, "db-01");
  const mailNames = mail.map((t) => t.name);
  assert.ok(mailNames.includes("mail-configure") && mailNames.includes("log-configure"), mailNames.join(","));
  assert.match(decode(mail.find((t) => t.name === "mail-configure")), new RegExp(labSecret(RUN, "mail-probe")));
});

test("dns-resolver never reconfigures networking over its own SSH session", () => {
  const s = vmSpec({
    "web-01": [{ kind: "dns", impl: "dnsmasq" }],
    "db-01": [{ kind: "db", impl: "postgres" }],
  });
  const task = tasksFor(s, RUN, "db-01").find((t) => t.name === "dns-resolver");
  assert.ok(task, "non-gateway hosts get the resolver task");
  const script = decode(task.raw);
  assert.doesNotMatch(script, /netplan apply/, "applying netplan drops the management SSH session Ansible is using");
  assert.doesNotMatch(script, /systemctl restart systemd-resolved/, "restarting the resolver mid-task is not needed for runtime settings");
  assert.match(script, /99-arena-dns\.yaml/, "the persistent drop-in is still written for the next boot");
  assert.match(script, /resolvectl dns /, "runtime per-link DNS is set without touching the links");
  assert.match(script, /resolvectl domain /, "runtime routing domains are set without touching the links");
  assert.match(script, /nameserver 10\.2\.32\.1/, "the static resolv.conf still names the gateway");
});

test("readiness: each readyWhen maps to a protocol probe; checks fail closed", async () => {
  const { probeFor, checkHostReadiness, checkSpecReadiness } = await import("../dist/configurator/readiness.js");
  const { labSecret } = await import("../dist/configurator/lab.js");
  const decls = [
    { kind: "ssh", impl: "openssh" }, { kind: "http", impl: "apache-php" }, { kind: "db", impl: "postgres" },
    { kind: "dns", impl: "dnsmasq" }, { kind: "dhcp", impl: "dnsmasq" }, { kind: "ldap", impl: "openldap" },
    { kind: "smtp", impl: "postfix" }, { kind: "imap", impl: "dovecot" }, { kind: "log", impl: "rsyslog-collector" },
  ];
  const ctx = { hostId: "gw-01", runId: "run-1", sshUser: "arena", services: decls, domain: "test-env.arena.lab" };
  const p = Object.fromEntries(decls.map((d) => [d.kind, probeFor(d, ctx)]));
  assert.match(p.http.command, /http:\/\/127\.0\.0\.1:80/);
  assert.equal(p.db.expect, "1");
  assert.match(p.dns.command, /dig \+short .*@127\.0\.0\.1/);
  assert.match(p.dhcp.command, /is-active dnsmasq/, "local dhcp probe proves the server; the lease is the lab-dhcp probe");
  assert.match(p.ldap.command, /ldapsearch/);
  assert.match(p.smtp.command, /swaks/);
  assert.match(p.imap.command, /imap:\/\//);
  assert.match(p.log.command, /dev\/tcp\/127\.0\.0\.1\/514/);
  assert.match(p.ssh.command, /id -un/);
  assert.equal(labSecret("run-1", "ldap-admin"), labSecret("run-1", "ldap-admin"));
  assert.notEqual(labSecret("run-1", "ldap-admin"), labSecret("run-2", "ldap-admin"));

  const s = vmSpec({ "web-01": [{ kind: "http", impl: "apache-php" }], "db-01": [{ kind: "db", impl: "postgres" }] });
  const ok = await checkHostReadiness({
    spec: s, runId: "run-1", hostId: "web-01", sshUser: "arena",
    exec: async (_h, cmd) => (cmd === "id -un" ? "arena\n" : "HTTP/1.1 200 OK"),
  });
  assert.equal(ok.ok, true, JSON.stringify(ok.checks));
  const bad = await checkHostReadiness({
    spec: s, runId: "run-1", hostId: "web-01", sshUser: "arena",
    exec: async (_h, cmd) => { if (cmd === "id -un") return "arena\n"; throw new Error("connection refused"); },
  });
  assert.equal(bad.ok, false);
  assert.match(bad.checks.find((c) => !c.ok).detail, /connection refused/);
  const wrongUser = await checkHostReadiness({
    spec: s, runId: "run-1", hostId: "web-01", sshUser: "root",
    exec: async () => "arena\n",
  });
  assert.equal(wrongUser.ok, false, "identity mismatch is not a pass");

  const results = await checkSpecReadiness({ spec: s, runId: "run-1", sshUserOf: () => "arena", exec: async (_h, cmd) => (cmd === "id -un" ? "arena\n" : "1") });
  assert.equal(results.length, 2, "only VM hosts are gated");
  const containerSpec = spec([]);
  assert.deepEqual(await checkSpecReadiness({ spec: containerSpec, runId: "run-1", sshUserOf: () => "arena", exec: async () => "x" }), []);
});

test("readiness: a host that declares ssh is probed once, not twice", async () => {
  const { checkHostReadiness } = await import("../dist/configurator/readiness.js");
  const s = vmSpec({ "dc-01": [{ kind: "ssh", impl: "openssh", port: 22, readyWhen: "ssh-login" }, { kind: "ldap", impl: "openldap", port: 389, readyWhen: "ldap-bind" }] });
  s.instances = s.instances.filter((i) => i.hostId === "db-01");
  s.instances[0] = { ...s.instances[0], hostId: "dc-01", name: "dc-01", role: "dc", serviceDecls: [{ kind: "ssh", impl: "openssh", port: 22, readyWhen: "ssh-login" }, { kind: "ldap", impl: "openldap", port: 389, readyWhen: "ldap-bind" }] };
  const res = await checkHostReadiness({
    spec: s, runId: "run-1", hostId: "dc-01", sshUser: "arena",
    exec: async (_h, cmd) => (cmd === "id -un" ? "arena" : "dn: dc=arena,dc=lab"),
  });
  assert.equal(res.checks.filter((c) => c.kind === "ssh/openssh").length, 1, JSON.stringify(res.checks));
  assert.equal(res.ok, true);
});

test("vm gates: canary and code-flaw proof are verified in guest telemetry, not exit codes", async () => {
  const { vmGateOptions } = await import("../dist/configurator/vm-executors.js");
  const { sensorCanary, proofGate } = await import("../dist/configurator/gates.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { gatesFor } = await import("../dist/activities/index.js");

  const s = vmSpec({});
  s.plantedVulns = [{ id: "v1", type: "code-flaw", techniqueId: "T1059", targetHostId: "web-01", pinnedVersion: "8", proofAtomicGuid: "g1", difficulty: "standard" }];
  const store = new EventStore();
  const state = { runId: RUN, specName: "x", netMode: "user", instances: { "web-01": { hostId: "web-01", accel: "hvf", netMode: "user", pid: 1, overlay: "", seedIso: "", goldenDigest: "", inProcess: false, startedAt: "" } } };
  const calls = [];
  let audit = "";
  let apache = "";
  const exec = async (_inst, cmd) => {
    calls.push(cmd);
    if (cmd.includes("auditctl -m")) {
      const m = /auditctl -m '([^']+)'/.exec(cmd);
      audit += `type=USER msg=audit(1.1:1): pid=1 uid=0 msg='text=${m[1]}'\n`;
      return "";
    }
    if (cmd.includes("audit.log")) return audit;
    if (cmd.includes("curl")) {
      const m = /echo (arena-proof-[A-Za-z0-9-]+)/.exec(decodeURIComponent(cmd));
      if (m) apache += `${m[1]}\n`;
      return "";
    }
    if (cmd.includes("error.log")) return apache;
    return "";
  };
  const gates = vmGateOptions(s, { runId: RUN, store, state, exec, settleMs: 0, attempts: 2 });
  const canary = await sensorCanary(RUN, "web-01", gates);
  assert.equal(canary.pass, true, canary.details.join("; "));
  const proof = await proofGate({ runId: RUN, spec: s }, gates);
  assert.equal(proof.pass, true, proof.details.join("; "));
  assert.equal(store.groundTruth(RUN).filter((e) => e.actor === "proof").length, 1);
  assert.ok(calls.some((c) => c.includes("auditctl -m")));
  assert.equal(gatesFor(s, {}, RUN).executor, "vm");
});

test("vm gates: blind guest (no telemetry) fails closed", async () => {
  const { vmGateOptions } = await import("../dist/configurator/vm-executors.js");
  const { sensorCanary, proofGate } = await import("../dist/configurator/gates.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const s = vmSpec({});
  s.plantedVulns = [{ id: "v1", type: "code-flaw", techniqueId: "T1059", targetHostId: "web-01", pinnedVersion: "8", proofAtomicGuid: "g1", difficulty: "standard" }];
  const store = new EventStore();
  const state = { runId: RUN, specName: "x", netMode: "user", instances: { "web-01": { hostId: "web-01", accel: "hvf", netMode: "user", pid: 1, overlay: "", seedIso: "", goldenDigest: "", inProcess: false, startedAt: "" } } };
  const gates = vmGateOptions(s, { runId: RUN, store, state, exec: async () => "", settleMs: 0, attempts: 2 });
  assert.equal((await sensorCanary(RUN, "web-01", gates)).pass, false);
  assert.equal((await proofGate({ runId: RUN, spec: s }, gates)).pass, false);
  assert.equal(store.groundTruth(RUN).length, 0, "no telemetry, no ground truth");

  // A vuln type the VM runtime cannot prove fails closed instead of passing.
  s.plantedVulns = [{ id: "v2", type: "cve", techniqueId: "T1190", targetHostId: "web-01", pinnedVersion: "1", proofAtomicGuid: "g2", difficulty: "standard" }];
  const unsupported = await proofGate({ runId: RUN, spec: s }, vmGateOptions(s, { runId: RUN, store, state, exec: async () => "", settleMs: 0, attempts: 1 }));
  assert.equal(unsupported.pass, false);
  assert.match(unsupported.details.join(" "), /not provable on the VM runtime/);
});

test("vm telemetry: apache/postgres/audit lines normalize and red markers attribute the actor", async () => {
  const { parseVmLogLine, vmLineTime } = await import("../dist/observability/vm-telemetry.js");
  const marker = "RED-o1-abc12345";
  const apache = `127.0.0.1 - - [28/Oct/2026:16:00:00 +0000] "GET /diag.php?host=x%3Becho%20${marker} HTTP/1.1" 200 12 "-" "curl/8"`;
  const a = parseVmLogLine("web-01", "web", { at: new Date().toISOString(), text: apache }, [marker]);
  assert.equal(a.kind, "http.request");
  assert.equal(a.actor, "red");
  assert.match(a.detail.path, /%3B/);
  assert.match(vmLineTime(apache), /^2026-10-28T16:00:00/);
  const bare = parseVmLogLine("web-01", "web", { at: new Date().toISOString(), text: marker }, [marker]);
  assert.equal(bare.kind, "process.stderr");
  assert.equal(bare.actor, "red");
  const pg = "2026-10-28 16:00:00.123 UTC [1] user=app db=app client=127.0.0.1 LOG:  statement: SELECT value FROM secrets /* " + marker + " */";
  const p = parseVmLogLine("db-01", "db", { at: new Date().toISOString(), text: pg }, [marker]);
  assert.equal(p.kind, "db.statement");
  assert.equal(p.actor, "red");
  assert.match(p.detail.statement, /secrets/);
  // A peer address is red even on a line without the marker: the attacker's
  // own session (connection, auth) belongs to the attack, not to persona noise.
  const conn = "2026-10-28 16:00:05.000 UTC [1] user=app db=app client=10.2.32.12 LOG:  connection authorized: user=app database=app";
  const bySource = parseVmLogLine("db-01", "db", { at: new Date().toISOString(), text: conn }, [], ["10.2.32.12"]);
  assert.equal(bySource.kind, "auth.logon");
  assert.equal(bySource.actor, "red");
  assert.equal(bySource.detail.src, "10.2.32.12");
  const persona = parseVmLogLine("db-01", "db", { at: new Date().toISOString(), text: conn.replace("10.2.32.12", "127.0.0.1") }, [], ["10.2.32.12"]);
  assert.equal(persona.actor, "noise", "another source stays noise");

  const audit = "type=USER msg=audit(1793206254.529:220): pid=1 uid=0 msg='text=canary-abc'";
  const au = parseVmLogLine("web-01", "web", { at: new Date().toISOString(), text: audit }, []);
  assert.equal(au.kind, "audit.user");
  assert.equal(au.actor, "platform");
  // sshd auth failures: attributable by the username, timestamped by syslog.
  const auth = `Oct 28 16:00:01 dc-01 sshd[4242]: Invalid user ${marker} from 127.0.0.1 port 40122`;
  const au2 = parseVmLogLine("dc-01", "dc", { at: new Date().toISOString(), text: auth }, [marker]);
  assert.equal(au2.kind, "auth.login.failed");
  assert.equal(au2.actor, "red");
  assert.equal(au2.detail.user, marker);
  assert.equal(au2.detail.src, "127.0.0.1");
  assert.match(vmLineTime(auth), /^\d{4}-10-28T16:00:01Z$/);
  const failedKey = "Oct 28 16:00:02 dc-01 sshd[4243]: Failed publickey for arena from 127.0.0.1 port 40123 ssh2";
  const au3 = parseVmLogLine("dc-01", "dc", { at: new Date().toISOString(), text: failedKey }, [marker]);
  assert.equal(au3.kind, "auth.login.failed");
  assert.equal(au3.actor, "noise");
  assert.equal(au3.detail.method, "publickey");
});

test("vm telemetry: Rocky sshd failures are collected from /var/log/secure", async () => {
  const { collectVmTelemetry } = await import("../dist/observability/vm-telemetry.js");
  const marker = "RED-o1-abc12345";
  const rockySpec = {
    ...spec([]),
    instances: [{ hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [] }],
  };
  const paths = [];
  const exec = async (_inst, command) => {
    const m = /tail -n \d+ (\S+)/.exec(command);
    if (m) paths.push(m[1]);
    return command.includes("/var/log/secure")
      ? `Oct 28 16:00:01 dc-01 sshd[4242]: Invalid user ${marker} from 127.0.0.1 port 40122`
      : "";
  };
  const events = await collectVmTelemetry(rockySpec, RUN, {
    state: { instances: { "dc-01": { hostId: "dc-01" } } }, exec, redMarkers: [marker],
  });
  assert.ok(paths.includes("/var/log/secure"), `secure is collected (got ${paths.join(", ")})`);
  const auth = events.find((e) => e.kind === "auth.login.failed");
  assert.ok(auth, "the Rocky sshd failure becomes an event");
  assert.equal(auth.actor, "red");
  assert.equal(auth.detail.user, marker);
});

test("vm telemetry: attacker web lines mentioning the proof path are kept, exact gate-proof artifacts are excluded", async () => {
  const { collectVmTelemetry } = await import("../dist/observability/vm-telemetry.js");
  const webSpec = {
    ...spec([FLAW]),
    instances: [{ hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: ["http"], databases: [] }],
  };
  const gateMarker = "arena-proof-g2-0123abcd";
  const lines = [
    `10.9.9.9 - - [28/Oct/2026:16:00:00 +0000] "GET /diag.php?host=x%3Bcat%20%2Fopt%2Farena-proof%2Farena-proof-o1 HTTP/1.1" 200 12 "-" "curl/8"`,
    `127.0.0.1 - - [28/Oct/2026:16:00:01 +0000] "GET /diag.php?host=x%3Becho%20${gateMarker} HTTP/1.1" 200 12 "-" "curl/8"`,
  ].join("\n");
  const exec = async (_inst, command) => command.includes("access.log") ? lines : "";
  const events = await collectVmTelemetry(webSpec, RUN, {
    state: { instances: { "web-01": { hostId: "web-01" } } }, exec, redSources: ["10.9.9.9"],
  });
  assert.equal(events.length, 1);
  assert.equal(events[0].actor, "red");
  assert.equal(events[0].kind, "http.request");
  assert.ok(!JSON.stringify(events).includes(gateMarker), "the gate-proof artifact is not exercise telemetry");
});

test("vm exercise: scripted red/blue scores two objectives from guest telemetry", async () => {
  const { runVmExercise, vmRedMarker } = await import("../dist/exercise/vm-live.js");
  const { livePack } = await import("../dist/exercise/live.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { canaryValue } = await import("../dist/configurator/ansible.js");
  const { deployability } = await import("../dist/provisioner/capability.js");

  const s = vmSpec({});
  s.objectives = [
    { id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "exec-marker", points: 10 },
    { id: "o2", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10 },
  ];
  s.plantedVulns = [
    { id: "v1", type: "code-flaw", techniqueId: "T1059", targetHostId: "web-01", pinnedVersion: "8", proofAtomicGuid: "g1", difficulty: "standard" },
    { id: "v2", type: "weak-cred", techniqueId: "T1078", targetHostId: "db-01", pinnedVersion: "16", proofAtomicGuid: "g2", difficulty: "standard" },
  ];
  assert.deepEqual(deployability(s), [], "a supported VM spec is deployable");

  const state = { runId: RUN, specName: "x", netMode: "user", instances: {
    "web-01": { hostId: "web-01", accel: "hvf", netMode: "user", pid: 1, overlay: "", seedIso: "", goldenDigest: "", inProcess: false, startedAt: "" },
    "db-01": { hostId: "db-01", accel: "hvf", netMode: "user", pid: 2, overlay: "", seedIso: "", goldenDigest: "", inProcess: false, startedAt: "" },
  } };
  const webMarker = vmRedMarker(RUN, "o1");
  const dbMarker = vmRedMarker(RUN, "o2");
  // Log timestamps are generated when the tail command runs (after the
  // exercise settles), matching a real guest that writes lines during red.
  const logStamps = () => {
    const now = new Date();
    const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    const d = String(now.getUTCDate()).padStart(2, "0");
    const hh = String(now.getUTCHours()).padStart(2, "0");
    const mm = String(now.getUTCMinutes()).padStart(2, "0");
    const ss = String(now.getUTCSeconds()).padStart(2, "0");
    return {
      stamp: `[${d}/${months[now.getUTCMonth()]}/${now.getUTCFullYear()}:${hh}:${mm}:${ss} +0000]`,
      pgStamp: `${now.getUTCFullYear()}-${String(now.getUTCMonth() + 1).padStart(2, "0")}-${d} ${hh}:${mm}:${ss}.000 UTC`,
    };
  };
  const diagCalls = [];
  const exec = async (_inst, cmd, timeoutMs) => {
    const { stamp, pgStamp } = logStamps();
    if (cmd.includes("audit.log")) return "";
    if (cmd.includes("access.log")) return `127.0.0.1 - - ${stamp} "GET /diag.php?host=x%3Becho%20${webMarker} HTTP/1.1" 200 12 "-" "curl/8"\n`;
    if (cmd.includes("error.log")) return `${webMarker}\n`;
    if (cmd.includes("postgresql-")) return `${pgStamp} [1] user=app db=app client=127.0.0.1 LOG:  statement: SELECT value FROM secrets WHERE objective_id='o2' /* ${dbMarker} */\n`;
    if (cmd.includes("psql") && cmd.includes("FROM secrets")) return canaryValue(RUN, "o2");
    if (cmd.includes("psql")) return "0";
    if (cmd.includes("diag.php")) { diagCalls.push({ cmd, timeoutMs }); return `x;echo ${webMarker}`; }
    if (cmd.includes("curl")) return "";
    return "";
  };
  const store = new EventStore();
  const pack = await livePack();
  // Stub Langfuse ingestion so the VM loop is held to the container trace
  // contract: one trace per run_id, one span per red/blue step, flush verified.
  const batches = [];
  const lf = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => { body += c; });
    req.on("end", () => { batches.push(JSON.parse(body)); res.writeHead(200, { "content-type": "application/json" }); res.end("{}"); });
  });
  await new Promise((r) => lf.listen(0, "127.0.0.1", r));
  const lfCfg = { host: `http://127.0.0.1:${lf.address().port}`, publicKey: "pk", secretKey: "sk" };
  const res = await runVmExercise({ spec: s, run: { runId: RUN, orgId: "org", deploymentId: "dep", mode: "blind", specDigest: "x", techniquePackVersion: "v1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm" } },
    { store, detections: pack.store, state, exec, noiseRounds: 1, langfuse: lfCfg });
  await new Promise((r) => lf.close(r));
  assert.equal(res.scorecard.objectivesAchieved, 2, JSON.stringify(res.scorecard));
  assert.equal(diagCalls.length, 1, "the web objective makes one diag request");
  assert.match(diagCalls[0].cmd, /--max-time 20\b/, "diag request allows a slow guest DNS lookup to finish");
  assert.ok(diagCalls[0].timeoutMs >= 30_000, `diag SSH timeout covers the HTTP budget (${diagCalls[0].timeoutMs})`);
  const entries = batches.flatMap((b) => b.batch);
  assert.equal(entries.filter((e) => e.type === "trace-create").length, 1, "one trace per run");
  assert.equal(entries.filter((e) => e.type === "trace-create")[0].body.id, RUN);
  const spans = entries.filter((e) => e.type === "span-create");
  assert.equal(spans.length, res.langfuseEvents - 1, "flush counts every entry it sent");
  assert.equal(spans.length, res.redSteps + new Set(res.alerts.map((a) => `${a.hostId}|${a.techniqueId}`)).size, "one span per red and blue step");
  assert.ok(spans.every((e) => e.body.traceId === RUN));
  assert.ok(res.alerts.length >= 2, `alerts: ${res.alerts.length}`);
  assert.equal(res.falsePositives, 0);
  assert.equal(res.redSteps, 2);

  // Unsupported VM vulns/roles stay blocked with a precise reason.
  s.plantedVulns = [{ id: "v3", type: "cve", techniqueId: "T1190", targetHostId: "web-01", pinnedVersion: "1", proofAtomicGuid: "g3", difficulty: "standard" }];
  assert.ok(deployability(s).some((r) => /not provable on role "web"/.test(r)));
});

test("vm exercise: failed SSH logins are collected, detected and attributed", async () => {
  const { runVmExercise, vmRedMarker } = await import("../dist/exercise/vm-live.js");
  const { livePack } = await import("../dist/exercise/live.js");
  const { EventStore } = await import("../dist/observability/events.js");
  const { deployability } = await import("../dist/provisioner/capability.js");
  const marker = vmRedMarker(RUN, "o3");
  const spec = {
    version: 1, name: "ssh-lab", provider: "kvm", seed: "s", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
    instances: [{ hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Debian 12", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "openldap", port: 389, readyWhen: "ldap-bind" }] }],
    personas: [], objectives: [{ id: "o3", asset: "dc-01", techniqueId: "T1110", successSignal: "auth-failures", points: 10 }],
    requiredTelemetry: ["auditd"], plantedVulns: [], budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
  };
  assert.deepEqual(deployability(spec), [], "credential guessing is deployable on a directory host");

  const state = { runId: RUN, specName: "ssh-lab", netMode: "user", instances: {
    "dc-01": { hostId: "dc-01", accel: "hvf", netMode: "user", pid: 1, overlay: "", seedIso: "", goldenDigest: "", inProcess: false, startedAt: "" } } };
  const month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const syslog = () => {
    const n = new Date();
    return `${month[n.getUTCMonth()]} ${String(n.getUTCDate()).padStart(2, "0")} ${String(n.getUTCHours()).padStart(2, "0")}:${String(n.getUTCMinutes()).padStart(2, "0")}:${String(n.getUTCSeconds()).padStart(2, "0")}`;
  };
  const exec = async (_inst, cmd) => {
    if (cmd.includes("BatchMode=yes")) return "Permission denied (publickey).\n";
    if (cmd.includes("auth.log")) return `${syslog()} dc-01 sshd[1]: Invalid user ${marker} from 127.0.0.1 port 40000\n`;
    return "";
  };
  const store = new EventStore();
  const pack = await livePack();
  const res = await runVmExercise({ spec, run: { runId: RUN, orgId: "org", deploymentId: "dep", mode: "blind", specDigest: "x", techniquePackVersion: "v1", modelIds: {}, truthLayer: "mirror-only", backend: "kvm" } },
    { store, detections: pack.store, state, exec, noiseRounds: 1 });
  assert.equal(res.scorecard.objectivesAchieved, 1, JSON.stringify(res.scorecard));
  assert.equal(res.falsePositives, 0);
  assert.ok(res.alerts.some((a) => a.techniqueId === "T1110"), `alerts: ${JSON.stringify(res.alerts.map((a) => a.techniqueId))}`);
});

test("deployability: a VM disk smaller than the catalog image is rejected", async () => {
  const { deployability } = await import("../dist/provisioner/capability.js");
  const { MIN_VM_DISK_GB } = await import("../dist/provisioner/images.js");
  const s = vmSpec({});
  s.instances[0].resources = { vcpu: 1, memoryMb: 512, diskGb: MIN_VM_DISK_GB - 2 };
  const blocked = deployability(s);
  assert.equal(blocked.length, 1, blocked.join("; "));
  assert.match(blocked[0], /smaller than the catalog image/);
  s.instances[0].resources = { vcpu: 1, memoryMb: 512, diskGb: MIN_VM_DISK_GB };
  assert.deepEqual(deployability(s), []);
});

test("clinic org archetype: the fixed-seed demo design validates and stays deployable", async () => {
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const { validateDesign, digestOf } = await import("../dist/designer/pipeline.js");
  const { deployability } = await import("../dist/provisioner/capability.js");
  const { validatePendingSpec } = await import("../dist/workflows/trigger.js");
  const s = clinicOrgSpec();
  assert.deepEqual(validateDesign(s), []);
  assert.deepEqual(deployability(s), []);
  // The workflow trigger parses the stored spec; a hand-built demo spec that
  // skips this check can be missing required service fields.
  const trigger = validatePendingSpec(s);
  assert.equal(trigger.ok, true, trigger.ok ? "" : trigger.reason);
  assert.equal(s.instances.length, 6);
  assert.equal(s.personas.length, 8);
  assert.equal(s.objectives.length, 3);
  assert.equal(digestOf(s), digestOf(clinicOrgSpec()), "fixed seed is deterministic");
});

test("org archetypes: the clinic materialises deterministically and pins its versions", async () => {
  const { CLINIC_ARCHETYPE, materializeArchetype, designPin, pinnedDesignDigest, findArchetype } = await import("../dist/designer/archetypes.js");
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const { validateDesign, digestOf } = await import("../dist/designer/pipeline.js");
  const { deployability } = await import("../dist/provisioner/capability.js");

  const a = materializeArchetype(CLINIC_ARCHETYPE);
  assert.equal(digestOf(a), digestOf(clinicOrgSpec()), "clinicOrgSpec is the materialised archetype");
  assert.deepEqual(validateDesign(a), []);
  assert.deepEqual(deployability(a), []);
  assert.equal(findArchetype("clinic").version, 1);
  assert.equal(findArchetype("clinic", 2), undefined);
  assert.equal(findArchetype("nope"), undefined);

  const pin = designPin(CLINIC_ARCHETYPE);
  assert.equal(pin.archetype, "clinic@1");
  assert.equal(pin.catalog, "arena-catalog-4");
  assert.equal(designPin(null).archetype, "model", "model-authored specs have no archetype");
  const pinned = pinnedDesignDigest(a, pin);
  assert.match(pinned, /^sha256:[0-9a-f]{64}$/);
  assert.equal(pinned, pinnedDesignDigest(clinicOrgSpec(), pin), "pinned digest is deterministic");
  assert.notEqual(pinned, pinnedDesignDigest(a, { ...pin, image: "arena-golden-debian12-catalog-4" }), "a version change changes the digest");
  assert.notEqual(pinned, digestOf(a), "the pinned digest is not the bare spec digest");
});

test("run record pins the versions that produced the design (T-17)", async () => {
  const { CLINIC_ARCHETYPE, designPin, pinnedDesignDigest, pinForSpec } = await import("../dist/designer/archetypes.js");
  const { clinicOrgSpec, clinicOrgSpecWithAttacker } = await import("../dist/designer/clinic.js");
  const { digestOf } = await import("../dist/designer/pipeline.js");
  const { runRecordFor } = await import("../dist/workflows/trigger.js");

  assert.equal(pinForSpec(clinicOrgSpec()).archetype, "clinic@1", "archetype provenance is recovered from the spec itself");
  assert.equal(pinForSpec(clinicOrgSpecWithAttacker()).archetype, "clinic@1", "the attacker variant is still the clinic");
  assert.equal(pinForSpec(clinicOrgSpec({ ttlHours: 2 })).archetype, "clinic@1", "TTL is a budget, not provenance");
  assert.equal(pinForSpec(vmSpec({})).archetype, "model", "a non-archetype spec pins as model-authored");

  const run = runRecordFor("dep-1", "org-1", clinicOrgSpec());
  assert.equal(run.specDigest, pinnedDesignDigest(clinicOrgSpec(), designPin(CLINIC_ARCHETYPE)),
    "the trigger-built run record carries the pinned digest, like the demo dataset");
  assert.notEqual(run.specDigest, digestOf(clinicOrgSpec()), "never the bare spec digest");
});

test("designer output budget leaves room for reasoning tokens", async () => {
  const { designEnvironment } = await import("../dist/designer/pipeline.js");
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  let seen = 0;
  const client = {
    modelId: "spy",
    async generateTurn() { throw new Error("unused"); },
    async generateObject(args) { seen = args.maxTokens ?? 0; return clinicOrgSpec(); },
  };
  const r = await designEnvironment(client, "clinic", { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 });
  assert.ok(r.withinBudget, JSON.stringify({ v: r.violations, e: r.designErrors }));
  // Reasoning tokens count against the budget; 8192 produced an empty response live.
  assert.ok(seen >= 32768, `designer must budget beyond reasoning tokens (got ${seen})`);
});

test("vm cost: per-role estimates replace the flat vm rate", async () => {
  const { estimateCostPerHour } = await import("../dist/designer/cost.js");
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const s = clinicOrgSpec();
  const only = (hostId) => ({ ...s, instances: [s.instances.find((i) => i.hostId === hostId)] });
  assert.ok(estimateCostPerHour(s) > 0 && estimateCostPerHour(s) <= 5, `clinic within budget: ${estimateCostPerHour(s)}`);
  assert.ok(estimateCostPerHour(only("db-01")) > estimateCostPerHour(only("web-01")), "db costs more than web");
  assert.ok(estimateCostPerHour(only("web-01")) > estimateCostPerHour(only("gw-01")), "web costs more than the gateway");
});

test("vm drift: observed from the readiness probes, not reported unobserved", async () => {
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const { observeVmState } = await import("../dist/ops/maintenance.js");
  const { detectDrift } = await import("../dist/ops/drift.js");
  const spec = clinicOrgSpec();
  const instances = Object.fromEntries(spec.instances.map((i, n) => [i.hostId, {
    hostId: i.hostId, accel: "hvf", netMode: "user", pid: n + 1, overlay: "", seedIso: "", goldenDigest: "", inProcess: false, startedAt: "",
  }]));
  const state = { runId: RUN, specName: "clinic", netMode: "user", instances };
  const exec = async (hostId, cmd) => {
    if (hostId === "gw-01" && cmd.includes("dig")) throw new Error("dnsmasq down");
    if (cmd === "id -un") return "arena";
    if (cmd.includes("psql")) return "1";
    if (cmd.includes("ldapsearch")) return "dn: dc=arena,dc=lab";
    // The log-shipping proof polls until the marker appears; answer it first time.
    if (cmd.includes("grep -c")) return "1";
    return "ok";
  };

  const observed = await observeVmState(spec, RUN, { state, exec });
  assert.equal(observed.length, 6);
  assert.deepEqual(observed.find((o) => o.hostId === "gw-01").services, [], "a failed probe is not observed as running");
  assert.deepEqual(observed.find((o) => o.hostId === "web-01").services, ["http"]);
  assert.deepEqual(detectDrift(spec, observed).filter((d) => d.drifted),
    [{ hostId: "gw-01", drifted: true, missingServices: ["dns"], extraServices: [] }], "only the failed service drifts");

  // A host missing from the registry is gone, never "in sync".
  const empty = await observeVmState(spec, RUN, { state: { ...state, instances: {} }, exec });
  assert.equal(detectDrift(spec, empty).filter((d) => d.drifted).length, 6);
  // No registry at all is the same verdict, not a clean bill of health.
  assert.deepEqual(await observeVmState(spec, RUN, { state: null, exec }), []);
});

test("org coherence: an org that cannot be scored is rejected with a named reason", async () => {
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const { validateDesign } = await import("../dist/designer/pipeline.js");
  const { isOrgSpec, validateCoherence } = await import("../dist/designer/coherence.js");
  const { validatePendingSpec } = await import("../dist/workflows/trigger.js");

  const base = clinicOrgSpec();
  assert.equal(isOrgSpec(base), true);
  assert.deepEqual(validateCoherence(base), [], "the clinic is coherent");
  assert.deepEqual(validateDesign(base), []);

  const wrongAsset = structuredClone(base);
  wrongAsset.objectives[0].asset = "gw-01";
  assert.ok(validateDesign(wrongAsset).some((e) => /cannot realize T1059/.test(e)), "an objective needs a host that can realize its technique");

  const unknownTechnique = structuredClone(base);
  unknownTechnique.objectives[0].techniqueId = "T9999";
  assert.ok(validateDesign(unknownTechnique).some((e) => /no known proof path/.test(e)), "an unknown technique fails closed");

  // Model-authored specs append parameters to the signal text; the technique decides the proof path.
  const parameterised = structuredClone(base);
  parameterised.objectives[0].successSignal = "exec-marker:web-01:intranet-pwned";
  parameterised.objectives[1].successSignal = "canary-hash:patient-db:9f2c4a7e";
  parameterised.objectives[2].successSignal = "auth-log-guess-marker:dc-01:sshd-success";
  assert.deepEqual(validateCoherence(parameterised), [], "signal parameters are accepted");
  const stillWrongHost = structuredClone(parameterised);
  stillWrongHost.objectives[0].asset = "gw-01";
  assert.ok(validateCoherence(stillWrongHost).some((e) => /cannot realize T1059/.test(e)), "the host check still applies");

  const cyclic = structuredClone(base);
  cyclic.instances.find((i) => i.hostId === "gw-01").dependsOn = ["db-01"];
  assert.ok(validateDesign(cyclic).some((e) => /dependency cycle/.test(e)), "dependency cycles are rejected");
  const pending = validatePendingSpec(cyclic);
  assert.equal(pending.ok, false);
  assert.match(pending.reason, /invalid design: .*dependency cycle/);

  const isolated = structuredClone(base);
  isolated.instances.find((i) => i.hostId === "web-01").dependsOn = [];
  isolated.personas = isolated.personas.filter((p) => p.workstation === "web-01");
  assert.ok(validateDesign(isolated).some((e) => /workstation "web-01" has no client tools/.test(e)));

  const unplaced = structuredClone(base);
  unplaced.topology.subnets.push({ name: "clinic-dmz", cidr: "10.2.48.0/20", zone: "b" });
  assert.ok(validateDesign(unplaced).some((e) => /no subnet placed in a 2-subnet topology/.test(e)));

  const duplicateHost = structuredClone(base);
  duplicateHost.instances[1].hostId = "gw-01";
  assert.ok(validateDesign(duplicateHost).some((e) => /instance hostId "gw-01" is duplicated/.test(e)), "hostIds must be unique");

  // requiredTelemetry must be something the base profile or a declared service emits.
  const unknownTelemetry = structuredClone(base);
  unknownTelemetry.requiredTelemetry = ["zeek.conn"];
  assert.ok(validateDesign(unknownTelemetry).some((e) => /requiredTelemetry "zeek.conn" is not emitted/.test(e)));
  const declaredTelemetry = structuredClone(base);
  declaredTelemetry.requiredTelemetry = ["auditd", "auth.log", "postgres.log"];
  assert.deepEqual(validateDesign(declaredTelemetry), [], "base-profile and declared-service telemetry are accepted");

  // Container specs keep their existing validation.
  const container = structuredClone(base);
  for (const i of container.instances) { i.runtime = "container"; i.serviceDecls = []; }
  assert.equal(isOrgSpec(container), false);
  assert.deepEqual(validateCoherence(container), []);
});

test("trigger runs the same design and plan gates as the designer", async () => {
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const { validatePendingSpec } = await import("../dist/workflows/trigger.js");
  const base = clinicOrgSpec();

  const noSignal = structuredClone(base);
  noSignal.objectives[0].successSignal = "";
  const a = validatePendingSpec(noSignal);
  assert.equal(a.ok, false);
  assert.match(a.reason, /invalid design: .*successSignal/);

  const noTelemetry = structuredClone(base);
  noTelemetry.requiredTelemetry = [];
  const b = validatePendingSpec(noTelemetry);
  assert.equal(b.ok, false);
  assert.match(b.reason, /requiredTelemetry/);

  // A malformed or too-small subnet used to pass the trigger and fail only
  // when the lab plan ran; it must be refused before any guest boots.
  const badCidr = structuredClone(base);
  badCidr.topology.subnets[0].cidr = "10.2.32.0";
  const c = validatePendingSpec(badCidr);
  assert.equal(c.ok, false);
  assert.match(c.reason, /cannot be planned: .*not a CIDR/);

  const tooSmall = structuredClone(base);
  tooSmall.topology.subnets[0].cidr = "10.2.32.0/29";
  const d = validatePendingSpec(tooSmall);
  assert.equal(d.ok, false);
  assert.match(d.reason, /cannot be planned: .*cannot hold/);

  const clinic = validatePendingSpec(base);
  assert.equal(clinic.ok, true, "the clinic still passes every gate");
  assert.equal(clinic.plan.hosts.length, base.instances.length, "the gate returns the plan it approved");
});

test("deployability: dns+dhcp on a VM gateway is deployable", async () => {
  const { deployability } = await import("../dist/provisioner/capability.js");
  const s = vmSpec({});
  const gw = { hostId: "gw-01", name: "gw-01", role: "gateway", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
    serviceDecls: [{ kind: "dns", impl: "dnsmasq" }] };
  s.instances.push(gw);
  assert.deepEqual(deployability(s), [], "dns-only gateway is deployable");
  gw.serviceDecls = [{ kind: "dns", impl: "dnsmasq" }, { kind: "dhcp", impl: "dnsmasq" }];
  assert.deepEqual(deployability(s), [], "dns+dhcp gateway is deployable on the VM runtime");
});

test("dhcp: lease pool, configure task, deployability and lab lease probe", async () => {
  const { dhcpPoolFor } = await import("../dist/provisioner/lab-network.js");
  const { deployability } = await import("../dist/provisioner/capability.js");
  const { probeFor, labProbesFor } = await import("../dist/configurator/readiness.js");

  // The pool sits at the top of the subnet; static lab addresses (.1, .10+)
  // can never collide with a lease.
  assert.deepEqual(dhcpPoolFor("10.2.32.0/20"), { start: "10.2.47.223", end: "10.2.47.254", netmask: "255.255.240.0" });
  assert.deepEqual(dhcpPoolFor("10.9.0.0/24"), { start: "10.9.0.223", end: "10.9.0.254", netmask: "255.255.255.0" });

  const s = vmSpec({});
  s.instances.push({ hostId: "gw-01", name: "gw-01", role: "gateway", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
    serviceDecls: [{ kind: "dns", impl: "dnsmasq" }, { kind: "dhcp", impl: "dnsmasq" }] });
  const gwTasks = tasksFor(s, RUN, "gw-01");
  const dhcpTask = gwTasks.find((t) => t.name === "dhcp-configure");
  assert.ok(dhcpTask, `dhcp-configure task exists (${gwTasks.map((t) => t.name).join(",")})`);
  const script = decode(dhcpTask.raw);
  assert.match(script, /dhcp-range=10\.2\.47\.223,10\.2\.47\.254,255\.255\.240\.0/);
  assert.match(script, /dhcp-authoritative/);
  assert.match(script, /dhcp-option=option:router,10\.2\.32\.1/);
  assert.match(script, /dhcp-option=option:dns-server,10\.2\.32\.1/);

  assert.deepEqual(deployability(s).filter((r) => /dhcp/i.test(r)), [], "VM dhcp on the gateway is deployable");
  const containerSpec = { ...s, instances: s.instances.map((i) => ({ ...i, runtime: "container" })) };
  assert.ok(deployability(containerSpec).some((r) => /dhcp.*VM runtime/.test(r)), "container dhcp is blocked precisely");

  const local = probeFor({ kind: "dhcp", impl: "dnsmasq" }, { hostId: "gw-01", runId: RUN, sshUser: "arena", services: [], domain: "x.arena.lab" });
  assert.match(local.command, /is-active dnsmasq/, "the local probe proves the server, not a lease that cannot exist yet");
  assert.match(local.command, /:67/);

  const lab = labProbesFor(s, RUN).find((p) => p.probe === "lab-dhcp");
  assert.ok(lab, "a cross-host lease probe is planned");
  assert.equal(lab.to, "gw-01");
  assert.notEqual(lab.from, "gw-01");
  assert.match(lab.command, /python3/, "the lease proof speaks real DHCP from a peer guest");
  assert.equal(lab.expect, "DHCPACK");
});

test("lab-sql: the web tier reads from the database over the segment with a probe credential", async () => {
  const { labProbesFor } = await import("../dist/configurator/readiness.js");
  const { labSecret } = await import("../dist/configurator/lab.js");
  const s = vmSpec({});

  const dbTasks = tasksFor(s, RUN, "db-01");
  const seed = decode(dbTasks.find((t) => t.name === "db-seed-access").raw);
  assert.match(seed, /arena_probe/, "a dedicated probe role is seeded");
  assert.match(seed, new RegExp(labSecret(RUN, "db-probe")), "the probe password is the per-run lab secret");
  assert.match(seed, /arena_probe_ping/, "a probe-readable table is seeded");
  assert.match(seed, /arena-db-ready/);
  const configure = decode(dbTasks.find((t) => t.name === "db-configure").raw);
  assert.match(configure, /host all arena_probe 10\.2\.32\.0\/20 scram-sha-256/, "the probe role may authenticate from the lab segment only");

  const probes = labProbesFor(s, RUN);
  assert.ok(!probes.some((p) => p.probe === "lab-tcp"), "the port-only db probe is superseded by a real read");
  const sql = probes.find((p) => p.probe === "lab-sql");
  assert.ok(sql, "a cross-host SQL read probe is planned");
  assert.equal(sql.from, "web-01");
  assert.equal(sql.to, "db-01");
  assert.equal(sql.expect, "arena-db-ready");
  assert.match(sql.command, /-U arena_probe/);
  assert.match(sql.command, /SELECT v FROM arena_probe_ping/);
  assert.match(sql.command, new RegExp(`not-${labSecret(RUN, "db-probe")}`), "a wrong probe password must fail first (no trust-rule pass)");
});

test("container readiness: role-derived probes run over docker exec; VM default unchanged", async () => {
  const { checkSpecReadiness } = await import("../dist/configurator/readiness.js");
  const { execInContainerShell } = await import("../dist/configurator/docker-executors.js");
  const s = spec([]);
  const exec = async (_h, cmd) => {
    if (cmd === "id -un") return "root\n";
    if (cmd.includes("curl")) return "OK";
    if (cmd.includes("SELECT 1")) return "1";
    return "";
  };
  assert.deepEqual(await checkSpecReadiness({ spec: s, runId: RUN, sshUserOf: () => "arena", exec }), [],
    "the default (VM) pass still ignores container instances");
  const results = await checkSpecReadiness({ spec: s, runId: RUN, runtime: "container", sshUserOf: () => "root", exec });
  assert.equal(results.length, 2, JSON.stringify(results));
  assert.ok(results.every((r) => r.ok), JSON.stringify(results));
  assert.ok(results.find((r) => r.hostId === "web-01").checks.some((c) => c.kind === "http/apache-php" && c.ok), "web role derives the http probe");
  assert.ok(results.find((r) => r.hostId === "db-01").checks.some((c) => c.kind === "db/postgres" && c.ok), "db role derives the sql probe");
  const down = await checkSpecReadiness({
    spec: s, runId: RUN, runtime: "container", sshUserOf: () => "root",
    exec: async (_h, cmd) => { if (cmd === "id -un") return "root\n"; if (cmd.includes("curl")) throw new Error("connection refused"); return "1"; },
  });
  assert.equal(down.find((r) => r.hostId === "web-01").ok, false, "a stopped container service fails readiness");
  assert.equal(down.find((r) => r.hostId === "db-01").ok, true);
  const echoed = await execInContainerShell("ma-x-web-01", "id -un", { docker: "/bin/echo" });
  assert.match(echoed, /exec ma-x-web-01 sh -c id -un/, "shell exec targets the run container");
  await assert.rejects(execInContainerShell("ma-x-web-01", "id -un", { docker: "/bin/false" }), "a failing docker exec throws so probes fail closed");
});

test("readiness: a disabled declared service fails by host and service, other hosts still pass", async () => {
  const { checkSpecReadiness } = await import("../dist/configurator/readiness.js");
  const { readFileSync } = await import("node:fs");
  const s = vmSpec({ "web-01": [{ kind: "http", impl: "apache-php" }], "db-01": [{ kind: "db", impl: "postgres" }] });
  const results = await checkSpecReadiness({
    spec: s, runId: RUN, sshUserOf: () => "arena",
    exec: async (hostId, cmd) => {
      if (cmd === "id -un") return "arena\n";
      if (hostId === "web-01" && cmd.includes("curl")) throw new Error("curl: (7) connection refused");
      if (cmd.includes("SELECT v FROM arena_probe_ping")) return "arena-db-ready";
      return "1";
    },
  });
  const web = results.find((r) => r.hostId === "web-01");
  const db = results.find((r) => r.hostId === "db-01");
  assert.equal(web.ok, false, "the host with the disabled service fails readiness");
  const failed = web.checks.filter((c) => !c.ok);
  assert.ok(failed.some((c) => c.kind === "http/apache-php"), `the failed service is named: ${JSON.stringify(failed)}`);
  assert.equal(db.ok, true, `an unrelated host still passes: ${JSON.stringify(db.checks)}`);
  // The live acceptance scenario is wired into the config smoke harness.
  const smoke = readFileSync(new URL("../scripts/vm-config-smoke.mjs", import.meta.url), "utf8");
  assert.match(smoke, /--negative/, "config smoke has a service-disabled acceptance mode");
  assert.match(smoke, /READINESS NEGATIVE/, "the negative mode reports its own verdict");
});

test("lab-mail: IMAP authenticates against OpenLDAP from a peer guest", async () => {
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const { labProbesFor } = await import("../dist/configurator/readiness.js");
  const { labSecret } = await import("../dist/configurator/lab.js");
  const clinic = clinicOrgSpec();

  const mail = decode(tasksFor(clinic, RUN, "mail-01").find((t) => t.name === "mail-configure").raw);
  assert.match(mail, /dovecot-ldap\.conf\.ext/, "dovecot gets an LDAP config on a directory-backed mail host");
  assert.match(mail, /auth_bind_userdn = uid=%u,ou=people,/, "passdb binds as the user against OpenLDAP");
  assert.match(mail, /hosts = 10\.2\.32\.10:389/, "the directory is reached at its lab address");
  assert.match(mail, /useradd -m -u 10001/, "the mailbox system user matches the directory uidNumber");
  assert.ok(!/chpasswd/.test(mail), "no local mail password on a directory-backed host (LDAP is the only passdb)");

  const seed = decode(tasksFor(clinic, RUN, "dc-01").find((t) => t.name === "ldap-seed").raw);
  assert.match(seed, /posixAccount/, "the directory probe user carries POSIX attributes for the userdb");
  assert.match(seed, /uidNumber: 10001/);
  assert.match(seed, /ldappasswd/, "the directory probe password is set through the password-modify exop");
  assert.match(seed, new RegExp(labSecret(RUN, "mail-probe")));

  const standalone = { ...clinic, instances: clinic.instances.map((i) => (i.hostId === "mail-01" ? { ...i, dependsOn: [] } : i)) };
  const plain = decode(tasksFor(standalone, RUN, "mail-01").find((t) => t.name === "mail-configure").raw);
  assert.ok(!plain.includes("dovecot-ldap.conf.ext"), "no directory auth without the declared dependency");
  assert.match(plain, /chpasswd/, "an unjoined mail host keeps the local probe account");

  const probes = labProbesFor(clinic, RUN);
  const labMail = probes.find((p) => p.probe === "lab-mail");
  assert.ok(labMail, "a cross-host mail login probe is planned");
  assert.equal(labMail.to, "mail-01");
  assert.notEqual(labMail.from, "mail-01");
  assert.match(labMail.command, /imap:\/\/10\.2\.32\.11:143\/INBOX/, "login runs against the mail lab address from a peer");
  assert.match(labMail.command, new RegExp(`not-${labSecret(RUN, "mail-probe")}`), "a wrong directory password must be refused");
  assert.ok(!labProbesFor(standalone, RUN).some((p) => p.probe === "lab-mail"), "no directory mail claim without membership");
});

test("designer: the worker's capabilities decide what can be designed", async () => {
  const { classifyHost } = await import("../dist/provisioner/kvm.js");
  const { hostCapabilities, hostBrief, bakedStatusFor } = await import("../dist/provisioner/host-capabilities.js");
  const { deployability, capabilityCatalog } = await import("../dist/provisioner/capability.js");
  const kvm = classifyHost({ platform: "linux", arch: "x64", hasKvmDevice: true, qemuX86: "/usr/bin/qemu-system-x86_64", qemuArm: null });
  const tcg = classifyHost({ platform: "linux", arch: "x64", hasKvmDevice: false, qemuX86: "/usr/bin/qemu-system-x86_64", qemuArm: null });

  const scored = hostCapabilities(kvm, { baked: "staged", container: true });
  assert.equal(scored.vmRuns, true);
  assert.equal(scored.guestArch, "x86_64");
  assert.match(hostBrief(scored), /VM guests are available/);
  assert.match(hostBrief(scored), /truth layer cap: mirror-only/);

  const noVm = hostCapabilities(tcg, { baked: "absent", container: true });
  assert.equal(noVm.vmRuns, false);
  assert.match(hostBrief(noVm), /VM guests cannot run on this worker/);
  assert.match(hostBrief(noVm), /Design a container lab/);

  // The same VM spec is deployable on KVM and refused where guests cannot boot.
  const s = vmSpec({});
  assert.equal(deployability(s, { caps: scored }).length, 0, deployability(s, { caps: scored }).join("; "));
  assert.ok(deployability(s, { caps: noVm }).some((r) => /VM guests cannot boot on this worker/.test(r)));

  // A worker with no docker cannot run container labs either.
  assert.ok(deployability({ ...s, instances: s.instances.map((i) => ({ ...i, runtime: "container", serviceDecls: [] })) }, { caps: { ...scored, container: false } })
    .some((r) => /need docker/.test(r)));

  // An operator-pinned platform is part of deployability, not a UI hint.
  const wrongRuntime = { ...s, platform: { runtimeTarget: "container", modelSurface: "meta", exerciseEngine: "scripted" } };
  assert.ok(deployability(wrongRuntime, { caps: scored }).some((r) => /selected container platform requires runtime "container"/.test(r)));
  // Muse Spark Open on Modal serves agent tool turns, so Modal agents deploy like Meta agents.
  const modalAgents = { ...s, platform: { runtimeTarget: "vm", modelSurface: "meta-modal", exerciseEngine: "agents" } };
  assert.ok(!deployability(modalAgents, { caps: scored }).some((r) => /Meta Modal|tool-turn surface/.test(r)));

  assert.match(capabilityCatalog(hostBrief(scored)), /## This worker/);
  assert.equal(bakedStatusFor("x86_64", "/nonexistent-cache"), "pinned-but-missing", "x86_64 pinned but not staged here");
  assert.equal(bakedStatusFor("aarch64", "/nonexistent-cache"), "pinned-but-missing", "pinned but not staged here");
});

test("designer: one bounded semantic repair, then the refusal stands", async () => {
  const { designEnvironment } = await import("../dist/designer/pipeline.js");
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const budget = { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 };
  const bad = clinicOrgSpec();
  bad.personas = bad.personas.map((p, i) => (i === 0 ? { ...p, workstation: "gw-01" } : p));

  let calls = 0;
  const fixing = {
    modelId: "spy",
    async generateTurn() { throw new Error("unused"); },
    async generateObject() { calls += 1; return calls === 1 ? bad : clinicOrgSpec(); },
  };
  const fixed = await designEnvironment(fixing, "clinic", budget);
  assert.equal(calls, 2, "one repair attempt after a semantic refusal");
  assert.equal(fixed.withinBudget, true, JSON.stringify({ v: fixed.violations, e: fixed.designErrors }));
  assert.equal(fixed.repaired, true);
  assert.match(fixed.digest, /^sha256:/);

  let stubbornCalls = 0;
  const stubborn = {
    modelId: "spy",
    async generateTurn() { throw new Error("unused"); },
    async generateObject() { stubbornCalls += 1; return bad; },
  };
  const still = await designEnvironment(stubborn, "clinic", budget);
  assert.equal(stubbornCalls, 2, "never more than one retry");
  assert.equal(still.withinBudget, false);
  assert.ok(still.designErrors.some((e) => /no client tools/.test(e)));
  assert.equal(still.repaired, undefined, "a failed repair does not claim to have fixed anything");
});

test("designer: provisioning blockers enter the bounded semantic repair", async () => {
  const { designEnvironment } = await import("../dist/designer/pipeline.js");
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const budget = { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 };
  const bad = clinicOrgSpec();
  bad.instances = bad.instances.map((instance) =>
    instance.hostId === "dc-01"
      ? {
          ...instance,
          hostId: "ipa-01",
          name: "ipa-01",
          os: "Debian 12",
          services: ["ldap"],
          serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
        }
      : { ...instance, dependsOn: (instance.dependsOn ?? []).map((id) => id === "dc-01" ? "ipa-01" : id) });
  bad.objectives = bad.objectives.map((objective) =>
    objective.asset === "dc-01" ? { ...objective, asset: "ipa-01" } : objective);
  bad.plantedVulns = bad.plantedVulns.map((vuln) =>
    vuln.id === "v1" ? { ...vuln, targetHostId: "mail-01" } : vuln);

  let calls = 0;
  let repairPrompt = "";
  const client = {
    modelId: "mock",
    async generateObject(args) {
      calls += 1;
      if (calls === 2) repairPrompt = args.prompt;
      return calls === 1 ? bad : clinicOrgSpec();
    },
  };

  const fixed = await designEnvironment(client, "clinic with FreeIPA", budget);
  assert.equal(calls, 2, "deployability failures get the same one bounded repair as coherence failures");
  assert.match(repairPrompt, /FreeIPA server needs Rocky Linux 9/);
  assert.match(repairPrompt, /code-flaw.*not provable on role "mail"/);
  assert.equal(fixed.repaired, true);
  assert.deepEqual(fixed.designErrors, []);
});

test("designer skills: the injected catalog matches the runtime catalog and the validation gates", async () => {
  const { capabilityCatalog } = await import("../dist/provisioner/capability.js");
  const { SERVICE_CATALOG } = await import("../dist/configurator/catalog.js");
  const { BASE_TELEMETRY } = await import("../dist/designer/coherence.js");
  const text = capabilityCatalog();
  // Every deployable implementation is named for the model, or it can never be designed.
  for (const c of SERVICE_CATALOG) {
    assert.ok(text.includes(c.impl), `catalog text missing impl ${c.kind}/${c.impl}`);
    for (const t of c.telemetry) assert.ok(text.includes(t), `catalog text missing telemetry ${t} (${c.kind}/${c.impl})`);
  }
  // The base-profile names are duplicated into the catalog text; pin them to the gate's set.
  for (const t of BASE_TELEMETRY) assert.ok(text.includes(t), `catalog text missing base telemetry ${t}`);
  assert.match(text, /dhcp \(dnsmasq\) is deployable on a VM gateway/, "dhcp is offered with its VM-gateway constraints");
  assert.match(text, /attacker guest IN the spec/, "VM model exercises need the attacker designed in");
  assert.match(text, /git \(gitea, directory login — its host must dependsOn the FreeIPA server\)/);
});

test("designer refine: the system prompt carries the checked capability catalog", async () => {
  const { refineEnvironment } = await import("../dist/designer/pipeline.js");
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  let system = "";
  const spy = {
    modelId: "spy",
    async generateObject(args) { system = args.system; return clinicOrgSpec(); },
  };
  const out = await refineEnvironment(spy, clinicOrgSpec(), "rename the lab", { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 });
  assert.equal(out.withinBudget, true, JSON.stringify({ v: out.violations, e: out.designErrors }));
  assert.match(system, /## Capability catalog \(checked\)/, "a host-adding refinement gets the closed vocabulary too");
  assert.match(system, /gitea/);
  assert.match(system, /requiredTelemetry vocabulary/);
});

test("dns-resolver: the DNS gateway the directory depends on does not wait for the realm (configured first)", async () => {
  const { tasksFor, hostOrder } = await import("../dist/configurator/ansible.js");
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const s = structuredClone(clinicOrgSpec());
  // The shape the designer produced live: a FreeIPA directory that depends on the gateway.
  const dc = s.instances.find((i) => i.role === "dc");
  dc.os = "Rocky Linux 9";
  dc.serviceDecls = [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }];
  dc.dependsOn = ["gw-01"];
  assert.ok(hostOrder(s).indexOf("gw-01") < hostOrder(s).indexOf(dc.hostId), "gateway is configured before the directory");
  const decode = (hostId) => {
    const t = tasksFor(s, "run-x", hostId).find((x) => x.name === "dns-resolver");
    if (!t) return "";
    const b = t.raw.match(/([A-Za-z0-9+/=]{40,})/);
    return b ? Buffer.from(b[1], "base64").toString() : t.raw;
  };
  assert.ok(!/_kerberos\._udp/.test(decode("gw-01")), "gateway must not block on realm SRV records that cannot exist yet");
  assert.match(decode("mail-01"), /_kerberos\._udp/, "members still verify the realm");
});

test("Rocky FreeIPA host: SSH client tools resolve to Rocky's package name", async () => {
  const { resolveProfile, resolveProfilePackages } = await import("../dist/configurator/profiles.js");
  const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
  const s = structuredClone(clinicOrgSpec());
  const dc = s.instances.find((i) => i.role === "dc");
  dc.os = "Rocky Linux 9";
  dc.serviceDecls = [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }];
  // The live design gave the directory an ssh dependency, which pulls the SSH client.
  s.instances.push({ hostId: "jump-01", name: "jump-01", role: "workstation", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [], serviceDecls: [{ kind: "ssh", impl: "openssh", port: 22, readyWhen: "ssh-login" }] });
  dc.dependsOn = [...(dc.dependsOn ?? []), "jump-01"];
  const pkgs = resolveProfilePackages(resolveProfile(s, dc.hostId), dc.os);
  assert.ok(pkgs.includes("openssh-clients"), pkgs.join(" "));
  assert.ok(!pkgs.includes("openssh-client"), "the Debian name does not exist on Rocky");
});

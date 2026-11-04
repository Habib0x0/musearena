/**
 * Live P3 source-control smoke — Gitea logs in domain users via FreeIPA LDAP.
 *
 *   node scripts/vm-gitea-smoke.mjs
 *
 * Rocky dc-01 (FreeIPA, persona p1 seeded) + Debian git-01 (git/gitea,
 * dependsOn dc-01, joined, baked Gitea binary). Proves:
 *   - Gitea serves /api/v1/version
 *   - p1 authenticates through the LDAP auth source (GET /api/v1/user)
 *   - a wrong password is refused by 389-ds, not a local account
 *   - readiness git-ldap-login passes as the domain user
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
import { ipaUserIdFor, ipaUserSecret } from "../dist/configurator/lab.js";
import { labDomainFor } from "../dist/configurator/dns.js";

const run = promisify(execFile);
const host = detectHost();
const runId = `run-vm-git-${Date.now().toString(36)}`;
const stateRoot = process.env.VM_STATE_ROOT ?? path.join(process.cwd(), ".disposable");
const lifecycle = { stateRoot, runId };
console.log("host:", host.platform, host.arch, "accel:", host.accel);

const spec = {
  version: 1, name: "gitea-smoke", provider: "kvm", seed: "smoke", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Rocky Linux 9", stack: [], services: ["ldap"], databases: [],
      serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
      resources: { vcpu: 2, memoryMb: 4096, diskGb: 12 } },
    { hostId: "git-01", name: "git-01", role: "git", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 2048, diskGb: 10 } },
  ],
  personas: [
    { id: "p1", role: "nurse", workstation: "git-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "charting", relationships: [] },
    { id: "p3", role: "receptionist", workstation: "git-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "scheduling", relationships: [] },
    { id: "p4", role: "physician", workstation: "git-01", access: ["intranet"], credentialsProfile: "standard", riskProfile: "low", routine: "rounds", relationships: [] },
  ],
  objectives: [], requiredTelemetry: [], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

const domain = labDomainFor(spec);
const gitFqdn = `git-01.${domain}`;
const uid = ipaUserIdFor("p1");
const userPw = ipaUserSecret(runId, "p1");

let primaryError = null;
try {
  // Gitea ships in the baked catalog image (no Debian package), so this
  // smoke boots the baked tier on purpose — the preflight fails on base.
  const [rockyBaked, debian] = await Promise.all([ensureRockyFreeipaImage(host.hostArch), resolveGoldenImage(host.hostArch)]);
  const rocky = rockyBaked ?? await ensureRockyGoldenImage(host.hostArch);
  const res = await startRunVms(spec, { ...lifecycle, goldenByFamily: { rocky, debian } }, (hostId, pubKey) => ({
    hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId },
  }));
  const state = res.state;
  for (const inst of Object.values(state.instances)) {
    await probeGuestIdentity(inst, { runId }, { attempts: 60, delayMs: 2000, timeoutMs: 15000 });
    await waitForLabAddress(inst);
    console.log(`${inst.hostId}: ready lab=${inst.lab?.address}`);
  }
  const dir = path.join(stateRoot, "ansible", runId);
  await mkdir(dir, { recursive: true });
  await writeFile(path.join(dir, "inventory.json"), inventoryFor(spec, vmTargetsFromState(state)));
  await writeFile(path.join(dir, "playbook.yml"), playbookFor(spec, runId));
  console.log("configure: ansible-playbook over SSH…");
  const { stdout } = await run("ansible-playbook", [path.join(dir, "playbook.yml"), "-i", path.join(dir, "inventory.json")], {
    timeout: 45 * 60_000, maxBuffer: 32 * 1024 * 1024,
  }).catch((e) => ({ stdout: `${e.stdout ?? ""}\n${e.stderr ?? ""}\n${e.message}` }));
  const recap = parseRecap(stdout, spec.instances.map((i) => i.hostId));
  for (const [h, r] of recap) console.log(`${h}: ${r.line}`);
  if ([...recap.values()].some((r) => !r.ok)) throw new Error(`configure failed:\n${stdout.slice(-3500)}`);

  const git = state.instances["git-01"];
  const exec = (cmd, t = 90_000) => execInGuest(git, cmd, { timeoutMs: t }).then((r) => r.stdout);

  const boot = await exec("gitea --version; sudo -n systemctl is-active gitea; for i in $(seq 1 30); do curl -fsS --max-time 3 http://127.0.0.1:3000/api/v1/version >/dev/null && { echo API-UP; break; }; sleep 2; done", 120_000);
  console.log("gitea:", boot.trim().replace(/\n/g, " | "));
  if (!boot.includes("API-UP")) throw new Error("Gitea API did not come up");

  const good = await exec(`curl -fsS --max-time 10 -u '${uid}:${userPw}' http://127.0.0.1:3000/api/v1/user 2>&1 | head -c 300`);
  console.log(`domain user ${uid}:`, good.trim());
  if (!good.includes(`"login":"${uid}"`)) {
    const diag = await exec(`sudo -n -u git gitea admin auth list --config /etc/gitea/app.ini 2>&1; echo ===cfg===; sudo -n -u git python3 -c "import json,sqlite3; db=sqlite3.connect('/var/lib/gitea/data/gitea.db'); [print(i, json.dumps({k:v for k,v in json.loads(c).items() if k != 'BindPassword'})) for i,c in db.execute('select id,cfg from login_source')]" 2>&1; echo ===log===; sudo -n tail -n 60 /var/lib/gitea/log/gitea.log 2>&1`);
    throw new Error(`domain user could not authenticate through the LDAP source\n${diag.slice(-2500)}`);
  }

  const bad = await exec(`curl -fsS --max-time 10 -u '${uid}:wrong-password' http://127.0.0.1:3000/api/v1/user >/dev/null 2>&1 && echo WRONG-ACCEPTED || echo WRONG-REFUSED`);
  console.log("wrong password:", bad.trim());
  if (!bad.includes("WRONG-REFUSED")) throw new Error("Gitea accepted a wrong domain password");

  const readiness = await checkSpecReadiness({
    spec, runId,
    sshUserOf: () => git.ssh?.user ?? "arena",
    exec: async (hostId, command, timeoutMs) => {
      const inst = state.instances[hostId];
      if (!inst) throw new Error(`no VM ${hostId}`);
      return (await execInGuest(inst, command, { timeoutMs })).stdout;
    },
  });
  for (const h of readiness) for (const c of h.checks) console.log(`${h.hostId}: ${c.ok ? "PASS" : "FAIL"} ${c.kind}/${c.probe} — ${c.detail}`);
  if (readiness.some((h) => !h.ok)) throw new Error(`readiness failed: ${JSON.stringify(readiness.filter((h) => !h.ok))}`);
  // T-42: Gitea SSH transport + PR workflow + per-repo directory-group authz.
  const sshEnv = (dir) => `GIT_SSH_COMMAND="ssh -i ${dir}/key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p 2222"`;
  const prepareUser = async (id) => {
    const u = ipaUserIdFor(id);
    const pw = ipaUserSecret(runId, id);
    const dir = `/tmp/gitea-${u}`;
    await exec(`rm -rf ${dir} && mkdir -p ${dir} && ssh-keygen -q -t ed25519 -N '' -f ${dir}/key`);
    const login = await exec(`curl -fsS --max-time 10 -u '${u}:${pw}' http://127.0.0.1:3000/api/v1/user`);
    if (!login.includes(`"login":"${u}"`)) throw new Error(`${u}: LDAP login failed before SSH setup`);
    await exec(`printf '{"title":"%s","key":"%s"}' '${u}-$(date +%s)' "$(cat ${dir}/key.pub)" > ${dir}/key.json && curl -fsS --max-time 10 -u '${u}:${pw}' -X POST -H 'Content-Type: application/json' --data-binary @${dir}/key.json http://127.0.0.1:3000/api/v1/user/keys >/dev/null`);
    return { u, pw, dir };
  };

  const p1 = await prepareUser("p1");
  const clone = await exec(`${sshEnv(p1.dir)} git clone -q ssh://git@${gitFqdn}:2222/arena/patient-records.git ${p1.dir}/patient-records 2>&1; echo CLONE-OK`);
  if (!clone.includes("CLONE-OK")) throw new Error(`p1 SSH clone failed: ${clone.slice(0, 300)}`);
  console.log("PROOF PASS p1 (nurse) SSH clone of the private repo");

  const push = await exec(`cd ${p1.dir}/patient-records && git config user.email '${p1.u}@${domain}' && git config user.name '${p1.u}' && git checkout -q -b p1-change && echo p1 > p1.txt && git add p1.txt && git commit -q -m 'p1 change' && ${sshEnv(p1.dir)} git push -q origin p1-change 2>&1 && echo PUSH-OK`);
  if (!push.includes("PUSH-OK")) throw new Error(`p1 push failed: ${push.slice(0, 400)}`);
  console.log("PROOF PASS p1 (nurse) push over SSH");

  const pr = await exec(`curl -fsS --max-time 15 -u '${p1.u}:${p1.pw}' -X POST -H 'Content-Type: application/json' -d '{"head":"p1-change","base":"main","title":"p1 change"}' http://127.0.0.1:3000/api/v1/repos/arena/patient-records/pulls`);
  const prNumber = JSON.parse(pr).number;
  if (!prNumber) throw new Error(`PR creation returned no number: ${pr.slice(0, 300)}`);
  const merge = await exec(`curl -fsS --max-time 15 -u '${p1.u}:${p1.pw}' -X POST -H 'Content-Type: application/json' -d '{"Do":"merge"}' http://127.0.0.1:3000/api/v1/repos/arena/patient-records/pulls/${prNumber}/merge`);
  if (!merge.toLowerCase().includes("merged") && !merge.toLowerCase().includes("merge")) throw new Error(`PR merge failed: ${merge.slice(0, 300)}`);
  console.log(`PROOF PASS p1 (nurse) opened and merged PR #${prNumber}`);

  const p4 = await prepareUser("p4");
  const p4clone = await exec(`${sshEnv(p4.dir)} git clone -q ssh://git@${gitFqdn}:2222/arena/patient-records.git ${p4.dir}/patient-records 2>&1; echo CLONE-OK`);
  if (!p4clone.includes("CLONE-OK")) throw new Error(`p4 (physician) clone failed: ${p4clone.slice(0, 300)}`);
  const p4push = await exec(`cd ${p4.dir}/patient-records && git config user.email '${p4.u}@${domain}' && git config user.name '${p4.u}' && git checkout -q -b p4-change && echo p4 > p4.txt && git add p4.txt && git commit -q -m 'p4 change' && (${sshEnv(p4.dir)} git push -q origin p4-change >/dev/null 2>&1 && echo PUSH-ACCEPTED || echo PUSH-DENIED)`);
  if (!p4push.includes("PUSH-DENIED")) throw new Error(`physician push was not denied: ${p4push.slice(0, 300)}`);
  console.log("PROOF PASS p4 (physician) read-only: clone ok, push denied");

  const p3 = await prepareUser("p3");
  const p3clone = await exec(`${sshEnv(p3.dir)} git clone -q ssh://git@${gitFqdn}:2222/arena/patient-records.git ${p3.dir}/patient-records >/dev/null 2>&1; echo CLONE-DENIED`);
  if (!p3clone.includes("CLONE-DENIED")) throw new Error(`receptionist clone was not denied: ${p3clone.slice(0, 300)}`);
  console.log("PROOF PASS p3 (receptionist) has no access: clone denied");

  console.log("VM GITEA SMOKE OK");
} catch (err) {
  primaryError = err;
  console.error("SMOKE FAILURE:", err instanceof Error ? err.message.slice(0, 2500) : err);
} finally {
  if (process.env.GIT_KEEP === "1" && primaryError) console.log(`kept: ${path.join(stateRoot, "kvm", runId)}`);
  else {
    await destroyRunVms(lifecycle).catch(() => undefined);
    const leaked = await run("pgrep", ["-f", `musearena-${runId}-`]).then(() => true).catch(() => false);
    if (leaked && !primaryError) primaryError = new Error("leaked QEMU");
    console.log(leaked ? "LEAKED QEMU" : "destroyed: no leaked QEMU");
  }
}
if (primaryError) process.exit(1);

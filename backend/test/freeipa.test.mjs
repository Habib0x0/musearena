import test from "node:test";
import assert from "node:assert/strict";

/**
 * FreeIPA is the Linux AD: Kerberos KDC + 389-ds + integrated DNS. The server
 * is a real install with real resource needs, members join by declared
 * dependency, and the gateway delegates the realm's subdomain to it. These
 * tests pin the wording and the wiring; they do not claim a live IPA run.
 */

const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
const { catalogEntry, implsFor } = await import("../dist/configurator/catalog.js");
const { resolveProfile, resolveProfilePackages, resolveProfileUnits } = await import("../dist/configurator/profiles.js");
const {
  labDomainFor, ipaDomainFor, ipaRealmFor, ipaBaseFor, ipaAdminDnFor,
} = await import("../dist/configurator/dns.js");
const { planDeployment } = await import("../dist/configurator/plan.js");
const { tasksFor } = await import("../dist/configurator/ansible.js");
const { probeFor, gssapiProbeFor, giteaSshProbeFor, labProbesFor } = await import("../dist/configurator/readiness.js");
const labSecretModule = await import("../dist/configurator/lab.js");
const { labSecret } = labSecretModule;
const { labPlanFor } = await import("../dist/provisioner/lab-network.js");
const { deployability } = await import("../dist/provisioner/capability.js");

const caps = {
  platform: "darwin", arch: "arm64", guestArch: "aarch64", accel: "hvf",
  vmRuns: true, container: true, bakedCatalog: "staged", truthLayerCap: "mirror-only",
  maxVmInstances: 8, notes: [],
};

const base = clinicOrgSpec();
const asFreeipa = (overrides = {}) => ({
  ...base,
  instances: base.instances.map((i) =>
    i.hostId === "dc-01"
      ? {
          ...i,
          os: "Rocky Linux 9",
          services: ["ldap"],
          serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
          resources: { vcpu: 2, memoryMb: 2048, diskGb: 12 },
          ...overrides,
        }
      : i),
});

const spec = asFreeipa();
const domain = labDomainFor(spec);
const ipaDomain = ipaDomainFor(spec);
const decode = (task) => Buffer.from(/printf '%s' '([^']+)'/.exec(task.raw)[1], "base64").toString("utf8");

test("the catalog knows FreeIPA as a Linux directory implementation", () => {
  const entry = catalogEntry({ kind: "ldap", impl: "freeipa" });
  assert.ok(entry, "freeipa is catalogued");
  assert.ok(entry.rockyPackages.includes("ipa-server"));
  assert.ok(entry.rockyPackages.includes("ipa-server-dns"));
  assert.ok(!entry.packages.includes("ipa-server"), "Debian set must not name Rocky-only packages");
  assert.equal(entry.readyWhen, "ldap-bind");
  assert.ok(implsFor("ldap").includes("freeipa"));
  assert.ok(implsFor("ldap").includes("openldap"), "the plain LDAP path is unchanged");
});

test("the FreeIPA realm lives under the environment namespace", () => {
  assert.equal(ipaDomain, `ipa.${domain}`);
  assert.equal(ipaRealmFor(spec), ipaDomain.toUpperCase());
  assert.equal(ipaBaseFor(domain), `dc=ipa,${domain.split(".").map((l) => `dc=${l}`).join(",")}`);
  assert.equal(ipaAdminDnFor(domain), `uid=admin,cn=users,cn=accounts,${ipaBaseFor(domain)}`);
});

test("the server profile installs FreeIPA and its members get client tooling", () => {
  const dc = resolveProfile(spec, "dc-01");
  const rocky = resolveProfilePackages(dc, "Rocky Linux 9");
  assert.ok(rocky.includes("ipa-server"));
  assert.ok(rocky.includes("osquery"), "the Rocky bake carries the osquery sensor");
  assert.ok(resolveProfileUnits(dc, "Rocky Linux 9").includes("osqueryd"), "the sensor unit is enabled on Rocky");
  const mail = resolveProfile(spec, "mail-01");
  assert.ok(mail.packages.includes("freeipa-client"), "a dependent host receives the join tooling");
  assert.ok(mail.packages.includes("sssd"));
  assert.ok(mail.groups.some((g) => g.name === "ipa-client-join"), "joining is an explicit profile group");
});

test("the plan describes a FreeIPA server, not slapd", () => {
  const plan = planDeployment(spec, { runId: "run-ipa" });
  const dc = plan.hosts.find((h) => h.hostId === "dc-01");
  assert.ok(dc.config.some((c) => c.path === "/etc/ipa/default.conf"));
  assert.ok(!dc.config.some((c) => c.path === "slapd debconf"), "the OpenLDAP recipe is not reused");
  assert.ok(dc.seeds.some((s) => s.target === `cn=users,cn=accounts,${ipaBaseFor(domain)}`));
});

test("a Gitea member is plannable: the plan renders the domain probe readiness runs", async () => {
  const { ipaUserSecret } = labSecretModule;
  const withGit = {
    ...spec,
    instances: [...spec.instances, {
      hostId: "git-01", name: "git-01", role: "git", runtime: "vm", os: "Debian 12",
      stack: [], services: [], databases: [],
      serviceDecls: [{ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }],
      dependsOn: ["dc-01"], resources: { vcpu: 2, memoryMb: 2048, diskGb: 10 },
    }],
  };
  const plan = planDeployment(withGit, { runId: "run-ipa" });
  const git = plan.hosts.find((h) => h.hostId === "git-01");
  assert.ok(git, "git-01 is in the plan");
  const probe = git.readiness.find((p) => p.probe === "git-ldap-login");
  assert.ok(probe, "the git-ldap-login probe is planned");
  assert.equal(probe.expect, '"login":"p1"', "the probe authenticates as the seeded persona");
  assert.ok(!JSON.stringify(plan).includes(ipaUserSecret("run-ipa", "p1")), "the plan carries no per-run secret");
});

test("the server task provisions a realm with integrated DNS and a lab address", () => {
  const dcTasks = tasksFor(spec, "run-ipa", "dc-01");
  const install = dcTasks.find((t) => t.name === "freeipa-install");
  assert.ok(install, "the FreeIPA server install task exists");
  const cmd = decode(install);
  assert.match(cmd, /ipa-server-install --unattended/);
  assert.ok(cmd.includes(`--realm='${ipaRealmFor(spec)}'`));
  assert.ok(cmd.includes(`--domain='${ipaDomain}'`));
  assert.ok(cmd.includes("--setup-dns"));
  assert.ok(cmd.includes("--no-reverse"));
  assert.ok(cmd.includes('--ip-address="$IP"'));
  assert.ok(cmd.includes("--admin-password="));
  assert.ok(cmd.includes("/etc/ipa/default.conf"), "re-running does not reinstall the realm");
  assert.ok(!dcTasks.some((t) => t.name === "ldap-configure" || t.name === "ldap-seed"), "the OpenLDAP tasks are skipped");
  const seed = decode(dcTasks.find((t) => t.name === "ipa-seed"));
  assert.ok(seed.includes(`dnsforwardzone-add '${domain}.'`), "the realm delegates the parent lab zone to the gateway");
  assert.ok(dcTasks.some((t) => t.name === "ipa-seed"), "personas are seeded into the directory");
});

test("a declared member joins the realm; a non-dependent host does not", () => {
  const mailJoin = tasksFor(spec, "run-ipa", "mail-01").find((t) => t.name === "ipa-client-join");
  assert.ok(mailJoin, "mail depends on the directory and joins");
  const cmd = decode(mailJoin);
  assert.match(cmd, /ipa-client-install --unattended/);
  assert.ok(cmd.includes(`--domain='${ipaDomain}'`));
  assert.ok(cmd.includes("--mkhomedir"));

  const logTasks = tasksFor(spec, "run-ipa", "log-01");
  assert.ok(!logTasks.some((t) => t.name === "ipa-client-join"), "an unrelated host is not joined");
});

test("the gateway delegates the realm subdomain to the directory", () => {
  const dns = decode(tasksFor(spec, "run-ipa", "gw-01").find((t) => t.name === "dns-configure"));
  const dc = labPlanFor(spec, "run-ipa").find((e) => e.hostId === "dc-01");
  assert.ok(dns.includes(`server=/${ipaDomain}/${dc.address}`), "the more specific server= forwards the IPA zone");
  assert.ok(dns.includes(`local=/${domain}/`), "the parent zone stays local");
});

test("readiness binds the FreeIPA admin DN, not cn=admin", () => {
  const decl = { kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" };
  const probe = probeFor(decl, { hostId: "dc-01", runId: "run-ipa", sshUser: "arena", services: [decl], domain });
  assert.ok(probe.command.includes(`-D ${ipaAdminDnFor(domain)}`));
  assert.ok(probe.command.includes("-b " + ipaBaseFor(domain)));
  assert.ok(probe.command.includes(labSecret("run-ipa", "ipa-admin")));

  const cross = labProbesFor(spec, "run-ipa").find((p) => p.probe === "lab-ldap");
  assert.ok(cross.command.includes(`-D ${ipaAdminDnFor(domain)}`), "the cross-host probe uses the same admin identity");
});

test("FreeIPA resource and co-location limits are enforced before provisioning", () => {
  assert.deepEqual(deployability(spec, { caps }), [], "the sized design is deployable");

  const debianServer = asFreeipa({ os: "Debian 12" });
  assert.match(deployability(debianServer, { caps }).join(" | "), /Rocky Linux 9/, "a Debian FreeIPA server is refused: the server packages do not exist there");

  const small = asFreeipa({ resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 } });
  const smallReasons = deployability(small, { caps }).join(" | ");
  assert.match(smallReasons, /at least 2048 MB/);
  assert.match(smallReasons, /at least 12 GB disk/);
  assert.match(smallReasons, /at least 2 vCPU/);

  const colocated = {
    ...spec,
    instances: spec.instances.map((i) =>
      i.hostId === "dc-01"
        ? { ...i, serviceDecls: [...i.serviceDecls, { kind: "dns", impl: "dnsmasq", port: 53, readyWhen: "dns-query" }] }
        : i),
  };
  assert.match(deployability(colocated, { caps }).join(" | "), /owns port 53/);

  const two = {
    ...spec,
    instances: [
      ...spec.instances,
      {
        hostId: "dc-02", name: "dc-02", role: "dc", runtime: "vm", os: "Rocky Linux 9",
        stack: [], services: ["ldap"], databases: [],
        serviceDecls: [{ kind: "ldap", impl: "freeipa", port: 389, readyWhen: "ldap-bind" }],
        resources: { vcpu: 2, memoryMb: 2048, diskGb: 12 },
      },
    ],
  };
  assert.match(deployability(two, { caps }).join(" | "), /one realm per environment/);
});

test("a planted weak-cred on the DC seeds a sprayable service account; unplanted does not", () => {
  const planted = tasksFor({ ...spec, plantedVulns: [{ id: "v9", type: "weak-cred", techniqueId: "T1110", targetHostId: "dc-01", pinnedVersion: "4", proofAtomicGuid: "g9", difficulty: "standard" }] }, "run-ipa", "dc-01");
  const seed = decode(planted.find((t) => t.name === "ipa-seed"));
  assert.ok(seed.includes("svc-report"), "weak service account is seeded only when planted");
  assert.ok(seed.includes("Summer2024!"), "the planted password is the labelled weak password");
  const clean = decode(tasksFor(spec, "run-ipa", "dc-01").find((t) => t.name === "ipa-seed"));
  assert.ok(!clean.includes("svc-report"), "no service account without the planted vuln");
});

test("the OpenLDAP path is untouched", () => {
  const plain = clinicOrgSpec();
  assert.ok(tasksFor(plain, "run-ldap", "dc-01").some((t) => t.name === "ldap-configure"));
  assert.ok(tasksFor(plain, "run-ldap", "dc-01").some((t) => t.name === "ldap-seed"));
  assert.ok(!tasksFor(plain, "run-ldap", "dc-01").some((t) => t.name === "freeipa-install"));
  assert.deepEqual(deployability(plain, { caps }), []);
});

test("a joined mail host authenticates IMAP against FreeIPA; an unjoined one does not", () => {
  const joined = spec;
  const mailTask = tasksFor(joined, "run-mail", "mail-01").find((t) => t.name === "mail-configure");
  const conf = decode(mailTask);
  const users = `cn=users,cn=accounts,${ipaBaseFor(domain)}`;
  assert.ok(conf.includes("dovecot-ldap.conf.ext"), "dovecot gets an LDAP config");
  assert.ok(conf.includes(`auth_bind_userdn = uid=%u,${users}`), "passdb binds as the user");
  assert.ok(conf.includes(`base = ${users}`), "search base is the IPA users container");
  assert.ok(conf.includes("auth_username_format = %Ln"), "domain-qualified logins are accepted");
  assert.ok(conf.includes("auth_mechanisms = plain login gssapi"), "GSSAPI joins the existing mechanisms");
  assert.ok(conf.includes("passdb {") && conf.includes("driver = ldap"), "passdb is the ldap driver");

  // A mail host that does not depend on the FreeIPA server keeps local auth.
  const standalone = {
    ...joined,
    instances: joined.instances.map((i) =>
      i.hostId === "mail-01" ? { ...i, dependsOn: [] } : i),
  };
  const plain = decode(tasksFor(standalone, "run-mail", "mail-01").find((t) => t.name === "mail-configure"));
  assert.ok(!plain.includes("dovecot-ldap.conf.ext"), "no directory auth without membership");
});

test("the mail probe authenticates as the seeded persona and refuses a wrong password", () => {
  const { ipaUserIdFor, ipaUserSecret } = labSecretModule;
  const uid = ipaUserIdFor(spec.personas[0].id);
  const check = probeFor(
    { kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" },
    { hostId: "mail-01", runId: "run-mail", sshUser: "arena", services: [{ kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" }], domain, domainUser: { uid, password: ipaUserSecret("run-mail", spec.personas[0].id) } },
  );
  assert.match(check.command, new RegExp(`-u '${uid}:`), "logs in as the directory user");
  assert.match(check.command, /accepted a wrong password/, "a wrong password must be refused");
  assert.ok(check.command.indexOf("ok=1") < check.command.indexOf("accepted a wrong password"), "delivery leg runs before the auth legs");

  const plain = probeFor(
    { kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" },
    { hostId: "mail-01", runId: "run-mail", sshUser: "arena", services: [{ kind: "imap", impl: "dovecot", port: 143, readyWhen: "smtp-imap-roundtrip" }], domain },
  );
  assert.ok(!plain.command.includes("accepted a wrong password"), "unjoined hosts keep the local roundtrip only");
});

test("a member database authenticates domain users via LDAP and refuses a wrong password", () => {
  const dbSpec = {
    ...spec,
    instances: spec.instances.map((i) => i.hostId === "db-01" ? { ...i, dependsOn: ["dc-01"] } : i),
  };
  const tasks = tasksFor(dbSpec, "run-db", "db-01");
  const conf = decode(tasks.find((t) => t.name === "db-configure"));
  assert.ok(conf.includes("ldap ldapserver="), "pg_hba has an ldap rule");
  assert.ok(conf.includes('ldapprefix="uid="'), "the LDAP bind uses the directory uid");
  assert.ok(conf.includes("cn=users,cn=accounts,"), "bind DN is in the IPA users container");
  const seed = decode(tasks.find((t) => t.name === "db-seed-access"));
  assert.ok(seed.includes('CREATE ROLE "p1" LOGIN'), "each persona gets a login role");

  const probe = probeFor({ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }, {
    hostId: "db-01", runId: "run-db", sshUser: "arena", services: [], domain,
    domainUser: { uid: "p1", password: "Arena-test" },
  });
  assert.match(probe.command, /PGPASSWORD='Arena-test' psql -h 127\.0\.0\.1 -U 'p1'/);
  assert.match(probe.command, /not-Arena-test/, "a wrong password must be exercised");
  const plain = probeFor({ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }, {
    hostId: "db-01", runId: "run-db", sshUser: "arena", services: [], domain,
  });
  assert.ok(plain.command.includes("-U app"), "unjoined hosts keep the local app probe");
});

test("T-40: member services get service keytabs and additive GSSAPI config", () => {
  const dbSpec = {
    ...spec,
    instances: spec.instances.map((i) => i.hostId === "db-01" ? { ...i, dependsOn: ["dc-01"] } : i),
  };
  const dbTasks = tasksFor(dbSpec, "run-gss", "db-01");
  const names = dbTasks.map((t) => t.name);
  assert.ok(names.indexOf("ipa-client-join") < names.indexOf("ipa-service-keytabs"), "keytabs follow the join");
  assert.ok(names.indexOf("ipa-service-keytabs") < names.indexOf("db-gssapi"), "GSS config follows the keytab");
  const kt = decode(dbTasks.find((t) => t.name === "ipa-service-keytabs"));
  assert.match(kt, /ipa service-show "postgres\/\$FQDN"/, "the service principal is looked up first");
  assert.match(kt, /ipa service-add --force "postgres\/\$FQDN"/, "the service principal is created");
  assert.match(kt, /ipa-getkeytab -s "\$SRV" -p "postgres\/\$FQDN"/, "the keytab is retrieved from the realm");
  assert.match(kt, /chmod 0600/, "the keytab is owner-only");
  assert.match(kt, /kdestroy/, "the admin ticket is destroyed");
  const gss = decode(dbTasks.find((t) => t.name === "db-gssapi"));
  assert.match(gss, /host gssdb all .* gss include_realm=0/, "GSSAPI is a separate database");
  assert.match(gss, /krb_server_keyfile = '\/etc\/postgresql\/postgres\.keytab'/);
  const dbConf = decode(dbTasks.find((t) => t.name === "db-configure"));
  assert.ok(dbConf.includes("ldap ldapserver="), "the T-33 LDAP path is preserved");
  const seed = decode(dbTasks.find((t) => t.name === "db-seed-access"));
  assert.ok(seed.includes("createdb -O app gssdb"), "the GSS database exists before the probe");

  const mailGss = decode(tasksFor(spec, "run-gss", "mail-01").find((t) => t.name === "imap-gssapi"));
  assert.match(mailGss, /auth_krb5_keytab = \/etc\/dovecot\/dovecot\.keytab/, "GSSAPI uses the service keytab");
  assert.match(mailGss, /auth_krb5_keytab = \/etc\/dovecot\/dovecot\.keytab/);
  assert.match(mailGss, /driver = ldap/, "the LDAP passdb is still required");

  const webGss = decode(tasksFor(spec, "run-gss", "web-01").find((t) => t.name === "http-gssapi"));
  assert.match(webGss, /GssapiCredStore keytab:\/etc\/apache2\/http\.keytab/);
  assert.match(webGss, /Require valid-user/);

  const uid = "p1";
  const ctx = { hostId: "db-01", runId: "run-gss", sshUser: "arena", services: [], domain, domainUser: { uid, password: "Arena-test" } };
  const probe = gssapiProbeFor({ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }, ctx);
  assert.equal(probe.probe, "gssapi-sql");
  assert.match(probe.command, /kinit 'p1'/);
  assert.match(probe.command, /-U 'p1' -d gssdb/);
  assert.equal(gssapiProbeFor({ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }, ctx), null, "only Kerberized services get a GSS probe");
  assert.equal(gssapiProbeFor({ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }, { ...ctx, domainUser: undefined }), null, "unjoined hosts have no GSS probe");
});

test("Gitea logs in domain users through an LDAP auth source, and refuses without the realm", () => {
  const gitSpec = {
    ...spec,
    instances: [
      ...spec.instances.filter((i) => ["gw-01", "dc-01"].includes(i.hostId)),
      { hostId: "git-01", name: "git-01", role: "git", runtime: "vm", os: "Debian 12", stack: [], services: [],
        databases: [], dependsOn: ["dc-01"],
        serviceDecls: [{ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }],
        resources: { vcpu: 2, memoryMb: 2048, diskGb: 10 } },
    ],
  };
  assert.deepEqual(deployability(gitSpec, { caps }), [], "a member Gitea deploys");

  const tasks = tasksFor(gitSpec, "run-git", "git-01");
  const names = tasks.map((t) => t.name);
  assert.ok(names.indexOf("ipa-client-join") < names.indexOf("git-configure"), "Gitea is configured after the join");
  const conf = decode(tasks.find((t) => t.name === "git-configure"));
  const ldap = decode(tasks.find((t) => t.name === "git-ldap-source"));
  const seed = decode(tasks.find((t) => t.name === "git-seed"));
  assert.ok(conf.includes("gitea binary missing"), "a base image fails closed with a clear reason");
  assert.ok(conf.includes("gitea.service"), "a unit is installed");
  assert.ok(conf.includes("START_SSH_SERVER = true"), "Gitea's built-in SSH server is enabled");
  assert.ok(conf.includes("SSH_PORT = 2222"), "SSH listens on the dedicated port");
  assert.ok(ldap.includes("admin auth add-ldap"), "the LDAP source is created through the admin CLI");
  assert.ok(ldap.includes("--user-search-base"), "the search base flag used by 1.22");
  assert.ok(ldap.includes("(&(objectClass=posixAccount)(uid=%s))"), "the directory filter");
  assert.ok(ldap.includes('"GroupsEnabled": True'), "LDAP group sync is configured in the source");
  assert.ok(ldap.includes('"GroupTeamMap"'), "directory groups map to Gitea teams");
  assert.ok(ldap.includes('"GroupMemberUID": "member"') && ldap.includes('"UserUID": "dn"'), "FreeIPA groups expose member DNs, not memberUid");
  assert.ok(seed.includes("/api/v1/orgs/arena"), "the org is created through the admin API");
  assert.ok(seed.includes("patient-records"), "the private repo is created");
  assert.ok(names.indexOf("git-configure") < names.indexOf("git-ldap-source"), "stages are ordered");
  assert.ok(names.indexOf("git-ldap-source") < names.indexOf("git-seed"), "stages are ordered");

  const orphan = { ...gitSpec, instances: gitSpec.instances.map((i) => i.hostId === "git-01" ? { ...i, dependsOn: [] } : i) };
  assert.match(deployability(orphan, { caps }).join(" | "), /git\/gitea needs a declared dependsOn/);

  const probe = probeFor({ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }, {
    hostId: "git-01", runId: "run-git", sshUser: "arena", services: [], domain,
    domainUser: { uid: "p1", password: "Arena-test" },
  });
  assert.match(probe.command, /not-Arena-test/, "a wrong password must be exercised");
  assert.equal(probe.expect, '"login":"p1"');
  assert.throws(() => probeFor({ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }, {
    hostId: "git-01", runId: "run-git", sshUser: "arena", services: [], domain,
  }), /domain identity/);

  const sshProbe = giteaSshProbeFor({ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }, {
    hostId: "git-01", runId: "run-git", sshUser: "arena", services: [], domain,
    domainUser: { uid: "p1", password: "Arena-test" },
  });
  assert.equal(sshProbe.probe, "git-ssh");
  assert.match(sshProbe.command, /ssh:\/\/git@git-01\..*:2222\/arena\/public\.git/);
  assert.equal(giteaSshProbeFor({ kind: "git", impl: "gitea", port: 3000, readyWhen: "git-ldap-login" }, {
    hostId: "git-01", runId: "run-git", sshUser: "arena", services: [], domain,
  }), null, "unjoined hosts have no SSH probe");
});

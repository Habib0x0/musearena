import test from "node:test";
import assert from "node:assert/strict";

/**
 * Per-environment DNS. The domain is derived from the spec, so two labs never
 * share a namespace and the same design always produces the same one. Every
 * consumer (dnsmasq, LDAP, postfix, readiness) must read the same function.
 */

const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
const { labDomainFor, ldapBaseFor } = await import("../dist/configurator/dns.js");
const { planDeployment } = await import("../dist/configurator/plan.js");
const { tasksFor } = await import("../dist/configurator/ansible.js");
const { labProbesFor } = await import("../dist/configurator/readiness.js");
const { topologyFor } = await import("../dist/designer/topology.js");

const spec = clinicOrgSpec();
const domain = labDomainFor(spec);
const decode = (task) => Buffer.from(/printf '%s' '([^']+)'/.exec(task.raw)[1], "base64").toString("utf8");

test("the DNS domain is derived from the environment, not a constant", () => {
  assert.match(domain, /^[a-z0-9-]+-[0-9a-f]{8}\.arena\.lab$/);
  assert.ok(domain.split(".")[0].length <= 63, "the first label is a valid DNS label");
  assert.equal(labDomainFor(structuredClone(spec)), domain, "the same spec yields the same domain");
  assert.notEqual(labDomainFor({ ...spec, name: "another-clinic" }), domain, "the name is part of the identity");
  assert.notEqual(labDomainFor({ ...spec, seed: "different-seed" }), domain, "a different environment yields a different domain");
  assert.equal(labDomainFor({ ...spec, budgets: { ...spec.budgets, ttlHours: 1 } }), domain, "a TTL change does not rename the lab");
  assert.notEqual(domain, "arena.lab", "the old shared namespace is gone");
});

test("LDAP DNs follow the environment domain", () => {
  assert.equal(ldapBaseFor(domain), domain.split(".").map((label) => `dc=${label}`).join(","));
  assert.ok(ldapBaseFor(domain).startsWith("dc="));
});

test("the plan, topology map, config and probes all use the same domain", () => {
  const plan = planDeployment(spec, { runId: "run-dns" });
  assert.equal(plan.topology.domain, domain);
  assert.equal(topologyFor(spec).domain, domain);

  const probes = labProbesFor(spec, "run-dns");
  const dns = probes.filter((p) => p.probe === "lab-dns");
  assert.ok(dns.length > 0, "the gateway DNS is probed");
  assert.ok(dns.every((p) => p.command.includes(`.${domain}`)), "the DNS probe asks for the environment's names");
  const ldap = probes.find((p) => p.probe === "lab-ldap");
  assert.ok(ldap.command.includes(`-b ${ldapBaseFor(domain)}`), "the LDAP probe binds the environment's base DN");

  const dc = plan.hosts.find((h) => h.hostId === "dc-01");
  assert.ok(dc.seeds.some((s) => s.target === `ou=people,${ldapBaseFor(domain)}`), "the plan seeds the derived base DN");
  assert.ok(dc.config.some((c) => c.path === ldapBaseFor(domain)), "the plan names the derived base DN");

  const dnsTask = tasksFor(spec, "run-dns", "gw-01").find((t) => t.name === "dns-configure");
  const dnsConfig = decode(dnsTask);
  assert.ok(dnsConfig.includes(`domain=${domain}`), "dnsmasq serves the derived domain");
  assert.ok(!dnsConfig.includes("domain=arena.lab"), "the shared domain is not hardcoded");
  assert.ok(dnsConfig.includes(`dc-01.${domain}`), "host records are fully qualified in the derived domain");

  const mailConfig = decode(tasksFor(spec, "run-dns", "mail-01").find((t) => t.name === "mail-configure"));
  assert.ok(mailConfig.includes(`mailname string mail-01.${domain}`), "postfix is named in the derived domain");
  const ldapSeed = decode(tasksFor(spec, "run-dns", "dc-01").find((t) => t.name === "ldap-seed"));
  assert.ok(ldapSeed.includes(`dn: uid=probe,ou=people,${ldapBaseFor(domain)}`), "the seeded user lives under the derived base DN");
  assert.ok(ldapSeed.includes(`mail: probe@${domain}`), "the seeded user's mail address uses the derived domain");
});

test("a different environment produces a different domain everywhere", () => {
  const other = { ...spec, name: "small-shop", seed: "small-shop-2" };
  const otherDomain = labDomainFor(other);
  assert.notEqual(otherDomain, domain);
  assert.equal(planDeployment(other, { runId: "run-dns" }).topology.domain, otherDomain);
  const dnsConfig = decode(tasksFor(other, "run-dns", "gw-01").find((t) => t.name === "dns-configure"));
  assert.ok(dnsConfig.includes(`domain=${otherDomain}`));
  assert.ok(!dnsConfig.includes(`domain=${domain}`));
});

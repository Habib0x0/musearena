import test from "node:test";
import assert from "node:assert/strict";

/**
 * P0 org topology: sites, zones, derived subnets/addresses, structured policy
 * and the allowed/denied graph. Pure only — nothing here boots a segment.
 */

/**
 * P1b multi-segment runtime: per-zone hubs, router NICs, live zone probes.
 * The lifecycle attaches one socket NIC per segment (the router gets one per
 * zone); zone probes execute the allowed/denied graph through the router.
 */

const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
const {
  normalizeOrg, reachabilityFor, negativeProbesFor, validateOrgTopology,
  envOctetOf, orgZoneRef, segmentsFor, routerAttachmentsFor, nftablesFor,
  negativeProbeCommands,
} = await import("../dist/designer/org-topology.js");
const { validateDesign } = await import("../dist/designer/coherence.js");
const { planDeployment } = await import("../dist/configurator/plan.js");
const { tasksFor } = await import("../dist/configurator/ansible.js");
const { deployability } = await import("../dist/provisioner/capability.js");
const { labDomainFor } = await import("../dist/configurator/dns.js");

const caps = {
  platform: "linux", arch: "x86_64", guestArch: "x86_64", accel: "kvm",
  vmRuns: true, container: true, bakedCatalog: "staged", truthLayerCap: "mirror-only",
  maxVmInstances: 8, notes: [],
};

const inst = (hostId, role, site, zone, decls = [], extra = {}) => ({
  hostId, name: hostId, role, runtime: "vm", os: "Debian 12",
  stack: [], services: decls.map((d) => d.kind), databases: role === "db" ? ["app"] : [],
  site, zone, serviceDecls: decls, ...extra,
});

const bank = () => ({
  version: 2,
  name: "meridian-bank",
  provider: "kvm",
  seed: "meridian-1",
  difficulty: "standard",
  truthLayer: "mirror-only",
  topology: {
    cidr: "10.42.0.0/16",
    subnets: [],
    sites: [
      { id: "hq", name: "Headquarters", kind: "hq" },
      { id: "north", name: "North Branch", kind: "branch" },
    ],
    zones: [
      { id: "edge", site: "hq", kind: "edge" },
      { id: "dmz", site: "hq", kind: "dmz" },
      { id: "server", site: "hq", kind: "server" },
      { id: "corp", site: "north", kind: "corp" },
      { id: "ot", site: "north", kind: "ot" },
    ],
    links: [{ from: "hq", to: "north", allowed: [{ proto: "tcp", port: 53 }, { proto: "tcp", port: 88 }] }],
    policies: [
      { from: "*/edge", to: "hq/dmz", proto: "tcp", port: 80, action: "allow", reason: "public web" },
      { from: "hq/dmz", to: "hq/server", proto: "tcp", port: 5432, action: "allow", reason: "app to db" },
      { from: "north/corp", to: "hq/server", proto: "tcp", port: 22, action: "allow", reason: "admin ssh" },
      { from: "north/corp", to: "hq/server", proto: "tcp", port: 5432, action: "deny", reason: "branch does not reach the DB" },
    ],
    firewallRules: [],
  },
  instances: [
    inst("edge-router", "router", "hq", "edge", [
      { kind: "router", impl: "nftables", port: 22, readyWhen: "ssh-login" },
      { kind: "dns", impl: "dnsmasq", port: 53, readyWhen: "dns-query" },
    ]),
    inst("attacker", "attacker", "hq", "edge"),
    inst("web-01", "web", "hq", "dmz", [{ kind: "http", impl: "apache-php", port: 80, readyWhen: "http-2xx" }]),
    inst("db-01", "db", "hq", "server", [{ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }]),
    inst("ws-01", "workstation", "north", "corp"),
    inst("ot-01", "sensor", "north", "ot"),
  ],
  personas: [],
  objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary-hash", points: 10 }],
  requiredTelemetry: ["auditd"],
  plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 10, ttlHours: 2 },
});

test("v2 sites and zones derive /24 subnets and deterministic addresses", () => {
  const spec = bank();
  const model = normalizeOrg(spec);
  assert.deepEqual(model.sites.map((s) => s.id), ["hq", "north"]);
  assert.deepEqual(model.subnets.map((s) => s.cidr), [
    "10.42.0.0/24", "10.42.1.0/24", "10.42.2.0/24", "10.42.16.0/24", "10.42.17.0/24",
  ]);
  assert.equal(model.byHost.get("edge-router").address, "10.42.0.1", "the router owns .1");
  assert.equal(model.byHost.get("attacker").address, "10.42.0.10");
  assert.equal(model.byHost.get("db-01").address, "10.42.2.10");
  assert.equal(model.byHost.get("db-01").fqdn, `db-01.hq.${labDomainFor(spec)}`);
  assert.equal(envOctetOf(spec.topology.cidr), 42);
  assert.equal(orgZoneRef(model.byHost.get("db-01")), "hq/server");

  // Reordering instances must not move addresses: allocation is by host id.
  const reversed = { ...spec, instances: [...spec.instances].reverse() };
  assert.equal(normalizeOrg(reversed).byHost.get("db-01").address, "10.42.2.10");
});

test("the reachability graph honours allow, deny and WAN policy", () => {
  const spec = bank();
  const reach = reachabilityFor(spec);
  const allowed = reach.allowed;
  assert.ok(allowed.some((e) => e.fromZone === "hq/edge" && e.toZone === "hq/dmz" && e.port === 80), "public web path");
  assert.ok(allowed.some((e) => e.fromZone === "hq/dmz" && e.toZone === "hq/server" && e.port === 5432), "app to db path");

  const deniedDb = reach.denied.find((e) => e.fromZone === "north/corp" && e.toZone === "hq/server" && e.port === 5432);
  assert.ok(deniedDb, "the branch DB path is denied");
  assert.match(deniedDb.reason, /branch does not reach the DB/);

  // WAN: only the ports on the link, and only when no policy denies.
  const wanDns = allowed.find((e) => e.fromZone === "north/corp" && e.toZone === "hq/edge" && e.port === 53);
  assert.ok(wanDns, "DNS crosses the WAN link");
  assert.equal(wanDns.reason, "allowed by WAN link");

  const negatives = negativeProbesFor(spec);
  assert.ok(negatives.some((e) => e.fromZone === "north/ot" && e.toZone === "hq/server"), "an unrelated zone has a negative probe");
});

test("a single-site bank passes design validation and is deployable on the VM runtime", () => {
  const oneSite = () => {
    const spec = bank();
    const keep = new Set(["hq/edge", "hq/dmz", "hq/server"]);
    return {
      ...spec,
      topology: {
        ...spec.topology,
        sites: [spec.topology.sites[0]],
        zones: spec.topology.zones.filter((z) => z.site === "hq"),
        links: [],
        policies: spec.topology.policies.filter((p) => [...keep].some((k) => p.from.endsWith(k.split("/")[1]) || p.from === "any" || p.from.startsWith("*/")) && p.to.startsWith("hq/")),
      },
      instances: spec.instances.filter((i) => i.site === "hq"),
    };
  };
  const spec = oneSite();
  assert.deepEqual(validateOrgTopology(spec), [], validateOrgTopology(spec).join(" | "));
  assert.deepEqual(validateDesign(spec), [], validateDesign(spec).join(" | "));
  assert.deepEqual(deployability(spec, { caps }).join(" | "), "", "single-site org is deployable (P1 runtime)");

  assert.match(deployability(bank(), { caps }).join(" | "), /one site/, "multi-site is refused until WAN links are enforced (P5)");

  const noRouter = oneSite();
  noRouter.instances = noRouter.instances.map((i) =>
    i.hostId === "edge-router"
      ? { ...i, role: "gateway", serviceDecls: (i.serviceDecls ?? []).filter((d) => d.kind !== "router") }
      : i);
  assert.match(validateOrgTopology(noRouter).join(" | "), /no router/, "a multi-zone site without a router is refused");
  assert.match(deployability(noRouter, { caps }).join(" | "), /no router/, "deployability agrees");

  const plan = planDeployment(spec, { runId: "run-p0" });
  assert.deepEqual(plan.gaps, [], "the plan is complete even though deployment is refused");
  assert.equal(plan.topology.sites.length, 1);
  assert.equal(plan.topology.zones.length, 3);
  assert.equal(plan.topology.reachability.allowed.length > 0, true);
  assert.equal(plan.topology.addresses["db-01"], "10.42.2.10/24");
  assert.equal(plan.hosts.find((h) => h.hostId === "db-01").address, "10.42.2.10/24");
  assert.equal(plan.topology.segments.length, 3);
  assert.match(plan.topology.routerRules, /policy drop/);
  assert.ok(plan.negativeProbes.length > 0);
  assert.ok(plan.labProbes.some((p) => p.probe === "lab-allow"), "allowed zone flows are planned");
});

test("segments, router interfaces and nftables come from the same policy", () => {
  const spec = bank();
  const segs = segmentsFor(spec, "run-a");
  assert.equal(segs.length, 5);
  assert.equal(new Set(segs.map((s) => s.hubPort)).size, 5, "segment ports are unique");
  assert.deepEqual(segmentsFor(spec, "run-a"), segs, "stable per run");
  assert.notEqual(segmentsFor(spec, "run-b")[0].hubPort, segs[0].hubPort, "ports are run-scoped");

  const routers = routerAttachmentsFor(spec);
  assert.equal(routers.length, 1);
  assert.deepEqual(routers[0].interfaces.map((i) => i.address), ["10.42.0.1", "10.42.1.1", "10.42.2.1"]);

  const rules = nftablesFor(spec);
  assert.match(rules, /policy drop/);
  assert.match(rules, /10\.42\.16\.0\/24.*10\.42\.2\.0\/24.*dport 5432.*drop/s);
  assert.match(rules, /10\.42\.0\.0\/24.*10\.42\.1\.0\/24.*dport 80.*accept/s);
  assert.ok(rules.indexOf("arena-deny") < rules.indexOf("dport 80"), "explicit deny precedes allows");
  assert.match(rules, /dport 53.*accept/s, "the WAN link allows DNS");

  const neg = negativeProbeCommands(spec);
  assert.ok(neg.some((p) => p.from === "ot-01" && p.command.includes("10.42.2.10") && p.command.includes("5432")));

  const routerTask = tasksFor(spec, "run-a", "edge-router").find((t) => t.name === "router-configure");
  assert.ok(routerTask, "the router has a configuration task");
  const cmd = Buffer.from(/printf '%s' '([^']+)'/.exec(routerTask.raw)[1], "base64").toString("utf8");
  assert.ok(cmd.includes("net.ipv4.ip_forward=1"));
  assert.ok(cmd.includes("policy drop"));
  assert.ok(cmd.includes("arena-deny"));
});

test("the lab wires one NIC per segment; the router is multi-homed", async () => {
  const { labSegmentsFor } = await import("../dist/provisioner/lab-network.js");
  const { nicMac } = await import("../dist/provisioner/lab-network.js");
  const spec = bank();
  const single = {
    ...spec,
    topology: { ...spec.topology, sites: [spec.topology.sites[0]], zones: spec.topology.zones.filter((z) => z.site === "hq"), links: [] },
    instances: spec.instances.filter((i) => i.site === "hq"),
  };
  const atts = labSegmentsFor(single, "run-seg-1");
  // edge (router + attacker), dmz (web), server (db): the router has 3 NICs.
  assert.equal(atts.length, 4 + 2, "every host has a NIC; the router has one per zone");
  const router = atts.filter((a) => a.hostId === "edge-router");
  assert.equal(router.length, 3, "the router touches every zone segment");
  assert.deepEqual(router.map((a) => a.address), ["10.42.0.1", "10.42.1.1", "10.42.2.1"], "the router owns .1 everywhere");
  assert.equal(new Set(router.map((a) => a.mac)).size, 3, "router NIC MACs are distinct");
  assert.equal(new Set(atts.map((a) => a.hubPort)).size, 3, "one hub per zone segment");
  const db = atts.find((a) => a.hostId === "db-01");
  assert.equal(db.address, "10.42.2.10", "regular hosts keep their derived address");
  assert.equal(db.mac, nicMac("db-01", "lab"), "single-NIC MACs are unchanged from v1");
  // Run-scoped ports, stable per run.
  assert.deepEqual(labSegmentsFor(single, "run-seg-1"), atts, "stable per run");
  assert.notDeepEqual(labSegmentsFor(single, "run-seg-2").map((a) => a.hubPort), atts.map((a) => a.hubPort), "ports are run-scoped");
});

test("the QEMU args carry one socket NIC per segment with distinct MACs", async () => {
  const { qemuRunArgs } = await import("../dist/provisioner/vm-lifecycle.js");
  const { labSegmentsFor, nicMac } = await import("../dist/provisioner/lab-network.js");
  const spec = bank();
  const single = {
    ...spec,
    topology: { ...spec.topology, sites: [spec.topology.sites[0]], zones: spec.topology.zones.filter((z) => z.site === "hq"), links: [] },
    instances: spec.instances.filter((i) => i.site === "hq"),
  };
  const atts = labSegmentsFor(single, "run-seg-1");
  const routerNics = atts.filter((a) => a.hostId === "edge-router").map((a) => ({ hubPort: a.hubPort, mac: a.mac }));
  const def = { hostId: "edge-router", guestArch: "aarch64", accel: "hvf", memoryMb: 512, cpus: 1, diskGb: 6, binary: "qemu-system-aarch64" };
  const args = qemuRunArgs(def, { stateDir: "/tmp", overlay: "/tmp/o", seedIso: "/tmp/s", sshHostPort: 22000, runId: "run-seg-1", labs: routerNics });
  for (const [i, nic] of routerNics.entries()) {
    assert.ok(args.includes(`socket,id=net${i + 1},connect=127.0.0.1:${nic.hubPort}`), `router NIC ${i + 1} connects to its segment hub`);
    assert.ok(args.includes(`virtio-net-pci,netdev=net${i + 1},mac=${nic.mac}`), `router NIC ${i + 1} pins its MAC`);
  }
  // The v1 single-NIC path is unchanged.
  const v1 = qemuRunArgs({ ...def, hostId: "web-01" }, { stateDir: "/tmp", overlay: "/tmp/o", seedIso: "/tmp/s", sshHostPort: 22000, runId: "run-seg-1", lab: { hubPort: 45001 } });
  assert.ok(v1.includes("socket,id=net1,connect=127.0.0.1:45001"), "v1 lab NIC connects to the run hub");
  assert.ok(v1.includes(`virtio-net-pci,netdev=net0,mac=${nicMac("web-01", "mgmt")}`), "management NIC pins its MAC");
});

test("a multi-zone site without a router is refused", () => {
  const noRouter = bank();
  noRouter.topology = { ...noRouter.topology, sites: [noRouter.topology.sites[0]] };
  noRouter.instances = noRouter.instances
    .filter((i) => i.site === "hq")
    .map((i) => i.role === "router"
      ? { ...i, role: "gateway", serviceDecls: (i.serviceDecls ?? []).filter((d) => d.kind !== "router") }
      : i);
  assert.match(validateOrgTopology(noRouter).join(" | "), /no router/, "the validator names the missing enforcement point");
});

test("zone probes execute the reachability graph: allows pass, denies fail", async () => {
  const { zoneProbesFor, checkSpecReadiness } = await import("../dist/configurator/readiness.js");
  const spec = bank();
  const single = {
    ...spec,
    topology: { ...spec.topology, sites: [spec.topology.sites[0]], zones: spec.topology.zones.filter((z) => z.site === "hq"), links: [] },
    instances: spec.instances.filter((i) => i.site === "hq"),
  };
  const probes = zoneProbesFor(single);
  assert.ok(probes.some((p) => p.expect === "pass" && p.to === "db-01" && p.command.includes("10.42.2.10/5432")), "an allowed flow targets the real address");
  assert.ok(probes.some((p) => p.expect === "fail" && p.to === "db-01"), "a denied flow to the DB is probed for failure");
  assert.ok(probes.every((p) => p.from !== p.to), "no self-probes");
  // v1 flat labs have no zone probes.
  assert.deepEqual(zoneProbesFor(clinicOrgSpec()), [], "v1 keeps the single-segment probes");

  // A faithful router: allows pass, denies fail, hosts answer SSH → ok.
  // The mock exec answers per command shape, exactly like the guests would:
  // zone-allow connects (the reachability graph's pass edges) succeed, the
  // zone-deny connects (fail edges) are refused, and every other command the
  // gate runs — SSH login, loopback service probes, log shipping — succeeds.
  // That is what a faithful nftables ruleset looks like from a guest.
  const allowCmds = new Set(probes.filter((p) => p.expect === "pass").map((p) => p.command));
  const denyCmds = new Set(probes.filter((p) => p.expect === "fail").map((p) => p.command));
  assert.ok(allowCmds.size > 0 && denyCmds.size > 0, "the mock distinguishes pass from fail commands");
  assert.equal(
    [...allowCmds].filter((c) => denyCmds.has(c)).length, 0,
    "no command is both an allow and a deny probe",
  );
  // The exec mock returns the tokens each probe shape expects: the SSH
  // user for logins, the resolved address for DNS, "1" for SQL, and empty
  // success for the zone-allow connects. Only the zone-deny connects fail.
  const exec = async (hostId, cmd) => {
    if (typeof cmd !== "string") throw new Error(`unexpected exec input: ${String(cmd)}`);
    if (denyCmds.has(cmd)) throw new Error(`connection refused: ${cmd}`);
    if (cmd === "id -un") return "arena\n";
    if (cmd.startsWith("dig ")) return `${cmd.trim().split(/\s+/).pop()}\n`;
    if (cmd.includes("SELECT 1")) return "1\n";
    return "";
  };
  const ok = await checkSpecReadiness({ spec: single, runId: "run-zone-1", sshUserOf: () => "arena", exec });
  assert.equal(ok.every((r) => r.ok), true, JSON.stringify(ok.flatMap((r) => `${r.hostId}:${r.checks.filter((c) => !c.ok).map((c) => `${c.probe}:${c.detail}`).join(";")}`)));
  assert.ok(ok.flatMap((r) => r.checks).some((c) => c.probe === "lab-allow"), "allowed flows are recorded");
  assert.ok(ok.flatMap((r) => r.checks).some((c) => c.probe === "lab-deny"), "denied flows are recorded");
  // A broken router (cross-zone TCP refused) fails the allowed probes.
  // Hosts and their loopback services still answer; only /dev/tcp fails.
  const localOk = async (hostId, cmd) => {
    if (typeof cmd === "string" && cmd.includes("/dev/tcp")) throw new Error("connection refused");
    return exec(hostId, cmd);
  };
  const broken = await checkSpecReadiness({
    spec: single, runId: "run-zone-1", sshUserOf: () => "arena", exec: localOk,
  });
  assert.equal(broken.every((r) => r.ok), false, "allowed flows must pass");
  assert.ok(broken.flatMap((r) => r.checks).some((c) => c.probe === "lab-allow" && !c.ok), "the failure is an allowed flow");
  // A leaking router (zone connects succeed) fails the denied probes.
  // Loopback services answer normally so the failure is the leak, not a host.
  const leaking = await checkSpecReadiness({
    spec: single, runId: "run-zone-1", sshUserOf: () => "arena", exec: async () => "",
  });
  assert.equal(leaking.every((r) => r.ok), false, "denied flows must fail");
  assert.ok(leaking.flatMap((r) => r.checks).some((c) => c.probe === "lab-deny" && !c.ok), "the failure is a denied flow");
});

test("validation names the design errors instead of approximating", () => {
  const attackerInServer = bank();
  attackerInServer.instances = attackerInServer.instances.map((i) =>
    i.hostId === "attacker" ? { ...i, zone: "server" } : i);
  assert.match(validateOrgTopology(attackerInServer).join(" | "), /attacker .* server zone/);

  const noPath = bank();
  noPath.topology.policies = noPath.topology.policies.filter((p) => p.to !== "hq/server" || p.port !== 5432);
  assert.match(validateOrgTopology(noPath).join(" | "), /no allowed path/);

  const unplaced = bank();
  unplaced.instances = unplaced.instances.map((i) =>
    i.hostId === "ws-01" ? { ...i, site: undefined, zone: undefined } : i);
  assert.match(validateOrgTopology(unplaced).join(" | "), /no placement/);

  const badRef = bank();
  badRef.topology.policies = [...badRef.topology.policies,
    { from: "hq/nowhere", to: "hq/dmz", proto: "tcp", port: 80, action: "allow", reason: "typo" }];
  assert.match(validateOrgTopology(badRef).join(" | "), /does not name a site\/zone/);

  const contradiction = bank();
  contradiction.topology.policies = [...contradiction.topology.policies,
    { from: "*/edge", to: "hq/dmz", proto: "tcp", port: 80, action: "deny", reason: "conflict" }];
  assert.match(validateOrgTopology(contradiction).join(" | "), /both allow and deny/);

  const duplicateSite = bank();
  duplicateSite.topology.sites = [...duplicateSite.topology.sites, { id: "hq", name: "Dup", kind: "hq" }];
  assert.match(validateOrgTopology(duplicateSite).join(" | "), /site "hq" is duplicated/);

  const tooMany = bank();
  tooMany.topology.sites = Array.from({ length: 16 }, (_, i) => ({ id: `s${i}`, name: `S${i}`, kind: "branch" }));
  assert.match(validateOrgTopology(tooMany).join(" | "), /allows 15/);
});

test("v1 flat labs are unchanged and need no sites", () => {
  const clinic = clinicOrgSpec();
  assert.deepEqual(validateOrgTopology(clinic), []);
  const plan = planDeployment(clinic, { runId: "run-p0" });
  assert.equal(plan.topology.sites, undefined);
  assert.equal(plan.topology.reachability, undefined);
  assert.ok(plan.labProbes.length > 0, "v1 keeps its executable lab probes");
  assert.equal(plan.topology.addresses["gw-01"], "10.2.32.1/20");
});

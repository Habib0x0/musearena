import test from "node:test";
import assert from "node:assert/strict";

/**
 * Deployment-plan conformance. The plan is the design's bill of
 * materials only if it names exactly the machines the executor builds:
 * the same task list, the same packages the image carries, the same probes
 * readiness will run, and the same addresses the lab assigns.
 */

const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
const { planDeployment } = await import("../dist/configurator/plan.js");
const { tasksFor, playbookFor, hostOrder } = await import("../dist/configurator/ansible.js");
const { allProvisionablePackages } = await import("../dist/configurator/profiles.js");

const spec = clinicOrgSpec();
const plan = planDeployment(spec, { runId: "run-plan-test" });

test("every host has a bill of materials and a probe set", () => {
  assert.equal(plan.hosts.length, spec.instances.length);
  assert.deepEqual(plan.gaps, []);
  for (const h of plan.hosts) {
    assert.ok(h.packages.includes("openssh-server"), `${h.hostId} has the base package set`);
    assert.ok(h.units.includes("ssh"), `${h.hostId} enables sshd`);
    assert.ok(h.readiness.length > 0, `${h.hostId} has acceptance criteria`);
    assert.ok(h.config.length > 0, `${h.hostId} has config intent`);
  }
});

test("the plan's tasks are exactly the executor's tasks, in the executor's order", () => {
  const plays = JSON.parse(playbookFor(spec, "run-plan-test"));
  const planned = new Map(plan.hosts.map((h) => [h.hostId, h]));
  assert.deepEqual(plays.map((p) => p.hosts), [...new Set(plan.steps.map((s) => s.hostId))], "playbook order equals step order");
  for (const play of plays) {
    const h = planned.get(play.hosts);
    const expected = tasksFor(spec, "run-plan-test", h.hostId).map((t) => t.name);
    assert.deepEqual(h.tasks, expected, `${h.hostId} plan matches tasksFor`);
    assert.deepEqual(play.tasks.map((t) => t.name), expected, `${h.hostId} plan matches the playbook`);
  }
  // Every host's steps are contiguous, and dependencies run first.
  const firstAt = new Map();
  const finished = new Set();
  let previous = null;
  plan.steps.forEach((s, i) => {
    if (s.hostId !== previous) {
      assert.ok(!finished.has(s.hostId), `${s.hostId} steps are contiguous`);
      if (previous) finished.add(previous);
      firstAt.set(s.hostId, i);
      previous = s.hostId;
    }
  });
  for (const inst of spec.instances) {
    for (const dep of inst.dependsOn ?? []) assert.ok(firstAt.get(dep) < firstAt.get(inst.hostId), `${dep} is configured before ${inst.hostId}`);
  }
});

test("the clinic's planned order is unchanged by the dependency sort", () => {
  assert.deepEqual(hostOrder(spec), spec.instances.map((i) => i.hostId));
});

test("configuration order follows dependencies, not the order instances were emitted", () => {
  const reversed = { ...spec, instances: [...spec.instances].reverse() };
  const p = planDeployment(reversed, { runId: "run-plan-order" });
  const order = [...new Set(p.steps.map((s) => s.hostId))];
  assert.equal(order.length, reversed.instances.length, "every host is planned exactly once");
  for (const inst of reversed.instances) {
    for (const dep of inst.dependsOn ?? []) {
      assert.ok(order.indexOf(dep) < order.indexOf(inst.hostId), `${dep} before ${inst.hostId}`);
    }
  }
  const plays = JSON.parse(playbookFor(reversed, "run-plan-order"));
  assert.deepEqual(plays.map((x) => x.hosts), order, "the executor uses the same dependency order");
});

test("packages come only from the baked image set", () => {
  const known = new Set(allProvisionablePackages());
  for (const h of plan.hosts) for (const p of h.packages) assert.ok(known.has(p), `${h.hostId}: ${p}`);
});

test("every declared service contributes config, a seed or a probe", () => {
  const byHost = new Map(plan.hosts.map((h) => [h.hostId, h]));
  for (const inst of spec.instances) {
    for (const d of inst.serviceDecls ?? []) {
      const h = byHost.get(inst.hostId);
      const represented =
        h.config.some((c) => c.path.toLowerCase().includes(d.kind) || c.purpose.toLowerCase().includes(d.kind)) ||
        h.seeds.some((s) => s.target.toLowerCase().includes(d.kind) || s.purpose.toLowerCase().includes(d.kind)) ||
        h.readiness.some((p) => p.kind.startsWith(`${d.kind}/`));
      assert.ok(represented, `${inst.hostId}: ${d.kind} is represented in the plan`);
    }
  }
});

test("the wiring lists declared dependencies and log shipping with real addresses", () => {
  const webToDc = plan.edges.find((e) => e.from === "web-01" && e.to === "dc-01");
  assert.ok(webToDc, "web-01 consumes the directory");
  assert.equal(webToDc.protocol, "ldap");
  assert.equal(webToDc.address, "10.2.32.10");

  const logEdges = plan.edges.filter((e) => e.protocol === "syslog");
  assert.equal(logEdges.length, plan.hosts.length - 1, "every other guest ships logs");
  assert.ok(logEdges.every((e) => e.to === "log-01" && e.address === "10.2.32.14"));
});

test("topology in the plan is the designed topology", () => {
  assert.equal(plan.topology.cidr, "10.2.0.0/16", "environment CIDR");
  assert.deepEqual(plan.topology.subnets, [{ name: "clinic-lan", cidr: "10.2.32.0/20", zone: "a" }]);
  assert.equal(plan.topology.addresses["gw-01"], "10.2.32.1/20");
});

test("an unknown service is a plan gap, not a silent omission", () => {
  const bad = {
    ...spec,
    instances: spec.instances.map((i) => i.hostId === "web-01"
      ? { ...i, services: ["nginx"], serviceDecls: [{ kind: "http", impl: "nginx", port: 80, readyWhen: "http-2xx" }] }
      : i),
  };
  const p = planDeployment(bad, { runId: "run-plan-bad" });
  assert.match(p.gaps.join("; "), /web-01: service http\/nginx is not in the runtime catalog/);
});

test("cross-host acceptance is planned from the same probes readiness runs", () => {
  assert.ok(plan.labProbes.length > 0, "the plan names the cross-host proofs");
  const dns = plan.labProbes.filter((p) => p.probe === "lab-dns");
  assert.equal(dns.length, plan.hosts.length - 1, "every non-gateway host resolves through the gateway");
  assert.ok(dns.every((p) => p.to !== "gw-01"), "the gateway does not query itself");
  for (const p of plan.labProbes) {
    assert.ok(plan.hosts.some((h) => h.hostId === p.from), `${p.probe}: from ${p.from} is a planned host`);
    assert.ok(plan.hosts.some((h) => h.hostId === p.to), `${p.probe}: to ${p.to} is a planned host`);
    assert.equal("command" in p, false, "probe commands (and their secrets) never reach the plan");
  }
  assert.ok(plan.labProbes.some((p) => p.probe === "lab-http" && p.to === "web-01"));
  assert.ok(plan.labProbes.some((p) => p.probe === "lab-smtp" && p.to === "mail-01"));
  assert.ok(plan.labProbes.some((p) => p.probe === "lab-sql" && p.from === "web-01" && p.to === "db-01"));
});

test("a model-authored org is planned by declared services, not role names", () => {
  const base = clinicOrgSpec();
  // The designer may not emit `gateway`/`mail` roles; it declares the
  // services instead. The planner must find the same hosts either way.
  const roleOverrides = { "gw-01": "sensor", "mail-01": "workstation" };
  const renamed = {
    ...base,
    instances: base.instances.map((i) => (roleOverrides[i.hostId] ? { ...i, role: roleOverrides[i.hostId] } : i)),
  };
  const p = planDeployment(renamed, { runId: "run-plan-roles" });
  assert.deepEqual(p.gaps, []);
  assert.equal(p.topology.addresses["gw-01"], "10.2.32.1/20", "the DNS host owns the segment gateway address");
  assert.ok(p.labProbes.some((x) => x.probe === "lab-ldap" && x.to === "dc-01"), "the LDAP probe targets the host that declares LDAP");
  assert.ok(p.labProbes.some((x) => x.probe === "lab-smtp" && x.to === "mail-01"), "the SMTP probe follows the declaration, not a `mail` role");
  assert.ok(p.labProbes.some((x) => x.probe === "lab-dns" && x.to === "dc-01"), "DNS covers every guest");
});

test("an imported spec is packaged with the same gates, digest and plan as a design", async () => {
  const { orchestrateSpec } = await import("../dist/designer/orchestrator.js");
  const budget = { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 };

  const good = orchestrateSpec(clinicOrgSpec(), budget);
  assert.equal(good.canProvision, true, good.blockReasons.join("; "));
  assert.deepEqual(good.blockReasons, []);
  assert.equal(good.plan.hosts.length, spec.instances.length);
  assert.match(good.digest, /^sha256:[0-9a-f]{64}$/);
  const { digestOf } = await import("../dist/designer/pipeline.js");
  assert.equal(good.digest, digestOf(clinicOrgSpec()), "an import is digested by content, not a placeholder");

  const noSignal = structuredClone(spec);
  noSignal.objectives[0].successSignal = "";
  const blocked = orchestrateSpec(noSignal, budget);
  assert.equal(blocked.canProvision, false);
  assert.match(blocked.blockReasons.join("; "), /successSignal/);

  const tooBig = orchestrateSpec(spec, { ...budget, maxInstances: 2 });
  assert.equal(tooBig.canProvision, false);
  assert.match(tooBig.blockReasons.join("; "), /instances 6 > cap 2/);
});

test("the approved plan digest is checked before deploy", async () => {
  const { validateApprovedPlan } = await import("../dist/workflows/trigger.js");
  const { digestOfSpec } = await import("../dist/lib/digest.js");
  const approved = digestOfSpec(planDeployment(spec));
  assert.deepEqual(validateApprovedPlan(planDeployment(spec), approved), { ok: true });

  const missing = validateApprovedPlan(planDeployment(spec), undefined);
  assert.equal(missing.ok, false);
  assert.match(missing.reason, /no approved plan digest/);

  const bigger = {
    ...spec,
    instances: spec.instances.map((i) => i.hostId === "web-01" ? { ...i, resources: { ...i.resources, memoryMb: 2048 } } : i),
  };
  const drifted = validateApprovedPlan(planDeployment(bigger), approved);
  assert.equal(drifted.ok, false);
  assert.match(drifted.reason, /plan changed since approval/);
});

test("the plan is independent of runId, so an approval digest can be rechecked", () => {
  const a = planDeployment(spec, { runId: "run-approval" });
  const b = planDeployment(spec, { runId: "run-later" });
  assert.deepEqual(a, b, "per-run secrets and ports never leak into the reviewed plan");
});

test("the stored spec digest is checked before claim", async () => {
  const { validateStoredSpecDigest } = await import("../dist/workflows/trigger.js");
  const { digestOf } = await import("../dist/designer/pipeline.js");
  assert.deepEqual(validateStoredSpecDigest(spec, digestOf(spec)), { ok: true });

  const missing = validateStoredSpecDigest(spec, undefined);
  assert.equal(missing.ok, false);
  assert.match(missing.reason, /no spec digest/);

  const changed = validateStoredSpecDigest(spec, "sha256:" + "0".repeat(64));
  assert.equal(changed.ok, false);
  assert.match(changed.reason, /does not match its digest/);
});

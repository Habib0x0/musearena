import test from "node:test";
import assert from "node:assert/strict";

/**
 * Topology invariants. The design is the source of truth:
 * the diagram must show the placement the lab plan uses, a run's container
 * copy keeps the designed shape inside its allocated /16, and a design the
 * runtime cannot realize is refused with a reason instead of approximated.
 */

const { clinicOrgSpec } = await import("../dist/designer/clinic.js");
const { deployability } = await import("../dist/provisioner/capability.js");
const { topologyFor } = await import("../dist/designer/topology.js");
const { remapSubnets } = await import("../dist/provisioner/cidr.js");

test("remapSubnets keeps the designed shape and moves only the run octet", () => {
  const designed = [
    { name: "lan", cidr: "10.2.32.0/20", zone: "a" },
    { name: "mgmt", cidr: "10.2.48.0/20", zone: "b" },
  ];
  assert.deepEqual(remapSubnets(designed, 7), [
    { name: "lan", cidr: "10.7.32.0/20", zone: "a" },
    { name: "mgmt", cidr: "10.7.48.0/20", zone: "b" },
  ]);
  // Non-10 addresses are left alone rather than silently rewritten.
  assert.deepEqual(remapSubnets([{ cidr: "192.168.0.0/24" }], 9), [{ cidr: "192.168.0.0/24" }]);
});

test("topology map honours explicit instance placement, not array order", () => {
  const spec = {
    ...clinicOrgSpec(),
    topology: {
      cidr: "10.2.0.0/16",
      subnets: [
        { name: "servers", cidr: "10.2.32.0/20", zone: "a" },
        { name: "staff", cidr: "10.2.48.0/20", zone: "b" },
      ],
      firewallRules: [],
    },
    instances: [
      { ...clinicOrgSpec().instances[0], hostId: "a-01", name: "a-01", subnet: "staff" },
      { ...clinicOrgSpec().instances[1], hostId: "b-01", name: "b-01", subnet: "servers" },
    ],
  };
  const map = topologyFor(spec);
  const servers = map.subnets.find((s) => s.name === "servers").nodes.map((n) => n.hostId);
  const staff = map.subnets.find((s) => s.name === "staff").nodes.map((n) => n.hostId);
  assert.deepEqual(servers, ["b-01"]);
  assert.deepEqual(staff, ["a-01"]);
});

test("a multi-subnet design is refused on the container path: one flat network", () => {
  const base = clinicOrgSpec();
  const containerized = {
    ...base,
    instances: base.instances.map((i) => ({ ...i, runtime: "container" })),
    topology: {
      ...base.topology,
      subnets: [...base.topology.subnets, { name: "second", cidr: "10.2.48.0/20", zone: "b" }],
    },
  };
  assert.match(deployability(containerized).join("; "), /one flat network/);
});

test("a display service with no declaration is refused; base-profile names are not", () => {
  const base = clinicOrgSpec();
  const withGuest = (services) => ({
    ...base,
    instances: [...base.instances, {
      hostId: "ws-01", name: "ws-01", role: "workstation", runtime: "vm", os: "Debian 12",
      stack: [], services, databases: [], serviceDecls: [], dependsOn: [],
      resources: { vcpu: 1, memoryMb: 1024, diskGb: 6 },
    }],
  });
  assert.match(deployability(withGuest(["nginx"])).join("; "), /"nginx" is a display name with no serviceDecl/);
  assert.deepEqual(deployability(withGuest(["ssh"])), [], "ssh comes from the base profile");
  assert.deepEqual(deployability(withGuest([])), [], "a bare workstation is fine");
});

test("the clinic stays deployable", () => {
  assert.deepEqual(deployability(clinicOrgSpec()), []);
});

test("stack outputs keep structured values instead of [object Object]", async () => {
  const { flattenOutputs } = await import("../dist/provisioner/deploy.js");
  const flat = flattenOutputs({
    "web-01": { value: "vm:hvf:web-01" },
    subnets: { value: [{ name: "lan", cidr: "10.2.32.0/20", zone: "a" }] },
  });
  assert.equal(flat["web-01"], "vm:hvf:web-01");
  assert.deepEqual(JSON.parse(flat.subnets), [{ name: "lan", cidr: "10.2.32.0/20", zone: "a" }]);
});

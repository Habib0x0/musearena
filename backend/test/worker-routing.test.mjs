import { test } from "node:test";
import assert from "node:assert/strict";
import {
  claimAccessInfo,
  deploymentOwnedByWorker,
  requiredWorkerRoute,
  workerCanRunDeployment,
  workerRoutingConfig,
} from "../dist/lib/worker-routing.js";

const vmSpec = (over = {}) => ({
  truthLayer: "mirror-only",
  platform: { runtimeTarget: "vm", modelSurface: "meta", exerciseEngine: "scripted" },
  instances: [{ hostId: "web-01", runtime: "vm", os: "Debian 12" }],
  ...over,
});

const containerSpec = () => ({
  truthLayer: "mirror-only",
  platform: { runtimeTarget: "container", modelSurface: "meta", exerciseEngine: "scripted" },
  instances: [{ hostId: "web-01", runtime: "container", os: "Debian 12" }],
});

const caps = (over = {}) => ({
  platform: "linux",
  arch: "x64",
  guestArch: "x86_64",
  accel: "kvm",
  vmRuns: true,
  container: true,
  bakedCatalog: "absent",
  truthLayerCap: "mirror-only",
  maxVmInstances: 8,
  notes: [],
  ...over,
});

test("worker routing defaults preserve the legacy single-worker queue", () => {
  const routing = workerRoutingConfig({});
  assert.equal(routing.workerId, null);
  assert.equal(routing.taskQueue, "musearena");
  assert.deepEqual(routing.routes, ["kvm", "vm", "container"]);
  assert.equal(routing.ownsUnrouted, true);
});

test("worker routing derives a stable host task queue and validates routes", () => {
  const routing = workerRoutingConfig({
    MUSEARENA_WORKER_ID: "linux-kvm",
    MUSEARENA_WORKER_ROUTES: "kvm, vm",
  });
  assert.equal(routing.workerId, "linux-kvm");
  assert.equal(routing.taskQueue, "musearena-linux-kvm");
  assert.deepEqual(routing.routes, ["kvm", "vm"]);
  assert.equal(routing.ownsUnrouted, false);
  assert.throws(
    () => workerRoutingConfig({ MUSEARENA_WORKER_ROUTES: "kvm,cloud" }),
    /unknown worker route "cloud"/,
  );
  assert.throws(
    () => workerRoutingConfig({ MUSEARENA_WORKER_ID: "bad worker" }),
    /MUSEARENA_WORKER_ID/,
  );
});

test("required route follows truth layer and runtime", () => {
  assert.equal(requiredWorkerRoute(vmSpec({ truthLayer: "kvm-vmi" })), "kvm");
  assert.equal(requiredWorkerRoute(vmSpec()), "vm");
  assert.equal(requiredWorkerRoute(containerSpec()), "container");
});

test("only a KVM-capable routed worker may claim a kvm-vmi deployment", () => {
  const spec = vmSpec({ truthLayer: "kvm-vmi" });
  const linux = workerRoutingConfig({ MUSEARENA_WORKER_ID: "linux-kvm", MUSEARENA_WORKER_ROUTES: "kvm,vm" });
  const mac = workerRoutingConfig({ MUSEARENA_WORKER_ID: "mac-hvf", MUSEARENA_WORKER_ROUTES: "kvm,vm,container" });

  assert.equal(workerCanRunDeployment({ spec, routing: linux, caps: caps() }).eligible, true);

  const macDecision = workerCanRunDeployment({
    spec,
    routing: mac,
    caps: caps({ platform: "darwin", arch: "arm64", guestArch: "aarch64", accel: "hvf" }),
  });
  assert.equal(macDecision.eligible, false);
  assert.match(macDecision.reason, /kvm-vmi.*KVM|KVM.*kvm-vmi/i);
});

test("explicit worker targeting and route allowlists fail closed", () => {
  const linux = workerRoutingConfig({ MUSEARENA_WORKER_ID: "linux-kvm", MUSEARENA_WORKER_ROUTES: "vm" });
  assert.equal(
    workerCanRunDeployment({ spec: vmSpec(), accessInfo: { workerId: "mac-hvf" }, routing: linux, caps: caps() }).eligible,
    false,
  );
  assert.equal(
    workerCanRunDeployment({ spec: containerSpec(), routing: linux, caps: caps() }).eligible,
    false,
  );
  const invalid = workerCanRunDeployment({
    spec: vmSpec(), accessInfo: { workerRoute: "cloud" }, routing: linux, caps: caps(),
  });
  assert.equal(invalid.eligible, false);
  assert.match(invalid.reason, /workerRoute/);
});

test("guest architecture, Windows image, and instance caps are host eligibility gates", () => {
  const linux = workerRoutingConfig({ MUSEARENA_WORKER_ID: "linux-kvm", MUSEARENA_WORKER_ROUTES: "vm" });
  const armSpec = vmSpec({ instances: [{ hostId: "web-01", runtime: "vm", os: "Debian 12 (arm64)" }] });
  assert.equal(workerCanRunDeployment({ spec: armSpec, routing: linux, caps: caps() }).eligible, false);

  const windowsSpec = vmSpec({ instances: [{ hostId: "ws-01", runtime: "vm", os: "Windows 11" }] });
  assert.equal(workerCanRunDeployment({ spec: windowsSpec, routing: linux, caps: caps(), windowsImageConfigured: false }).eligible, false);
  assert.equal(workerCanRunDeployment({ spec: windowsSpec, routing: linux, caps: caps(), windowsImageConfigured: true }).eligible, true);

  const tooMany = vmSpec({ instances: Array.from({ length: 9 }, (_, i) => ({ hostId: `h-${i}`, runtime: "vm", os: "Debian 12" })) });
  assert.equal(workerCanRunDeployment({ spec: tooMany, routing: linux, caps: caps() }).eligible, false);
});

test("maintenance ownership is exact for routed workers", () => {
  const legacy = workerRoutingConfig({});
  const linux = workerRoutingConfig({ MUSEARENA_WORKER_ID: "linux-kvm" });
  const linuxLegacyOwner = workerRoutingConfig({ MUSEARENA_WORKER_ID: "linux-kvm", MUSEARENA_WORKER_OWNS_UNROUTED: "1" });

  assert.equal(deploymentOwnedByWorker({}, legacy), true);
  assert.equal(deploymentOwnedByWorker({ workerId: "linux-kvm" }, linux), true);
  assert.equal(deploymentOwnedByWorker({ workerId: "mac-hvf" }, linux), false);
  assert.equal(deploymentOwnedByWorker({}, linux), false);
  assert.equal(deploymentOwnedByWorker({}, linuxLegacyOwner), true);
});

test("claim stamp preserves approval evidence and records the owner", () => {
  const linux = workerRoutingConfig({ MUSEARENA_WORKER_ID: "linux-kvm" });
  const info = claimAccessInfo({ planDigest: "sha256:approved", platform: vmSpec().platform }, linux, "vm", "2026-11-03T12:00:00.000Z");
  assert.equal(info.planDigest, "sha256:approved");
  assert.deepEqual(info.platform, vmSpec().platform);
  assert.equal(info.workerId, "linux-kvm");
  assert.equal(info.workerRoute, "vm");
  assert.equal(info.workerTaskQueue, "musearena-linux-kvm");
  assert.equal(info.workerClaimedAt, "2026-11-03T12:00:00.000Z");
});

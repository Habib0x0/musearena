import { test } from "node:test";
import assert from "node:assert/strict";
import { detectHost, vmPlanFor, qemuArgsFor, assertKvmUsable, bootProbeGuest, bootLinuxVm, classifyHost, guestArchOf, scoredVmAccel } from "../dist/provisioner/kvm.js";

const spec = {
  version: 1, name: "kvm-org", provider: "kvm", seed: "s1", difficulty: "standard", truthLayer: "mirror-only",
  topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
  instances: [
    { hostId: "web-01", name: "web-01", role: "web", runtime: "container", os: "Ubuntu 24.04", stack: [], services: ["http"], databases: [] },
    { hostId: "dc-01", name: "dc-01", role: "dc", runtime: "vm", os: "Ubuntu 24.04", stack: [], services: ["ldap"], databases: [] },
  ],
  personas: [], objectives: [{ id: "o1", asset: "dc-01", techniqueId: "T1003.001", successSignal: "canary", points: 10 }],
  requiredTelemetry: ["zeek.conn"], plantedVulns: [],
  budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
};

test("host gate never permits kvm-vmi without Linux /dev/kvm", () => {
  const host = detectHost();
  if (!host.canKvmVmi) {
    assert.throws(() => assertKvmUsable({ ...spec, truthLayer: "kvm-vmi" }, host), /kvm-vmi/);
  }
  assert.equal(assertKvmUsable(spec, host).truthLayer, "mirror-only");
});

test("plan covers only vm-runtime instances (hybrid rule)", () => {
  const host = detectHost();
  const plan = vmPlanFor(spec, host);
  assert.deepEqual(plan.map((v) => v.hostId), ["dc-01"]);
  const args = qemuArgsFor(plan[0], { stateDir: "/tmp/kvm-test-state" });
  assert.ok(args.includes("-accel"));
  assert.ok(args.some((a) => ["kvm", "hvf", "tcg"].includes(a)));
});

test("Windows VM guests fail closed without a supplied image", () => {
  const win = { ...spec, instances: [{ hostId: "w1", name: "w1", role: "workstation", runtime: "vm", os: "Windows 11", stack: [], services: [], databases: [] }] };
  assert.throws(() => assertKvmUsable(win, detectHost()), /no guest image/);
});

test("tiny Linux guest boots a real kernel and prints marker", async (t) => {
  const host = detectHost();
  if (host.accel === "none") { t.skip("no qemu accelerator on this host"); return; }
  const def = { hostId: "tiny", name: "tiny", role: "server", guestArch: host.arch === "arm64" ? "aarch64" : "x86_64", binary: host.arch === "arm64" ? host.qemuArm : host.qemuX86, accel: host.arch === "arm64" ? host.accel : "tcg", memoryMb: 256, cpus: 1 };
  const res = await bootLinuxVm(def, { stateDir: "/tmp/kvm-test-state", timeoutMs: 90000 });
  assert.match(res.serialLog, /MUSEARENA-LINUX-BOOT Linux/);
});

test("host classification: native KVM needs Linux /dev/kvm + the host-arch QEMU binary", () => {
  assert.equal(guestArchOf("x64"), "x86_64");
  assert.equal(guestArchOf("arm64"), "aarch64");
  assert.equal(guestArchOf("ia32"), null);
  const linuxX86 = classifyHost({ platform: "linux", arch: "x64", hasKvmDevice: true, qemuX86: "/usr/bin/qemu-system-x86_64", qemuArm: null });
  assert.deepEqual([linuxX86.accel, linuxX86.hostArch, linuxX86.canKvmVmi], ["kvm", "x86_64", true]);
  const linuxArm = classifyHost({ platform: "linux", arch: "arm64", hasKvmDevice: true, qemuX86: null, qemuArm: "/usr/bin/qemu-system-aarch64" });
  assert.deepEqual([linuxArm.accel, linuxArm.hostArch], ["kvm", "aarch64"], "aarch64 Linux host gets native KVM (was misclassified x86-only)");
  const armWrongBinary = classifyHost({ platform: "linux", arch: "arm64", hasKvmDevice: true, qemuX86: "/usr/bin/qemu-system-x86_64", qemuArm: null });
  assert.equal(armWrongBinary.accel, "tcg", "KVM device with only the foreign-arch QEMU binary is not native");
  assert.match(armWrongBinary.reason, /not installed/);
  assert.equal(classifyHost({ platform: "linux", arch: "x64", hasKvmDevice: false, qemuX86: "/usr/bin/qemu-system-x86_64", qemuArm: null }).accel, "tcg", "no /dev/kvm → no KVM claim");
  assert.deepEqual(
    (() => { const h = classifyHost({ platform: "darwin", arch: "arm64", hasKvmDevice: false, qemuX86: null, qemuArm: "/opt/homebrew/bin/qemu-system-aarch64" }); return [h.accel, h.canKvmVmi]; })(),
    ["hvf", false]);
  assert.equal(classifyHost({ platform: "linux", arch: "x64", hasKvmDevice: false, qemuX86: null, qemuArm: null }).accel, "none");
});

test("scored VM runs refuse emulation: tcg/none fail closed, kvm/hvf allowed", () => {
  assert.equal(scoredVmAccel({ accel: "kvm" }), "kvm");
  assert.equal(scoredVmAccel({ accel: "hvf" }), "hvf");
  assert.equal(scoredVmAccel({ accel: "tcg" }), null);
  assert.equal(scoredVmAccel({ accel: "none" }), null);
});

test("vm plan follows the host arch and fails closed on cross-arch OS strings", () => {
  const armHost = classifyHost({ platform: "linux", arch: "arm64", hasKvmDevice: true, qemuX86: null, qemuArm: "/usr/bin/qemu-system-aarch64" });
  const armSpec = { ...spec, instances: [{ hostId: "w1", name: "w1", role: "web", runtime: "vm", os: "Debian 12 (arm64)", stack: [], services: [], databases: [] }] };
  const plan = vmPlanFor(armSpec, armHost);
  assert.deepEqual([plan[0].guestArch, plan[0].accel, plan[0].binary], ["aarch64", "kvm", "/usr/bin/qemu-system-aarch64"]);
  assert.throws(() => vmPlanFor({ ...armSpec, instances: [{ ...armSpec.instances[0], os: "Ubuntu 24.04 x86_64" }] }, armHost), /cross-arch/);
  assert.throws(() => vmPlanFor(armSpec, classifyHost({ platform: "linux", arch: "x64", hasKvmDevice: true, qemuX86: "/usr/bin/qemu-system-x86_64", qemuArm: null })), /cross-arch/);
});

test("probe guest actually boots and prints marker", async (t) => {
  const host = detectHost();
  if (host.accel === "none") { t.skip("no qemu accelerator on this host"); return; }
  const res = await bootProbeGuest({ stateDir: "/tmp/kvm-test-state" });
  assert.match(res.serialLog, /MUSEARENA-KVM-BOOT/);
});

test("golden images: catalog pins both arches; ensure rejects unverified bytes, accepts matching hash", async () => {
  const { GOLDEN_IMAGES, GOLDEN_CATALOG_VERSION, ensureGoldenImage, hashFile } = await import("../dist/provisioner/images.js");
  const { mkdtempSync, writeFileSync, existsSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  assert.equal(GOLDEN_IMAGES.x86_64.file, "debian-12-generic-amd64.qcow2");
  assert.equal(GOLDEN_IMAGES.aarch64.file, "debian-12-generic-arm64.qcow2");
  for (const g of Object.values(GOLDEN_IMAGES)) {
    assert.match(g.sha512, /^[0-9a-f]{128}$/);
    assert.ok(g.digest.includes(GOLDEN_CATALOG_VERSION), "digest carries the catalog pin");
    assert.ok(g.url.startsWith("https://cloud.debian.org/images/cloud/bookworm/"));
  }
  const dir = mkdtempSync(`${tmpdir()}/golden-`);
  const good = `${dir}/good.bin`;
  writeFileSync(good, "verified-bytes");
  const goodHash = await hashFile(good);
  let calls = 0;
  const res = await ensureGoldenImage("aarch64", { cacheDir: dir, expectedSha512: goodHash, downloadImpl: async (_u, dest) => { calls += 1; writeFileSync(dest, "verified-bytes"); } });
  assert.equal(res.path, `${dir}/${res.image.file}`);
  assert.equal(calls, 1);
  await assert.rejects(
    ensureGoldenImage("aarch64", { cacheDir: `${dir}/bad`, expectedSha512: goodHash, downloadImpl: async (_u, dest) => { writeFileSync(dest, "tampered"); } }),
    /failed SHA512 verification twice/);
  assert.ok(existsSync(dir));
});

test("vm lifecycle: start registers persistent guests (CoW overlay, seed, pidfile); stop/destroy clean up", async () => {
  const { startRunVms, stopRunVms, destroyRunVms, listVmRuns, vmStateDir, seedFilesFor } = await import("../dist/provisioner/vm-lifecycle.js");
  const { labPlanFor, labHubPortFor, nicMac } = await import("../dist/provisioner/lab-network.js");
  const { mkdtempSync, writeFileSync, existsSync, readFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const stateRoot = mkdtempSync(`${tmpdir()}/arena-vm-`);
  const goldenPath = `${stateRoot}/golden.qcow2`;
  writeFileSync(goldenPath, "golden-bytes");
  const golden = { image: { guestArch: "aarch64", name: "debian-12-generic", url: "file://golden", file: "debian-12-generic-arm64.qcow2", format: "qcow2", sha512: "0".repeat(128), digest: "sha512:test/arena-golden-debian12-1" }, path: goldenPath };
  const fixture = (n) => new URL(`./fixtures/${n}`, import.meta.url).pathname;
  const runId = "run-lifecycle-1";
  const vmSpec = {
    version: 1, name: "clinic", provider: "kvm", seed: "s1", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
    instances: [
      { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: ["http"], databases: [], resources: { vcpu: 1, memoryMb: 512, diskGb: 4 } },
      { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: ["postgres"], databases: ["app"] },
    ],
    personas: [], objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary", points: 10 }],
    requiredTelemetry: ["auditd"], plantedVulns: [], budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
  };
  const lifecycle = { stateRoot, runId, qemuBinary: fixture("fake-qemu.mjs"), qemuImg: fixture("fake-qemu-img.mjs"), isoTool: fixture("fake-genisoimage.mjs"), golden };
  const res = await startRunVms(vmSpec, lifecycle, (hostId, pubKey) => ({ hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId } }));
  assert.equal(res.golden.digest, golden.image.digest);
  const dir = vmStateDir(lifecycle);
  for (const hostId of ["web-01", "db-01"]) {
    const st = res.state.instances[hostId];
    assert.ok(st && st.pid > 0, `${hostId} registered with a pid`);
    assert.equal(st.netMode, "lab", "every guest is attached to the run's lab segment");
    assert.ok(st.lab?.address.startsWith("10.2.32."), `${hostId} has a lab address (${st.lab?.address})`);
    assert.notEqual(st.lab.address, "10.2.32.0");
    const overlay = JSON.parse(readFileSync(st.overlay, "utf8"));
    assert.equal(overlay.backing, goldenPath, "overlay is copy-on-write over the verified golden image");
    const seed = readFileSync(st.seedIso, "utf8");
    assert.ok(seed.includes(hostId) && seed.includes("ssh-rsa") === false && seed.includes("ssh-ed25519"), "seed ISO carries hostname + run SSH key");
    assert.ok(seedFilesFor({ runId, specName: "clinic", seed: "s1", host: { hostname: hostId, sshAuthorizedKey: "ssh-ed25519 AAA", identity: { RUN_ID: runId } } })["user-data"].includes("MUSEARENA-GUEST-READY"));
  }
  const plan = labPlanFor(vmSpec, runId);
  assert.equal(plan.length, 2);
  assert.equal(plan[0].address, "10.2.32.10");
  assert.equal(plan[1].address, "10.2.32.11");
  assert.equal(new Set(plan.map((e) => e.mcast)).size, 1, "one segment per run");
  assert.notEqual(nicMac("web-01", "lab"), nicMac("web-01", "mgmt"));
  assert.equal(labHubPortFor("run-a") === labHubPortFor("run-b"), false, "runs do not share a hub");
  assert.ok(labHubPortFor(runId) >= 45000 && labHubPortFor(runId) <= 60000, "hub port avoids the SSH hostfwd range");
  assert.ok(res.state.labHub?.pid > 0, "the run registers its lab hub process");

  const { qemuRunArgs } = await import("../dist/provisioner/vm-lifecycle.js");
  const def = { hostId: "web-01", guestArch: "aarch64", accel: "hvf", memoryMb: 512, cpus: 1, diskGb: 4, binary: "qemu-system-aarch64" };
  const args = qemuRunArgs(def, { stateDir: "/tmp", overlay: "/tmp/o", seedIso: "/tmp/s", sshHostPort: 22000, runId, lab: { hubPort: 45001 } });
  assert.ok(args.includes("socket,id=net1,connect=127.0.0.1:45001"), "lab NIC connects to the run hub");
  assert.ok(args.includes(`virtio-net-pci,netdev=net0,mac=${nicMac("web-01", "mgmt")}`), "management NIC pins its MAC");

  const seed = seedFilesFor({ runId, specName: "clinic", seed: "s1", host: { hostname: "web-01", sshAuthorizedKey: "ssh-ed25519 AAA", identity: {}, mgmtMac: nicMac("web-01", "mgmt"), lab: { address: "10.2.32.10", prefix: 20, mac: nicMac("web-01", "lab") } } });
  assert.ok(seed["network-config"].includes("macaddress: \"52:54:00:"), "network-config matches the management NIC by MAC");
  assert.ok(seed["network-config"].includes("10.2.32.10/20"), "network-config declares the lab address statically");
  assert.ok(!seed["network-config"].includes("all-en"), "the lab NIC is not matched by an en* DHCP rule");
  assert.ok(seed["user-data"].includes("ip addr replace 10.2.32.10/20"), "seed configures the lab address");

  const kvmArgs = qemuRunArgs({ ...def, accel: "kvm" }, { stateDir: "/tmp", overlay: "/tmp/o", seedIso: "/tmp/s", sshHostPort: 22000, runId });
  assert.ok(kvmArgs.join(" ").includes("-accel kvm -cpu host"), "KVM uses the host CPU model");
  const tcgArgs = qemuRunArgs({ ...def, accel: "tcg" }, { stateDir: "/tmp", overlay: "/tmp/o", seedIso: "/tmp/s", sshHostPort: 22000, runId });
  assert.ok(!tcgArgs.join(" ").includes("-cpu host"), "emulation must not claim the host CPU model");

  const noLab = qemuRunArgs(def, { stateDir: "/tmp", overlay: "/tmp/o", seedIso: "/tmp/s", sshHostPort: 22000, runId });
  assert.ok(!noLab.some((a) => a.includes("net1")), "lab NIC is opt-in per call");

  assert.equal((await listVmRuns(stateRoot)).length, 1);
  await assert.rejects(startRunVms(vmSpec, lifecycle, (h, k) => ({ hostname: h, sshAuthorizedKey: k, identity: {} })), /already has live VM pids/);
  const stopped = await stopRunVms(lifecycle);
  assert.ok(Object.values(stopped.instances).every((i) => i.stoppedAt), "stop records stoppedAt for every guest");
  assert.deepEqual(await destroyRunVms(lifecycle), { removed: true });
  assert.equal(existsSync(dir), false, "destroy removes the run state dir (overlays, seeds, keys)");
  assert.equal((await listVmRuns(stateRoot)).length, 0);
});

test("vm lifecycle: v2 org spec starts one hub per zone segment; teardown removes every hub", async () => {
  const { startRunVms, stopRunVms, destroyRunVms, vmStateDir, seedFilesFor } = await import("../dist/provisioner/vm-lifecycle.js");
  const { labSegmentsFor } = await import("../dist/provisioner/lab-network.js");
  const { mkdtempSync, writeFileSync, existsSync, readFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const stateRoot = mkdtempSync(`${tmpdir()}/arena-vm-seg-`);
  const goldenPath = `${stateRoot}/golden.qcow2`;
  writeFileSync(goldenPath, "golden-bytes");
  const golden = { image: { guestArch: "aarch64", name: "debian-12-generic", url: "file://golden", file: "debian-12-generic-arm64.qcow2", format: "qcow2", sha512: "0".repeat(128), digest: "sha512:test/arena-seg" }, path: goldenPath };
  const fixture = (n) => new URL(`./fixtures/${n}`, import.meta.url).pathname;
  const runId = "run-seg-live-1";
  // One site, two zones: the router touches both segments, each host one.
  const segSpec = {
    version: 2, name: "seg-lab", provider: "kvm", seed: "s1", difficulty: "standard", truthLayer: "mirror-only",
    topology: {
      cidr: "10.42.0.0/16", subnets: [], firewallRules: [],
      sites: [{ id: "hq", name: "HQ", kind: "hq" }],
      zones: [{ id: "edge", site: "hq", kind: "edge" }, { id: "server", site: "hq", kind: "server" }],
      links: [],
      policies: [{ from: "hq/edge", to: "hq/server", proto: "tcp", port: 5432, action: "allow", reason: "app to db" }],
    },
    instances: [
      { hostId: "r-01", name: "r-01", role: "router", runtime: "vm", os: "Debian 12", stack: [], services: ["router"], databases: [], site: "hq", zone: "edge", serviceDecls: [{ kind: "router", impl: "nftables", port: 22, readyWhen: "ssh-login" }], resources: { vcpu: 1, memoryMb: 512, diskGb: 6 } },
      { hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: ["http"], databases: [], site: "hq", zone: "edge", serviceDecls: [{ kind: "http", impl: "apache-php", port: 80, readyWhen: "http-2xx" }], resources: { vcpu: 1, memoryMb: 512, diskGb: 6 } },
      { hostId: "db-01", name: "db-01", role: "db", runtime: "vm", os: "Debian 12", stack: [], services: ["db"], databases: ["app"], site: "hq", zone: "server", serviceDecls: [{ kind: "db", impl: "postgres", port: 5432, readyWhen: "sql-select" }], resources: { vcpu: 1, memoryMb: 512, diskGb: 6 } },
    ],
    personas: [], objectives: [{ id: "o1", asset: "db-01", techniqueId: "T1078", successSignal: "canary", points: 10 }],
    requiredTelemetry: ["auditd"], plantedVulns: [], budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
  };
  const lifecycle = { stateRoot, runId, qemuBinary: fixture("fake-qemu.mjs"), qemuImg: fixture("fake-qemu-img.mjs"), isoTool: fixture("fake-genisoimage.mjs"), golden };
  const res = await startRunVms(segSpec, lifecycle, (hostId, pubKey) => ({ hostname: hostId, sshAuthorizedKey: pubKey, identity: { RUN_ID: runId, HOST_ID: hostId } }));
  assert.equal(res.state.netMode, "lab", "segmented runs are lab runs");
  assert.equal(res.state.labHub, undefined, "v2 runs do not start the legacy single hub");
  assert.equal(res.state.labHubs?.length, 2, "one hub process per zone segment");
  assert.equal(new Set(res.state.labHubs.map((h) => h.port)).size, 2, "segment hub ports are distinct");
  const byId = res.state.instances;
  assert.equal(byId["r-01"].labs?.length, 2, "the router is multi-homed");
  assert.deepEqual(byId["r-01"].labs.map((l) => l.address), ["10.42.0.1", "10.42.1.1"], "the router owns .1 in each zone");
  assert.equal(byId["web-01"].labs?.length, 1, "regular hosts get one NIC");
  assert.equal(byId["web-01"].lab?.address, "10.42.0.10", "primary address mirrors labs[0]");
  assert.equal(byId["db-01"].lab?.address, "10.42.1.10", "the server zone address is derived");
  // The seed configures every segment NIC; the router seed has two address lines.
  const seedIso = readFileSync(byId["r-01"].seedIso, "utf8");
  assert.ok(seedIso.includes("10.42.0.1/24"), "router seed configures the edge address");
  assert.ok(seedIso.includes("10.42.1.1/24"), "router seed configures the server address");
  assert.ok(seedFilesFor({
    runId, specName: "seg-lab", seed: "s1",
    host: { hostname: "r-01", sshAuthorizedKey: "ssh-ed25519 AAA", identity: {}, mgmtMac: "52:54:00:aa:bb:cc", labs: [{ segment: "a", address: "10.42.0.1", prefix: 24, mac: "52:54:00:dd:ee:ff" }, { segment: "b", address: "10.42.1.1", prefix: 24, mac: "52:54:00:11:22:33" }] },
  })["user-data"].includes("10.42.1.1/24"), "multi-NIC seeds configure every segment address");
  const webAtt = labSegmentsFor(segSpec, runId).find((a) => a.hostId === "web-01");
  assert.deepEqual(webAtt.routesVia, [{ cidr: "10.42.1.0/24", via: "10.42.0.1" }], "edge host routes to the server zone via the router");
  const routedSeed = seedFilesFor({
    runId, specName: "seg-lab", seed: "s1",
    host: { hostname: "web-01", sshAuthorizedKey: "ssh-ed25519 AAA", identity: {}, mgmtMac: "52:54:00:aa:bb:cc", labs: [{ segment: "edge", address: "10.42.0.10", prefix: 24, mac: "52:54:00:dd:ee:ff", routes: [{ to: "10.42.1.0/24", via: "10.42.0.1" }] }] },
  });
  assert.ok(routedSeed["network-config"].includes("via: 10.42.0.1"), "seed network-config carries the cross-zone route");
  assert.ok(routedSeed["user-data"].includes("ip route replace 10.42.1.0/24 via 10.42.0.1"), "seed runcmd carries the cross-zone route");
  const atts = labSegmentsFor(segSpec, runId);
  assert.deepEqual(
    atts.filter((a) => a.hostId === "r-01").map((a) => a.hubPort).sort((a, b) => a - b),
    res.state.labHubs.map((h) => h.port).sort((a, b) => a - b),
    "guest NICs connect to the hubs this run started",
  );
  const stopped = await stopRunVms(lifecycle);
  assert.ok(Object.values(stopped.instances).every((i) => i.stoppedAt), "stop records stoppedAt");
  assert.deepEqual(await destroyRunVms(lifecycle), { removed: true });
  assert.equal(existsSync(vmStateDir(lifecycle)), false, "destroy removes the run state dir");
  assert.equal((await (await import("../dist/provisioner/vm-lifecycle.js")).listVmRuns(stateRoot)).length, 0);
});

test("vm lifecycle: partial start destroys what it started (no leaked guests)", async () => {
  const { startRunVms } = await import("../dist/provisioner/vm-lifecycle.js");
  const { mkdtempSync, writeFileSync, existsSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const stateRoot = mkdtempSync(`${tmpdir()}/arena-vm-fail-`);
  const goldenPath = `${stateRoot}/golden.qcow2`;
  writeFileSync(goldenPath, "golden-bytes");
  const golden = { image: { guestArch: "aarch64", name: "debian-12-generic", url: "file://golden", file: "debian-12-generic-arm64.qcow2", format: "qcow2", sha512: "0".repeat(128), digest: "sha512:test" }, path: goldenPath };
  const fixture = (n) => new URL(`./fixtures/${n}`, import.meta.url).pathname;
  const vmSpec = {
    version: 1, name: "clinic", provider: "kvm", seed: "s1", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
    instances: [{ hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [] }],
    personas: [], objectives: [{ id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "x", points: 1 }],
    requiredTelemetry: ["auditd"], plantedVulns: [], budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
  };
  // Broken ISO tool forces a failure after the first guest would have started.
  await assert.rejects(startRunVms(vmSpec, { stateRoot, runId: "run-fail-1", qemuBinary: fixture("fake-qemu.mjs"), qemuImg: fixture("fake-qemu-img.mjs"), isoTool: "/nonexistent/genisoimage", golden },
    (h, k) => ({ hostname: h, sshAuthorizedKey: k, identity: {} })));
  assert.equal(existsSync(`${stateRoot}/kvm/run-fail-1`), false, "failed start leaves no run state behind");
});

test("seed ISO: built-in ISO9660 writer produces a parseable CIDATA image", async () => {
  const { buildSeedIso, isoName } = await import("../dist/provisioner/seed-iso.js");
  assert.equal(isoName("user-data"), "USER-DATA;1");
  assert.equal(isoName("network-config"), "NETWORK-CONFIG;1");
  const iso = buildSeedIso({ "user-data": "#cloud-config\nhostname: web-01\n", "meta-data": "instance-id: x\n", "network-config": "" });
  assert.equal(iso.length % 2048, 0);
  assert.equal(iso.subarray(16 * 2048 + 1, 16 * 2048 + 6).toString("ascii"), "CD001");
  assert.equal(iso.subarray(16 * 2048 + 40, 16 * 2048 + 46).toString("ascii").trim(), "CIDATA");
  const text = iso.toString("utf8");
  assert.ok(text.includes("USER-DATA;1") && text.includes("hostname: web-01"));
  assert.ok(text.includes("META-DATA;1"));
});

test("vm ssh: identity output parses; registry state yields configurer targets", async () => {
  const { parseGuestExecOutput, vmTargetsFromState } = await import("../dist/configurator/vm-ssh.js");
  const id = parseGuestExecOutput("HOSTNAME=web-01\nUSER=arena\nIDENTITY-BEGIN\nRUN_ID=run-1\nHOST_ID=web-01\nROLE=web\nIDENTITY-END\n");
  assert.deepEqual([id.hostname, id.user, id.runId, id.hostId, id.extra.ROLE], ["web-01", "arena", "run-1", "web-01", "web"]);
  assert.throws(() => parseGuestExecOutput("HOSTNAME=web-01\n"), /missing USER/);
  const targets = vmTargetsFromState({ instances: { "web-01": { hostId: "web-01", ssh: { host: "127.0.0.1", port: 23001, user: "arena", privateKeyPath: "/tmp/k" } } } });
  assert.deepEqual([targets[0].connectVia, targets[0].ssh.port], ["arena@127.0.0.1:23001", 23001]);
});

test("vm lifecycle: registry records the SSH endpoint for each guest", async () => {
  const { startRunVms, destroyRunVms } = await import("../dist/provisioner/vm-lifecycle.js");
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const stateRoot = mkdtempSync(`${tmpdir()}/arena-vm-ssh-`);
  const goldenPath = `${stateRoot}/golden.qcow2`;
  writeFileSync(goldenPath, "golden-bytes");
  const golden = { image: { guestArch: "aarch64", name: "debian-12-generic", url: "file://golden", file: "debian-12-generic-arm64.qcow2", format: "qcow2", sha512: "0".repeat(128), digest: "sha512:test" }, path: goldenPath };
  const fixture = (n) => new URL(`./fixtures/${n}`, import.meta.url).pathname;
  const vmSpec = {
    version: 1, name: "clinic", provider: "kvm", seed: "s1", difficulty: "standard", truthLayer: "mirror-only",
    topology: { cidr: "10.2.0.0/16", subnets: [{ name: "private-a", cidr: "10.2.32.0/20", zone: "a" }], firewallRules: [] },
    instances: [{ hostId: "web-01", name: "web-01", role: "web", runtime: "vm", os: "Debian 12", stack: [], services: [], databases: [] }],
    personas: [], objectives: [{ id: "o1", asset: "web-01", techniqueId: "T1059", successSignal: "x", points: 1 }],
    requiredTelemetry: ["auditd"], plantedVulns: [], budgets: { maxInstances: 8, maxDollarsPerHour: 5, ttlHours: 8 },
  };
  const lifecycle = { stateRoot, runId: "run-ssh-1", qemuBinary: fixture("fake-qemu.mjs"), qemuImg: fixture("fake-qemu-img.mjs"), isoTool: fixture("fake-genisoimage.mjs"), golden };
  const res = await startRunVms(vmSpec, lifecycle, (h, k) => ({ hostname: h, sshAuthorizedKey: k, identity: { RUN_ID: "run-ssh-1", HOST_ID: h } }));
  const ssh = res.state.instances["web-01"].ssh;
  assert.ok(ssh && ssh.host === "127.0.0.1" && ssh.user === "arena" && ssh.port >= 22000, `registry ssh endpoint: ${JSON.stringify(ssh)}`);
  assert.ok(ssh.privateKeyPath.endsWith("id_ed25519"));
  await destroyRunVms(lifecycle);
});

test("baked image: manifest pins verify, tampered artifacts are refused, missing artifacts fall back", async () => {
  const { parseBakedManifest, ensureBakedImage, ensureRockyFreeipaImage, BAKED_IMAGE_NAME, ROCKY_BAKED_IMAGE_NAME } = await import("../dist/provisioner/images.js");
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { createHash } = await import("node:crypto");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(`${tmpdir()}/baked-`);
  const file = "debian-12-catalog-aarch64.qcow2";
  writeFileSync(`${dir}/${file}`, "baked-bytes");
  const sha512 = createHash("sha512").update("baked-bytes").digest("hex");
  const manifestPath = `${dir}/baked-images.json`;
  writeFileSync(manifestPath, JSON.stringify({
    version: 1, catalogVersion: "arena-golden-debian12-catalog-3",
    images: { aarch64: { file, sha512, packages: ["jq"], builtAt: "2026-10-28T00:00:00Z", baseDigest: "sha512:test" } },
  }));
  const res = await ensureBakedImage("aarch64", { manifestPath, cacheDir: dir });
  assert.equal(res.image.name, BAKED_IMAGE_NAME);
  assert.equal(res.path, `${dir}/${file}`);
  assert.match(res.image.digest, /arena-golden-debian12-catalog-3/);
  assert.equal(await ensureBakedImage("x86_64", { manifestPath, cacheDir: dir }), null, "no entry for this arch");
  writeFileSync(`${dir}/${file}`, "tampered");
  await assert.rejects(ensureBakedImage("aarch64", { manifestPath, cacheDir: dir }), /failed SHA512 verification/);
  const emptyDir = mkdtempSync(`${tmpdir()}/baked-empty-`);
  assert.equal(await ensureBakedImage("aarch64", { manifestPath, cacheDir: emptyDir }), null, "pinned but not staged falls back");
  assert.throws(() => parseBakedManifest(JSON.stringify({ version: 2, catalogVersion: "x", images: {} })), /version/);
  assert.throws(() => parseBakedManifest(JSON.stringify({ version: 1, catalogVersion: "x", images: { aarch64: { file, sha512: "abc", packages: [], builtAt: "t", baseDigest: "d" } } })), /SHA512/);

  // Rocky FreeIPA tier: no cloud fallback. A manifest whose Rocky entry
  // cannot name the FreeIPA server packages is refused, never booted.
  writeFileSync(`${dir}/${file}`, "baked-bytes");
  const sha2 = createHash("sha512").update("baked-bytes").digest("hex");
  writeFileSync(manifestPath, JSON.stringify({
    version: 1, catalogVersion: "arena-golden-rocky9-freeipa-1",
    images: { aarch64: { file: "rocky-9-freeipa-aarch64.qcow2", sha512: sha2, packages: ["ipa-server", "ipa-server-dns", "ipa-client", "krb5-workstation", "sssd", "sssd-tools", "nftables", "osquery"], builtAt: "2026-10-30T00:00:00Z", baseDigest: "sha256:test" } },
  }));
  await runTestRocky(dir, file, sha2, manifestPath, ensureRockyFreeipaImage, ROCKY_BAKED_IMAGE_NAME);

  async function runTestRocky() {
    writeFileSync(`${dir}/rocky-9-freeipa-aarch64.qcow2`, "baked-bytes");
    const rocky = await ensureRockyFreeipaImage("aarch64", { manifestPath, cacheDir: dir });
    assert.equal(rocky.image.name, ROCKY_BAKED_IMAGE_NAME, "rocky tier resolves to the rocky baked name");
    assert.equal(rocky.path, `${dir}/rocky-9-freeipa-aarch64.qcow2`);
    assert.equal(await ensureBakedImage("aarch64", { manifestPath, cacheDir: dir }), null, "debian request must not resolve a rocky artifact");
    writeFileSync(manifestPath, JSON.stringify({
      version: 1, catalogVersion: "arena-golden-rocky9-freeipa-1",
      images: { aarch64: { file: "rocky-9-freeipa-aarch64.qcow2", sha512: sha2, packages: ["ipa-client"], builtAt: "2026-10-30T00:00:00Z", baseDigest: "sha256:test" } },
    }));
    await assert.rejects(ensureRockyFreeipaImage("aarch64", { manifestPath, cacheDir: dir }), /missing FreeIPA packages/);
  }
});

test("checked-in Debian baked manifest pins both native architectures", async () => {
  const { parseBakedManifest, bakedManifestPath, BAKED_CATALOG_VERSION, GOLDEN_IMAGES } = await import("../dist/provisioner/images.js");
  const { allProvisionablePackages } = await import("../dist/configurator/profiles.js");
  const { readFileSync } = await import("node:fs");
  const manifest = parseBakedManifest(readFileSync(bakedManifestPath(), "utf8"));
  assert.equal(manifest.catalogVersion, BAKED_CATALOG_VERSION);
  for (const arch of ["aarch64", "x86_64"]) {
    const entry = manifest.images[arch];
    assert.ok(entry, `${arch} baked artifact is pinned`);
    assert.equal(entry.file, `debian-12-catalog-${arch}.qcow2`);
    assert.match(entry.sha512, /^[0-9a-f]{128}$/);
    assert.equal(entry.baseDigest, GOLDEN_IMAGES[arch].digest);
    assert.deepEqual(entry.packages, allProvisionablePackages(), `${arch} artifact carries the current offline package union`);
  }
});

test("guest image pins name the image each guest actually booted", async () => {
  const { guestImagePins } = await import("../dist/provisioner/vm-lifecycle.js");
  const state = {
    runId: "run-pins", specName: "x", netMode: "lab",
    instances: {
      "web-01": { hostId: "web-01", goldenDigest: "sha512:ffb8…/arena-golden-debian12-catalog-3", imageName: "debian-12-catalog" },
      "db-01": { hostId: "db-01", goldenDigest: "sha512:ba60…/arena-golden-debian12-1", imageName: "debian-12-generic" },
      "old-01": { hostId: "old-01", goldenDigest: "sha512:legacy" },
    },
  };
  assert.deepEqual(guestImagePins(state), {
    "web-01": { name: "debian-12-catalog", digest: "sha512:ffb8…/arena-golden-debian12-catalog-3" },
    "db-01": { name: "debian-12-generic", digest: "sha512:ba60…/arena-golden-debian12-1" },
  }, "complete pins only: a registry row without an image name names nothing");
  assert.deepEqual(guestImagePins({ ...state, instances: {} }), {});
});

test("rocky baked tier: the default manifest path is the Rocky manifest, separate from Debian", async () => {
  const { ensureRockyFreeipaImage, ROCKY_BAKED_CATALOG_VERSION, ROCKY_FREEIPA_PACKAGES, rockyBakedManifestPath } = await import("../dist/provisioner/images.js");
  const { mkdtempSync, writeFileSync } = await import("node:fs");
  const { createHash } = await import("node:crypto");
  const { tmpdir } = await import("node:os");
  const dir = mkdtempSync(`${tmpdir()}/rocky-baked-`);
  const file = "rocky-9-freeipa-aarch64.qcow2";
  writeFileSync(`${dir}/${file}`, "rocky-baked-bytes");
  const sha512 = createHash("sha512").update("rocky-baked-bytes").digest("hex");
  const manifestPath = `${dir}/baked-rocky-images.json`;
  writeFileSync(manifestPath, JSON.stringify({
    version: 1, catalogVersion: ROCKY_BAKED_CATALOG_VERSION,
    images: { aarch64: { file, sha512, packages: [...ROCKY_FREEIPA_PACKAGES], builtAt: "2026-11-02T00:00:00Z", baseDigest: "sha256:test" } },
  }));
  const prevManifest = process.env.ARENA_ROCKY_GOLDEN_MANIFEST;
  const prevCache = process.env.KVM_IMAGE_CACHE;
  process.env.ARENA_ROCKY_GOLDEN_MANIFEST = manifestPath;
  process.env.KVM_IMAGE_CACHE = dir;
  try {
    assert.equal(rockyBakedManifestPath(), manifestPath);
    const res = await ensureRockyFreeipaImage("aarch64");
    assert.equal(res?.image.name, "rocky-9-freeipa");
    assert.equal(res?.path, `${dir}/${file}`);
  } finally {
    if (prevManifest === undefined) delete process.env.ARENA_ROCKY_GOLDEN_MANIFEST; else process.env.ARENA_ROCKY_GOLDEN_MANIFEST = prevManifest;
    if (prevCache === undefined) delete process.env.KVM_IMAGE_CACHE; else process.env.KVM_IMAGE_CACHE = prevCache;
  }
});

test("state roots anchor to the backend package, not the caller's cwd", async () => {
  // Found live: the worker runs from backend/, RUNBOOK scripts from the repo
  // root; a cwd-relative Pulumi state root split state across both and a
  // root-run teardown destroyed an empty stack, leaking the real containers.
  const { vmStateRoot } = await import("../dist/provisioner/deploy.js");
  const { imageCacheDir } = await import("../dist/provisioner/images.js");
  const { tmpdir } = await import("node:os");
  const prev = { cwd: process.cwd(), PULUMI_STATE_DIR: process.env.PULUMI_STATE_DIR, VM_STATE_DIR: process.env.VM_STATE_DIR, KVM_IMAGE_CACHE: process.env.KVM_IMAGE_CACHE };
  delete process.env.PULUMI_STATE_DIR; delete process.env.VM_STATE_DIR; delete process.env.KVM_IMAGE_CACHE;
  process.chdir(tmpdir());
  try {
    assert.ok(vmStateRoot().endsWith("backend/.pulumi-state/vm-state"), `vmStateRoot under the package from any cwd (got ${vmStateRoot()})`);
    assert.ok(imageCacheDir().endsWith("backend/.kvm-images"), `imageCacheDir under the package from any cwd (got ${imageCacheDir()})`);
  } finally {
    process.chdir(prev.cwd);
    for (const k of ["PULUMI_STATE_DIR", "VM_STATE_DIR", "KVM_IMAGE_CACHE"]) {
      if (prev[k] === undefined) delete process.env[k]; else process.env[k] = prev[k];
    }
  }
});

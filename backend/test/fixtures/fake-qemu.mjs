#!/usr/bin/env node
// Fake `qemu-system-*` for VM lifecycle tests: honours -pidfile (writes its own
// daemon child's pid), -serial (writes a ready line), -daemonize (exits parent).
// The daemon is killed by lifecycle stop/destroy via the recorded pid.
import { writeFileSync } from "node:fs";
import { spawn } from "node:child_process";

const args = process.argv.slice(2);
const take = (flag) => { const i = args.indexOf(flag); return i >= 0 ? args[i + 1] : undefined; };
const pidfile = take("-pidfile");
const serial = (take("-serial") ?? "").replace(/^file:/, "");

if (process.env.FAKE_QEMU_DAEMON !== "1") {
  const child = spawn(process.execPath, [new URL(import.meta.url).pathname, ...args], {
    detached: true,
    stdio: "ignore",
    env: { ...process.env, FAKE_QEMU_DAEMON: "1" },
  });
  child.unref();
  // Parent exits (like -daemonize); pidfile points at the daemon.
  if (pidfile) writeFileSync(pidfile, String(child.pid));
  process.exit(0);
}
// Daemon body: announce readiness on the serial log, then sleep until killed.
if (serial) writeFileSync(serial, "MUSEARENA-GUEST-READY fake-qemu\n");
process.on("SIGTERM", () => process.exit(0));
setInterval(() => {}, 1 << 30);

#!/usr/bin/env node
// Fake `qemu-img` for VM lifecycle tests.
//   create -f qcow2 -b <backing> -F qcow2 <overlay> [size]
// Writes a marker file recording the backing chain and checks the backing exists.
//   info --output=json <file>  ->  {"format":"qcow2","backing-filename": ...}
import { writeFileSync, readFileSync, existsSync } from "node:fs";

const args = process.argv.slice(2);
if (args[0] === "--version") { process.stdout.write("qemu-img version 0.0-fake\n"); process.exit(0); }
if (args[0] === "create") {
  const backing = args[args.indexOf("-b") + 1];
  const overlay = args.at(-1).endsWith("G") || /^\d+G$/.test(args.at(-1)) ? args.at(-2) : args.at(-1);
  if (!existsSync(backing)) { process.stderr.write(`backing ${backing} missing\n`); process.exit(1); }
  writeFileSync(overlay, JSON.stringify({ fakeQcow2: true, backing }));
  process.exit(0);
}
if (args[0] === "info") {
  const file = args.at(-1);
  try {
    const body = JSON.parse(readFileSync(file, "utf8"));
    process.stdout.write(JSON.stringify({ format: "qcow2", "backing-filename": body.backing ?? null, filename: file }));
    process.exit(0);
  } catch { process.stderr.write("not a fake qcow2\n"); process.exit(1); }
}
process.stderr.write(`fake-qemu-img: unsupported ${args.join(" ")}\n`);
process.exit(1);

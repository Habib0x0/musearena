#!/usr/bin/env node
// Fake genisoimage for VM lifecycle tests:
//   -output <iso> -volid cidata -joliet -rock <seedDir>
// Concatenates the seed files into a readable marker "ISO" so tests can
// assert hostname/key content landed in the seed.
import { copyFileSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const out = args[args.indexOf("-output") + 1];
const dir = args.at(-1);
const names = readdirSync(dir).sort();
const parts = names.map((n) => `=== ${n} ===\n${readFileSync(path.join(dir, n), "utf8")}`);
writeFileSync(out, `FAKE-SEED-ISO cidata\n${parts.join("\n")}`);
process.exit(0);
void copyFileSync;

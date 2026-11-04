/**
 * Build the pinned ATT&CK technique index from the official MITRE STIX bundle
 * (Req §7.1, design: Navigator layer "from the pinned ATT&CK STIX bundle").
 * Writes attack/enterprise-attack-<ver>.index.json: technique id → name +
 * tactics (kill-chain phases), revoked/deprecated excluded, stamped with the
 * bundle's sha256 so the index is traceable to an exact upstream file.
 *
 *   node scripts/build-attack-index.mjs 15.1 [path-to-bundle.json]
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";

const ver = process.argv[2] ?? "15.1";
const url = `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-${ver}.json`;
const raw = process.argv[3] ? readFileSync(process.argv[3]) : Buffer.from(await (await fetch(url)).arrayBuffer());
const sha256 = createHash("sha256").update(raw).digest("hex");
const bundle = JSON.parse(raw.toString("utf8"));
const techniques = {};
for (const o of bundle.objects) {
  if (o.type !== "attack-pattern" || o.revoked || o.x_mitre_deprecated) continue;
  const ext = (o.external_references ?? []).find((r) => r.source_name === "mitre-attack");
  if (!ext?.external_id) continue;
  techniques[ext.external_id] = { name: o.name, tactics: (o.kill_chain_phases ?? []).filter((p) => p.kill_chain_name === "mitre-attack").map((p) => p.phase_name) };
}
const sorted = Object.fromEntries(Object.entries(techniques).sort(([a], [b]) => a.localeCompare(b)));
const out = new URL(`../attack/enterprise-attack-${ver}.index.json`, import.meta.url);
writeFileSync(out, JSON.stringify({ attackVersion: ver, source: url, bundleSha256: sha256, techniques: sorted }) + "\n");
console.log(`wrote ${Object.keys(sorted).length} techniques, bundle sha256 ${sha256}`);

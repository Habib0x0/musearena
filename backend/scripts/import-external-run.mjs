import { readFile } from "node:fs/promises";
import { ExternalRunExport, toCaptureTraces } from "../dist/learning/external-runs.js";

/**
 * Import an exported agent-run log through the capture endpoint.
 *
 *   MUSEARENA_CAPTURE_KEY=muse_ck_... \
 *   node scripts/import-external-run.mjs --file run.json
 *
 * Optional: --url http://127.0.0.1:8788 --source imported|field
 * The file is a source-neutral JSON export:
 *
 *   {
 *     "runId": "run-...",
 *     "framework": "caller-named source system",
 *     "source": "imported",
 *     "steps": [
 *       { "at": "2026-01-01T00:00:00.000Z", "host": "web-01", "actor": "red",
 *         "technique": "T1190", "tool": "curl",
 *         "command": ["curl", "-s", "http://web-01/login"],
 *         "output": "...", "outcome": "succeeded" }
 *     ]
 *   }
 *
 * An importer that owns a different format maps it to this shape; the platform
 * never parses a vendor format directly.
 */
const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 ? argv[i + 1] : undefined;
};
const file = flag("file");
if (!file) {
  console.error("usage: node scripts/import-external-run.mjs --file <export.json> [--url ...] [--key ...] [--source imported|field]");
  process.exit(2);
}
const base = (flag("url") ?? process.env.MUSEARENA_API_URL ?? "http://127.0.0.1:8788").replace(/\/$/, "");
const key = flag("key") ?? process.env.MUSEARENA_CAPTURE_KEY;
if (!key) {
  console.error("a capture key is required: --key or MUSEARENA_CAPTURE_KEY");
  process.exit(2);
}

const raw = JSON.parse(await readFile(file, "utf8"));
if (flag("source")) raw.source = flag("source");
const parsed = ExternalRunExport.safeParse(raw);
if (!parsed.success) {
  console.error("invalid export:", parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; "));
  process.exit(1);
}

const steps = toCaptureTraces(parsed.data);
let accepted = 0;
for (const step of steps) {
  const res = await fetch(`${base}/capture/v1/traces`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify(step),
  });
  if (res.status !== 202) {
    console.error(`step ${step.stepIndex} rejected: HTTP ${res.status} ${await res.text()}`);
    process.exit(1);
  }
  accepted++;
}

console.log(JSON.stringify({ ok: true, runId: parsed.data.runId, source: parsed.data.source, steps: accepted }, null, 2));

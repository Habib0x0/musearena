/**
 * Offline replay of a recorded org-lab demo (T-20).
 *
 *   node scripts/org-demo-replay.mjs [captures/org-demo/<runId>]
 *
 * No VMs, no network, no model. Re-verifies the recorded dataset's own hash
 * and re-scores the recorded trace against the recorded spec, then checks the
 * result matches the score the live run wrote. Exits non-zero on any drift.
 */
import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { verifyExportHash } from "../dist/traces/integrity.js";
import { scoreExercise } from "../dist/exercise/evaluator.js";

const root = path.join(process.cwd(), "captures", "org-demo");
const arg = process.argv[2];
const dir = arg
  ? path.resolve(arg)
  : path.join(root, (await readdir(root).catch(() => [])).sort().at(-1) ?? "");
if (!dir || !(await readFile(path.join(dir, "run.json"), "utf8").catch(() => null))) {
  console.error(`no recorded run at ${dir || root}; run scripts/org-demo.mjs first`);
  process.exit(1);
}

const art = JSON.parse(await readFile(path.join(dir, "run.json"), "utf8"));
if (art.error) { console.error(`recorded run failed: ${art.error}`); process.exit(1); }
const exp = JSON.parse(await readFile(path.join(dir, "dataset.json"), "utf8"));

assert.equal(exp.meta.runId, art.runId, "dataset belongs to this run");
assert.equal(exp.meta.contentHash, art.dataset.contentHash, "dataset hash matches the recorded run");
assert.equal(exp.run.specDigest, art.design.pinnedDigest, "dataset pins the design versions");
assert.equal(verifyExportHash(exp), true, "dataset content hash verifies");

const replayed = scoreExercise(art.spec, exp.join);
assert.equal(replayed.objectivesAchieved, art.score.objectivesAchieved, "objectives re-score identically");
assert.equal(replayed.pointsEarned, art.score.pointsEarned, "points re-score identically");
assert.equal(replayed.objectivesTotal, art.spec.objectives.length);

console.log(`replay ${art.runId}`);
console.log(`  design    ${art.design.mode} · ${art.spec.instances.length} hosts · ${art.host.arch}/${art.host.accel}`);
console.log(`  score     ${replayed.objectivesAchieved}/${replayed.objectivesTotal} objectives · ${replayed.pointsEarned}/${replayed.pointsTotal} points`);
console.log(`  alerts    ${art.exercise.alerts} · ${art.exercise.falsePositives} false positives over ${art.exercise.benignEvents} benign events`);
console.log(`  dataset   ${exp.meta.contentHash} (${exp.join.steps.length} steps) verified`);
console.log(`  page      ${path.relative(process.cwd(), path.join(dir, "index.html"))}`);
console.log("ORG DEMO REPLAY OK");

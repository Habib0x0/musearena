import test from "node:test";
import assert from "node:assert/strict";
import { ModelDefinition, ruleMatches, RuleDefinition } from "../dist/learning/signals.js";

const AT = "2026-01-01T00:00:00.000Z";
const trace = {
  org_id: "org-1", run_id: "run-1", dataset_id: null, step_index: 0, at: AT,
  host_id: "db-01", technique_id: "T1003.001", actor: "red",
  action: "pg_dump", observation: "dump the table", reasoning: null,
  tool_call: "exec", outcome: "succeeded", matched: true, split: "train", payload: {},
};

const rule = (match, conditions) => RuleDefinition.parse({ match, conditions });
const cond = (field, op, value) => ({ field, op, ...(value === undefined ? {} : { value }) });

test("rule signals: all/any over closed fields, no expression language", () => {
  assert.equal(ruleMatches(rule("all", [cond("actor", "eq", "red"), cond("outcome", "eq", "succeeded")]), trace), true);
  assert.equal(ruleMatches(rule("all", [cond("actor", "eq", "red"), cond("outcome", "eq", "failed")]), trace), false);
  assert.equal(ruleMatches(rule("any", [cond("actor", "eq", "blue"), cond("outcome", "eq", "succeeded")]), trace), true);
  assert.equal(ruleMatches(rule("all", [cond("techniqueId", "prefix", "T1003")]), trace), true);
  assert.equal(ruleMatches(rule("all", [cond("techniqueId", "prefix", "T1190")]), trace), false);
  assert.equal(ruleMatches(rule("all", [cond("actor", "in", ["blue", "red"])]), trace), true);
  assert.equal(ruleMatches(rule("all", [cond("actor", "ne", "blue")]), trace), true);
  assert.equal(ruleMatches(rule("all", [cond("matched", "eq", true)]), trace), true);
});

test("rule signals: exists distinguishes a present field from an empty one", () => {
  assert.equal(ruleMatches(rule("all", [cond("techniqueId", "exists", true)]), trace), true);
  const withoutTechnique = { ...trace, technique_id: null };
  assert.equal(ruleMatches(rule("all", [cond("techniqueId", "exists", true)]), withoutTechnique), false);
  assert.equal(ruleMatches(rule("all", [cond("techniqueId", "exists", false)]), withoutTechnique), true);
});

test("rule signals: an unknown field or op is rejected at definition time", () => {
  assert.throws(() => RuleDefinition.parse({ match: "all", conditions: [cond("payload", "eq", "x")] }), /invalid/i);
  assert.throws(() => RuleDefinition.parse({ match: "all", conditions: [cond("actor", "regex", "red")] }), /invalid/i);
  assert.throws(() => RuleDefinition.parse({ match: "all", conditions: [] }), /at least 1|too_small/i);
  assert.throws(() => RuleDefinition.parse({ match: "all", conditions: [cond("actor", "eq", "red")], extra: true }), /unrecognized key/i);
});

test("model signals: the judge and question are pinned at definition time", () => {
  assert.doesNotThrow(() => ModelDefinition.parse({ model: "muse-spark-1.3", question: "did the agent read the secrets table?" }));
  assert.throws(() => ModelDefinition.parse({ question: "no judge" }), /model/i);
  assert.throws(() => ModelDefinition.parse({ model: "muse-spark-1.3", question: "x", temperature: 0 }), /unrecognized key/i);
  assert.throws(() => ModelDefinition.parse({ model: "", question: "x" }), /too_small|at least/i);
});

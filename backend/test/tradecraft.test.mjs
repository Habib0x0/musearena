import test from "node:test";
import assert from "node:assert/strict";
import { classifyAction, programOf, realismShare } from "../dist/exercise/tradecraft.js";

test("tradecraft: real tools classify by phase", () => {
  assert.equal(classifyAction("nmap", "nmap -sV web-01").phase, "recon");
  assert.equal(classifyAction("ffuf", "ffuf -u http://web-01/FUZZ").phase, "enumeration");
  assert.equal(classifyAction("ssh", "ssh app@db-01").phase, "access");
  assert.equal(classifyAction("psql", "psql -h db-01 -U app").phase, "collection");
  assert.equal(classifyAction("chisel", "chisel client ...").phase, "execution");
  assert.equal(classifyAction("tar", "tar -czf /tmp/x.tgz /data").phase, "exfiltration");
});

test("tradecraft: shell wrappers unwrap to the real program", () => {
  assert.equal(programOf("sh", 'sh -c "curl -s http://web-01/login"'), "curl");
  assert.equal(programOf("/usr/bin/nmap", null), "nmap");
  assert.equal(programOf(null, "python3 -c 'print(1)'"), "python3");
  assert.equal(classifyAction("sh", 'sh -c "ffuf -u http://web-01/FUZZ"').known, true);
});

test("tradecraft: unknown or platform actions are not counted as real tooling", () => {
  assert.equal(classifyAction("custom-tool", "custom-tool --x").known, false);
  assert.equal(classifyAction("respond", null).known, false);
  assert.equal(classifyAction("fetch_telemetry", null).known, false);
});

test("tradecraft: realism share is computed over the action set", () => {
  const rows = [
    { action: "nmap", tool_call: "nmap -sV web-01" },
    { action: "curl", tool_call: "curl http://web-01/" },
    { action: "custom-tool", tool_call: "custom-tool" },
    { action: "respond", tool_call: null },
  ];
  const report = realismShare(rows);
  assert.equal(report.actions, 4);
  assert.equal(report.knownToolActions, 2);
  assert.equal(report.share, 0.5);
  assert.deepEqual(realismShare([]), { actions: 0, knownToolActions: 0, share: 0 });
});

#!/usr/bin/env node
// Fake `docker` for live-exercise unit tests. Behaviour from FAKE_DOCKER_STATE (json file):
// attacker exec returns canary/marker; logs return scripted lines with timestamps.
import { readFileSync, writeFileSync } from "node:fs";
const st = JSON.parse(readFileSync(process.env.FAKE_DOCKER_STATE, "utf8"));
const args = process.argv.slice(2);
const save = () => writeFileSync(process.env.FAKE_DOCKER_STATE, JSON.stringify(st));
const now = () => new Date(st.clock += 10).toISOString();
if (args[0] === "inspect") { process.stdout.write(args.at(-1).endsWith("-attacker") ? "10.9.0.9" : "10.9.0.2"); process.exit(0); }
if (args[0] === "network") { st.disconnected = true; save(); process.exit(0); }
if (args[0] === "logs") {
  const name = args.at(-1);
  process.stdout.write((st.logs[name] ?? []).map((l) => `${l.at} ${l.text}`).join("\n") + "\n");
  process.exit(0);
}
if (args[0] === "exec") {
  const rest = args.slice(1).filter((a, i, arr) => a !== "-e" && arr[i - 1] !== "-e");
  const [container, ...cmd] = rest;
  const line = cmd.join(" ");
  const log = (name, text) => { (st.logs[name] ??= []).push({ at: now(), text }); };
  const planted = /UPDATE secrets SET value='([^']+)'/.exec(line);
  if (planted && !container.endsWith("-attacker")) {
    st.canary = planted[1];
  } else if (container.endsWith("-attacker") && line.includes("secrets")) {
    log(st.db, `x user=app db=app client=10.9.0.9 LOG:  connection authorized: user=app database=app`);
    log(st.db, `x user=app db=app client=10.9.0.9 LOG:  statement: SELECT value FROM secrets WHERE objective_id='o1'`);
    process.stdout.write(st.canary + "\n");
  } else if (container.endsWith("-attacker") && line.includes("diag.php")) {
    const marker = decodeURIComponent(/host=([^ ]+)/.exec(line)[1]).split("echo ")[1];
    log(st.web, `10.9.0.9 - - [x] "GET /diag.php?host=x%3Becho%20${marker} HTTP/1.1" 200 10 "-" "Wget"`);
    process.stdout.write(`<pre>${marker}\n</pre>`);
  } else if (line.includes("arena-canary") || (line.includes("SELECT 'canary-"))) {
    // Canary: logged only while the sensor is on.
    if (!st.sensorOff) {
      const m = /(canary-[A-Za-z0-9-]+)/.exec(line)[1];
      if (container === st.web) log(st.web, `127.0.0.1 - - [x] "GET /arena-canary/${m} HTTP/1.1" 404 10 "-" "curl/8"`);
      else log(st.db, `x user=app db=app client=127.0.0.1 LOG:  statement: SELECT '${m}'`);
    }
  } else if (line.includes("curl")) {
    log(st.web, `127.0.0.1 - - [x] "GET / HTTP/1.1" 200 10 "-" "curl/8"`);
  } else if (line.includes("employees")) {
    log(st.db, `x user=app db=app client=[local] LOG:  statement: SELECT count(*) FROM employees`);
  }
  save();
  process.exit(0);
}
process.exit(1);

/**
 * Live platform checks (not a unit test): tenant isolation (Req §6.1),
 * audit chain integrity + append-only (§6.2), unauthenticated rejection, and
 * Realtime delivery of deployment changes (§6.5). Uses the Supabase
 * Management API to run SQL as the `authenticated` role with forged org
 * claims inside a transaction that is always rolled back.
 */
import { readFileSync } from "node:fs";
import { createClient } from "@supabase/supabase-js";

const root = new URL("../../", import.meta.url).pathname;
const env = Object.fromEntries(readFileSync(root + ".env", "utf8").split("\n").filter((l) => l.includes("="))
  .map((l) => { const i = l.indexOf("="); return [l.slice(0, i).trim(), l.slice(i + 1).trim()]; }));
const ref = new URL(env.SUPABASE_URL).hostname.split(".")[0];
const sql = async (query) => {
  const r = await fetch(`https://api.supabase.com/v1/projects/${ref}/database/query`, {
    method: "POST", headers: { Authorization: `Bearer ${env.SUPABASE_ACCESS_TOKEN}`, "Content-Type": "application/json" }, body: JSON.stringify({ query }),
  });
  const body = await r.json();
  return { ok: r.ok, body };
};
const results = [];
const check = (name, pass, detail) => { results.push({ name, pass, detail }); console.log(`${pass ? "PASS" : "FAIL"} ${name}${detail ? ` — ${detail}` : ""}`); };
const asOrg = (org) => `set local role authenticated; set local request.jwt.claims = '{"sub":"u-${org}","o":{"id":"${org}"}}';`;

// 1. tenant isolation (rolled back: begin without commit)
const iso = await sql(`begin;
insert into environments (org_id, created_by, spec, spec_digest, status) values ('chk-a','u','{}','d','draft'),('chk-b','u','{}','d','draft');
${asOrg("chk-a")}
select (select count(*) from environments where org_id='chk-a') own, (select count(*) from environments where org_id='chk-b') other,
       (select count(*) from runs) runs_visible, (select count(*) from audit_log) audit_visible;`);
const row = iso.body?.[0] ?? {};
check("cross-org read isolation", Number(row.own) === 1 && Number(row.other) === 0 && Number(row.runs_visible) === 0 && Number(row.audit_visible) === 0, JSON.stringify(row));
const cross = await sql(`begin; ${asOrg("chk-a")} insert into environments (org_id, created_by, spec, spec_digest, status) values ('chk-b','u','{}','d','draft');`);
check("cross-org write refused", !cross.ok && /row-level security/.test(JSON.stringify(cross.body)));

// 2. unauthenticated
const anon = createClient(env.SUPABASE_URL, env.SUPABASE_PUBLISHABLE_KEY, { auth: { persistSession: false } });
const { data: anonRows } = await anon.from("deployments").select("id").limit(5);
const { error: anonWrite } = await anon.from("environments").insert({ org_id: "x", created_by: "x", spec: {}, spec_digest: "x", status: "draft" });
const noKey = await fetch(`${env.SUPABASE_URL}/rest/v1/runs?select=*`);
check("unauthenticated read sees nothing", (anonRows ?? []).length === 0);
check("unauthenticated write refused", !!anonWrite);
check("request without key rejected", noKey.status === 401, `HTTP ${noKey.status}`);

// 3. audit chain
const orgs = await sql("select distinct org_id from audit_log");
for (const { org_id } of orgs.body) {
  const v = await sql(`select * from audit_verify('${org_id.replace(/'/g, "''")}')`);
  check(`audit chain verifies (${org_id})`, v.ok && v.body.length === 0, v.body.length ? JSON.stringify(v.body[0]) : undefined);
}
const tamper = await sql("update audit_log set actor = 'tamper' where id = (select min(id) from audit_log)");
check("audit_log refuses UPDATE", !tamper.ok && /append-only/.test(JSON.stringify(tamper.body)));
const del = await sql("delete from audit_log where id = (select min(id) from audit_log)");
check("audit_log refuses DELETE", !del.ok && /append-only/.test(JSON.stringify(del.body)));

// 4. realtime
const svc = createClient(env.SUPABASE_URL, env.SUPABASE_SECRET_KEY, { auth: { persistSession: false } });
const { data: envRow } = await svc.from("environments").insert({ org_id: "chk-rt", created_by: "chk", spec: {}, spec_digest: "d", status: "draft" }).select("id").single();
const got = await new Promise(async (resolve) => {
  const timer = setTimeout(() => resolve(null), 20_000);
  const ch = svc.channel("chk-rt").on("postgres_changes", { event: "INSERT", schema: "public", table: "deployments", filter: "org_id=eq.chk-rt" }, (p) => { clearTimeout(timer); resolve(p); });
  ch.subscribe(async (status) => {
    // SUBSCRIBED precedes postgres_changes registration server-side; settle first.
    if (status === "SUBSCRIBED") await new Promise((r) => setTimeout(r, 3_000)), await svc.from("deployments").insert({ org_id: "chk-rt", environment_id: envRow.id, stack_id: "none", status: "destroyed", access_info: {} });
  });
});
await svc.from("deployments").delete().eq("org_id", "chk-rt");
await svc.from("environments").delete().eq("org_id", "chk-rt");
check("realtime delivers deployment insert", !!got, got ? `event ${got.eventType} status=${got.new?.status}` : "no event in 20s");
await svc.removeAllChannels();

const failed = results.filter((r) => !r.pass);
console.log(failed.length ? `PLATFORM CHECK FAILED (${failed.length})` : `PLATFORM CHECK OK (${results.length} checks)`);
process.exit(failed.length ? 1 : 0);

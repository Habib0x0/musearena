import { test } from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";

const dir = new URL("../supabase/migrations", import.meta.url);

test("supabase migrations have unique numeric versions and a unique template-version migration", async () => {
  const files = (await readdir(dir)).filter((file) => file.endsWith(".sql")).sort();
  const versions = files.map((file) => file.split("_", 1)[0]);
  assert.deepEqual([...new Set(versions)], versions, "Supabase CLI versions must be unambiguous");
  const template = files.find((file) => file.endsWith("_template_version_unique.sql"));
  assert.equal(template, "0017_template_version_unique.sql", "the template migration has its own applied version");
  const sql = await readFile(new URL(template, `${dir}/`), "utf8");
  assert.match(sql, /templates_org_name_version_key/);
});

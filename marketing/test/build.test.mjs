import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.dirname(fileURLToPath(import.meta.url)) + "/..";

test("marketing build emits dist/index.html describing the loop and linking the Designer (F-3)", () => {
  const dist = path.join(root, "dist/index.html");
  assert.ok(existsSync(dist), "dist/index.html missing — run npm run build first");
  const html = readFileSync(dist, "utf8");
  assert.match(html, /href="\/designer"/, "Designer link missing");
  assert.match(html, /Open the Designer/);
  for (const word of ["Design", "Deploy", "Exercise"]) {
    assert.ok(html.includes(word), `missing product section: ${word}`);
  }
});

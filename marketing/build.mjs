import { cpSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const root = new URL(".", import.meta.url).pathname;
const out = join(root, "dist");
const pages = [
  { file: "index.html", path: "/index.html" },
  { file: "product.html", path: "/product.html" },
  { file: "pricing.html", path: "/pricing.html" },
  { file: "docs.html", path: "/docs.html" },
];

mkdirSync(out, { recursive: true });

for (const page of pages) {
  const html = readFileSync(join(root, page.file), "utf8");
  if (!html.includes("APP_ORIGIN")) throw new Error(`${page.file}: APP_ORIGIN placeholder missing`);
  const origin = process.env.MARKETING_APP_ORIGIN ?? "";
  const clean = origin.replace(/\/+$/, "");
  const built = html.replaceAll("APP_ORIGIN", clean);
  writeFileSync(join(out, page.file), built);
}

for (const entry of readdirSync(root)) {
  if (["assets", "styles.css", "theme.js", "scroll.js", "robots.txt"].includes(entry)) {
    cpSync(join(root, entry), join(out, entry), { recursive: true });
  }
}


console.log(`marketing: built ${pages.length} pages into dist/ (app origin: ${process.env.MARKETING_APP_ORIGIN ?? "/console"})`);

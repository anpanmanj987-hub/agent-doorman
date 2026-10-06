// Fails when release placeholders are still present. Run by `npm run check:placeholders`
// and automatically before `npm publish` (prepublishOnly).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const TOKENS = ["__OWNER__", "__AUTHOR__", "__SECURITY_EMAIL__"];
const SKIP = new Set(["node_modules", "dist", ".git", "scripts"]);
const hits = [];

function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walk(p);
    else if (st.size < 1_000_000 && /\.(json|md|ts|mjs|js|yml|yaml|txt)$|^NOTICE$|^LICENSE$/.test(name)) {
      const text = readFileSync(p, "utf8");
      text.split("\n").forEach((line, i) => {
        for (const t of TOKENS) if (line.includes(t)) hits.push(`${p}:${i + 1}: ${t}`);
      });
    }
  }
}

walk(process.cwd());
if (hits.length) {
  console.error(`Replace these placeholders before publishing:\n${hits.map((h) => `  ${h}`).join("\n")}`);
  process.exit(1);
}
console.log("No placeholders left.");

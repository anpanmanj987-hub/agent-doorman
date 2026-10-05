// One-shot replacement of release placeholders:
//   node scripts/set-owner.mjs <github-owner> "<Author Name>" <security-contact-email>
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const [owner, author, email] = process.argv.slice(2);
if (!owner || !author || !email) {
  console.error('usage: node scripts/set-owner.mjs <github-owner> "<Author Name>" <security-contact-email>');
  process.exit(1);
}
const map = { __OWNER__: owner, __AUTHOR__: author, __SECURITY_EMAIL__: email };
const SKIP = new Set(["node_modules", "dist", ".git", "scripts"]);
// This checklist names the placeholders on purpose; never rewrite or flag it.
const SKIP_FILES = new Set(["PUBLISHING.ja.md"]);
let changed = 0;
(function walk(dir) {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name) || SKIP_FILES.has(name)) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p);
    else if (/\.(json|md|ts|mjs|js|yml|yaml)$|^NOTICE$/.test(name)) {
      const before = readFileSync(p, "utf8");
      let after = before;
      for (const [k, v] of Object.entries(map)) after = after.split(k).join(v);
      if (after !== before) {
        writeFileSync(p, after);
        changed++;
        console.log(`updated ${p}`);
      }
    }
  }
})(process.cwd());
console.log(`${changed} file(s) updated.`);

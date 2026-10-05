// npm run demo: start a naive shop and a doorman-guarded shop on localhost, audit both,
// and write example reports to docs/examples/. Nothing leaves your machine.
// The audits use friendly hostnames; a small fetch shim routes them to localhost and passes
// X-Forwarded-Host, which the guarded shop trusts (trustProxy) for signature @authority.
import { mkdirSync, writeFileSync } from "node:fs";
import { renderHtml, renderMarkdown, renderText } from "../src/audit/render.js";
import { runAudit } from "../src/audit/run.js";
import { generateKeyPair } from "../src/httpsig/jwk.js";
import { naiveSite, protectedSite } from "../test/fixtures/sites.js";
import { startServer } from "../test/helpers.js";

const kp = await generateKeyPair();
const naive = await startServer(naiveSite());
const guarded = await startServer(protectedSite(kp.publicJwk, { trustProxy: true }));
const routes: Record<string, string> = { "naive-shop.example": naive.url, "plaque-shop.example": guarded.url };

const shim: typeof fetch = (input, init) => {
  const url = new URL(input instanceof Request ? input.url : String(input));
  const local = routes[url.host];
  if (!local) return fetch(input, init);
  const headers = new Headers(init?.headers);
  headers.set("x-forwarded-host", url.host);
  headers.set("x-forwarded-proto", url.protocol.replace(":", ""));
  return fetch(local + url.pathname + url.search, { ...init, headers });
};

mkdirSync("docs/examples", { recursive: true });
try {
  for (const [name, url, paths, key] of [
    ["naive", "https://naive-shop.example/", ["/signup"], undefined],
    ["guarded", "https://plaque-shop.example/", ["/checkout"], kp.privateJwk],
  ] as const) {
    const report = await runAudit({ url, paths: [...paths], active: true, delayMs: 0, signKey: key, fetch: shim });
    process.stdout.write(renderText(report, { color: process.stdout.isTTY }));
    writeFileSync(`docs/examples/${name}-report.html`, renderHtml(report));
    writeFileSync(`docs/examples/${name}-report.md`, renderMarkdown(report));
    writeFileSync(`docs/examples/${name}-report.json`, `${JSON.stringify(report, null, 2)}\n`);
  }
  process.stdout.write("Example reports written to docs/examples/\n");
} finally {
  await naive.close();
  await guarded.close();
}

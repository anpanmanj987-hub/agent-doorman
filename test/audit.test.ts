import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { parseHtml } from "../src/audit/html.js";
import { renderHtml, renderMarkdown, renderText } from "../src/audit/render.js";
import { type AuditReport, runAudit } from "../src/audit/run.js";
import { generateKeyPair } from "../src/httpsig/jwk.js";
import { naiveSite, protectedSite } from "./fixtures/sites.js";
import { startServer } from "./helpers.js";

// Async on purpose: the demo servers live in this process and must keep serving while the CLI runs.
function cli(args: string[]): Promise<{ status: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      ["--import", "tsx", "src/cli/main.ts", ...args],
      { encoding: "utf8", env: { ...process.env, NO_COLOR: "1" } },
      (err, stdout, stderr) => resolve({ status: err ? Number((err as { code?: number }).code ?? 1) : 0, stdout, stderr }),
    );
  });
}

const status = (r: AuditReport, id: string) => r.categories.flatMap((c) => c.checks).find((c) => c.id === id)?.status;

describe("html analyzer", () => {
  it("finds labels, autocomplete, buttons and placeholders", () => {
    const p = parseHtml(`<html lang="ja"><body><form>
      <label for="e">Mail</label><input id="e" type="email" autocomplete="email">
      <input name="phone" placeholder="Phone">
      <label>Name <input name="family-name" autocomplete="family-name"></label>
      <button aria-label="Search"><svg></svg></button><button><img src="x" alt="Go"></button><button><span></span></button>
      <input type="hidden" name="csrf"></form></body></html>`);
    assert.equal(p.lang, "ja");
    const f = p.forms[0]!;
    assert.equal(f.fields.length, 3);
    assert.deepEqual(f.fields.map((x) => x.labelled), [true, false, true]);
    assert.equal(f.fields[1]!.placeholderOnly, true);
    assert.equal(f.fields[1]!.kind, "tel");
    assert.deepEqual(f.buttons.map((b) => b.named), [true, true, false]);
  });

  it("detects challenge widgets and JS-only shells", () => {
    const p = parseHtml('<html><body><div id="root"></div><noscript>Please enable JavaScript</noscript><div class="cf-turnstile"></div></body></html>');
    assert.ok(p.needsJavaScript);
    assert.ok(p.challengeMarkers.includes("Cloudflare Turnstile"));
    assert.ok(p.textLength < 80);
  });
});

describe("audit", () => {
  let naive: Awaited<ReturnType<typeof startServer>>;
  let guarded: Awaited<ReturnType<typeof startServer>>;
  let kp: Awaited<ReturnType<typeof generateKeyPair>>;
  before(async () => {
    kp = await generateKeyPair();
    naive = await startServer(naiveSite());
    guarded = await startServer(protectedSite(kp.publicJwk));
  });
  after(async () => {
    await naive.close();
    await guarded.close();
  });

  it("flags a site that trusts User-Agent claims", async () => {
    const r = await runAudit({ url: naive.url, paths: ["/signup"], active: true, delayMs: 0 });
    assert.equal(status(r, "ua-allowlist"), "fail");
    assert.equal(status(r, "forged-signature"), "warn");
    assert.equal(status(r, "sensitive-paths"), "warn");
    assert.equal(status(r, "readable-refusals"), "fail");
    assert.equal(status(r, "server-rendered"), "fail");
    assert.equal(status(r, "labels"), "fail");
    assert.equal(status(r, "autocomplete"), "fail");
    assert.equal(status(r, "buttons"), "fail");
    assert.equal(status(r, "captcha"), "warn");
    assert.equal(status(r, "robots"), "warn");
    assert.ok(r.score < 50, `score ${r.score}`);
    assert.equal(r.verdict, "not-ready");
    assert.equal(r.fixes[0]?.check, "ua-allowlist");
    const home = r.probes.filter((p) => p.path === "/");
    assert.ok(home.filter((p) => p.visitor === "claimed").every((p) => p.concern?.level === "fail"));
    assert.equal(home.find((p) => p.visitor === "browser")?.concern, undefined);
    assert.equal(home.find((p) => p.visitor === "script")?.concern?.level, "warn");
  });

  it("passes a site guarded by agent-doorman", async () => {
    const r = await runAudit({ url: guarded.url, paths: ["/checkout"], active: true, delayMs: 0, signKey: kp.privateJwk });
    for (const id of ["ua-allowlist", "forged-signature", "sensitive-paths", "readable-refusals", "verified-admitted", "server-rendered", "labels", "autocomplete", "buttons", "input-types", "structured-data", "robots", "sitemap", "llms-txt", "browser-reachable", "captcha"]) {
      assert.equal(status(r, id), "pass", `${id}: ${JSON.stringify(r.categories.flatMap((c) => c.checks).find((c) => c.id === id))}`);
    }
    assert.equal(status(r, "agent-policy"), "info");
    assert.ok(r.score >= 95, `score ${r.score}`);
    assert.ok(r.probes.every((p) => !p.concern), JSON.stringify(r.probes.filter((p) => p.concern)));
    const checkout = r.probes.filter((p) => p.path === "/checkout");
    assert.equal(checkout.find((p) => p.visitor === "claimed")?.verdict, "challenged");
    assert.equal(checkout.find((p) => p.visitor === "verified")?.verdict, "admitted");
    const text = renderText(r);
    assert.match(text, /Door test/);
    assert.match(renderMarkdown(r), /\| `\/checkout` \|/);
    const html = renderHtml(r);
    assert.match(html, /<title>Door report for 127\.0\.0\.1:\d+<\/title>/);
    assert.doesNotMatch(html, /<script/);
  });

  it("passive mode never impersonates agents", async () => {
    const seen: string[] = [];
    const srv = await (await import("./helpers.js")).startServer((req, res) => {
      seen.push(String(req.headers["user-agent"]));
      res.setHeader("content-type", "text/html");
      res.end("<html lang=en><head><title>x</title></head><body>hello</body></html>");
    });
    const r = await runAudit({ url: srv.url });
    await srv.close();
    assert.equal(r.mode, "passive");
    assert.equal(r.probes.length, 0);
    assert.ok(seen.every((ua) => !/GPTBot|ClaudeBot|Perplexity|meta-external|python-requests/.test(ua)));
    assert.equal(status(r, "door-test"), "skip");
  });

  it("CLI: audit writes reports and honours --fail-under", async () => {
    const dir = mkdtempSync(join(tmpdir(), "doorman-"));
    const ok = await cli(["audit", guarded.url, "--path", "/checkout", "--json", join(dir, "r.json"), "--html", join(dir, "r.html"), "--markdown", join(dir, "r.md"), "--fail-under", "60"]);
    assert.equal(ok.status, 0, ok.stderr);
    assert.equal((JSON.parse(readFileSync(join(dir, "r.json"), "utf8")) as AuditReport).mode, "passive");
    assert.match(readFileSync(join(dir, "r.md"), "utf8"), /agent-ready/);
    const bad = await cli(["audit", naive.url, "--active", "--delay", "0", "--fail-under", "90"]);
    assert.equal(bad.status, 2);
    assert.match(bad.stderr, /Only run this against sites you operate/);
    assert.match(bad.stdout, /Claims GPTBot, no proof/);
  });

  it("CLI: init, keygen, sign and report", async () => {
    const dir = mkdtempSync(join(tmpdir(), "doorman-"));
    const run = cli;
    assert.equal((await run(["init", "--out", join(dir, "p.json")])).status, 0);
    assert.equal(JSON.parse(readFileSync(join(dir, "p.json"), "utf8")).mode, "monitor");
    assert.equal((await run(["init", "--out", join(dir, "p.json")])).status, 1);
    const kg = await run(["keygen", "--out-dir", dir]);
    assert.equal(kg.status, 0, kg.stderr);
    const dirDoc = JSON.parse(readFileSync(join(dir, "http-message-signatures-directory.json"), "utf8"));
    assert.equal(dirDoc.keys[0].d, undefined, "public directory must not leak the private key");
    const sg = await run(["sign", "https://shop.example/x", "--key", join(dir, "agent-key.private.jwk.json"), "--signature-agent", "https://agent.example", "--curl"]);
    assert.equal(sg.status, 0, sg.stderr);
    assert.match(sg.stdout, /^curl -i /);
    assert.match(sg.stdout, /-H 'signature: sig1=:[A-Za-z0-9+/=]+:'/);
    assert.ok(sg.stdout.includes(`-H 'signature-agent: sig1="https://agent.example"'`));
    const log = join(dir, "d.jsonl");
    const decision = (cls: string, action: string, rule: string) =>
      JSON.stringify({ time: "", method: "GET", host: "h", path: "/", trust: { class: cls, agent: cls === "claimed" ? "GPTBot" : undefined, reason: "" }, rule, action, enforced: false, mode: "monitor" });
    writeFileSync(log, [decision("browser", "allow", "browse"), decision("claimed", "challenge", "checkout"), decision("claimed", "allow", "browse"), "not json"].join("\n"));
    const rp = await run(["report", log]);
    assert.equal(rp.status, 0, rp.stderr);
    assert.match(rp.stdout, /3 decisions \(1 unreadable lines skipped\), monitor mode/);
    assert.match(rp.stdout, /GPTBot \(claimed\)\s+2/);
  });
});

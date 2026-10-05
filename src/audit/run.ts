// The audit: how does a site treat AI agent traffic, and how easy is it for agents to use?
//
// Passive mode (default) only reads public pages, robots.txt and friends.
// Active mode (--active) also runs the door test: the same URL is requested as a browser,
// a script, several *claimed* AI agents, an agent with a forged signature and, optionally,
// an agent signing with your key. Only run active mode against sites you operate.

import { bytesToBase64, bytesToBase64Url } from "../b64.js";
import { KNOWN_AGENTS } from "../gate/agents.js";
import { signRequest } from "../httpsig/sign.js";
import { VERSION } from "../version.js";
import { hasUsefulAutocomplete, type ParsedField, type ParsedPage, parseHtml } from "./html.js";

export type CheckStatus = "pass" | "warn" | "fail" | "skip" | "info";

export interface CheckResult {
  id: string;
  title: string;
  status: CheckStatus;
  weight: number;
  summary: string;
  details: string[];
  fix?: string;
}

export interface CategoryResult {
  id: "identity" | "discovery" | "readability" | "forms" | "walls";
  title: string;
  weight: number;
  score: number | null;
  checks: CheckResult[];
}

export type Visitor = "browser" | "script" | "claimed" | "forged" | "verified";
export type Verdict = "admitted" | "turned_away" | "challenged" | "rate_limited" | "not_found" | "error" | "other";

export interface ProbeResult {
  path: string;
  visitor: Visitor;
  label: string;
  status: number | null;
  verdict: Verdict;
  machineReadable: boolean;
  acceptSignature: boolean;
  ms: number;
  error?: string;
  /** Set when this outcome is a problem, so reports can highlight it. */
  concern?: { level: "fail" | "warn"; note: string };
}

export interface PageSummary {
  url: string;
  status: number | null;
  textLength: number;
  forms: number;
  fields: number;
}

export interface Fix {
  check: string;
  category: string;
  status: CheckStatus;
  title: string;
  fix: string;
}

export interface AuditReport {
  tool: { name: "agent-doorman"; version: string };
  target: string;
  auditedAt: string;
  mode: "passive" | "active";
  score: number;
  verdict: "ready" | "partly-ready" | "not-ready";
  categories: CategoryResult[];
  probes: ProbeResult[];
  pages: PageSummary[];
  fixes: Fix[];
  notes: string[];
}

export interface AuditOptions {
  url: string;
  /** Extra paths to audit, e.g. ["/cart", "/checkout", "/signup"]. */
  paths?: string[];
  /** Run the door test (sends requests claiming to be AI agents). */
  active?: boolean;
  /** Private JWK of your own agent key, to test that verified agents get in. */
  signKey?: JsonWebKey;
  /** Signature-Agent URL to send with signKey. */
  signatureAgent?: string;
  /** Agent tokens to impersonate in the door test. */
  claimedTokens?: string[];
  timeoutMs?: number;
  /** Pause between door-test requests. Default 150 ms. */
  delayMs?: number;
  fetch?: typeof fetch;
  now?: () => Date;
}

export const BROWSER_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
const SCRIPT_UA = "python-requests/2.32.3";
const DEFAULT_TOKENS = ["GPTBot", "ClaudeBot", "PerplexityBot", "ChatGPT-User", "meta-externalagent"];
const BROWSER_HEADERS = {
  accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  "accept-language": "en-US,en;q=0.9",
};
const MAX_BODY = 2 * 1024 * 1024;

interface Fetched {
  status: number | null;
  headers: Headers;
  text: string;
  ms: number;
  error?: string;
}

async function fetchText(
  fetchImpl: typeof fetch,
  url: string,
  headers: Record<string, string>,
  timeoutMs: number,
): Promise<Fetched> {
  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetchImpl(url, { headers, redirect: "follow", signal: controller.signal });
    let text = "";
    if (res.body) {
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let total = 0;
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        text += decoder.decode(value, { stream: true });
        if (total > MAX_BODY) {
          await reader.cancel().catch(() => {});
          break;
        }
      }
      text += decoder.decode();
    }
    return { status: res.status, headers: res.headers, text, ms: Date.now() - started };
  } catch (e) {
    const msg = controller.signal.aborted ? `timed out after ${timeoutMs} ms` : (e as Error).message;
    return { status: null, headers: new Headers(), text: "", ms: Date.now() - started, error: msg };
  } finally {
    clearTimeout(timer);
  }
}

const INTERSTITIAL = new Set(["Cloudflare challenge page", "DataDome", "HUMAN (PerimeterX)", "Kasada", "AWS WAF CAPTCHA"]);

function verdictOf(f: Fetched): { verdict: Verdict; machineReadable: boolean; acceptSignature: boolean } {
  const acceptSignature = f.headers.has("accept-signature");
  const ct = f.headers.get("content-type") ?? "";
  const machineReadable =
    acceptSignature ||
    /json/i.test(ct) ||
    (f.status === 429 && f.headers.has("retry-after")) ||
    /rel="?agent-policy/i.test(f.headers.get("link") ?? "");
  if (f.status === null) return { verdict: "error", machineReadable, acceptSignature };
  const parsed = /html/i.test(ct) || /^\s*</.test(f.text) ? parseHtml(f.text) : null;
  const interstitial = !!parsed?.challengeMarkers.some((m) => INTERSTITIAL.has(m)) && (parsed?.textLength ?? 0) < 600;
  let verdict: Verdict;
  if (f.status === 429) verdict = "rate_limited";
  else if (f.status === 401 || f.status === 403) verdict = acceptSignature || interstitial ? "challenged" : "turned_away";
  else if (f.status === 404 || f.status === 410) verdict = "not_found";
  else if (f.status === 503 && interstitial) verdict = "challenged";
  else if (f.status >= 200 && f.status < 400) verdict = interstitial ? "challenged" : "admitted";
  else verdict = "other";
  return { verdict, machineReadable, acceptSignature };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const OUT: Record<Verdict, string> = {
  admitted: "was admitted",
  turned_away: "was turned away",
  challenged: "was challenged",
  rate_limited: "was rate limited",
  not_found: "got 404",
  error: "got no response",
  other: "got an unexpected status",
};

function check(
  id: string,
  title: string,
  weight: number,
  status: CheckStatus,
  summary: string,
  details: string[] = [],
  fix?: string,
): CheckResult {
  return { id, title, weight, status, summary, details, ...(fix ? { fix } : {}) };
}

function ratio(n: number, d: number): string {
  return `${n}/${d}`;
}

export async function runAudit(options: AuditOptions): Promise<AuditReport> {
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs ?? 15_000;
  const delayMs = options.delayMs ?? 150;
  const target = new URL(options.url);
  if (target.protocol !== "https:" && target.protocol !== "http:") throw new Error("audit target must be http(s)");
  const origin = target.origin;
  const paths = [...new Set([target.pathname + target.search, ...(options.paths ?? [])])].map((p) =>
    p.startsWith("/") ? p : `/${p}`,
  );
  const notes: string[] = [];

  // ------------------------------------------------------------------ pages
  const pages: Array<{ path: string; fetched: Fetched; parsed: ParsedPage | null }> = [];
  for (const path of paths) {
    const fetched = await fetchText(fetchImpl, origin + path, { "user-agent": BROWSER_UA, ...BROWSER_HEADERS }, timeoutMs);
    const parsed = fetched.status !== null ? parseHtml(fetched.text) : null;
    pages.push({ path, fetched, parsed });
  }
  const okPages = pages.filter((p) => p.fetched.status !== null && p.fetched.status >= 200 && p.fetched.status < 300 && p.parsed);

  const side = async (path: string) =>
    fetchText(fetchImpl, origin + path, { "user-agent": BROWSER_UA, accept: "text/plain,application/json,*/*" }, timeoutMs);
  const robots = await side("/robots.txt");
  const llms = await side("/llms.txt");
  const agentPolicy = await side("/.well-known/agent-policy.json");
  const robotsText = robots.status === 200 && !/^\s*</.test(robots.text) ? robots.text : "";
  const sitemapDeclared = /^\s*sitemap\s*:/im.test(robotsText);
  const sitemap = sitemapDeclared ? null : await side("/sitemap.xml");

  // ------------------------------------------------------------- door test
  const probes: ProbeResult[] = [];
  if (options.active) {
    const tokens = options.claimedTokens ?? DEFAULT_TOKENS;
    for (const [i, page] of pages.entries()) {
      const path = page.path;
      const record = (visitor: Visitor, label: string, f: Fetched) => {
        const v = verdictOf(f);
        probes.push({ path, visitor, label, status: f.status, ms: f.ms, ...v, ...(f.error ? { error: f.error } : {}) });
      };
      record("browser", "Browser", page.fetched);
      const go = async (headers: Record<string, string>) => {
        await sleep(delayMs);
        return fetchText(fetchImpl, origin + path, headers, timeoutMs);
      };
      record("script", "Script (python-requests)", await go({ "user-agent": SCRIPT_UA, accept: "*/*" }));
      for (const token of i === 0 ? tokens : tokens.slice(0, 2)) {
        const ua = `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ${token}/1.0)`;
        record("claimed", `Claims ${token}, no proof`, await go({ "user-agent": ua, ...BROWSER_HEADERS }));
      }
      const created = Math.floor(Date.now() / 1000);
      const forgedKeyid = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
      const forgedSig = bytesToBase64(crypto.getRandomValues(new Uint8Array(64)));
      record(
        "forged",
        `Claims ${tokens[0] ?? "GPTBot"}, fake signature`,
        await go({
          "user-agent": `Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ${tokens[0] ?? "GPTBot"}/1.0)`,
          ...BROWSER_HEADERS,
          "signature-agent": 'sig1="https://agent-doorman.invalid"',
          "signature-input": `sig1=("@authority" "signature-agent";key="sig1");created=${created};keyid="${forgedKeyid}";alg="ed25519";expires=${created + 300};tag="web-bot-auth"`,
          signature: `sig1=:${forgedSig}:`,
        }),
      );
      if (options.signKey) {
        const signed = await signRequest(
          { method: "GET", url: origin + path },
          options.signatureAgent ? { privateJwk: options.signKey, signatureAgent: options.signatureAgent } : { privateJwk: options.signKey },
        );
        record(
          "verified",
          "Verified agent (your key)",
          await go({ "user-agent": `agent-doorman-audit/${VERSION}`, ...BROWSER_HEADERS, ...signed }),
        );
      }
    }
  }

  // ---------------------------------------------------------------- checks
  const identity: CheckResult[] = [];
  if (!options.active) {
    identity.push(
      check("door-test", "Door test", 0, "skip", "Not run. Re-run with --active to see who gets in.", [
        "The door test sends requests that claim to be AI agents. Only run it against sites you operate.",
      ]),
    );
  } else {
    const at = (path: string, v: Visitor) => probes.filter((p) => p.path === path && p.visitor === v);
    const flag = (p: ProbeResult, level: "fail" | "warn", note: string) => {
      if (!p.concern || (p.concern.level === "warn" && level === "fail")) p.concern = { level, note };
    };
    for (const p of probes) if (p.visitor === "browser" && p.verdict !== "admitted" && p.verdict !== "not_found") flag(p, "fail", "a plain browser was refused");
    const refused = (p: ProbeResult) => p.verdict === "turned_away" || p.verdict === "challenged" || p.verdict === "rate_limited";
    const reachable = pages.filter((p) => at(p.path, "browser")[0]?.verdict === "admitted").map((p) => p.path);
    if (reachable.length === 0) {
      identity.push(
        check("door-test", "Door test", 0, "skip", "The browser request itself was refused, so agent handling cannot be compared.", [
          "See the walls category: browser-like agents will hit the same barrier.",
        ]),
      );
    } else {
      // 1. Does bot protection trust User-Agent claims?
      const bypass: string[] = [];
      let scriptsRefused = false;
      for (const path of reachable) {
        const s = at(path, "script")[0];
        if (s && refused(s)) {
          scriptsRefused = true;
          for (const c of at(path, "claimed")) {
            if (c.verdict !== "admitted") continue;
            bypass.push(`${path}: "${c.label}" got in while a plain script was refused`);
            flag(c, "fail", "got in on a claim alone");
          }
        }
      }
      identity.push(
        bypass.length
          ? check(
              "ua-allowlist",
              "Agent claims are not trusted blindly",
              3,
              "fail",
              "Your bot protection lets in anyone who claims to be a known AI agent.",
              bypass,
              "Stop allowlisting by User-Agent. Admit named agents only when their Web Bot Auth signature verifies (agent-doorman verifies signatures; many CDNs can too).",
            )
          : check(
              "ua-allowlist",
              "Agent claims are not trusted blindly",
              3,
              "pass",
              scriptsRefused
                ? "Requests that only claim to be AI agents get the same treatment as other scripts."
                : "No User-Agent allowlisting detected (scripts are not refused either).",
            ),
      );

      // 2. Does a signature header alone buy trust?
      // The fake signature uses an unknown key, which a correct verifier reports as "unverified"
      // (draft Appendix A.1), not "invalid". So the bar is: it must never get MORE access than an
      // unsigned claim. Refusing it outright, or answering with Accept-Signature, shows checking.
      const rank = (p: ProbeResult) => (p.verdict === "admitted" ? 2 : p.verdict === "rate_limited" ? 1 : 0);
      const forgedIn: string[] = [];
      let forgedRefusedSomewhere = false;
      for (const path of reachable) {
        const f = at(path, "forged")[0];
        if (!f) continue;
        if (refused(f)) forgedRefusedSomewhere = true;
        const best = Math.max(-1, ...at(path, "claimed").map(rank));
        if (best >= 0 && rank(f) > best) {
          forgedIn.push(`${path}: "${f.label}" ${OUT[f.verdict]} where unsigned claims were refused`);
          flag(f, "fail", "a fake signature bought access");
        }
      }
      const signals = probes.some((p) => p.acceptSignature);
      identity.push(
        forgedIn.length
          ? check(
              "forged-signature",
              "Fake signatures buy nothing",
              2,
              "fail",
              "A request with a made-up signature got further than an unsigned one.",
              forgedIn,
              "Verify Web Bot Auth signatures cryptographically; never treat the presence of Signature headers as proof.",
            )
          : forgedRefusedSomewhere || signals
            ? check("forged-signature", "Fake signatures buy nothing", 2, "pass", "A fake signature got no more access than an unsigned claim, and was refused where it mattered.")
            : check(
                "forged-signature",
                "Fake signatures buy nothing",
                2,
                "warn",
                "No signature checking observed: a fake signature was treated like any other visit.",
                [],
                "Verify Web Bot Auth signatures so you can tell real agents from impostors, and require verification on transactional paths.",
              ),
      );

      // 3. Sensitive paths.
      const extra = reachable.filter((p) => p !== paths[0]);
      if (extra.length === 0) {
        identity.push(
          check("sensitive-paths", "Transactional pages need proof", 0, "skip", "Only one page audited. Add --path /cart --path /checkout to test transactional pages."),
        );
      } else {
        const open: string[] = [];
        for (const path of extra) {
          for (const c of at(path, "claimed")) {
            if (c.verdict !== "admitted") continue;
            open.push(`${path}: "${c.label}" admitted`);
            flag(c, "warn", "unverified claim on a transactional page");
          }
        }
        identity.push(
          open.length
            ? check(
                "sensitive-paths",
                "Transactional pages need proof",
                2,
                "warn",
                "Unverified agent claims reach the extra pages you listed.",
                open,
                "Require a browser or a verified agent on cart, checkout and account paths (see the ecommerce preset). The audit only sends GET requests, so this is a signal, not proof that actions are possible.",
              )
            : check("sensitive-paths", "Transactional pages need proof", 2, "pass", "Unverified agent claims are refused on the extra pages you listed."),
        );
      }

      // 4. Refusals that agents can understand.
      const refusals = probes.filter((p) => p.visitor !== "browser" && refused(p));
      if (refusals.length === 0) {
        identity.push(check("readable-refusals", "Refusals explain themselves", 0, "skip", "Nothing was refused, so there was nothing to explain."));
      } else {
        const good = refusals.filter((p) => p.machineReadable).length;
        for (const p of refusals) if (!p.machineReadable) flag(p, "warn", "refused with no reason an agent can read");
        identity.push(
          good === refusals.length
            ? check("readable-refusals", "Refusals explain themselves", 1, "pass", "Refused agents get a machine-readable reason (JSON, Accept-Signature or Retry-After).")
            : check(
                "readable-refusals",
                "Refusals explain themselves",
                1,
                good > 0 ? "warn" : "fail",
                `Only ${ratio(good, refusals.length)} refusals told the agent why or how to get in.`,
                [],
                "Answer refused agents with a JSON body and an Accept-Signature header (Web Bot Auth §4.3) or Retry-After, not an HTML wall.",
              ),
        );
      }

      // 5. Verified agents get in.
      const verified = probes.filter((p) => p.visitor === "verified" && reachable.includes(p.path));
      if (!options.signKey) {
        identity.push(
          check("verified-admitted", "Verified agents get in", 0, "skip", "Not tested. Pass --sign-key (and --signature-agent) to check that a signed agent is admitted."),
        );
      } else {
        const blocked = verified.filter((p) => p.verdict !== "admitted");
        for (const p of blocked) flag(p, "fail", "a verified agent was refused");
        identity.push(
          blocked.length === 0
            ? check("verified-admitted", "Verified agents get in", 2, "pass", "Requests signed with your key were admitted.")
            : check(
                "verified-admitted",
                "Verified agents get in",
                2,
                "fail",
                "Signed requests were refused along with impostors.",
                blocked.map((p) => `${p.path}: HTTP ${p.status ?? "error"} (${p.verdict})`),
                "Make sure your verifier can resolve the agent's key (directory reachable, or key configured out of band) and that policy admits the verified class.",
              ),
        );
      }
    }
  }

  // Discovery
  const discovery: CheckResult[] = [];
  const aiTokens = KNOWN_AGENTS.map((a) => a.token.toLowerCase());
  const uaLines = robotsText
    .split(/\r?\n/)
    .map((l) => /^\s*user-agent\s*:\s*(.+?)\s*$/i.exec(l)?.[1]?.toLowerCase())
    .filter((x): x is string => !!x);
  const aiGroups = [...new Set(uaLines.filter((u) => aiTokens.includes(u)))].map(
    (u) => KNOWN_AGENTS.find((a) => a.token.toLowerCase() === u)!.token,
  );
  discovery.push(
    robotsText === ""
      ? check("robots", "robots.txt states an agent policy", 2, "warn", "No robots.txt found.", [], "Publish robots.txt with explicit groups for the AI crawlers you allow or refuse.")
      : aiGroups.length
        ? check("robots", "robots.txt states an agent policy", 2, "pass", `robots.txt has explicit groups for ${aiGroups.length} AI agent token(s).`, [aiGroups.join(", ")])
        : check(
            "robots",
            "robots.txt states an agent policy",
            2,
            "warn",
            "robots.txt exists but says nothing specific about AI agents.",
            [],
            "Add explicit User-agent groups (e.g. GPTBot, ClaudeBot, PerplexityBot) so your choice is deliberate rather than inherited from '*'.",
          ),
  );
  const sitemapOk = sitemapDeclared || (sitemap?.status === 200 && /<(urlset|sitemapindex)\b/i.test(sitemap.text));
  discovery.push(
    sitemapOk
      ? check("sitemap", "Pages are discoverable", 1, "pass", sitemapDeclared ? "robots.txt declares a sitemap." : "Found /sitemap.xml.")
      : check("sitemap", "Pages are discoverable", 1, "warn", "No sitemap found.", [], "Publish a sitemap and reference it from robots.txt."),
  );
  const llmsOk = llms.status === 200 && !/^\s*</.test(llms.text) && llms.text.trim().length > 0;
  discovery.push(
    llmsOk
      ? check("llms-txt", "llms.txt summary", 1, "pass", "Found /llms.txt.")
      : check("llms-txt", "llms.txt summary", 1, "warn", "No /llms.txt.", [], "Optional: publish /llms.txt, a short Markdown guide to your site for language models (proposal at llmstxt.org)."),
  );
  let policyDoc: unknown = null;
  try {
    policyDoc = agentPolicy.status === 200 ? JSON.parse(agentPolicy.text) : null;
  } catch {
    policyDoc = null;
  }
  discovery.push(
    policyDoc
      ? check("agent-policy", "Published agent policy", 0, "info", "Found /.well-known/agent-policy.json.")
      : check("agent-policy", "Published agent policy", 0, "info", "No /.well-known/agent-policy.json (optional, experimental format served by agent-doorman).", [], ""),
  );

  // Readability
  const readability: CheckResult[] = [];
  if (okPages.length === 0) {
    readability.push(check("pages", "Pages load", 0, "skip", "No audited page returned 2xx, so content could not be analysed."));
  } else {
    const noLang = okPages.filter((p) => !p.parsed!.lang).map((p) => p.path);
    readability.push(
      noLang.length
        ? check("lang", "Language is declared", 1, "warn", `${noLang.length} page(s) lack <html lang>.`, noLang, 'Set <html lang="..."> so agents pick the right language model behaviour and locale.')
        : check("lang", "Language is declared", 1, "pass", "Every audited page declares its language."),
    );
    const noMeta = okPages.filter((p) => !p.parsed!.title || !p.parsed!.description).map((p) => p.path);
    readability.push(
      noMeta.length
        ? check("title-description", "Title and description", 1, "warn", `${noMeta.length} page(s) miss a title or meta description.`, noMeta, "Give every page a specific <title> and <meta name=\"description\">.")
        : check("title-description", "Title and description", 1, "pass", "Every audited page has a title and description."),
    );
    const withLd = okPages.filter((p) => p.parsed!.jsonLd.length > 0);
    const types = [...new Set(okPages.flatMap((p) => p.parsed!.jsonLdTypes))];
    const ldErrors = okPages.reduce((n, p) => n + p.parsed!.jsonLdErrors, 0);
    const productIssues: string[] = [];
    for (const p of okPages) {
      const nodes: Array<Record<string, unknown>> = [];
      const walk = (n: unknown): void => {
        if (Array.isArray(n)) return n.forEach(walk);
        if (n && typeof n === "object") {
          const o = n as Record<string, unknown>;
          nodes.push(o);
          if (o["@graph"]) walk(o["@graph"]);
        }
      };
      p.parsed!.jsonLd.forEach(walk);
      for (const prod of nodes.filter((n) => n["@type"] === "Product" || (Array.isArray(n["@type"]) && (n["@type"] as unknown[]).includes("Product")))) {
        const offers = prod.offers as Record<string, unknown> | Array<Record<string, unknown>> | undefined;
        const o = Array.isArray(offers) ? offers[0] : offers;
        const missing = ["price", "priceCurrency", "availability"].filter((k) => !o || (o[k] === undefined && !(k === "price" && o.lowPrice !== undefined)));
        if (missing.length) productIssues.push(`${p.path}: Product offer lacks ${missing.join(", ")}`);
      }
    }
    readability.push(
      withLd.length === 0
        ? check("structured-data", "Structured data", 2, "warn", "No JSON-LD found on audited pages.", [], "Add schema.org JSON-LD (Organization, Product with offers, BreadcrumbList...) so agents read facts instead of guessing from layout.")
        : productIssues.length || ldErrors
          ? check(
              "structured-data",
              "Structured data",
              2,
              "warn",
              `JSON-LD present (${types.join(", ") || "untyped"}) but incomplete${ldErrors ? `; ${ldErrors} block(s) failed to parse` : ""}.`,
              productIssues,
              "Complete Product offers with price, priceCurrency and availability, and fix invalid JSON-LD blocks.",
            )
          : check("structured-data", "Structured data", 2, "pass", `JSON-LD present: ${types.join(", ") || "untyped"}.`),
    );
    const thin = okPages.filter((p) => p.parsed!.textLength < 300 || p.parsed!.needsJavaScript);
    const empty = thin.filter((p) => p.parsed!.textLength < 80);
    readability.push(
      thin.length === 0
        ? check("server-rendered", "Content without JavaScript", 3, "pass", "Audited pages carry readable text in the HTML itself.")
        : check(
            "server-rendered",
            "Content without JavaScript",
            3,
            empty.length ? "fail" : "warn",
            `${thin.length} page(s) show little or no text before JavaScript runs.`,
            thin.map((p) => `${p.path}: ${p.parsed!.textLength} characters${p.parsed!.needsJavaScript ? ", asks to enable JavaScript" : ""}`),
            "Server-render (or pre-render) key content. Agents that fetch HTML without running scripts see an empty shell.",
          ),
    );
  }

  // Forms
  const formsCat: CheckResult[] = [];
  const fields: ParsedField[] = okPages.flatMap((p) => p.parsed!.forms.flatMap((f) => f.fields));
  const buttons = okPages.flatMap((p) => p.parsed!.forms.flatMap((f) => f.buttons));
  if (fields.length === 0) {
    formsCat.push(
      check("forms", "Forms", 0, "skip", "No form fields on the audited pages. Add --path for your sign-up, cart or checkout page."),
    );
  } else {
    const labelled = fields.filter((f) => f.labelled).length;
    const placeholderOnly = fields.filter((f) => f.placeholderOnly).map((f) => f.hint);
    const r = labelled / fields.length;
    formsCat.push(
      check(
        "labels",
        "Every field has a label",
        3,
        r >= 0.9 ? "pass" : r >= 0.6 ? "warn" : "fail",
        `${ratio(labelled, fields.length)} fields have a label or accessible name.`,
        placeholderOnly.length ? [`Placeholder only: ${placeholderOnly.slice(0, 8).join(", ")}${placeholderOnly.length > 8 ? "..." : ""}`] : [],
        r >= 0.9 ? undefined : "Use <label for>, a wrapping <label> or aria-label. Placeholders vanish when typing and many agents ignore them.",
      ),
    );
    const relevant = fields.filter((f) => f.kind !== "other");
    if (relevant.length === 0) {
      formsCat.push(check("autocomplete", "Fields say what they are", 0, "skip", "No identity, address, contact or payment fields found."));
    } else {
      const good = relevant.filter(hasUsefulAutocomplete).length;
      const a = good / relevant.length;
      const missing = relevant.filter((f) => !hasUsefulAutocomplete(f)).map((f) => `${f.hint} (${f.kind}${f.autocomplete ? `, autocomplete="${f.autocomplete}"` : ""})`);
      formsCat.push(
        check(
          "autocomplete",
          "Fields say what they are",
          3,
          a >= 0.8 ? "pass" : a >= 0.4 ? "warn" : "fail",
          `${ratio(good, relevant.length)} identity, contact, address and payment fields carry an autocomplete token.`,
          missing.slice(0, 10),
          a >= 0.8 ? undefined : 'Add autocomplete tokens (email, tel, given-name, street-address, postal-code, cc-number, current-password...). They tell agents and password managers exactly what each field wants.',
        ),
      );
    }
    const unnamed = buttons.filter((b) => !b.named).length;
    formsCat.push(
      buttons.length === 0
        ? check("buttons", "Buttons are named", 0, "skip", "No buttons found in forms.")
        : check(
            "buttons",
            "Buttons are named",
            2,
            unnamed === 0 ? "pass" : unnamed / buttons.length > 0.2 ? "fail" : "warn",
            `${ratio(buttons.length - unnamed, buttons.length)} buttons have a text or accessible name.`,
            [],
            unnamed ? "Give icon-only buttons an aria-label that says what they do (\"Add to cart\", not \"button\")." : undefined,
          ),
    );
    const typed = fields.filter((f) => f.kind === "email" || f.kind === "tel");
    const wrongType = typed.filter((f) => f.tag === "input" && f.type !== f.kind).map((f) => `${f.hint} is type="${f.type}"`);
    formsCat.push(
      typed.length === 0
        ? check("input-types", "Inputs use specific types", 0, "skip", "No email or phone fields found.")
        : check(
            "input-types",
            "Inputs use specific types",
            1,
            wrongType.length ? "warn" : "pass",
            `${ratio(typed.length - wrongType.length, typed.length)} email/phone fields use type="email"/"tel".`,
            wrongType,
            wrongType.length ? 'Use type="email" and type="tel" so agents format and validate input correctly.' : undefined,
          ),
    );
  }

  // Walls
  const walls: CheckResult[] = [];
  const blockedPages = pages.filter((p) => {
    const v = verdictOf(p.fetched).verdict;
    return v === "turned_away" || v === "challenged" || v === "rate_limited" || v === "error";
  });
  walls.push(
    blockedPages.length
      ? check(
          "browser-reachable",
          "Browser-like visits get through",
          3,
          "fail",
          `${blockedPages.length} page(s) refused or challenged a plain browser request.`,
          blockedPages.map((p) => `${p.path}: ${p.fetched.status ?? p.fetched.error}`),
          "Agents that drive a real browser hit this wall too. Exempt verified agents from challenges and make sure ordinary page views are not challenged.",
        )
      : check("browser-reachable", "Browser-like visits get through", 3, "pass", "Plain browser requests reached every audited page."),
  );
  const widgets = [...new Set(okPages.flatMap((p) => p.parsed!.challengeMarkers))];
  walls.push(
    widgets.length
      ? check(
          "captcha",
          "No CAPTCHA in the way",
          1,
          "warn",
          `Challenge technology found on audited pages: ${widgets.join(", ")}.`,
          [],
          "Keep challenges for suspicious traffic and let verified agents skip them; otherwise legitimate agents stall at this step.",
        )
      : check("captcha", "No CAPTCHA in the way", 1, "pass", "No CAPTCHA or bot-challenge widgets detected in the audited HTML."),
  );

  // ---------------------------------------------------------------- scoring
  const categories: CategoryResult[] = [
    { id: "identity", title: "Who gets in", weight: 35, score: null, checks: identity },
    { id: "discovery", title: "Can agents find your rules", weight: 15, score: null, checks: discovery },
    { id: "readability", title: "Can agents read your pages", weight: 20, score: null, checks: readability },
    { id: "forms", title: "Can agents fill in your forms", weight: 20, score: null, checks: formsCat },
    { id: "walls", title: "Walls in the way", weight: 10, score: null, checks: walls },
  ];
  const value: Record<CheckStatus, number | null> = { pass: 1, warn: 0.5, fail: 0, skip: null, info: null };
  let total = 0;
  let weightSum = 0;
  for (const c of categories) {
    let s = 0;
    let w = 0;
    for (const ch of c.checks) {
      const v = value[ch.status];
      if (v === null || ch.weight === 0) continue;
      s += v * ch.weight;
      w += ch.weight;
    }
    c.score = w > 0 ? Math.round((s / w) * 100) : null;
    if (c.score !== null) {
      total += c.score * c.weight;
      weightSum += c.weight;
    }
  }
  const score = weightSum > 0 ? Math.round(total / weightSum) : 0;
  const verdict = score >= 85 ? "ready" : score >= 60 ? "partly-ready" : "not-ready";

  const fixes: Fix[] = categories
    .flatMap((c) =>
      c.checks
        .filter((ch) => (ch.status === "fail" || ch.status === "warn") && ch.fix)
        .map((ch) => ({ ch, c, rank: (ch.status === "fail" ? 2 : 1) * ch.weight * c.weight })),
    )
    .sort((a, b) => b.rank - a.rank)
    .map(({ ch, c }) => ({ check: ch.id, category: c.title, status: ch.status, title: ch.title, fix: ch.fix! }));

  if (!options.active) notes.push("Passive audit: the door test was not run, so the score covers readability, forms, discovery and walls only.");
  notes.push(
    "Agents that present themselves as an ordinary browser and do not sign requests look like people. Neither this audit nor User-Agent rules can tell them apart; signatures are what make agents distinguishable.",
  );
  notes.push("Pages were read as raw HTML without running JavaScript.");

  return {
    tool: { name: "agent-doorman", version: VERSION },
    target: target.href,
    auditedAt: (options.now?.() ?? new Date()).toISOString(),
    mode: options.active ? "active" : "passive",
    score,
    verdict,
    categories,
    probes,
    pages: pages.map((p) => ({
      url: origin + p.path,
      status: p.fetched.status,
      textLength: p.parsed?.textLength ?? 0,
      forms: p.parsed?.forms.length ?? 0,
      fields: p.parsed?.forms.reduce((n, f) => n + f.fields.length, 0) ?? 0,
    })),
    fixes,
    notes,
  };
}

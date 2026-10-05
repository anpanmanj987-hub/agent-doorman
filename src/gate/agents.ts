// User-Agent tokens that AI vendors publish for their crawlers and agents.
// A matching User-Agent is only a *claim*: anyone can send it. That is the point of
// classifying it separately from a verified Web Bot Auth signature.
//
// Search-engine crawlers (Googlebot, Bingbot, Applebot...) are deliberately NOT listed:
// a policy that restricted "claimed" traffic must never accidentally block real search
// indexing. Verify those with your existing reverse-DNS based bot management.
//
// Keep this list current against vendor documentation. PRs welcome.

export interface KnownAgent {
  token: string;
  vendor: string;
  /** crawler: bulk collection; assistant: fetches on behalf of a user; search: AI search index. */
  kind: "crawler" | "assistant" | "search";
}

export const KNOWN_AGENTS: readonly KnownAgent[] = [
  { token: "GPTBot", vendor: "OpenAI", kind: "crawler" },
  { token: "OAI-SearchBot", vendor: "OpenAI", kind: "search" },
  { token: "ChatGPT-User", vendor: "OpenAI", kind: "assistant" },
  { token: "ClaudeBot", vendor: "Anthropic", kind: "crawler" },
  { token: "Claude-SearchBot", vendor: "Anthropic", kind: "search" },
  { token: "Claude-User", vendor: "Anthropic", kind: "assistant" },
  { token: "PerplexityBot", vendor: "Perplexity", kind: "search" },
  { token: "Perplexity-User", vendor: "Perplexity", kind: "assistant" },
  { token: "meta-externalagent", vendor: "Meta", kind: "crawler" },
  { token: "meta-externalfetcher", vendor: "Meta", kind: "assistant" },
  { token: "FacebookBot", vendor: "Meta", kind: "crawler" },
  { token: "Amazonbot", vendor: "Amazon", kind: "crawler" },
  { token: "Bytespider", vendor: "ByteDance", kind: "crawler" },
  { token: "CCBot", vendor: "Common Crawl", kind: "crawler" },
  { token: "MistralAI-User", vendor: "Mistral", kind: "assistant" },
  { token: "DuckAssistBot", vendor: "DuckDuckGo", kind: "assistant" },
  { token: "cohere-ai", vendor: "Cohere", kind: "crawler" },
  { token: "YouBot", vendor: "You.com", kind: "search" },
  { token: "Diffbot", vendor: "Diffbot", kind: "crawler" },
];

const tokenPatterns = KNOWN_AGENTS.map((a) => ({
  agent: a,
  re: new RegExp(`(^|[^A-Za-z0-9-])${a.token.replace(/[-]/g, "\\-")}([/;\\s)]|$)`, "i"),
}));

export function matchKnownAgent(userAgent: string | null | undefined): KnownAgent | undefined {
  if (!userAgent) return undefined;
  return tokenPatterns.find((p) => p.re.test(userAgent))?.agent;
}

const AUTOMATION_PATTERNS: ReadonlyArray<[RegExp, string]> = [
  [/HeadlessChrome/i, "headless Chrome"],
  [/PhantomJS/i, "PhantomJS"],
  [/\bpuppeteer\b/i, "Puppeteer"],
  [/\bplaywright\b/i, "Playwright"],
  [/\bselenium\b/i, "Selenium"],
  [/^python-requests\//i, "python-requests"],
  [/^python-urllib/i, "Python urllib"],
  [/\baiohttp\//i, "aiohttp"],
  [/^python-httpx\//i, "httpx"],
  [/^curl\//i, "curl"],
  [/^Wget\//i, "Wget"],
  [/^Go-http-client\//i, "Go net/http"],
  [/^okhttp\//i, "OkHttp"],
  [/^axios\//i, "axios"],
  [/^node-fetch/i, "node-fetch"],
  [/^undici/i, "undici"],
  [/^node$/i, "Node.js fetch"],
  [/^Java\//i, "Java HTTP client"],
  [/^libwww-perl/i, "libwww-perl"],
  [/\bScrapy\//i, "Scrapy"],
];

/** Returns a short reason when the User-Agent looks like a script or automation framework. */
export function automationHint(userAgent: string | null | undefined): string | undefined {
  if (userAgent === null || userAgent === undefined || userAgent.trim() === "") return "empty User-Agent";
  return AUTOMATION_PATTERNS.find(([re]) => re.test(userAgent))?.[1];
}

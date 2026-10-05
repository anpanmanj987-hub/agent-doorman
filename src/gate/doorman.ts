// The doorman: classify each request, apply the policy, and say what to do with it.
// Runtime-agnostic: works with any Fetch-API style Request (Workers, Next.js, Deno, Bun, Node).

import type { MessageContext, RequestLike } from "../httpsig/base.js";
import { createVerifier, type VerificationResult, type Verifier, type VerifyOptions } from "../httpsig/verify.js";
import { automationHint, matchKnownAgent } from "./agents.js";
import {
  compileGlob,
  compilePolicy,
  type Policy,
  publicPolicyDocument,
  type TrustClass,
} from "./policy.js";
import { createMemoryRateLimitStore, type RateLimitStore } from "./ratelimit.js";

export const POLICY_PATH = "/.well-known/agent-policy.json";
export const SPEC_URL = "https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/";
const ACCEPT_SIGNATURE = 'sig1=("@authority" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"';

export interface TrustInfo {
  class: TrustClass;
  /** Who they are, as far as we can tell: verified agent name/origin, claimed token, or automation hint. */
  agent?: string;
  vendor?: string;
  keyid?: string;
  signatureAgent?: string;
  reason: string;
}

export type Action = "allow" | "deny" | "challenge" | "rate_limit";

export interface Decision {
  time: string;
  method: string;
  host: string;
  path: string;
  ip?: string;
  userAgent?: string;
  trust: TrustInfo;
  rule: string;
  action: Action;
  /** True only when mode is "enforce" and the action is not "allow". */
  enforced: boolean;
  mode: "monitor" | "enforce";
  retryAfter?: number;
}

export interface DoormanOptions {
  policy: Policy;
  /** Overrides policy.mode. Default "monitor": decide and log, never block. */
  mode?: "monitor" | "enforce";
  /** Verification settings, or a ready Verifier. */
  verify?: VerifyOptions | Verifier;
  /** Use X-Forwarded-Host/-Proto (for signature @authority) and CF-Connecting-IP/X-Forwarded-For (for rate keys). */
  trustProxy?: boolean;
  /** `false` disables rate limiting. Default: in-memory token buckets. */
  rateLimitStore?: RateLimitStore | false;
  onDecision?: (decision: Decision) => void | Promise<void>;
  /** Serve the public policy document at /.well-known/agent-policy.json. Default true. */
  servePolicy?: boolean;
  /** Paths never gated. Default ["/robots.txt", "/.well-known/**"]. */
  exemptPaths?: string[];
  now?: () => number;
}

export interface Doorman {
  readonly mode: "monitor" | "enforce";
  /** Classify and decide. Never throws on hostile input. */
  evaluate(req: RequestLike, ctx?: { ip?: string }): Promise<Decision>;
  /** Returns a Response to send (block, challenge, rate limit, policy document) or undefined to continue. */
  guard(req: RequestLike, ctx?: { ip?: string }): Promise<Response | undefined>;
  /** Like guard, but also returns the decision (undefined for exempt paths and the policy document). */
  check(req: RequestLike, ctx?: { ip?: string }): Promise<{ decision?: Decision; response?: Response }>;
  /** The Response for an enforced decision, or undefined. */
  responseFor(decision: Decision): Response | undefined;
  policyDocument(): Record<string, unknown>;
}

function isVerifier(v: unknown): v is Verifier {
  return typeof (v as Verifier | undefined)?.verify === "function";
}

function firstValue(h: string | null): string | undefined {
  const v = h?.split(",")[0]?.trim();
  return v || undefined;
}

export function classify(req: RequestLike, verification: VerificationResult): TrustInfo {
  switch (verification.outcome) {
    case "verified": {
      const v = verification.verified!;
      return {
        class: "verified",
        agent: v.agentName ?? v.signatureAgent ?? `key ${v.keyid?.slice(0, 10)}`,
        keyid: v.keyid,
        signatureAgent: v.signatureAgent,
        reason: v.reason,
      };
    }
    case "invalid":
    case "unverified": {
      const s = verification.signatures[0];
      return {
        class: verification.outcome,
        agent: s?.signatureAgent,
        keyid: s?.keyid,
        signatureAgent: s?.signatureAgent,
        reason: verification.reason,
      };
    }
    case "absent":
      break;
  }
  const ua = req.headers.get("user-agent");
  const known = matchKnownAgent(ua);
  if (known) {
    return {
      class: "claimed",
      agent: known.token,
      vendor: known.vendor,
      reason: `User-Agent names ${known.token} (${known.vendor}) without a signature`,
    };
  }
  const hint = automationHint(ua);
  if (hint) return { class: "automated", agent: hint, reason: `looks automated: ${hint}` };
  return { class: "browser", reason: "browser-like, unsigned" };
}

function denyMessage(t: TrustInfo): string {
  switch (t.class) {
    case "claimed":
      return `This action needs a verified agent. The request names ${t.agent} but carries no Web Bot Auth signature.`;
    case "automated":
      return "Automated clients may not do this. Sign your requests with Web Bot Auth to be recognised.";
    case "invalid":
      return `The Web Bot Auth signature on this request failed verification (${t.reason}).`;
    case "unverified":
      return `The Web Bot Auth signature on this request could not be checked (${t.reason}).`;
    default:
      return `Site policy does not allow ${t.class} visitors to do this.`;
  }
}

export function createDoorman(options: DoormanOptions): Doorman {
  const compiled = compilePolicy(options.policy);
  const mode = options.mode ?? compiled.policy.mode ?? "monitor";
  const verifier = isVerifier(options.verify) ? options.verify : createVerifier(options.verify ?? {});
  const store = options.rateLimitStore === false ? null : (options.rateLimitStore ?? createMemoryRateLimitStore({ now: options.now }));
  const exempt = (options.exemptPaths ?? ["/robots.txt", "/.well-known/**"]).map(compileGlob);
  const servePolicy = options.servePolicy !== false;
  const now = options.now ?? (() => Date.now());
  const doc = publicPolicyDocument(compiled.policy);

  function context(req: RequestLike): MessageContext | undefined {
    if (!options.trustProxy) return undefined;
    const authority = firstValue(req.headers.get("x-forwarded-host"));
    const scheme = firstValue(req.headers.get("x-forwarded-proto"));
    return authority || scheme ? { authority, scheme } : undefined;
  }

  function clientIp(req: RequestLike, ctx?: { ip?: string }): string | undefined {
    if (ctx?.ip) return ctx.ip;
    if (!options.trustProxy) return undefined;
    return firstValue(req.headers.get("cf-connecting-ip")) ?? firstValue(req.headers.get("x-forwarded-for"));
  }

  async function evaluate(req: RequestLike, ctx?: { ip?: string }): Promise<Decision> {
    const url = new URL(req.url);
    const ip = clientIp(req, ctx);
    let verification: VerificationResult;
    try {
      verification = await verifier.verify(req, context(req));
    } catch (e) {
      verification = { outcome: "unverified", reason: `verifier error: ${(e as Error).message}`, signatures: [] };
    }
    const trust = classify(req, verification);
    const rule = compiled.match(req.method, url.pathname);
    let action: Action = "allow";
    let retryAfter: number | undefined;
    if (!rule.allows(trust.class)) {
      action = rule.rule.onDeny === "challenge" ? "challenge" : "deny";
    } else {
      const rate = rule.rateFor(trust.class);
      if (rate && store) {
        const who =
          trust.class === "verified"
            ? `${trust.signatureAgent ?? ""}|${trust.keyid ?? ""}`
            : `${trust.agent ?? ""}|${ip ?? req.headers.get("user-agent") ?? ""}`;
        const res = await store.take(`${rule.name}|${trust.class}|${who}`, rate);
        if (!res.ok) {
          action = "rate_limit";
          retryAfter = res.retryAfterSeconds;
        }
      }
    }
    const decision: Decision = {
      time: new Date(now()).toISOString(),
      method: req.method.toUpperCase(),
      host: url.host,
      path: url.pathname,
      ...(ip ? { ip } : {}),
      ...(req.headers.get("user-agent") ? { userAgent: req.headers.get("user-agent")!.slice(0, 256) } : {}),
      trust,
      rule: rule.name,
      action,
      enforced: mode === "enforce" && action !== "allow",
      mode,
      ...(retryAfter ? { retryAfter } : {}),
    };
    if (options.onDecision) {
      try {
        await options.onDecision(decision);
      } catch {
        // logging must never take the site down
      }
    }
    return decision;
  }

  function responseFor(d: Decision): Response | undefined {
    if (!d.enforced) return undefined;
    const headers = new Headers({
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      link: `<${POLICY_PATH}>; rel="agent-policy"`,
    });
    if (d.action === "rate_limit") {
      headers.set("retry-after", String(d.retryAfter ?? 60));
      return new Response(
        JSON.stringify({
          error: "rate_limited",
          message: `Too many requests for ${d.trust.class} visitors on this part of the site.`,
          rule: d.rule,
          trust: d.trust.class,
          retryAfter: d.retryAfter,
          policy: POLICY_PATH,
        }),
        { status: 429, headers },
      );
    }
    if (d.action === "challenge") headers.set("accept-signature", ACCEPT_SIGNATURE);
    return new Response(
      JSON.stringify({
        error: "agent_not_permitted",
        message: denyMessage(d.trust),
        rule: d.rule,
        trust: d.trust.class,
        policy: POLICY_PATH,
        authentication: SPEC_URL,
      }),
      { status: 403, headers },
    );
  }

  return {
    mode,
    evaluate,
    responseFor,
    policyDocument: () => doc,
    check,
    async guard(req, ctx) {
      return (await check(req, ctx)).response;
    },
  };

  async function check(req: RequestLike, ctx?: { ip?: string }): Promise<{ decision?: Decision; response?: Response }> {
    const path = new URL(req.url).pathname;
    const method = req.method.toUpperCase();
    if (servePolicy && path === POLICY_PATH && (method === "GET" || method === "HEAD")) {
      const response = new Response(method === "HEAD" ? null : JSON.stringify(doc, null, 2), {
        status: 200,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "public, max-age=300",
          "access-control-allow-origin": "*",
        },
      });
      return { response };
    }
    if (exempt.some((re) => re.test(path))) return {};
    const decision = await evaluate(req, ctx);
    const response = responseFor(decision);
    return response ? { decision, response } : { decision };
  }
}

/** onDecision helper: one JSON object per line. `agent-doorman report` reads this format. */
export function jsonLines(write: (line: string) => void): (d: Decision) => void {
  return (d) => write(`${JSON.stringify(d)}\n`);
}

// Agent policy: which kinds of visitors may do what, per path and method.

export const TRUST_CLASSES = ["verified", "browser", "claimed", "automated", "unverified", "invalid"] as const;
export type TrustClass = (typeof TRUST_CLASSES)[number];

export const TRUST_CLASS_DESCRIPTIONS: Record<TrustClass, string> = {
  verified: "Carries a valid Web Bot Auth signature from a key we could resolve.",
  browser: "Looks like an ordinary browser. Could be a person or an agent that does not identify itself.",
  claimed: "Names a known AI agent in its User-Agent but proves nothing. Anyone can send this.",
  automated: "Looks like a script or automation framework (curl, python-requests, headless Chrome...).",
  unverified: "Carries a Web Bot Auth signature we could not check (unknown key or directory unavailable).",
  invalid: "Carries a Web Bot Auth signature that failed verification (forged, expired, replayed or malformed).",
};

export interface PolicyRule {
  name: string;
  description?: string;
  match?: { paths?: string[]; methods?: string[] };
  allow: TrustClass[] | "*";
  /** Per-class limits such as "60/min", "10/s", "1000/hour". */
  rateLimit?: Partial<Record<TrustClass, string>>;
  /** block: plain 403. challenge: 403 + Accept-Signature asking for Web Bot Auth. Default "block". */
  onDeny?: "block" | "challenge";
}

export interface Policy {
  version: 1;
  /** monitor: decide and log, never block. enforce: block. Default "monitor". */
  mode?: "monitor" | "enforce";
  rules: PolicyRule[];
  /** Applies when no rule matches. Default: allow everyone. */
  default?: Omit<PolicyRule, "name" | "match">;
  contact?: string;
}

export class PolicyError extends Error {
  override name = "PolicyError";
}

export interface Rate {
  limit: number;
  windowMs: number;
}

const UNIT_MS: Record<string, number> = {
  s: 1000,
  sec: 1000,
  second: 1000,
  m: 60_000,
  min: 60_000,
  minute: 60_000,
  h: 3_600_000,
  hour: 3_600_000,
  d: 86_400_000,
  day: 86_400_000,
};

export function parseRate(spec: string): Rate {
  const m = /^\s*(\d+)\s*\/\s*(\d+)?\s*([a-z]+)\s*$/i.exec(spec);
  const unit = m?.[3]?.toLowerCase() ?? "";
  const unitMs = UNIT_MS[unit] ?? UNIT_MS[unit.replace(/s$/, "")];
  if (!m || unitMs === undefined) {
    throw new PolicyError(`invalid rate "${spec}" (use e.g. "60/min", "10/s", "1000/hour")`);
  }
  const limit = Number(m[1]);
  if (limit <= 0) throw new PolicyError(`rate limit must be positive: "${spec}"`);
  return { limit, windowMs: unitMs * Number(m[2] ?? 1) };
}

export function compileGlob(pattern: string): RegExp {
  if (!pattern.startsWith("/")) throw new PolicyError(`path patterns must start with "/": ${pattern}`);
  let re = "";
  let rest = pattern;
  let trailingDeep = false;
  if (rest.endsWith("/**")) {
    trailingDeep = true;
    rest = rest.slice(0, -3);
  }
  for (let i = 0; i < rest.length; i++) {
    const c = rest[i]!;
    if (c === "*" && rest[i + 1] === "*") {
      re += ".*";
      i++;
    } else if (c === "*") re += "[^/]*";
    else re += c.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
  }
  if (trailingDeep) re += "(?:/.*)?";
  return new RegExp(`^${re}$`);
}

function validateAllow(v: unknown, where: string): TrustClass[] | "*" {
  if (v === "*") return "*";
  if (!Array.isArray(v)) throw new PolicyError(`${where}.allow must be "*" or an array of trust classes`);
  for (const c of v) {
    if (!TRUST_CLASSES.includes(c as TrustClass)) {
      throw new PolicyError(`${where}.allow has unknown class "${String(c)}" (expected ${TRUST_CLASSES.join(", ")})`);
    }
  }
  return v as TrustClass[];
}

function validateRuleBody(r: Record<string, unknown>, where: string): void {
  r.allow = validateAllow(r.allow ?? "*", where);
  if (r.onDeny !== undefined && r.onDeny !== "block" && r.onDeny !== "challenge") {
    throw new PolicyError(`${where}.onDeny must be "block" or "challenge"`);
  }
  if (r.rateLimit !== undefined) {
    if (typeof r.rateLimit !== "object" || r.rateLimit === null) throw new PolicyError(`${where}.rateLimit must be an object`);
    for (const [cls, spec] of Object.entries(r.rateLimit)) {
      if (!TRUST_CLASSES.includes(cls as TrustClass)) throw new PolicyError(`${where}.rateLimit has unknown class "${cls}"`);
      parseRate(String(spec));
    }
  }
}

/** Validate untrusted JSON into a Policy. Throws PolicyError with a readable path. */
export function validatePolicy(input: unknown): Policy {
  if (!input || typeof input !== "object") throw new PolicyError("policy must be a JSON object");
  const p = structuredClone(input) as Record<string, unknown>;
  if (p.version !== 1) throw new PolicyError('policy.version must be 1');
  if (p.mode !== undefined && p.mode !== "monitor" && p.mode !== "enforce") {
    throw new PolicyError('policy.mode must be "monitor" or "enforce"');
  }
  if (!Array.isArray(p.rules)) throw new PolicyError("policy.rules must be an array");
  const names = new Set<string>();
  p.rules.forEach((raw, i) => {
    const where = `rules[${i}]`;
    if (!raw || typeof raw !== "object") throw new PolicyError(`${where} must be an object`);
    const r = raw as Record<string, unknown>;
    if (typeof r.name !== "string" || !/^[a-z0-9][a-z0-9._-]*$/i.test(r.name)) {
      throw new PolicyError(`${where}.name must be a short identifier`);
    }
    if (names.has(r.name)) throw new PolicyError(`duplicate rule name "${r.name}"`);
    names.add(r.name);
    const m = (r.match ?? {}) as Record<string, unknown>;
    if (m.paths !== undefined) {
      if (!Array.isArray(m.paths) || m.paths.some((x) => typeof x !== "string")) {
        throw new PolicyError(`${where}.match.paths must be an array of strings`);
      }
      (m.paths as string[]).forEach(compileGlob);
    }
    if (m.methods !== undefined && (!Array.isArray(m.methods) || m.methods.some((x) => typeof x !== "string"))) {
      throw new PolicyError(`${where}.match.methods must be an array of strings`);
    }
    validateRuleBody(r, where);
  });
  if (p.default !== undefined) validateRuleBody(p.default as Record<string, unknown>, "default");
  return p as unknown as Policy;
}

export interface CompiledRule {
  name: string;
  rule: PolicyRule;
  allows(cls: TrustClass): boolean;
  rateFor(cls: TrustClass): Rate | undefined;
}

export interface CompiledPolicy {
  policy: Policy;
  match(method: string, path: string): CompiledRule;
}

function compileRule(rule: PolicyRule): CompiledRule & { test(method: string, path: string): boolean } {
  const paths = rule.match?.paths?.map(compileGlob);
  const methods = rule.match?.methods?.map((m) => m.toUpperCase());
  const rates = new Map<TrustClass, Rate>();
  for (const [cls, spec] of Object.entries(rule.rateLimit ?? {})) rates.set(cls as TrustClass, parseRate(spec!));
  return {
    name: rule.name,
    rule,
    test(method, path) {
      if (methods && !methods.includes(method.toUpperCase()) && !methods.includes("*")) return false;
      if (paths && !paths.some((re) => re.test(path))) return false;
      return true;
    },
    allows(cls) {
      return rule.allow === "*" || rule.allow.includes(cls);
    },
    rateFor(cls) {
      return rates.get(cls);
    },
  };
}

export function compilePolicy(policy: Policy): CompiledPolicy {
  const valid = validatePolicy(policy);
  const rules = valid.rules.map(compileRule);
  const fallback = compileRule({ name: "default", allow: "*", ...(valid.default ?? {}) });
  return {
    policy: valid,
    match(method, path) {
      return rules.find((r) => r.test(method, path)) ?? fallback;
    },
  };
}

/** What we publish at /.well-known/agent-policy.json (experimental format, see docs/agent-policy.md). */
export function publicPolicyDocument(policy: Policy): Record<string, unknown> {
  const expand = (a: TrustClass[] | "*") => (a === "*" ? [...TRUST_CLASSES] : a);
  return {
    agentPolicy: "0.1",
    status: "experimental",
    generator: "agent-doorman",
    authentication: {
      scheme: "web-bot-auth",
      specification: "https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/",
      requiredComponents: { anyOf: ["@authority", "@target-uri"] },
    },
    classes: TRUST_CLASS_DESCRIPTIONS,
    rules: policy.rules.map((r) => ({
      name: r.name,
      ...(r.description ? { description: r.description } : {}),
      methods: r.match?.methods ?? ["*"],
      paths: r.match?.paths ?? ["/**"],
      allow: expand(r.allow),
    })),
    default: { allow: expand(policy.default?.allow ?? "*") },
    ...(policy.contact ? { contact: policy.contact } : {}),
  };
}

// ------------------------------------------------------------------- presets

const BROWSE_CLASSES: TrustClass[] = ["browser", "verified", "claimed", "automated", "unverified"];
const PEOPLE_OR_PROVEN: TrustClass[] = ["browser", "verified"];

export const presets = {
  /** Shops: anyone may browse; carts, checkout and accounts need a browser or a verified agent. */
  ecommerce(): Policy {
    return {
      version: 1,
      mode: "monitor",
      rules: [
        {
          name: "account",
          description: "Sign-in, sign-up and account pages",
          match: { paths: ["/login", "/signin", "/signup", "/register", "/account/**", "/password/**"] },
          allow: PEOPLE_OR_PROVEN,
          rateLimit: { verified: "30/min" },
          onDeny: "challenge",
        },
        {
          name: "checkout",
          description: "Checkout and payment",
          match: { paths: ["/checkout/**", "/cart/checkout/**", "/payment/**", "/pay/**"] },
          allow: PEOPLE_OR_PROVEN,
          rateLimit: { verified: "30/min" },
          onDeny: "challenge",
        },
        {
          name: "cart",
          description: "Changes to the cart",
          match: { paths: ["/cart/**", "/basket/**"], methods: ["POST", "PUT", "PATCH", "DELETE"] },
          allow: PEOPLE_OR_PROVEN,
          rateLimit: { verified: "120/min" },
          onDeny: "challenge",
        },
        {
          name: "api",
          description: "JSON APIs",
          match: { paths: ["/api/**"] },
          allow: ["browser", "verified", "automated"],
          rateLimit: { automated: "60/min", verified: "300/min" },
          onDeny: "challenge",
        },
        {
          name: "browse",
          description: "Reading pages",
          match: { methods: ["GET", "HEAD"], paths: ["/**"] },
          allow: BROWSE_CLASSES,
          rateLimit: { claimed: "120/min", automated: "60/min", unverified: "60/min" },
        },
      ],
      default: { allow: PEOPLE_OR_PROVEN, onDeny: "challenge" },
    };
  },

  /** Publishers and docs sites: reading is open, forged signatures are refused, scrapers are slowed. */
  content(): Policy {
    return {
      version: 1,
      mode: "monitor",
      rules: [
        {
          name: "read",
          description: "Reading pages",
          match: { methods: ["GET", "HEAD"], paths: ["/**"] },
          allow: BROWSE_CLASSES,
          rateLimit: { claimed: "60/min", automated: "30/min", unverified: "30/min" },
        },
      ],
      default: { allow: PEOPLE_OR_PROVEN, onDeny: "challenge" },
    };
  },
} as const;

export type PresetName = keyof typeof presets;

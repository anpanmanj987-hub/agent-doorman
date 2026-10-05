// Verifies Web Bot Auth signatures (RFC 9421 + draft-meunier-webbotauth-httpsig-protocol-00).
// Outcomes follow the draft's Appendix A.1: verified / invalid / unverified.

import { toBufferSource, utf8 } from "../b64.js";
import {
  type BareItem,
  type Dictionary,
  type InnerList,
  type Item,
  parseDictionary,
  parseItem,
  serializeItem,
  Token,
} from "../sf.js";
import { ComponentError, createSignatureBase, type MessageContext, type RequestLike } from "./base.js";
import {
  createDirectoryResolver,
  type DirectoryResolver,
  type DiscoveryType,
  normalizeDiscoveryUrl,
} from "./directory.js";
import {
  algMatchesKey,
  importPublicKey,
  inferAlg,
  jwkThumbprint,
  KNOWN_TEST_KEY_THUMBPRINTS,
  type SigAlg,
  signatureAlgorithm,
  SUPPORTED_ALGS,
} from "./jwk.js";

export type VerifyOutcome = "verified" | "invalid" | "unverified";

export interface StaticKey {
  jwk: JsonWebKey;
  /** Friendly name used in logs/policies, e.g. "Acme shopping agent". */
  name?: string;
}

export interface NonceStore {
  /** Return false if (scope, nonce) was already seen before `expiresAtMs`; otherwise remember it and return true. */
  checkAndRemember(nonce: string, scope: string, expiresAtMs: number): boolean | Promise<boolean>;
}

export interface VerifyOptions {
  /** Keys known out of band. Matched by RFC 7638 thumbprint against `keyid`. */
  keys?: StaticKey[];
  /** Directory resolver for Signature-Agent discovery. `false` disables network discovery. */
  directory?: DirectoryResolver | false;
  /** Friendly names keyed by Signature-Agent origin, e.g. {"https://agent.example": "Example agent"}. */
  agentNames?: Record<string, string>;
  /** Current time in ms. */
  now?: () => number;
  /** Default 60 s. */
  clockSkewSeconds?: number;
  /** Reject signatures whose expires - created exceeds this. Default 86400 (draft §4.2 recommends <= 24h). */
  maxValiditySeconds?: number;
  /** Accept the RFC 9421 example keys. Never enable in production. Default false. */
  allowTestKeys?: boolean;
  /** Replay protection. Default: in-memory store. `false` disables. */
  nonceStore?: NonceStore | false;
  requireNonce?: boolean;
  /** Authority/scheme as seen by the client when behind a trusted proxy. */
  context?: MessageContext;
}

export interface SignatureResult {
  label: string;
  outcome: VerifyOutcome;
  reason: string;
  keyid?: string;
  alg?: string;
  created?: number;
  expires?: number;
  nonce?: string;
  /** Discovery URL from the covered Signature-Agent member (origin form). */
  signatureAgent?: string;
  agentName?: string;
  components: string[];
}

export interface VerificationResult {
  /** "absent" means the request carried no Web Bot Auth signature at all. */
  outcome: VerifyOutcome | "absent";
  reason: string;
  signatures: SignatureResult[];
  verified?: SignatureResult;
}

export function createMemoryNonceStore(maxEntries = 100_000, now: () => number = () => Date.now()): NonceStore {
  const seen = new Map<string, number>();
  return {
    checkAndRemember(nonce, scope, expiresAtMs) {
      const key = `${scope}|${nonce}`;
      const t = now();
      const prev = seen.get(key);
      if (prev !== undefined && prev > t) return false;
      if (seen.size >= maxEntries) {
        for (const [k, exp] of seen) if (exp <= t) seen.delete(k);
        while (seen.size >= maxEntries) {
          const oldest = seen.keys().next().value;
          if (oldest === undefined) break;
          seen.delete(oldest);
        }
      }
      seen.set(key, expiresAtMs);
      return true;
    },
  };
}

function str(v: BareItem | undefined): string | undefined {
  if (typeof v === "string") return v;
  if (v instanceof Token) return v.value;
  return undefined;
}

function int(v: BareItem | undefined): number | undefined {
  return typeof v === "number" && Number.isInteger(v) ? v : undefined;
}

interface Discovery {
  value: string;
  type: DiscoveryType;
}

interface AgentHeader {
  dict?: Dictionary;
  legacy?: string;
}

function parseAgentHeader(raw: string | null): AgentHeader | null | "error" {
  if (raw === null) return null;
  try {
    const dict = parseDictionary(raw);
    // A bare host (draft-00 style, e.g. `signer.example.com`) parses as a boolean-only dictionary.
    const allBare = [...dict.values()].every((m) => m.kind === "item" && m.value === true);
    if (dict.size > 0 && allBare && !raw.includes("=")) return { legacy: raw.trim() };
    return { dict };
  } catch {
    try {
      const it = parseItem(raw);
      if (typeof it.value === "string") return { legacy: it.value };
    } catch {
      /* fall through */
    }
    return "error";
  }
}

function discoveryFor(
  label: string,
  inner: InnerList,
  agent: AgentHeader | null,
): { discovery?: Discovery; error?: string } {
  if (!agent) return {};
  const covered = inner.items.filter((i) => i.value === "signature-agent");
  if (agent.legacy !== undefined) {
    if (!covered.some((i) => i.params.size === 0)) return { error: "Signature-Agent present but not covered" };
    return { discovery: { value: agent.legacy, type: "directory" } };
  }
  const dict = agent.dict!;
  const keyed = covered.find((i) => typeof i.params.get("key") === "string");
  if (keyed) {
    const memberName = keyed.params.get("key") as string;
    const m = dict.get(memberName);
    if (!m || m.kind !== "item" || typeof m.value !== "string") {
      return { error: `Signature-Agent member "${memberName}" missing or not a string` };
    }
    const type = (str(m.params.get("type")) ?? "directory") as DiscoveryType;
    if (!["directory", "jwks_uri", "cimd"].includes(type)) return { error: `unsupported discovery type ${type}` };
    return { discovery: { value: m.value, type } };
  }
  if (dict.has(label)) return { error: `Signature-Agent member "${label}" is not covered by the signature` };
  return {};
}

function agentOrigin(value: string, type: DiscoveryType): string | undefined {
  try {
    return normalizeDiscoveryUrl(value, type).origin;
  } catch {
    return undefined;
  }
}

export interface Verifier {
  verify(req: RequestLike, context?: MessageContext): Promise<VerificationResult>;
}

export function createVerifier(options: VerifyOptions = {}): Verifier {
  const now = options.now ?? (() => Date.now());
  const skew = options.clockSkewSeconds ?? 60;
  const maxValidity = options.maxValiditySeconds ?? 86_400;
  const resolver = options.directory === false ? null : (options.directory ?? createDirectoryResolver());
  const nonceStore = options.nonceStore === false ? null : (options.nonceStore ?? createMemoryNonceStore(100_000, now));
  let staticKeys: Promise<Array<StaticKey & { thumbprint: string }>> | null = null;
  const getStaticKeys = () =>
    (staticKeys ??= Promise.all(
      (options.keys ?? []).map(async (k) => ({ ...k, thumbprint: await jwkThumbprint(k.jwk) })),
    ));

  async function verifyOne(
    req: RequestLike,
    label: string,
    inner: InnerList,
    sigItem: Item | undefined,
    agent: AgentHeader | null,
    ctx: MessageContext | undefined,
  ): Promise<SignatureResult> {
    const components = inner.items.map(serializeItem);
    const p = inner.params;
    const r: SignatureResult = {
      label,
      outcome: "invalid",
      reason: "",
      components,
      keyid: str(p.get("keyid")),
      alg: str(p.get("alg")),
      created: int(p.get("created")),
      expires: int(p.get("expires")),
      nonce: str(p.get("nonce")),
    };
    const fail = (outcome: VerifyOutcome, reason: string): SignatureResult => Object.assign(r, { outcome, reason });

    if (!sigItem || sigItem.kind !== "item" || !(sigItem.value instanceof Uint8Array)) {
      return fail("invalid", `no Signature value for label ${label}`);
    }
    if (r.created === undefined) return fail("invalid", "created parameter is required");
    if (r.expires === undefined) return fail("invalid", "expires parameter is required");
    if (!r.keyid) return fail("invalid", "keyid parameter is required");
    const t = now() / 1000;
    if (r.created > t + skew) return fail("invalid", "created is in the future");
    if (r.expires < t - skew) return fail("invalid", "signature expired");
    if (r.expires <= r.created) return fail("invalid", "expires must be after created");
    if (r.expires - r.created > maxValidity) return fail("invalid", "validity window exceeds policy");
    if (!components.some((c) => c === '"@authority"' || c === '"@target-uri"')) {
      return fail("invalid", "signature must cover @authority or @target-uri");
    }
    if (r.alg !== undefined && !SUPPORTED_ALGS.includes(r.alg as SigAlg)) {
      return fail("invalid", `unsupported alg ${r.alg}`);
    }
    if (!options.allowTestKeys && KNOWN_TEST_KEY_THUMBPRINTS.has(r.keyid)) {
      return fail("invalid", "signed with a published test key");
    }
    if (options.requireNonce && !r.nonce) return fail("invalid", "nonce is required");

    const { discovery, error } = discoveryFor(label, inner, agent);
    if (error) return fail("invalid", error);
    if (discovery) r.signatureAgent = agentOrigin(discovery.value, discovery.type);

    // Key resolution: out-of-band keys first, then the covered Signature-Agent directory.
    let jwk: JsonWebKey | undefined;
    const statics = await getStaticKeys();
    const st = statics.find((k) => k.thumbprint === r.keyid);
    if (st) {
      jwk = st.jwk;
      if (st.name) r.agentName = st.name;
    } else if (discovery && resolver) {
      try {
        const keys = await resolver.resolve(discovery.value, discovery.type);
        jwk = keys.find((k) => k.thumbprint === r.keyid)?.jwk;
        if (!jwk) return fail("unverified", "keyid not found in agent directory");
      } catch (e) {
        return fail("unverified", `key discovery failed: ${(e as Error).message}`);
      }
    }
    if (!jwk) return fail("unverified", "unknown keyid and no usable Signature-Agent");
    if (r.signatureAgent && !r.agentName) r.agentName = options.agentNames?.[r.signatureAgent];

    const jw = jwk as JsonWebKey & { nbf?: number; exp?: number };
    if (typeof jw.nbf === "number" && jw.nbf > t + skew) return fail("invalid", "key not yet valid (nbf)");
    if (typeof jw.exp === "number" && jw.exp < t - skew) return fail("invalid", "key expired (exp)");

    const alg = (r.alg as SigAlg | undefined) ?? inferAlg(jwk);
    if (!alg || !algMatchesKey(alg, jwk)) return fail("invalid", "alg does not match key type");

    let base: string;
    try {
      base = createSignatureBase(req, inner, ctx);
    } catch (e) {
      if (e instanceof ComponentError) return fail("invalid", e.message);
      throw e;
    }
    let ok = false;
    try {
      const key = await importPublicKey(jwk, alg);
      ok = await crypto.subtle.verify(
        signatureAlgorithm(alg),
        key,
        toBufferSource(sigItem.value),
        toBufferSource(utf8(base)),
      );
    } catch (e) {
      return fail("invalid", `verification error: ${(e as Error).message}`);
    }
    if (!ok) return fail("invalid", "signature does not match");

    if (r.nonce && nonceStore) {
      const fresh = await nonceStore.checkAndRemember(r.nonce, r.keyid, (r.expires + skew) * 1000);
      if (!fresh) return fail("invalid", "nonce replayed");
    }
    return fail("verified", "signature verified");
  }

  return {
    async verify(req, context) {
      const ctx = context ?? options.context;
      const inputRaw = req.headers.get("signature-input");
      const sigRaw = req.headers.get("signature");
      if (inputRaw === null && sigRaw === null) {
        return { outcome: "absent", reason: "no signature headers", signatures: [] };
      }
      if (inputRaw === null || sigRaw === null) {
        return { outcome: "invalid", reason: "Signature and Signature-Input must both be present", signatures: [] };
      }
      let inputs: Dictionary;
      let sigs: Dictionary;
      try {
        inputs = parseDictionary(inputRaw);
        sigs = parseDictionary(sigRaw);
      } catch (e) {
        return { outcome: "invalid", reason: `malformed signature headers: ${(e as Error).message}`, signatures: [] };
      }
      const agent = parseAgentHeader(req.headers.get("signature-agent"));
      if (agent === "error") return { outcome: "invalid", reason: "malformed Signature-Agent header", signatures: [] };

      const results: SignatureResult[] = [];
      for (const [label, member] of inputs) {
        if (member.kind !== "inner") {
          results.push({ label, outcome: "invalid", reason: "Signature-Input member is not an inner list", components: [] });
          continue;
        }
        if (str(member.params.get("tag")) !== "web-bot-auth") continue; // other schemes are not ours to judge
        results.push(await verifyOne(req, label, member, sigs.get(label) as Item | undefined, agent, ctx));
      }
      if (results.length === 0) return { outcome: "absent", reason: "no web-bot-auth signatures", signatures: [] };
      const verified = results.find((r) => r.outcome === "verified");
      if (verified) return { outcome: "verified", reason: verified.reason, signatures: results, verified };
      const invalid = results.find((r) => r.outcome === "invalid");
      if (invalid) return { outcome: "invalid", reason: invalid.reason, signatures: results };
      return { outcome: "unverified", reason: results[0]!.reason, signatures: results };
    },
  };
}

/** One-shot convenience. Prefer `createVerifier` so caches persist between requests. */
export async function verifyWebBotAuth(req: RequestLike, options?: VerifyOptions): Promise<VerificationResult> {
  return createVerifier(options).verify(req);
}

// Signs requests the Web Bot Auth way. Useful for agent builders and for testing your own gate.

import { bytesToBase64, bytesToBase64Url, toBufferSource, utf8 } from "../b64.js";
import { type BareItem, innerList, item, serializeInnerList, serializeItem } from "../sf.js";
import { createSignatureBase, type MessageContext } from "./base.js";
import type { DiscoveryType } from "./directory.js";
import { importPrivateKey, inferAlg, jwkThumbprint, type SigAlg, signatureAlgorithm, toPublicJwk } from "./jwk.js";

export interface SignatureAgentSpec {
  /** Where verifiers find your key material, e.g. "https://agent.example". */
  url: string;
  type?: DiscoveryType;
  /** Dictionary member name. Defaults to the signature label (recommended by the draft). */
  key?: string;
  /** Emit the pre-04 sf-string form instead of a dictionary. Only for old verifiers. */
  legacy?: boolean;
}

export interface SignOptions {
  privateJwk: JsonWebKey;
  alg?: SigAlg;
  /** Defaults to the RFC 7638 thumbprint of the public key. */
  keyid?: string;
  label?: string;
  signatureAgent?: SignatureAgentSpec | string;
  /** Components to cover besides Signature-Agent. Default ["@authority"]. */
  components?: string[];
  /** Seconds since epoch. Default now. */
  created?: number;
  /** Seconds since epoch. Default created + ttlSeconds. */
  expires?: number;
  /** Default 300 s. */
  ttlSeconds?: number;
  /** Random 64 bytes (base64url) by default; pass a string to pin it or false to omit. */
  nonce?: string | false;
  /** Include alg in Signature-Input. Default true. */
  includeAlg?: boolean;
  tag?: string;
  context?: MessageContext;
}

export interface SignedHeaders {
  signature: string;
  "signature-input": string;
  "signature-agent"?: string;
}

export async function signRequest(
  request: { method: string; url: string; headers?: HeadersInit },
  options: SignOptions,
): Promise<SignedHeaders> {
  const label = options.label ?? "sig1";
  const alg = options.alg ?? inferAlg(options.privateJwk);
  if (!alg) throw new Error("cannot infer alg from key; pass options.alg");
  const keyid = options.keyid ?? (await jwkThumbprint(toPublicJwk(options.privateJwk)));
  const created = options.created ?? Math.floor(Date.now() / 1000);
  const expires = options.expires ?? created + (options.ttlSeconds ?? 300);
  const nonce =
    options.nonce === false
      ? undefined
      : (options.nonce ?? bytesToBase64Url(crypto.getRandomValues(new Uint8Array(64))));

  const headers = new Headers(request.headers);
  const comps = (options.components ?? ["@authority"]).map((c) => item(c));
  const out: Partial<SignedHeaders> = {};

  const sa = typeof options.signatureAgent === "string" ? { url: options.signatureAgent } : options.signatureAgent;
  if (sa) {
    if (sa.legacy) {
      out["signature-agent"] = `"${sa.url}"`;
      comps.push(item("signature-agent"));
    } else {
      const memberKey = sa.key ?? label;
      const typeParam = sa.type && sa.type !== "directory" ? `;type=${sa.type}` : "";
      out["signature-agent"] = `${memberKey}=${serializeItem(item(sa.url))}${typeParam}`;
      comps.push(item("signature-agent", { key: memberKey }));
    }
    headers.set("signature-agent", out["signature-agent"]!);
  }

  const params: Record<string, BareItem> = { created, keyid };
  if (options.includeAlg !== false) params.alg = alg;
  params.expires = expires;
  if (nonce) params.nonce = nonce;
  params.tag = options.tag ?? "web-bot-auth";
  const inner = innerList(comps, params);

  const base = createSignatureBase({ method: request.method, url: request.url, headers }, inner, options.context);
  const key = await importPrivateKey(options.privateJwk, alg);
  const sig = new Uint8Array(
    await crypto.subtle.sign(signatureAlgorithm(alg), key, toBufferSource(utf8(base))),
  );
  out["signature-input"] = `${label}=${serializeInnerList(inner)}`;
  out.signature = `${label}=:${bytesToBase64(sig)}:`;
  return out as SignedHeaders;
}

/** Build the JSON document to serve at /.well-known/http-message-signatures-directory. */
export function directoryDocument(publicJwks: JsonWebKey[]): { keys: JsonWebKey[] } {
  return { keys: publicJwks.map(toPublicJwk) };
}

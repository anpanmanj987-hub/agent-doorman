// Key discovery for Web Bot Auth (draft-meunier-webbotauth-httpsig-protocol §4.5)
// with the SSRF precautions from §5.8 and the caching guidance from Appendix A.

import { jwkThumbprint } from "./jwk.js";

export type DiscoveryType = "directory" | "jwks_uri" | "cimd";
export const WELL_KNOWN_DIRECTORY = "/.well-known/http-message-signatures-directory";

export interface DirectoryKey {
  jwk: JsonWebKey;
  thumbprint: string;
}

export interface DirectoryResolver {
  /** Resolve candidate keys named by a Signature-Agent member. Throws DirectoryError when unavailable. */
  resolve(value: string, type?: DiscoveryType): Promise<DirectoryKey[]>;
}

/** Throw from a HostGuard to block a fetch. */
export type HostGuard = (url: URL) => void | Promise<void>;

export interface DirectoryResolverOptions {
  fetch?: typeof fetch;
  /** Wall-clock timeout per fetch, including the body. Default 3000 ms. */
  timeoutMs?: number;
  /** Max decoded body size. Default 64 KiB. */
  maxBytes?: number;
  /** Max keys accepted in one directory. Default 32. */
  maxKeys?: number;
  /** Max redirects followed. Default 2. */
  maxRedirects?: number;
  /** Allow plain-http directories (tests/dev only). Default false. */
  allowHttp?: boolean;
  /** Address filter. Default: `defaultHostGuard` (blocks IP literals in private ranges and localhost). */
  hostGuard?: HostGuard;
  defaultTtlSeconds?: number;
  minTtlSeconds?: number;
  maxTtlSeconds?: number;
  /** Negative cache lifetime; capped at 300 s per Appendix A.5. */
  negativeTtlSeconds?: number;
  now?: () => number;
}

export class DirectoryError extends Error {
  override name = "DirectoryError";
}

// ------------------------------------------------------------- address checks

function ipv4ToInt(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return ((parts[0]! << 24) | (parts[1]! << 16) | (parts[2]! << 8) | parts[3]!) >>> 0;
}

const V4_BLOCKS: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

function inV4Block(n: number, base: string, bits: number): boolean {
  const b = ipv4ToInt(base)!;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (n & mask) === (b & mask);
}

function expandIPv6(ip: string): number[] | null {
  let s = ip.toLowerCase();
  const zone = s.indexOf("%");
  if (zone >= 0) s = s.slice(0, zone);
  // Embedded IPv4 tail.
  const v4m = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (v4m) {
    const n = ipv4ToInt(v4m[1]!);
    if (n === null) return null;
    s = s.slice(0, -v4m[1]!.length) + ((n >>> 16).toString(16) + ":" + (n & 0xffff).toString(16));
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null;
  const groups = [...head, ...Array(fill).fill("0"), ...tail].map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? parseInt(g, 16) : NaN));
  if (groups.length !== 8 || groups.some(Number.isNaN)) return null;
  return groups;
}

/** True for loopback, private, link-local, CGNAT, documentation, multicast and similar non-public addresses. */
export function isPrivateAddress(ip: string): boolean {
  const v4 = ipv4ToInt(ip);
  if (v4 !== null) return V4_BLOCKS.some(([b, bits]) => inV4Block(v4, b, bits));
  const g = expandIPv6(ip.replace(/^\[|\]$/g, ""));
  if (!g) return false;
  if (g.every((x) => x === 0)) return true; // ::
  if (g.slice(0, 7).every((x) => x === 0) && g[7] === 1) return true; // ::1
  if ((g[0]! & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
  if ((g[0]! & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  if ((g[0]! & 0xff00) === 0xff00) return true; // multicast
  if (g[0] === 0x2001 && g[1] === 0x0db8) return true; // documentation
  // IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible
  if (g.slice(0, 5).every((x) => x === 0) && (g[5] === 0xffff || g[5] === 0)) {
    const n = ((g[6]! << 16) | g[7]!) >>> 0;
    const dotted = [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
    return isPrivateAddress(dotted);
  }
  return false;
}

export function isIpLiteral(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "");
  return ipv4ToInt(h) !== null || expandIPv6(h) !== null;
}

/**
 * Runtime-agnostic guard: blocks localhost names and private IP literals.
 * It cannot see DNS answers; on Node use `nodeHostGuard` from "agent-doorman/node",
 * which also resolves hostnames and rejects private answers.
 */
export const defaultHostGuard: HostGuard = (url) => {
  const host = url.hostname.toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost") || host.endsWith(".internal") || host.endsWith(".local")) {
    throw new DirectoryError(`blocked host ${host}`);
  }
  if (isIpLiteral(host) && isPrivateAddress(host)) throw new DirectoryError(`blocked private address ${host}`);
};

// ------------------------------------------------------------------ resolver

export function normalizeDiscoveryUrl(value: string, type: DiscoveryType = "directory"): URL {
  const raw = value.trim();
  const url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  if (url.username || url.password) throw new DirectoryError("credentials in discovery URL are not allowed");
  url.hash = "";
  if (type === "directory" && (url.pathname === "/" || url.pathname === "")) url.pathname = WELL_KNOWN_DIRECTORY;
  return url;
}

function maxAgeSeconds(cacheControl: string | null): number | undefined {
  if (!cacheControl) return undefined;
  if (/\b(no-store|no-cache)\b/i.test(cacheControl)) return 0;
  const m = /\bs-maxage=(\d+)/i.exec(cacheControl) ?? /\bmax-age=(\d+)/i.exec(cacheControl);
  return m ? Number(m[1]) : undefined;
}

async function readCapped(res: Response, maxBytes: number): Promise<string> {
  const declared = Number(res.headers.get("content-length") ?? "NaN");
  if (Number.isFinite(declared) && declared > maxBytes) throw new DirectoryError("directory response too large");
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new DirectoryError("directory response too large");
    }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    all.set(c, off);
    off += c.byteLength;
  }
  return new TextDecoder().decode(all);
}

interface CacheEntry {
  until: number;
  keys?: DirectoryKey[];
  error?: string;
}

export function createDirectoryResolver(options: DirectoryResolverOptions = {}): DirectoryResolver {
  const fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs ?? 3000;
  const maxBytes = options.maxBytes ?? 64 * 1024;
  const maxKeys = options.maxKeys ?? 32;
  const maxRedirects = options.maxRedirects ?? 2;
  const guard = options.hostGuard ?? defaultHostGuard;
  const minTtl = options.minTtlSeconds ?? 60;
  const maxTtl = options.maxTtlSeconds ?? 86_400;
  const defaultTtl = options.defaultTtlSeconds ?? 3600;
  const negativeTtl = Math.min(options.negativeTtlSeconds ?? 300, 300);
  const now = options.now ?? (() => Date.now());
  const cache = new Map<string, CacheEntry>();
  const inflight = new Map<string, Promise<DirectoryKey[]>>();

  async function fetchJson(start: URL): Promise<{ json: unknown; ttl: number }> {
    let current = start;
    for (let hop = 0; ; hop++) {
      if (current.protocol !== "https:" && !(options.allowHttp && current.protocol === "http:")) {
        throw new DirectoryError(`refusing non-https directory ${current.origin}`);
      }
      await guard(current);
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetchImpl(current, {
          redirect: "manual",
          signal: controller.signal,
          headers: {
            accept:
              "application/http-message-signatures-directory+json, application/jwk-set+json, application/json;q=0.9",
          },
        });
        const location = res.headers.get("location");
        if (res.status >= 300 && res.status < 400 && location) {
          if (hop >= maxRedirects) throw new DirectoryError("too many redirects");
          await res.body?.cancel().catch(() => {});
          current = new URL(location, current);
          continue;
        }
        if (!res.ok) throw new DirectoryError(`directory fetch failed: HTTP ${res.status}`);
        const text = await readCapped(res, maxBytes);
        let json: unknown;
        try {
          json = JSON.parse(text);
        } catch {
          throw new DirectoryError("directory is not valid JSON");
        }
        const age = maxAgeSeconds(res.headers.get("cache-control"));
        const ttl = Math.min(maxTtl, Math.max(minTtl, age ?? defaultTtl));
        return { json, ttl };
      } catch (e) {
        if (e instanceof DirectoryError) throw e;
        if (controller.signal.aborted) throw new DirectoryError("directory fetch timed out");
        throw new DirectoryError(`directory fetch failed: ${(e as Error).message}`);
      } finally {
        clearTimeout(timer);
      }
    }
  }

  async function keysFrom(json: unknown): Promise<DirectoryKey[]> {
    const keys = (json as { keys?: unknown })?.keys;
    if (!Array.isArray(keys)) throw new DirectoryError("directory has no 'keys' array");
    if (keys.length > maxKeys) throw new DirectoryError(`directory has more than ${maxKeys} keys`);
    const out: DirectoryKey[] = [];
    for (const k of keys) {
      if (!k || typeof k !== "object") continue;
      try {
        out.push({ jwk: k as JsonWebKey, thumbprint: await jwkThumbprint(k as JsonWebKey) });
      } catch {
        // unsupported key type: skip
      }
    }
    return out;
  }

  async function load(url: URL, type: DiscoveryType): Promise<{ keys: DirectoryKey[]; ttl: number }> {
    const { json, ttl } = await fetchJson(url);
    if (type !== "cimd") return { keys: await keysFrom(json), ttl };
    const doc = json as { jwks?: unknown; jwks_uri?: unknown };
    if (doc.jwks) return { keys: await keysFrom(doc.jwks), ttl };
    if (typeof doc.jwks_uri === "string") {
      const inner = await fetchJson(normalizeDiscoveryUrl(doc.jwks_uri, "jwks_uri"));
      return { keys: await keysFrom(inner.json), ttl: Math.min(ttl, inner.ttl) };
    }
    throw new DirectoryError("client metadata document has neither jwks nor jwks_uri");
  }

  return {
    async resolve(value, type = "directory") {
      const url = normalizeDiscoveryUrl(value, type);
      const cacheKey = `${type} ${url.href}`;
      const hit = cache.get(cacheKey);
      if (hit && hit.until > now()) {
        if (hit.keys) return hit.keys;
        throw new DirectoryError(hit.error ?? "directory unavailable (cached)");
      }
      const pending = inflight.get(cacheKey);
      if (pending) return pending;
      const p = load(url, type)
        .then(({ keys, ttl }) => {
          cache.set(cacheKey, { until: now() + ttl * 1000, keys });
          return keys;
        })
        .catch((e: unknown) => {
          const msg = e instanceof Error ? e.message : String(e);
          cache.set(cacheKey, { until: now() + negativeTtl * 1000, error: msg });
          throw e instanceof DirectoryError ? e : new DirectoryError(msg);
        })
        .finally(() => inflight.delete(cacheKey));
      inflight.set(cacheKey, p);
      return p;
    },
  };
}

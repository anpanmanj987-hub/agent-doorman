// Rate limiting. The default store is in-memory and per-process (per-isolate on edge runtimes).
// For multi-instance deployments plug in a shared store (Redis, Durable Objects, KV...).

import type { Rate } from "./policy.js";

export interface RateLimitStore {
  /** Consume one unit for `key`. */
  take(key: string, rate: Rate): Promise<{ ok: boolean; retryAfterSeconds: number }> | { ok: boolean; retryAfterSeconds: number };
}

interface Bucket {
  tokens: number;
  updated: number;
  rate: Rate;
}

export function createMemoryRateLimitStore(options: { maxKeys?: number; now?: () => number } = {}): RateLimitStore {
  const maxKeys = options.maxKeys ?? 50_000;
  const now = options.now ?? (() => Date.now());
  const buckets = new Map<string, Bucket>();

  function refill(b: Bucket, t: number): void {
    const elapsed = Math.max(0, t - b.updated);
    b.tokens = Math.min(b.rate.limit, b.tokens + (elapsed * b.rate.limit) / b.rate.windowMs);
    b.updated = t;
  }

  return {
    take(key, rate) {
      const t = now();
      let b = buckets.get(key);
      if (!b || b.rate.limit !== rate.limit || b.rate.windowMs !== rate.windowMs) {
        if (buckets.size >= maxKeys) {
          // Evict full (idle) buckets first, then the oldest.
          for (const [k, v] of buckets) {
            refill(v, t);
            if (v.tokens >= v.rate.limit) buckets.delete(k);
          }
          while (buckets.size >= maxKeys) {
            const oldest = buckets.keys().next().value;
            if (oldest === undefined) break;
            buckets.delete(oldest);
          }
        }
        b = { tokens: rate.limit, updated: t, rate };
        buckets.set(key, b);
      } else {
        refill(b, t);
      }
      if (b.tokens >= 1) {
        b.tokens -= 1;
        return { ok: true, retryAfterSeconds: 0 };
      }
      const msPerToken = rate.windowMs / rate.limit;
      return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil(((1 - b.tokens) * msPerToken) / 1000)) };
    },
  };
}

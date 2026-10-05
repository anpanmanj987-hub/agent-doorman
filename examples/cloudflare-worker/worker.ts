// Cloudflare Worker in front of your origin. Bundle with wrangler (it resolves "agent-doorman").
// State (rate limits, nonces) is per isolate; plug in Durable Objects/KV stores for global limits.
import { createDoorman, presets } from "agent-doorman";

const doorman = createDoorman({
  policy: presets.ecommerce(),
  mode: "monitor",
  // Agents sign the public hostname; the Worker sees it directly, so no proxy trust is needed here.
  onDecision: (d) => console.log(JSON.stringify(d)),
});

export default {
  async fetch(request: Request): Promise<Response> {
    const blocked = await doorman.guard(request, { ip: request.headers.get("cf-connecting-ip") ?? undefined });
    if (blocked) return blocked;
    return fetch(request); // continue to your origin
  },
};

import { createDoorman, presets } from "agent-doorman";
declare const PUBLIC_JWK: JsonWebKey;
const decisions: unknown[] = [];
const doorman = createDoorman({
  policy: presets.ecommerce(),
  mode: "enforce",
  verify: { keys: [{ jwk: PUBLIC_JWK, name: "Edge test agent" }], directory: false },
  onDecision: (d) => void decisions.push(d),
});
export default {
  async fetch(request: Request): Promise<Response> {
    const blocked = await doorman.guard(request);
    if (blocked) return blocked;
    const last = decisions.at(-1) as { trust: { class: string; agent?: string } } | undefined;
    return new Response(`origin ok: ${last?.trust.class} ${last?.trust.agent ?? ""}`);
  },
};

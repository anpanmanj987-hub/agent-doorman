import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { createDoorman, type Decision } from "../src/gate/doorman.js";
import { presets } from "../src/gate/policy.js";
import { generateKeyPair } from "../src/httpsig/jwk.js";
import { signRequest } from "../src/httpsig/sign.js";
import { nodeMiddleware } from "../src/node.js";
import { startServer } from "./helpers.js";

const CHROME = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36";
const GPTBOT = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)";

describe("doorman", () => {
  let kp: Awaited<ReturnType<typeof generateKeyPair>>;
  before(async () => {
    kp = await generateKeyPair();
  });

  const make = (mode: "monitor" | "enforce", log: Decision[] = []) =>
    createDoorman({
      policy: presets.ecommerce(),
      mode,
      verify: { keys: [{ jwk: kp.publicJwk, name: "Acme shopper" }], directory: false },
      onDecision: (d) => void log.push(d),
    });

  it("classifies visitors", async () => {
    const d = make("enforce");
    const ev = async (h: Record<string, string>, url = "https://shop.example/") => (await d.evaluate(new Request(url, { headers: h }))).trust;
    assert.equal((await ev({ "user-agent": CHROME })).class, "browser");
    const claimed = await ev({ "user-agent": GPTBOT });
    assert.equal(claimed.class, "claimed");
    assert.equal(claimed.vendor, "OpenAI");
    assert.equal((await ev({ "user-agent": "curl/8.5.0" })).class, "automated");
    assert.equal((await ev({})).class, "automated");
    const signed = await signRequest({ method: "GET", url: "https://shop.example/" }, { privateJwk: kp.privateJwk, signatureAgent: "https://acme.example" });
    const v = await ev({ "user-agent": GPTBOT, ...signed });
    assert.equal(v.class, "verified");
    assert.equal(v.agent, "Acme shopper");
  });

  it("does not mistake substrings for agent tokens", async () => {
    const d = make("enforce");
    const t = (await d.evaluate(new Request("https://shop.example/", { headers: { "user-agent": "NotGPTBotReally/1.0" } }))).trust;
    assert.notEqual(t.class, "claimed");
  });

  it("monitor mode decides but never blocks", async () => {
    const log: Decision[] = [];
    const d = make("monitor", log);
    const res = await d.guard(new Request("https://shop.example/checkout", { headers: { "user-agent": GPTBOT } }));
    assert.equal(res, undefined);
    assert.equal(log[0]!.action, "challenge");
    assert.equal(log[0]!.enforced, false);
  });

  it("enforce mode challenges claimed agents on checkout with Accept-Signature", async () => {
    const d = make("enforce");
    const res = await d.guard(new Request("https://shop.example/checkout", { headers: { "user-agent": GPTBOT } }));
    assert.ok(res);
    assert.equal(res.status, 403);
    assert.match(res.headers.get("accept-signature") ?? "", /tag="web-bot-auth"/);
    const body = (await res.json()) as { error: string; trust: string; rule: string };
    assert.deepEqual([body.error, body.trust, body.rule], ["agent_not_permitted", "claimed", "checkout"]);
  });

  it("enforce mode admits browsers and verified agents on checkout", async () => {
    const d = make("enforce");
    assert.equal(await d.guard(new Request("https://shop.example/checkout", { headers: { "user-agent": CHROME } })), undefined);
    const signed = await signRequest({ method: "POST", url: "https://shop.example/checkout/pay" }, { privateJwk: kp.privateJwk });
    assert.equal(await d.guard(new Request("https://shop.example/checkout/pay", { method: "POST", headers: signed as unknown as HeadersInit })), undefined);
  });

  it("refuses forged signatures even on browse pages", async () => {
    const d = make("enforce");
    const signed = await signRequest({ method: "GET", url: "https://shop.example/" }, { privateJwk: kp.privateJwk });
    const tampered = { ...signed, signature: signed.signature.replace(/:(.)/, (_m, c: string) => `:${c === "A" ? "B" : "A"}`) };
    const res = await d.guard(new Request("https://shop.example/", { headers: tampered as unknown as HeadersInit }));
    assert.equal(res?.status, 403);
  });

  it("rate limits per class with Retry-After", async () => {
    const d = createDoorman({
      policy: { version: 1, rules: [{ name: "read", allow: "*", rateLimit: { claimed: "2/min" } }] },
      mode: "enforce",
      verify: { directory: false },
    });
    const req = () => new Request("https://shop.example/", { headers: { "user-agent": GPTBOT } });
    assert.equal(await d.guard(req(), { ip: "203.0.113.9" }), undefined);
    assert.equal(await d.guard(req(), { ip: "203.0.113.9" }), undefined);
    const third = await d.guard(req(), { ip: "203.0.113.9" });
    assert.equal(third?.status, 429);
    assert.ok(Number(third?.headers.get("retry-after")) >= 1);
    assert.equal(await d.guard(req(), { ip: "198.51.100.7" }), undefined);
  });

  it("serves the public policy and exempts well-known paths", async () => {
    const d = make("enforce");
    const res = await d.guard(new Request("https://shop.example/.well-known/agent-policy.json", { headers: { "user-agent": "curl/8" } }));
    assert.equal(res?.status, 200);
    assert.equal(((await res!.json()) as { generator: string }).generator, "agent-doorman");
    assert.equal(await d.guard(new Request("https://shop.example/robots.txt", { headers: { "user-agent": "curl/8" } })), undefined);
  });

  describe("node middleware", () => {
    let srv: Awaited<ReturnType<typeof startServer>>;
    const seen: Array<Decision | undefined> = [];
    before(async () => {
      const mw = nodeMiddleware(make("enforce"));
      srv = await startServer(async (req, res) => {
        await mw(req, res, () => {
          seen.push(req.agentDoorman);
          res.setHeader("content-type", "text/plain");
          res.end("welcome");
        });
      });
    });
    after(() => srv.close());

    it("passes allowed requests through with the decision attached", async () => {
      const r = await fetch(`${srv.url}/products`, { headers: { "user-agent": CHROME } });
      assert.equal(await r.text(), "welcome");
      assert.equal(seen.at(-1)?.trust.class, "browser");
    });

    it("answers refused requests itself", async () => {
      const r = await fetch(`${srv.url}/account/orders`, { headers: { "user-agent": GPTBOT } });
      assert.equal(r.status, 403);
      assert.ok(r.headers.get("accept-signature"));
    });

    it("admits a verified agent over real HTTP", async () => {
      const url = `${srv.url}/checkout`;
      const signed = await signRequest({ method: "GET", url }, { privateJwk: kp.privateJwk });
      const r = await fetch(url, { headers: { "user-agent": GPTBOT, ...signed } });
      assert.equal(r.status, 200);
      assert.equal(seen.at(-1)?.trust.class, "verified");
    });
  });
});

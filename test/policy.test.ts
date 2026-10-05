import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { compileGlob, compilePolicy, parseRate, PolicyError, presets, publicPolicyDocument, validatePolicy } from "../src/gate/policy.js";

describe("policy", () => {
  it("compiles globs", () => {
    const deep = compileGlob("/checkout/**");
    assert.ok(deep.test("/checkout"));
    assert.ok(deep.test("/checkout/pay/now"));
    assert.ok(!deep.test("/checkouts"));
    const one = compileGlob("/p/*/reviews");
    assert.ok(one.test("/p/123/reviews"));
    assert.ok(!one.test("/p/1/2/reviews"));
    assert.ok(compileGlob("/**").test("/anything/at/all"));
  });

  it("parses rates", () => {
    assert.deepEqual(parseRate("60/min"), { limit: 60, windowMs: 60_000 });
    assert.deepEqual(parseRate("10/s"), { limit: 10, windowMs: 1000 });
    assert.deepEqual(parseRate("1000 / hour"), { limit: 1000, windowMs: 3_600_000 });
    assert.deepEqual(parseRate("5/10min"), { limit: 5, windowMs: 600_000 });
    assert.throws(() => parseRate("lots"), PolicyError);
    assert.throws(() => parseRate("0/min"), PolicyError);
  });

  it("validates with readable errors", () => {
    assert.throws(() => validatePolicy({ version: 2, rules: [] }), /version/);
    assert.throws(() => validatePolicy({ version: 1, rules: [{ name: "x", allow: ["robots"] }] }), /unknown class "robots"/);
    assert.throws(() => validatePolicy({ version: 1, rules: [{ name: "x", allow: "*", match: { paths: ["cart"] } }] }), /must start with/);
    assert.throws(() => validatePolicy({ version: 1, rules: [{ name: "a", allow: "*" }, { name: "a", allow: "*" }] }), /duplicate/);
    assert.throws(() => validatePolicy({ version: 1, rules: [{ name: "a", allow: "*", rateLimit: { claimed: "fast" } }] }), /invalid rate/);
  });

  it("presets are valid and match as intended", () => {
    for (const p of Object.values(presets)) validatePolicy(p());
    const c = compilePolicy(presets.ecommerce());
    assert.equal(c.match("GET", "/").name, "browse");
    assert.equal(c.match("GET", "/checkout").name, "checkout");
    assert.equal(c.match("POST", "/cart/items").name, "cart");
    assert.equal(c.match("GET", "/cart").name, "browse");
    assert.equal(c.match("POST", "/newsletter").name, "default");
    assert.ok(!c.match("GET", "/checkout").allows("claimed"));
    assert.ok(c.match("GET", "/").allows("claimed"));
    assert.ok(!c.match("GET", "/").allows("invalid"));
  });

  it("publishes a public document without rate limits", () => {
    const doc = publicPolicyDocument(presets.ecommerce()) as { rules: Array<Record<string, unknown>>; status: string };
    assert.equal(doc.status, "experimental");
    assert.ok(doc.rules.every((r) => !("rateLimit" in r)));
  });
});

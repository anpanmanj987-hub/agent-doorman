import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { generateKeyPair, type SigAlg } from "../src/httpsig/jwk.js";
import { signRequest } from "../src/httpsig/sign.js";
import { createVerifier } from "../src/httpsig/verify.js";

const URL_ = "https://shop.example/checkout?step=2";

async function signed(alg: SigAlg = "ed25519", extra: Parameters<typeof signRequest>[1] extends infer O ? Partial<O> : never = {}) {
  const kp = await generateKeyPair(alg);
  const headers = await signRequest(
    { method: "POST", url: URL_ },
    { privateJwk: kp.privateJwk, signatureAgent: "https://agent.example", ...extra },
  );
  return { kp, req: new Request(URL_, { method: "POST", headers: headers as unknown as HeadersInit }), headers };
}

describe("sign/verify round trips", () => {
  for (const alg of ["ed25519", "ecdsa-p256-sha256", "ecdsa-p384-sha384", "rsa-pss-sha512", "rsa-v1_5-sha256"] as SigAlg[]) {
    it(`verifies ${alg}`, async () => {
      const { kp, req } = await signed(alg);
      const v = createVerifier({ keys: [{ jwk: kp.publicJwk, name: "Acme agent" }], directory: false });
      const res = await v.verify(req);
      assert.equal(res.outcome, "verified", res.reason);
      assert.equal(res.verified?.agentName, "Acme agent");
      assert.equal(res.verified?.signatureAgent, "https://agent.example");
    });
  }

  it("covers the Signature-Agent member and uses the label as member key by default", async () => {
    const { headers } = await signed();
    assert.equal(headers["signature-agent"], 'sig1="https://agent.example"');
    assert.match(headers["signature-input"], /^sig1=\("@authority" "signature-agent";key="sig1"\);created=\d+;keyid="[^"]+";alg="ed25519";expires=\d+;nonce="[^"]+";tag="web-bot-auth"$/);
  });

  it("detects a request replayed against another host", async () => {
    const { kp, headers } = await signed();
    const v = createVerifier({ keys: [{ jwk: kp.publicJwk }], directory: false });
    const res = await v.verify(new Request("https://evil.example/checkout", { method: "POST", headers: headers as unknown as HeadersInit }));
    assert.equal(res.outcome, "invalid");
    assert.match(res.reason, /does not match/);
  });

  it("detects a swapped Signature-Agent", async () => {
    const { kp, headers } = await signed();
    const h = new Headers(headers as unknown as HeadersInit);
    h.set("signature-agent", 'sig1="https://attacker.example"');
    const v = createVerifier({ keys: [{ jwk: kp.publicJwk }], directory: false });
    assert.equal((await v.verify(new Request(URL_, { method: "POST", headers: h }))).outcome, "invalid");
  });

  it("rejects a Signature-Agent member for the label that is not covered", async () => {
    const kp = await generateKeyPair();
    const headers = await signRequest({ method: "GET", url: URL_ }, { privateJwk: kp.privateJwk });
    const h = new Headers(headers as unknown as HeadersInit);
    h.set("signature-agent", 'sig1="https://agent.example"');
    const v = createVerifier({ keys: [{ jwk: kp.publicJwk }], directory: false });
    const res = await v.verify(new Request(URL_, { headers: h }));
    assert.equal(res.outcome, "invalid");
    assert.match(res.reason, /not covered/);
  });

  it("rejects expired and future-dated signatures", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expired = await signed("ed25519", { created: now - 4000, expires: now - 3000 });
    const v1 = createVerifier({ keys: [{ jwk: expired.kp.publicJwk }], directory: false });
    assert.match((await v1.verify(expired.req)).reason, /expired/);
    const future = await signed("ed25519", { created: now + 3600, expires: now + 3900 });
    const v2 = createVerifier({ keys: [{ jwk: future.kp.publicJwk }], directory: false });
    assert.match((await v2.verify(future.req)).reason, /future/);
  });

  it("rejects replayed nonces", async () => {
    const { kp, req } = await signed();
    const v = createVerifier({ keys: [{ jwk: kp.publicJwk }], directory: false });
    assert.equal((await v.verify(req)).outcome, "verified");
    const again = await v.verify(req);
    assert.equal(again.outcome, "invalid");
    assert.match(again.reason, /replay/);
  });

  it("returns unverified (not invalid) when the key is unknown", async () => {
    const { req } = await signed();
    const v = createVerifier({ directory: false });
    const res = await v.verify(req);
    assert.equal(res.outcome, "unverified");
  });

  it("requires @authority or @target-uri coverage", async () => {
    const kp = await generateKeyPair();
    const headers = await signRequest({ method: "GET", url: URL_ }, { privateJwk: kp.privateJwk, components: ["@method"] });
    const v = createVerifier({ keys: [{ jwk: kp.publicJwk }], directory: false });
    const res = await v.verify(new Request(URL_, { headers: headers as unknown as HeadersInit }));
    assert.equal(res.outcome, "invalid");
    assert.match(res.reason, /@authority/);
  });

  it("ignores signatures with other tags and reports absent", async () => {
    const kp = await generateKeyPair();
    const headers = await signRequest({ method: "GET", url: URL_ }, { privateJwk: kp.privateJwk, tag: "other-app" });
    const v = createVerifier({ keys: [{ jwk: kp.publicJwk }], directory: false });
    assert.equal((await v.verify(new Request(URL_, { headers: headers as unknown as HeadersInit }))).outcome, "absent");
  });

  it("treats malformed headers as invalid, never throws", async () => {
    const v = createVerifier({ directory: false });
    for (const [input, sig] of [
      ["sig1=(", "sig1=:AA==:"],
      ['sig1=("@authority");created=1;keyid="x";tag="web-bot-auth"', "garbage"],
      ['sig1=("@authority");tag="web-bot-auth"', "sig1=:AA==:"],
    ] as const) {
      const res = await v.verify(new Request(URL_, { headers: { "signature-input": input, signature: sig } }));
      assert.equal(res.outcome, "invalid", `${input} / ${sig}`);
    }
  });

  it("uses the externally visible authority behind a trusted proxy", async () => {
    const { kp, headers } = await signed();
    const v = createVerifier({ keys: [{ jwk: kp.publicJwk }], directory: false });
    const internal = new Request("http://10.0.0.5:8080/checkout?step=2", { method: "POST", headers: headers as unknown as HeadersInit });
    assert.equal((await v.verify(internal)).outcome, "invalid");
    const v2 = createVerifier({ keys: [{ jwk: kp.publicJwk }], directory: false });
    assert.equal((await v2.verify(internal, { authority: "shop.example", scheme: "https" })).outcome, "verified");
  });
});

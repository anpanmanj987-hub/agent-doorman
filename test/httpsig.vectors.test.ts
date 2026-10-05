// Interop: the Ed25519 test vectors from draft-meunier-webbotauth-httpsig-protocol-00, Appendix C.2.
// Key: RFC 9421 Appendix B.1.4 (test-key-ed25519). The vectors and key are IETF Code Components
// under the Revised BSD License; see test/fixtures/IETF-LICENSE.txt. Ed25519 is deterministic, so we can also
// check that our signer reproduces the published signatures byte for byte.

import assert from "node:assert/strict";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { describe, it } from "node:test";
import { createSignatureBase } from "../src/httpsig/base.js";
import { jwkThumbprint } from "../src/httpsig/jwk.js";
import { signRequest } from "../src/httpsig/sign.js";
import { createVerifier } from "../src/httpsig/verify.js";
import { parseDictionary } from "../src/sf.js";

const PRIVATE_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF
-----END PRIVATE KEY-----`;
const PUBLIC_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
-----END PUBLIC KEY-----`;

const privateJwk = createPrivateKey(PRIVATE_PEM).export({ format: "jwk" }) as JsonWebKey;
const publicJwk = createPublicKey(PUBLIC_PEM).export({ format: "jwk" }) as JsonWebKey;
const KEYID = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
const NOW = 1735689600_000 + 30_000;

interface Vector {
  name: string;
  label: string;
  signatureAgent?: string;
  signatureInput: string;
  signature: string;
  base: string;
  sign: Parameters<typeof signRequest>[1];
}

const vectors: Vector[] = [
  {
    name: "C.2.1 Signature-Agent absent",
    label: "sig1",
    signatureInput:
      'sig1=("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="zIW8+cdmA3vdYagbxojpONwa/l0EKJ/O3/wD486VvsQjO/RxPaSt6ZxvQaMcQzNnqKN/mQ6hpGiFro2L2qkz5A==";tag="web-bot-auth"',
    signature:
      "sig1=:QKN4fTdIYfh82fvoZCQiQA1weuozfCS/Led2zTMbewMMqH8PI2Wsy/5c4ao6B6D09nraNQdBNOADg8aM1MqfCg==:",
    base: [
      '"@authority": example.com',
      '"@signature-params": ("@authority");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="zIW8+cdmA3vdYagbxojpONwa/l0EKJ/O3/wD486VvsQjO/RxPaSt6ZxvQaMcQzNnqKN/mQ6hpGiFro2L2qkz5A==";tag="web-bot-auth"',
    ].join("\n"),
    sign: {
      privateJwk,
      label: "sig1",
      created: 1735689600,
      expires: 4889289600,
      nonce: "zIW8+cdmA3vdYagbxojpONwa/l0EKJ/O3/wD486VvsQjO/RxPaSt6ZxvQaMcQzNnqKN/mQ6hpGiFro2L2qkz5A==",
    },
  },
  {
    name: "C.2.2 Signature-Agent dictionary member",
    label: "sig2",
    signatureAgent: 'agent2="https://signature-agent.test"',
    signatureInput:
      'sig2=("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"',
    signature:
      "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:",
    base: [
      '"@authority": example.com',
      '"signature-agent";key="agent2": "https://signature-agent.test"',
      '"@signature-params": ("@authority" "signature-agent";key="agent2");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=4889289600;nonce="n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==";tag="web-bot-auth"',
    ].join("\n"),
    sign: {
      privateJwk,
      label: "sig2",
      signatureAgent: { url: "https://signature-agent.test", key: "agent2" },
      created: 1735689600,
      expires: 4889289600,
      nonce: "n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==",
    },
  },
  {
    name: "C.2.3 legacy sf-string Signature-Agent",
    label: "sig2",
    signatureAgent: '"https://signature-agent.test"',
    signatureInput:
      'sig2=("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"',
    signature:
      "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:",
    base: [
      '"@authority": example.com',
      '"signature-agent": "https://signature-agent.test"',
      '"@signature-params": ("@authority" "signature-agent");created=1735689600;keyid="poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";alg="ed25519";expires=1735693200;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==";tag="web-bot-auth"',
    ].join("\n"),
    sign: {
      privateJwk,
      label: "sig2",
      signatureAgent: { url: "https://signature-agent.test", legacy: true },
      created: 1735689600,
      expires: 1735693200,
      nonce: "e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==",
    },
  },
];

function requestFor(v: Vector): Request {
  const headers = new Headers({ "signature-input": v.signatureInput, signature: v.signature });
  if (v.signatureAgent) headers.set("signature-agent", v.signatureAgent);
  return new Request("https://example.com/foo?param=Value&Pet=dog", { method: "POST", headers });
}

describe("draft test vectors (Ed25519)", () => {
  it("keyid is the RFC 8037 thumbprint of the test key", async () => {
    assert.equal(await jwkThumbprint(publicJwk), KEYID);
  });

  for (const v of vectors) {
    it(`${v.name}: signature base matches`, () => {
      const req = requestFor(v);
      const member = parseDictionary(v.signatureInput).get(v.label)!;
      assert.equal(member.kind, "inner");
      assert.equal(createSignatureBase(req, member as never), v.base);
    });

    it(`${v.name}: verifies with the published key`, async () => {
      const verifier = createVerifier({
        keys: [{ jwk: publicJwk, name: "rfc9421-test-key" }],
        directory: false,
        allowTestKeys: true,
        maxValiditySeconds: Number.POSITIVE_INFINITY,
        now: () => NOW,
      });
      const res = await verifier.verify(requestFor(v));
      assert.equal(res.outcome, "verified", res.reason);
      assert.equal(res.verified?.agentName, "rfc9421-test-key");
    });

    it(`${v.name}: signer reproduces the vector byte for byte`, async () => {
      const req = requestFor(v);
      const out = await signRequest({ method: req.method, url: req.url }, v.sign);
      assert.equal(out["signature-input"], v.signatureInput);
      assert.equal(out.signature, v.signature);
      if (v.signatureAgent) assert.equal(out["signature-agent"], v.signatureAgent);
    });
  }

  it("rejects the published test key by default (draft §5.9)", async () => {
    const verifier = createVerifier({
      keys: [{ jwk: publicJwk }],
      directory: false,
      maxValiditySeconds: Number.POSITIVE_INFINITY,
      now: () => NOW,
    });
    const res = await verifier.verify(requestFor(vectors[0]!));
    assert.equal(res.outcome, "invalid");
    assert.match(res.reason, /test key/);
  });

  it("rejects the 100-year vector under the default 24h validity policy", async () => {
    const verifier = createVerifier({ keys: [{ jwk: publicJwk }], directory: false, allowTestKeys: true, now: () => NOW });
    const res = await verifier.verify(requestFor(vectors[0]!));
    assert.equal(res.outcome, "invalid");
    assert.match(res.reason, /validity window/);
  });
});

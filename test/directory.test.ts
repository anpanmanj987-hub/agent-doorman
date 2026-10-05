import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import {
  createDirectoryResolver,
  defaultHostGuard,
  isPrivateAddress,
  normalizeDiscoveryUrl,
  WELL_KNOWN_DIRECTORY,
} from "../src/httpsig/directory.js";
import { generateKeyPair } from "../src/httpsig/jwk.js";
import { directoryDocument, signRequest } from "../src/httpsig/sign.js";
import { createVerifier } from "../src/httpsig/verify.js";
import { startServer } from "./helpers.js";

describe("address classification", () => {
  for (const ip of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "::", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "224.0.0.1"]) {
    it(`blocks ${ip}`, () => assert.equal(isPrivateAddress(ip), true));
  }
  for (const ip of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) {
    it(`allows ${ip}`, () => assert.equal(isPrivateAddress(ip), false));
  }
  it("default guard blocks localhost names and private literals", () => {
    for (const u of ["https://localhost/x", "https://foo.localhost/", "https://127.0.0.1/", "https://[::1]/", "https://169.254.169.254/latest"]) {
      assert.throws(() => defaultHostGuard(new URL(u)), /blocked/);
    }
    assert.doesNotThrow(() => defaultHostGuard(new URL("https://agent.example/")));
  });
});

describe("discovery URL normalisation", () => {
  it("adds https and the well-known path for bare origins", () => {
    assert.equal(normalizeDiscoveryUrl("signer.example.com").href, `https://signer.example.com${WELL_KNOWN_DIRECTORY}`);
    assert.equal(normalizeDiscoveryUrl("https://a.example").href, `https://a.example${WELL_KNOWN_DIRECTORY}`);
    assert.equal(normalizeDiscoveryUrl("https://a.example/keys.json", "jwks_uri").href, "https://a.example/keys.json");
  });
  it("refuses credentials", () => assert.throws(() => normalizeDiscoveryUrl("https://u:p@a.example")));
});

describe("directory resolver against a live server", () => {
  let srv: Awaited<ReturnType<typeof startServer>>;
  let hits = 0;
  let kp: Awaited<ReturnType<typeof generateKeyPair>>;
  before(async () => {
    kp = await generateKeyPair();
    srv = await startServer((req, res) => {
      hits++;
      if (req.url === WELL_KNOWN_DIRECTORY) {
        res.setHeader("content-type", "application/http-message-signatures-directory+json");
        res.setHeader("cache-control", "max-age=600");
        res.end(JSON.stringify(directoryDocument([kp.publicJwk])));
      } else if (req.url === "/big/.well-known/http-message-signatures-directory" || req.url === "/big") {
        res.end(JSON.stringify({ keys: [], pad: "x".repeat(200_000) }));
      } else if (req.url?.startsWith("/loop")) {
        res.statusCode = 302;
        res.setHeader("location", "/loop");
        res.end();
      } else if (req.url === "/cimd") {
        res.end(JSON.stringify({ client_id: "x", jwks: directoryDocument([kp.publicJwk]) }));
      } else {
        res.statusCode = 404;
        res.end();
      }
    });
  });
  after(() => srv.close());
  const permissive = { allowHttp: true, hostGuard: () => {} };

  it("resolves, caches and coalesces", async () => {
    const r = createDirectoryResolver(permissive);
    hits = 0;
    const [a, b] = await Promise.all([r.resolve(srv.url), r.resolve(srv.url)]);
    assert.equal(a[0]!.thumbprint, kp.keyid);
    assert.equal(b[0]!.thumbprint, kp.keyid);
    await r.resolve(srv.url);
    assert.equal(hits, 1);
  });

  it("supports the cimd discovery type", async () => {
    const r = createDirectoryResolver(permissive);
    assert.equal((await r.resolve(`${srv.url}/cimd`, "cimd"))[0]!.thumbprint, kp.keyid);
  });

  it("enforces size and redirect limits and negative-caches failures", async () => {
    const r = createDirectoryResolver({ ...permissive, maxBytes: 10_000 });
    await assert.rejects(r.resolve(`${srv.url}/big`, "jwks_uri"), /too large/);
    await assert.rejects(r.resolve(`${srv.url}/loop`, "jwks_uri"), /redirects/);
    hits = 0;
    await assert.rejects(r.resolve(`${srv.url}/missing`, "jwks_uri"), /404/);
    await assert.rejects(r.resolve(`${srv.url}/missing`, "jwks_uri"), /404/);
    assert.equal(hits, 1);
  });

  it("refuses http and loopback by default", async () => {
    const r = createDirectoryResolver();
    await assert.rejects(r.resolve(srv.url), /non-https/);
    const r2 = createDirectoryResolver({ allowHttp: true });
    await assert.rejects(r2.resolve(srv.url), /blocked/);
  });

  it("verifies a request end to end via Signature-Agent discovery", async () => {
    const headers = await signRequest({ method: "GET", url: "https://shop.example/" }, { privateJwk: kp.privateJwk, signatureAgent: srv.url });
    const v = createVerifier({ directory: createDirectoryResolver(permissive), agentNames: { [srv.url]: "Local test agent" } });
    const res = await v.verify(new Request("https://shop.example/", { headers: headers as unknown as HeadersInit }));
    assert.equal(res.outcome, "verified", res.reason);
    assert.equal(res.verified?.agentName, "Local test agent");
  });

  it("reports unverified when discovery is blocked", async () => {
    const headers = await signRequest({ method: "GET", url: "https://shop.example/" }, { privateJwk: kp.privateJwk, signatureAgent: srv.url });
    const v = createVerifier({ directory: createDirectoryResolver({ allowHttp: true }) });
    const res = await v.verify(new Request("https://shop.example/", { headers: headers as unknown as HeadersInit }));
    assert.equal(res.outcome, "unverified");
    assert.match(res.reason, /blocked/);
  });
});

// JWK helpers: RFC 7638 thumbprints (keyid for Web Bot Auth) and WebCrypto import.

import { bytesToBase64Url, toBufferSource, utf8 } from "../b64.js";

export type SigAlg =
  | "ed25519"
  | "ecdsa-p256-sha256"
  | "ecdsa-p384-sha384"
  | "rsa-pss-sha512"
  | "rsa-v1_5-sha256";

export const SUPPORTED_ALGS: readonly SigAlg[] = [
  "ed25519",
  "ecdsa-p256-sha256",
  "ecdsa-p384-sha384",
  "rsa-pss-sha512",
  "rsa-v1_5-sha256",
];

/**
 * Thumbprints of the example keys published in RFC 9421 (Appendix B.1).
 * draft-meunier-webbotauth-httpsig-protocol §5.9: test keys MUST NOT be used in
 * production and verifiers SHOULD reject them.
 */
export const KNOWN_TEST_KEY_THUMBPRINTS: ReadonlySet<string> = new Set([
  "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U", // test-key-ed25519
  "oD0HwocPBSfpNy5W3bpJeyFGY_IQ_YpqxSjQ3Yd-CLA", // test-key-rsa-pss
]);

/** RFC 7638 / RFC 8037 A.3 thumbprint, base64url(SHA-256(canonical JSON)). */
export async function jwkThumbprint(jwk: JsonWebKey): Promise<string> {
  let canonical: string;
  switch (jwk.kty) {
    case "OKP":
      canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
      break;
    case "EC":
      canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
      break;
    case "RSA":
      canonical = JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n });
      break;
    default:
      throw new Error(`unsupported JWK kty: ${String(jwk.kty)}`);
  }
  const digest = await crypto.subtle.digest("SHA-256", toBufferSource(utf8(canonical)));
  return bytesToBase64Url(new Uint8Array(digest));
}

export function inferAlg(jwk: JsonWebKey): SigAlg | undefined {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") return "ed25519";
  if (jwk.kty === "EC" && jwk.crv === "P-256") return "ecdsa-p256-sha256";
  if (jwk.kty === "EC" && jwk.crv === "P-384") return "ecdsa-p384-sha384";
  if (jwk.kty === "RSA") return "rsa-pss-sha512";
  return undefined;
}

export function algMatchesKey(alg: SigAlg, jwk: JsonWebKey): boolean {
  switch (alg) {
    case "ed25519":
      return jwk.kty === "OKP" && jwk.crv === "Ed25519";
    case "ecdsa-p256-sha256":
      return jwk.kty === "EC" && jwk.crv === "P-256";
    case "ecdsa-p384-sha384":
      return jwk.kty === "EC" && jwk.crv === "P-384";
    case "rsa-pss-sha512":
    case "rsa-v1_5-sha256":
      return jwk.kty === "RSA";
  }
}

function importAlgorithm(alg: SigAlg): AlgorithmIdentifier | RsaHashedImportParams | EcKeyImportParams {
  switch (alg) {
    case "ed25519":
      return { name: "Ed25519" };
    case "ecdsa-p256-sha256":
      return { name: "ECDSA", namedCurve: "P-256" };
    case "ecdsa-p384-sha384":
      return { name: "ECDSA", namedCurve: "P-384" };
    case "rsa-pss-sha512":
      return { name: "RSA-PSS", hash: "SHA-512" };
    case "rsa-v1_5-sha256":
      return { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  }
}

export function signatureAlgorithm(alg: SigAlg): AlgorithmIdentifier | RsaPssParams | EcdsaParams {
  switch (alg) {
    case "ed25519":
      return { name: "Ed25519" };
    case "ecdsa-p256-sha256":
      return { name: "ECDSA", hash: "SHA-256" };
    case "ecdsa-p384-sha384":
      return { name: "ECDSA", hash: "SHA-384" };
    case "rsa-pss-sha512":
      return { name: "RSA-PSS", saltLength: 64 };
    case "rsa-v1_5-sha256":
      return { name: "RSASSA-PKCS1-v1_5" };
  }
}

const PUBLIC_MEMBERS: Record<string, readonly string[]> = {
  OKP: ["kty", "crv", "x"],
  EC: ["kty", "crv", "x", "y"],
  RSA: ["kty", "n", "e"],
};
const PRIVATE_MEMBERS: Record<string, readonly string[]> = {
  OKP: ["d"],
  EC: ["d"],
  RSA: ["d", "p", "q", "dp", "dq", "qi"],
};

/** Keep only the members WebCrypto needs (directories often carry kid/use/alg/nbf/exp). */
function minimalJwk(jwk: JsonWebKey, includePrivate: boolean): JsonWebKey {
  const kty = jwk.kty ?? "";
  const names = [...(PUBLIC_MEMBERS[kty] ?? []), ...(includePrivate ? PRIVATE_MEMBERS[kty] ?? [] : [])];
  const out: Record<string, unknown> = { ext: true };
  for (const n of names) {
    const v = (jwk as Record<string, unknown>)[n];
    if (v !== undefined) out[n] = v;
  }
  return out as JsonWebKey;
}

export function toPublicJwk(jwk: JsonWebKey): JsonWebKey {
  const pub = minimalJwk(jwk, false) as Record<string, unknown>;
  delete pub.ext;
  return pub as JsonWebKey;
}

export async function importPublicKey(jwk: JsonWebKey, alg: SigAlg): Promise<CryptoKey> {
  return crypto.subtle.importKey("jwk", minimalJwk(jwk, false), importAlgorithm(alg), false, ["verify"]);
}

export async function importPrivateKey(jwk: JsonWebKey, alg: SigAlg): Promise<CryptoKey> {
  if (!jwk.d) throw new Error("JWK has no private component 'd'");
  return crypto.subtle.importKey("jwk", minimalJwk(jwk, true), importAlgorithm(alg), false, ["sign"]);
}

/** Generate a fresh key pair as JWKs. Ed25519 by default (recommended for Web Bot Auth). */
export async function generateKeyPair(
  alg: SigAlg = "ed25519",
): Promise<{ privateJwk: JsonWebKey; publicJwk: JsonWebKey; keyid: string; alg: SigAlg }> {
  let params: AlgorithmIdentifier | RsaHashedKeyGenParams | EcKeyGenParams;
  switch (alg) {
    case "ed25519":
      params = { name: "Ed25519" };
      break;
    case "ecdsa-p256-sha256":
      params = { name: "ECDSA", namedCurve: "P-256" };
      break;
    case "ecdsa-p384-sha384":
      params = { name: "ECDSA", namedCurve: "P-384" };
      break;
    case "rsa-pss-sha512":
      params = { name: "RSA-PSS", hash: "SHA-512", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };
      break;
    case "rsa-v1_5-sha256":
      params = {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
      };
      break;
  }
  const pair = (await crypto.subtle.generateKey(params, true, ["sign", "verify"])) as CryptoKeyPair;
  const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  const publicJwk = toPublicJwk(await crypto.subtle.exportKey("jwk", pair.publicKey));
  return { privateJwk, publicJwk, keyid: await jwkThumbprint(publicJwk), alg };
}

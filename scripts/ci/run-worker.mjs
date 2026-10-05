// Runs an enforce-mode doorman inside workerd (Miniflare) and checks verification at the edge.
import { Miniflare } from "miniflare";
import { build } from "esbuild";
import { generateKeyPair, signRequest } from "agent-doorman";

const kp = await generateKeyPair();
const out = await build({
  entryPoints: ["test-worker.ts"], bundle: true, format: "esm", platform: "neutral", write: false,
  mainFields: ["module", "main"], conditions: ["worker", "browser"],
  define: { PUBLIC_JWK: JSON.stringify(kp.publicJwk) },
});
const mf = new Miniflare({ modules: true, script: out.outputFiles[0].text, compatibilityDate: "2025-09-01" });
const CHROME = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0 Safari/537.36";
let failures = 0;
const go = async (label, url, init, want) => {
  const r = await mf.dispatchFetch(url, init);
  const body = await r.text();
  if (r.status !== want) failures++;
  console.log(`${r.status === want ? "  ok  " : "  FAIL"} ${label}: ${r.status} ${body.slice(0, 70).replace(/\n/g, " ")}`);
};
const url = "https://shop.example/checkout";
await go("browser /checkout", url, { headers: { "user-agent": CHROME } }, 200);
await go("claimed GPTBot /checkout", url, { headers: { "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.2)" } }, 403);
const signed = await signRequest({ method: "GET", url }, { privateJwk: kp.privateJwk, signatureAgent: "https://edge-agent.example" });
await go("Ed25519-signed agent /checkout (verified in workerd)", url, { headers: { "user-agent": "GPTBot/1.2", ...signed } }, 200);
await go("same signature replayed (nonce)", url, { headers: { "user-agent": "GPTBot/1.2", ...signed } }, 403);
const fresh = await signRequest({ method: "GET", url }, { privateJwk: kp.privateJwk });
const tampered = { ...fresh, signature: fresh.signature.replace(/:(.)/, (_, c) => `:${c === "A" ? "B" : "A"}`) };
await go("tampered signature /", "https://shop.example/", { headers: { "user-agent": "GPTBot/1.2", ...tampered } }, 403);
await go("policy document", "https://shop.example/.well-known/agent-policy.json", {}, 200);
await mf.dispose();
if (failures) {
  console.error(`${failures} worker check(s) failed`);
  process.exit(1);
}

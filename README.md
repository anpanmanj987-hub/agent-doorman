# agent-doorman

> GitHub release: download `agent-doorman-0.1.0.tgz` from [Releases](https://github.com/anpanmanj987-hub/agent-doorman/releases) and run `npm install ./agent-doorman-0.1.0.tgz`. Then use `npx --no-install agent-doorman ...`. GitHub publication does not publish to npm. The GitHub Action builds the source at its selected Git ref.


**Check AI agents at the door.** Find out how your site treats AI agent traffic, then let
verified agents in and keep impostors out, with zero runtime dependencies.

[![ci](https://github.com/anpanmanj987-hub/agent-doorman/actions/workflows/ci.yml/badge.svg)](https://github.com/anpanmanj987-hub/agent-doorman/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

```sh
npx --no-install agent-doorman audit https://your-site.example --path /checkout
```

![A door report: a site that refuses scripts but admits anything claiming to be GPTBot](docs/images/door-report.png)

## Why

Personal agents now book, sign in and check out on people's behalf. Sites are reacting with
the tool they have, User-Agent rules, and that tool fails both ways:

- **Impostors get in.** A User-Agent is a claim. If your bot rules let `GPTBot` through,
  anyone who types `GPTBot` gets through. Bot-management vendors report that most sites they
  tested admit spoofed agent identities without a challenge
  ([DataDome](https://datadome.co/threat-research/meta-muse-doesnt-declare-itself-heres-why-that-matters/)).
- **Real agents get stuck, or blocked wholesale.** Agents that drive a real browser and do not
  identify themselves look like people. Amazon blocked Meta's Muse agent, saying it browsed
  without identifying itself as an AI agent
  ([TechRepublic](https://www.techrepublic.com/article/news-amazon-blocks-meta-muse/)).

[Web Bot Auth](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/)
fixes the identity half: agents sign requests with HTTP Message Signatures (RFC 9421) and
publish their keys, so a site can verify who is knocking. agent-doorman is the site side of
that, plus an audit that shows where you stand.

## What you get

| | |
|---|---|
| `agent-doorman audit` | A door test (browser, script, claimed agents, a fake signature, your own signed agent) and checks for what agents need: readable HTML, labelled forms, autocomplete tokens, structured data, no walls. Text, JSON, Markdown, HTML and a badge. |
| Gate middleware | Verifies Web Bot Auth signatures, sorts every request into six trust classes and applies a per-path policy: let anyone browse, require a person or a verified agent at checkout. Monitor first, enforce when ready. |
| Runs anywhere | Node.js (`node:http`, Express, Connect) and every Fetch API runtime (Cloudflare Workers, Next.js middleware, Deno, Bun). No runtime dependencies. |
| Standards-exact | Passes the Web Bot Auth draft's Ed25519 test vectors; the signer reproduces the published signatures byte for byte. |

## Audit your site

```sh
# Passive: reads public pages only. Safe to run anywhere.
npx --no-install agent-doorman audit https://example.com --path /cart --path /checkout --html report.html

# Active: adds the door test. Only for sites you operate.
npx --no-install agent-doorman audit https://staging.example.com --active --path /checkout
```

The door test requests the same page as different visitors and compares what happens:

| Visitor | What it proves when it is let in |
|---|---|
| Browser | Baseline. If this is refused, agents using real browsers are refused too. |
| Script (`python-requests`) | Baseline for automation. |
| Claims GPTBot, ClaudeBot, PerplexityBot... (no proof) | If these get in where the script is refused, your bot rules trust a claim anyone can make. |
| Claims GPTBot with a fake signature | A made-up signature must never buy more access than an unsigned claim. |
| Verified agent (your key, `--sign-key`) | Real, signed agents must get in where they are allowed. |

The audit sends GET requests only and never submits forms. `--fail-under 70` turns the score
into a CI gate. Run `npm run demo` in this repository to see a naive shop score 32 and a
guarded one score 100.

## Protect your site

```sh
npm install ./agent-doorman-0.1.0.tgz
npx --no-install agent-doorman init --preset ecommerce    # writes agent-policy.json in monitor mode
```

**Express, Connect, `node:http`**

```js
import { readFileSync } from "node:fs";
import { createDoorman, fileLogger, nodeMiddleware, validatePolicy } from "agent-doorman/node";

const policy = validatePolicy(JSON.parse(readFileSync("agent-policy.json", "utf8")));
const doorman = createDoorman({ policy, onDecision: fileLogger("agent-decisions.jsonl") });

app.use(nodeMiddleware(doorman, { getIp: (req) => req.ip }));
app.get("/", (req, res) => res.send(req.agentDoorman?.trust.class)); // "browser", "verified"...
```

**Cloudflare Workers, Next.js middleware, Deno, Bun**

```ts
import { createDoorman, presets } from "agent-doorman";

const doorman = createDoorman({ policy: presets.ecommerce(), mode: "monitor" });

export default {
  async fetch(request: Request) {
    const blocked = await doorman.guard(request);
    return blocked ?? fetch(request);
  },
};
```

More in [`examples/`](examples/). The `node:http`, Express and Worker examples run in CI
against the packed tarball, the Worker inside workerd.

### Trust classes

| Class | Meaning |
|---|---|
| `verified` | Valid Web Bot Auth signature from a key we could resolve |
| `invalid` | Signature present but forged, expired, replayed or malformed |
| `unverified` | Signature present but the key could not be fetched or is unknown |
| `claimed` | Names a known AI agent in `User-Agent`, proves nothing |
| `automated` | Looks like a script or automation framework |
| `browser` | Everything else: a person, or an agent that does not identify itself |

### Policy

```json
{
  "version": 1,
  "mode": "monitor",
  "rules": [
    { "name": "checkout", "match": { "paths": ["/checkout/**"] }, "allow": ["browser", "verified"], "onDeny": "challenge" },
    { "name": "browse", "match": { "methods": ["GET", "HEAD"], "paths": ["/**"] },
      "allow": ["browser", "verified", "claimed", "automated", "unverified"], "rateLimit": { "claimed": "120/min" } }
  ],
  "default": { "allow": ["browser", "verified"], "onDeny": "challenge" }
}
```

Refused agents get a JSON reason, an `Accept-Signature` header that asks for Web Bot Auth, and
a link to `/.well-known/agent-policy.json`, which the gate publishes so agents can learn the
rules by machine. That document is an experimental format proposed here, not a standard; see
[docs/agent-policy.md](docs/agent-policy.md).

### Roll out safely

1. Deploy in `monitor` mode (the default). Nothing is blocked; every decision is logged.
2. `npx --no-install agent-doorman report agent-decisions.jsonl` shows what would have been refused.
3. Fix rules until no `browser` or `verified` traffic would be refused, then set
   `"mode": "enforce"`.
4. Re-run `audit --active` against staging to confirm.

Behind a CDN or load balancer that rewrites `Host`, set `trustProxy: true`: signatures cover
the hostname the agent used. Only do this when clients cannot reach the app directly.

## Build a verifiable agent

```sh
npx --no-install agent-doorman keygen
# serve http-message-signatures-directory.json at
#   https://agent.example/.well-known/http-message-signatures-directory
npx --no-install agent-doorman sign https://shop.example/checkout --key agent-key.private.jwk.json \
  --signature-agent https://agent.example --curl
```

```ts
import { signRequest } from "agent-doorman";
const headers = await signRequest({ method: "GET", url }, { privateJwk, signatureAgent: "https://agent.example" });
await fetch(url, { headers });
```

## Standards and conformance

- [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421) HTTP Message Signatures and
  [RFC 8941](https://www.rfc-editor.org/rfc/rfc8941) Structured Fields, implemented from
  scratch with no dependencies.
- [draft-meunier-webbotauth-httpsig-protocol-00](https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/):
  dictionary and legacy `Signature-Agent`, `directory`, `jwks_uri` and `cimd` discovery,
  verified/invalid/unverified outcomes (Appendix A.1), test-key rejection (§5.9), SSRF limits
  on directory fetches (§5.8: timeout, size, key count, redirects, private addresses), HTTP
  caching and negative caching (Appendix A.4, A.5), nonce replay detection.
- Appendix C.2 test vectors pass, and the signer reproduces them byte for byte.
- Algorithms: `ed25519` (recommended), `ecdsa-p256-sha256`, `ecdsa-p384-sha384`,
  `rsa-pss-sha512`, `rsa-v1_5-sha256`. Shared-secret HMAC is refused, as the draft requires.
- Tested on Node.js 20, 22 and 24 and in workerd.

## Limits

- Agents that drive an ordinary browser without signing look like people. Nothing at this
  layer can separate them; pair agent-doorman with your existing bot management.
- The audit reads raw HTML and sends GET requests only. It does not run JavaScript or submit
  forms.
- Rate limits and nonce stores are in memory, per process or isolate. Plug in your own
  `RateLimitStore` and `NonceStore` for global limits.
- Signatures on key directory responses are not verified yet (the directory is fetched over
  HTTPS from the agent's declared origin).
- The list of claimed-agent tokens needs upkeep as vendors change them. Search-engine crawlers
  are deliberately not on it.

## Related projects

- [cloudflare/web-bot-auth](https://github.com/cloudflare/web-bot-auth): Cloudflare's
  signing and verification libraries, listed as implementations in the draft. Use them if you
  only need the cryptography; agent-doorman adds the audit, policy and rollout around it.
- [llms.txt](https://llmstxt.org/): a Markdown summary of your site for language models,
  which the audit checks for.

## Responsible use

`audit --active` impersonates AI agents and sends a fake signature. Point it only at sites
you operate or are authorised to test. Report security issues privately; see
[SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE). See [NOTICE](NOTICE).

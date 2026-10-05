---
name: agent-doorman
description: Audit how a website treats AI agent traffic and protect it with Web Bot Auth verification and per-path agent policies using the agent-doorman CLI and middleware. Use this whenever the user asks whether their site is ready for AI agents or agentic shoppers (Meta Muse, OpenAI dots, ChatGPT agent, Perplexity, Claude), wants to stop bots that pretend to be GPTBot or ClaudeBot, mentions Web Bot Auth, HTTP Message Signatures, Signature-Agent, agent traffic, agent-readiness scores, or wants to gate cart, checkout or login pages from unverified agents, even if they do not name agent-doorman.
---

# agent-doorman

agent-doorman does two things: `agent-doorman audit` reports how a site treats agents and how
usable it is for them, and the middleware verifies Web Bot Auth signatures and applies a
per-path policy. Work in that order: measure, then protect, then measure again.

## 1. Audit

Start passive. It only reads public pages and never impersonates anyone:

```sh
npx --no-install agent-doorman audit https://example.com --path /cart --path /checkout --path /signup --html report.html
```

Pick extra paths that hold forms and transactions; the home page alone says little about forms.

Run the door test (`--active`) only after the user confirms they operate the site or are
authorised to test it. It sends requests that claim to be AI agents and one with a fake
signature, which is impersonation if aimed at someone else's site.

```sh
npx --no-install agent-doorman audit https://staging.example.com --active --path /checkout --json report.json
```

Read the report in this order:

1. `ua-allowlist` fail: the site's bot rules trust User-Agent claims. Anyone can send `GPTBot`.
   This is the most urgent finding.
2. `forged-signature` fail: something treats the presence of signature headers as proof.
3. `sensitive-paths` warn: unverified claims reach cart/checkout/account pages.
4. Forms (`labels`, `autocomplete`, `buttons`): these decide whether real agents can complete
   tasks. Fixes are small HTML changes; offer to make them.
5. `server-rendered` fail: agents that do not run JavaScript see an empty page.

Explain the limit honestly: agents that drive an ordinary browser and do not sign look like
people. No audit or User-Agent rule can separate them; only signatures can.

## 2. Protect

Install and generate a policy. Always start in monitor mode, because enforcing an untested
policy can lock out customers:

```sh
npm install agent-doorman
npx --no-install agent-doorman init --preset ecommerce   # or: content
```

Express / Connect / node:http:

```js
import { createDoorman, nodeMiddleware, fileLogger, validatePolicy } from "agent-doorman/node";
import policy from "./agent-policy.json" with { type: "json" };

const doorman = createDoorman({ policy: validatePolicy(policy), onDecision: fileLogger("agent-decisions.jsonl") });
app.use(nodeMiddleware(doorman, { getIp: (req) => req.ip }));
```

Cloudflare Workers, Next.js middleware, Deno, Bun (Fetch API):

```ts
import { createDoorman, presets } from "agent-doorman";
const doorman = createDoorman({ policy: presets.ecommerce(), mode: "monitor" });
// in the handler:
const blocked = await doorman.guard(request);
if (blocked) return blocked;
```

Check these before shipping:

- Behind a load balancer or CDN that rewrites the Host header, set `trustProxy: true`.
  Signatures cover the hostname the agent saw; without it every signature fails. Never set it
  when clients can reach the app directly, because then they could spoof the headers.
- Keep reading pages open to `claimed` traffic unless the user wants to leave AI search.
- Never enable `allowTestKeys` outside tests.
- In-memory rate limits and nonce stores are per process or isolate. Mention this for
  multi-instance deployments.

## 3. Review and enforce

After some real traffic:

```sh
npx --no-install agent-doorman report agent-decisions.jsonl
```

Look at what would have been refused. If `browser` or `verified` traffic shows up under
refusals, fix the rules first. Then set `"mode": "enforce"` and re-run the audit with
`--active` against staging to confirm: claimed agents challenged on transactional paths,
verified agents admitted (test with `--sign-key` from `npx --no-install agent-doorman keygen`).

## For agent builders

To make an agent verifiable: `npx --no-install agent-doorman keygen`, serve the generated
`http-message-signatures-directory.json` at
`https://<agent-domain>/.well-known/http-message-signatures-directory`, and sign requests with
`signRequest()` or `npx --no-install agent-doorman sign <url> --key agent-key.private.jwk.json --signature-agent https://<agent-domain>`.
Never commit the private key.

## CI

```yaml
- uses: anpanmanj987-hub/agent-doorman@v0
  with:
    url: https://staging.example.com
    paths: /cart /checkout
    fail-under: 70
```

The policy format and refusal bodies are described in `docs/agent-policy.md` in the repository.

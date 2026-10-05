# Agent policy

agent-doorman uses two related documents:

1. **The policy file** you write (`agent-policy.json`), which the gate enforces.
2. **The public policy document** the gate serves at `/.well-known/agent-policy.json`, which
   tells agents what they may do and how to authenticate.

The public document is an **experimental format proposed by this project**. It is not an IETF
or W3C standard. It exists so that refused agents can discover, by machine, what the site
expects instead of guessing. If a standard for this emerges, agent-doorman will follow it.

## Trust classes

Every request is put in exactly one class before policy is applied.

| Class | Meaning | How it is decided |
|---|---|---|
| `verified` | Valid Web Bot Auth signature from a key we could resolve | Signature verifies against an out-of-band key or the covered `Signature-Agent` directory |
| `invalid` | Signature present but wrong | Bad signature, expired, replayed nonce, published test key, uncovered `Signature-Agent`, malformed headers |
| `unverified` | Signature present but could not be checked | Unknown key, directory unreachable or blocked (draft Appendix A.1) |
| `claimed` | Names a known AI agent in `User-Agent`, no signature | Matches a token in `src/gate/agents.ts` |
| `automated` | Looks like a script or automation framework | `curl`, `python-requests`, headless Chrome, empty `User-Agent`... |
| `browser` | Everything else | Could be a person, or an agent that does not identify itself |

The last row matters: an agent that drives a real browser and does not sign its requests is
indistinguishable from a person at this layer. Signatures are what make agents distinguishable.

## Policy file

```json
{
  "version": 1,
  "mode": "monitor",
  "rules": [
    {
      "name": "checkout",
      "description": "Checkout and payment",
      "match": { "paths": ["/checkout/**", "/payment/**"] },
      "allow": ["browser", "verified"],
      "rateLimit": { "verified": "30/min" },
      "onDeny": "challenge"
    },
    {
      "name": "browse",
      "match": { "methods": ["GET", "HEAD"], "paths": ["/**"] },
      "allow": ["browser", "verified", "claimed", "automated", "unverified"],
      "rateLimit": { "claimed": "120/min", "automated": "60/min" }
    }
  ],
  "default": { "allow": ["browser", "verified"], "onDeny": "challenge" },
  "contact": "mailto:web@example.com"
}
```

| Field | Notes |
|---|---|
| `version` | Always `1` for now. |
| `mode` | `monitor` (default): decide and log, never block. `enforce`: block. The `mode` option in code overrides it. |
| `rules` | Evaluated in order; the first match wins. |
| `rules[].name` | Short identifier; appears in logs and refusals. |
| `rules[].match.paths` | Globs. `*` matches within one segment, `**` across segments. A trailing `/**` also matches the bare prefix, so `/checkout/**` matches `/checkout`. |
| `rules[].match.methods` | Optional. Omit to match every method. |
| `rules[].allow` | Array of trust classes, or `"*"` for all six (including `invalid`). |
| `rules[].rateLimit` | Per class: `"60/min"`, `"10/s"`, `"1000/hour"`, `"5/10min"`. Keys are per rule, class and identity (verified key, or agent token plus client IP). |
| `rules[].onDeny` | `block` (default): `403` with a JSON reason. `challenge`: the same plus `Accept-Signature` asking for a Web Bot Auth signature (draft §4.3). |
| `default` | Applies when no rule matches. Without it, everything is allowed. |
| `contact` | Published in the public document. |

`agent-doorman init --preset ecommerce` (or `content`) writes a starting point.

### Rolling out

1. Start in `monitor` with `onDecision: fileLogger("agent-decisions.jsonl")`.
2. Run `agent-doorman report agent-decisions.jsonl` after a few days. Look at what *would*
   have been refused, especially `browser` and `verified` traffic.
3. Adjust rules, then switch to `enforce`.

Keep reading pages open to `claimed` traffic unless you mean to opt out of AI search: blocking
claimed agents on browse paths also blocks the real ones that do not sign yet.

## Public policy document (experimental)

Served at `GET /.well-known/agent-policy.json` with `Access-Control-Allow-Origin: *`. Rate
limits are not published.

```json
{
  "agentPolicy": "0.1",
  "status": "experimental",
  "generator": "agent-doorman",
  "authentication": {
    "scheme": "web-bot-auth",
    "specification": "https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/",
    "requiredComponents": { "anyOf": ["@authority", "@target-uri"] }
  },
  "classes": { "verified": "...", "browser": "...", "claimed": "...", "automated": "...", "unverified": "...", "invalid": "..." },
  "rules": [
    { "name": "checkout", "description": "Checkout and payment", "methods": ["*"], "paths": ["/checkout/**"], "allow": ["browser", "verified"] }
  ],
  "default": { "allow": ["browser", "verified"] }
}
```

Refusals point to it with `Link: </.well-known/agent-policy.json>; rel="agent-policy"`.

## Refusal bodies

```http
HTTP/1.1 403 Forbidden
Content-Type: application/json; charset=utf-8
Accept-Signature: sig1=("@authority" "signature-agent";key="sig1");created;expires;tag="web-bot-auth"
Link: </.well-known/agent-policy.json>; rel="agent-policy"

{"error":"agent_not_permitted","message":"This action needs a verified agent. The request names GPTBot but carries no Web Bot Auth signature.","rule":"checkout","trust":"claimed","policy":"/.well-known/agent-policy.json","authentication":"https://datatracker.ietf.org/doc/draft-meunier-webbotauth-httpsig-protocol/"}
```

Rate limits answer `429` with `Retry-After`.

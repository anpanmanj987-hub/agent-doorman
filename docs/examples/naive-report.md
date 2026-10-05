## Agent readiness: naive-shop.example

![agent-ready](https://img.shields.io/badge/agent--ready-32%2F100-red)

**32/100**, not ready for ai agents (active audit, agent-doorman 0.1.0).

### Door test

| Page | Visitor | HTTP | Outcome | Problem |
|---|---|---|---|---|
| `/` | Browser | 200 | admitted |  |
| `/` | Script (python-requests) | 403 | turned away | ! refused with no reason an agent can read |
| `/` | Claims GPTBot, no proof | 200 | admitted | ✕ got in on a claim alone |
| `/` | Claims ClaudeBot, no proof | 200 | admitted | ✕ got in on a claim alone |
| `/` | Claims PerplexityBot, no proof | 200 | admitted | ✕ got in on a claim alone |
| `/` | Claims ChatGPT-User, no proof | 200 | admitted | ✕ got in on a claim alone |
| `/` | Claims meta-externalagent, no proof | 200 | admitted | ✕ got in on a claim alone |
| `/` | Claims GPTBot, fake signature | 200 | admitted |  |
| `/signup` | Browser | 200 | admitted |  |
| `/signup` | Script (python-requests) | 403 | turned away | ! refused with no reason an agent can read |
| `/signup` | Claims GPTBot, no proof | 200 | admitted | ✕ got in on a claim alone |
| `/signup` | Claims ClaudeBot, no proof | 200 | admitted | ✕ got in on a claim alone |
| `/signup` | Claims GPTBot, fake signature | 200 | admitted |  |

### Checks

| Area | Check | Result | Finding |
|---|---|---|---|
| Who gets in | Agent claims are not trusted blindly | ✕ Fail | Your bot protection lets in anyone who claims to be a known AI agent. |
| Who gets in | Fake signatures buy nothing | ! Needs work | No signature checking observed: a fake signature was treated like any other visit. |
| Who gets in | Transactional pages need proof | ! Needs work | Unverified agent claims reach the extra pages you listed. |
| Who gets in | Refusals explain themselves | ✕ Fail | Only 0/2 refusals told the agent why or how to get in. |
| Who gets in | Verified agents get in | – Not tested | Not tested. Pass --sign-key (and --signature-agent) to check that a signed agent is admitted. |
| Can agents find your rules | robots.txt states an agent policy | ! Needs work | No robots.txt found. |
| Can agents find your rules | Pages are discoverable | ! Needs work | No sitemap found. |
| Can agents find your rules | llms.txt summary | ! Needs work | No /llms.txt. |
| Can agents find your rules | Published agent policy | i Note | No /.well-known/agent-policy.json (optional, experimental format served by agent-doorman). |
| Can agents read your pages | Language is declared | ! Needs work | 2 page(s) lack &lt;html lang>. |
| Can agents read your pages | Title and description | ! Needs work | 2 page(s) miss a title or meta description. |
| Can agents read your pages | Structured data | ! Needs work | No JSON-LD found on audited pages. |
| Can agents read your pages | Content without JavaScript | ✕ Fail | 2 page(s) show little or no text before JavaScript runs. |
| Can agents fill in your forms | Every field has a label | ✕ Fail | 0/4 fields have a label or accessible name. |
| Can agents fill in your forms | Fields say what they are | ✕ Fail | 0/4 identity, contact, address and payment fields carry an autocomplete token. |
| Can agents fill in your forms | Buttons are named | ✕ Fail | 0/1 buttons have a text or accessible name. |
| Can agents fill in your forms | Inputs use specific types | ! Needs work | 0/2 email/phone fields use type="email"/"tel". |
| Walls in the way | Browser-like visits get through | ✓ Pass | Plain browser requests reached every audited page. |
| Walls in the way | No CAPTCHA in the way | ! Needs work | Challenge technology found on audited pages: reCAPTCHA. |

### Fix first

1. **Agent claims are not trusted blindly.** Stop allowlisting by User-Agent. Admit named agents only when their Web Bot Auth signature verifies (agent-doorman verifies signatures; many CDNs can too).
2. **Content without JavaScript.** Server-render (or pre-render) key content. Agents that fetch HTML without running scripts see an empty shell.
3. **Every field has a label.** Use &lt;label for>, a wrapping &lt;label> or aria-label. Placeholders vanish when typing and many agents ignore them.
4. **Fields say what they are.** Add autocomplete tokens (email, tel, given-name, street-address, postal-code, cc-number, current-password...). They tell agents and password managers exactly what each field wants.
5. **Buttons are named.** Give icon-only buttons an aria-label that says what they do ("Add to cart", not "button").

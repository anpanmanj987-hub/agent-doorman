## Agent readiness: plaque-shop.example

![agent-ready](https://img.shields.io/badge/agent--ready-100%2F100-brightgreen)

**100/100**, ready for ai agents (active audit, agent-doorman 0.1.0).

### Door test

| Page | Visitor | HTTP | Outcome | Problem |
|---|---|---|---|---|
| `/` | Browser | 200 | admitted |  |
| `/` | Script (python-requests) | 200 | admitted |  |
| `/` | Claims GPTBot, no proof | 200 | admitted |  |
| `/` | Claims ClaudeBot, no proof | 200 | admitted |  |
| `/` | Claims PerplexityBot, no proof | 200 | admitted |  |
| `/` | Claims ChatGPT-User, no proof | 200 | admitted |  |
| `/` | Claims meta-externalagent, no proof | 200 | admitted |  |
| `/` | Claims GPTBot, fake signature | 200 | admitted |  |
| `/` | Verified agent (your key) | 200 | admitted |  |
| `/checkout` | Browser | 200 | admitted |  |
| `/checkout` | Script (python-requests) | 403 | challenged |  |
| `/checkout` | Claims GPTBot, no proof | 403 | challenged |  |
| `/checkout` | Claims ClaudeBot, no proof | 403 | challenged |  |
| `/checkout` | Claims GPTBot, fake signature | 403 | challenged |  |
| `/checkout` | Verified agent (your key) | 200 | admitted |  |

### Checks

| Area | Check | Result | Finding |
|---|---|---|---|
| Who gets in | Agent claims are not trusted blindly | ✓ Pass | Requests that only claim to be AI agents get the same treatment as other scripts. |
| Who gets in | Fake signatures buy nothing | ✓ Pass | A fake signature got no more access than an unsigned claim, and was refused where it mattered. |
| Who gets in | Transactional pages need proof | ✓ Pass | Unverified agent claims are refused on the extra pages you listed. |
| Who gets in | Refusals explain themselves | ✓ Pass | Refused agents get a machine-readable reason (JSON, Accept-Signature or Retry-After). |
| Who gets in | Verified agents get in | ✓ Pass | Requests signed with your key were admitted. |
| Can agents find your rules | robots.txt states an agent policy | ✓ Pass | robots.txt has explicit groups for 1 AI agent token(s). |
| Can agents find your rules | Pages are discoverable | ✓ Pass | robots.txt declares a sitemap. |
| Can agents find your rules | llms.txt summary | ✓ Pass | Found /llms.txt. |
| Can agents find your rules | Published agent policy | i Note | Found /.well-known/agent-policy.json. |
| Can agents read your pages | Language is declared | ✓ Pass | Every audited page declares its language. |
| Can agents read your pages | Title and description | ✓ Pass | Every audited page has a title and description. |
| Can agents read your pages | Structured data | ✓ Pass | JSON-LD present: Product. |
| Can agents read your pages | Content without JavaScript | ✓ Pass | Audited pages carry readable text in the HTML itself. |
| Can agents fill in your forms | Every field has a label | ✓ Pass | 6/6 fields have a label or accessible name. |
| Can agents fill in your forms | Fields say what they are | ✓ Pass | 6/6 identity, contact, address and payment fields carry an autocomplete token. |
| Can agents fill in your forms | Buttons are named | ✓ Pass | 1/1 buttons have a text or accessible name. |
| Can agents fill in your forms | Inputs use specific types | ✓ Pass | 2/2 email/phone fields use type="email"/"tel". |
| Walls in the way | Browser-like visits get through | ✓ Pass | Plain browser requests reached every audited page. |
| Walls in the way | No CAPTCHA in the way | ✓ Pass | No CAPTCHA or bot-challenge widgets detected in the audited HTML. |

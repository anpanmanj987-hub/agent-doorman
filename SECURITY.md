# Security policy

agent-doorman sits in front of web applications and makes trust decisions, so we treat
security reports as a priority.

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting
("Security" tab, "Report a vulnerability").

Include the version, a minimal reproduction and the impact you expect. We aim to
acknowledge reports within 3 working days and to ship a fix or mitigation for confirmed
issues within 30 days, coordinating disclosure with you.

## In scope

- Signature verification accepting what it should refuse (forgery, replay, downgrade,
  component confusion, parsing differentials)
- Key discovery reaching places it should not (SSRF), or being amplified
- Policy matching that lets requests bypass a rule
- Denial of service through crafted headers or directories

## Out of scope

- Findings that require a misconfiguration documented as unsafe (for example
  `allowTestKeys: true` or `trustProxy: true` without a trusted proxy)
- Results of running `agent-doorman audit --active` against sites you do not operate

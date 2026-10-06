# Changelog

## Unreleased

- GitHub Action: read the report through an environment variable instead of splicing its path into JavaScript, which broke on Windows runners (backslashes in `RUNNER_TEMP`).
- README: install and try straight from the GitHub release URL (`npx --yes --package=<release tgz>`); state that `verified` identifies the signer rather than implying trust, and note the DNS-rebinding window in `nodeHostGuard`; cite DataDome's figure precisely.
- Remove the pre-publication checklist and the one-shot owner script, which were only for the initial release.
- Checked on Windows 11 with Node 24: typecheck and all 91 tests pass, and the release tarball installs and runs from its URL.

## 0.1.0 — 2026-10-05

First public version.

- Web Bot Auth verification and signing (RFC 9421, draft-meunier-webbotauth-httpsig-protocol-00),
  passing the draft's Ed25519 test vectors byte for byte
- Key discovery with SSRF guards, caching, request coalescing and negative caching
- Doorman gate: six trust classes, per-path policies, monitor and enforce modes,
  Accept-Signature challenges, rate limits, `/.well-known/agent-policy.json`
- Adapters for Fetch API runtimes (Workers, Next.js middleware, Deno, Bun) and Node.js
  (`node:http`, Express, Connect)
- `agent-doorman audit` with a door test, readability, forms, discovery and walls checks,
  text, JSON, Markdown, HTML and badge output, and `--fail-under`
- `init`, `keygen`, `sign` and `report` commands
- GitHub Action

Publication preparation:

- Set repository ownership and use GitHub private vulnerability reporting.
- GitHub Action runs the source at its selected Git ref, without requiring an npm registry release.
- npm publication is a separate manual workflow.
- Package smoke cleanup only terminates the process it started.

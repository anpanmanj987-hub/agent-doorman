# Contributing

Thanks for helping. Small, focused pull requests with tests are the fastest to merge.

## Setup

```sh
npm ci
npm test          # unit, interop and end-to-end tests (Node >= 20)
npm run typecheck
npm run demo      # audits a naive and a guarded demo shop on localhost
```

`scripts/ci/package-smoke.sh` repeats what CI does with the packed tarball: real HTTP
servers, a Worker inside workerd, and TypeScript consumers.

## Ground rules

- No runtime dependencies. The core (`src/` except `src/node.ts` and `src/cli/`) must run on
  any Fetch API runtime, so no `node:` imports there.
- Security-sensitive changes (anything under `src/httpsig/` or `src/gate/`) need a test that
  fails without the change.
- Follow the draft precisely and cite the section in comments when behaviour comes from it.

## Updating the list of known agents

`src/gate/agents.ts` lists User-Agent tokens that vendors publish. When adding or changing an
entry, link the vendor's own documentation in the pull request. Do not add search-engine
crawlers: policies that restrict claimed agents must never block search indexing by accident.

# Validation

## Windows check — 2026-10-06

On Windows 11 with Node 24.21.0: `npm ci`, `npm run typecheck` and all 91 tests pass. The `v0.1.0` release tarball installs from its GitHub URL (`npm install <url>` and `npx --yes --package=<url> agent-doorman`) and the CLI runs. The Action's report-reading step was fixed for Windows paths and checked with a backslashed path.

## Publication validation — 2026-10-05

On macOS arm64 with Node 24.19.0, the source passed all 91 tests (zero skips), TypeScript type checking and the build. The packed tarball was installed in a clean temporary project. Node HTTP and Express examples, policy/challenge headers, logging, the Worker running inside workerd (including verified, replayed and tampered signatures), NodeNext/Bundler type consumers and the installed CLI passed the package smoke checks.

The synthetic demo generated scores 32/100 (naive) and 100/100 (guarded). These are fixture results, not a security assessment of a real site. The tests do not establish interoperability with live agent providers or production deployment safety.

The source GitHub Action is exercised against a loopback example in CI. See the [GitHub Actions results](https://github.com/anpanmanj987-hub/agent-doorman/actions/workflows/ci.yml) for Node 20/22/24, the package smoke checks, the demo and the Action smoke job.

## Not yet verified

- Interoperability with signatures from live agent providers.
- A real Next.js app on the Edge runtime (the example shares the Worker's Fetch API path but is not run in CI).
- `trustProxy` behind a real CDN or load balancer.

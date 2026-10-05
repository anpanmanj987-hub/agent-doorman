# Publication validation — 2026-10-05

On macOS arm64 with Node 24.19.0, the supplied source passed all 91 tests (zero skips), TypeScript type checking and the build. The packed tarball was installed in a clean temporary project. Node HTTP and Express examples, policy/challenge headers, logging, the Worker running inside workerd (including verified, replayed and tampered signatures), NodeNext/Bundler type consumers and the installed CLI passed the package smoke checks.

The synthetic demo generated scores 32/100 (naive) and 100/100 (guarded). These are fixture results, not a security assessment of a real site. The tests do not establish interoperability with live agent providers or production deployment safety.

The source GitHub Action is exercised against a loopback example in CI. Check the final [GitHub Actions results](https://github.com/anpanmanj987-hub/agent-doorman/actions/workflows/ci.yml) for Node 20/22/24, the package smoke checks, the demo and the Action smoke job. Publication only targets GitHub; npm publishing remains manual.

# Examples

| Example | Runtime | Status in CI |
|---|---|---|
| [`node-http/`](node-http/server.mjs) | Node.js `node:http` | Run against the packed tarball |
| [`express/`](express/server.mjs) | Express | Run against the packed tarball |
| [`cloudflare-worker/`](cloudflare-worker/worker.ts) | Cloudflare Workers | Bundled and run in workerd (Miniflare) before release |
| [`nextjs/`](nextjs/middleware.ts) | Next.js middleware (Edge) | Not yet run in CI; uses the same Fetch API path as the Worker |

[`agent-policy.json`](agent-policy.json) is the `ecommerce` preset, as written by `npx --no-install agent-doorman init`.

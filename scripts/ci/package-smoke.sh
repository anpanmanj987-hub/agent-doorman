#!/usr/bin/env bash
# Installs the packed tarball into a clean project and exercises it like a user would:
# node:http and Express examples over real HTTP, the Worker inside workerd, and TypeScript
# consumers under NodeNext and Bundler resolution. Usage: scripts/ci/package-smoke.sh <tarball>
set -euo pipefail
TARBALL="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
cleanup() {
  if [ -n "${PID:-}" ]; then kill "$PID" 2>/dev/null || true; fi
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK"
npm init -y >/dev/null
npm pkg set type=module >/dev/null
npm install --no-audit --no-fund "$TARBALL" express@4 miniflare@3 esbuild typescript@5 @types/node@22 @types/express >/dev/null
cp -r "$ROOT/examples" ./examples
cp "$ROOT"/scripts/ci/{test-worker.ts,run-worker.mjs,types-check.ts} .
node -e 'const fs=require("fs");const p=JSON.parse(fs.readFileSync("examples/agent-policy.json","utf8"));p.mode="enforce";fs.writeFileSync("examples/agent-policy.enforce.json",JSON.stringify(p))'
sed 's#../agent-policy.json#../agent-policy.enforce.json#' examples/express/server.mjs > examples/express/server.enforce.mjs

FAIL=0
code() { curl -s -m 5 -o /dev/null -w "%{http_code}" "$@"; }
expect() { if [ "$2" = "$3" ]; then echo "  ok   $1"; else echo "  FAIL $1: want $2 got $3"; FAIL=1; fi; }
probe() {
  rm -f agent-decisions.jsonl
  env $2 PORT=3101 node "$1" > server.log 2>&1 &
  PID=$!
  for _ in $(seq 1 50); do curl -s -m 1 -o /dev/null localhost:3101/ && break; sleep 0.2; done
  echo "== $1"
  expect "browser reaches /checkout" 200 "$(code -A 'Mozilla/5.0 (X11; Linux x86_64) Chrome/129.0' localhost:3101/checkout)"
  expect "claimed GPTBot challenged on /checkout" 403 "$(code -A 'Mozilla/5.0 (compatible; GPTBot/1.2)' localhost:3101/checkout)"
  expect "claimed GPTBot may browse /" 200 "$(code -A 'Mozilla/5.0 (compatible; GPTBot/1.2)' localhost:3101/)"
  expect "script refused on POST /cart/items" 403 "$(code -X POST localhost:3101/cart/items)"
  expect "policy document served" 200 "$(code localhost:3101/.well-known/agent-policy.json)"
  expect "challenge carries Accept-Signature" 1 "$(curl -s -m 5 -D - -o /dev/null -A 'GPTBot/1.2' localhost:3101/checkout | grep -ci '^accept-signature')"
  kill "$PID"; wait "$PID" 2>/dev/null || true
  PID=""
  expect "decisions logged" 6 "$(wc -l < agent-decisions.jsonl | tr -d ' ')"
  ./node_modules/.bin/agent-doorman report agent-decisions.jsonl >/dev/null || FAIL=1
}
probe examples/node-http/server.mjs DOORMAN_MODE=enforce
probe examples/express/server.enforce.mjs NOOP=1

echo "== worker bundle has no Node built-ins"
npx esbuild examples/cloudflare-worker/worker.ts --bundle --format=esm --platform=neutral --main-fields=module,main --conditions=worker,browser --outfile=worker.js --log-level=warning
expect "no node: imports in Worker bundle" 0 "$(grep -c 'node:' worker.js || true)"
echo "== Worker in workerd"
node run-worker.mjs || FAIL=1
echo "== TypeScript consumers"
npx tsc --noEmit --strict --module NodeNext --moduleResolution NodeNext --target ES2022 --types node --lib ES2022,DOM types-check.ts examples/cloudflare-worker/worker.ts && echo "  ok   NodeNext" || FAIL=1
npx tsc --noEmit --strict --module ESNext --moduleResolution Bundler --target ES2022 --types node --lib ES2022,DOM types-check.ts examples/cloudflare-worker/worker.ts && echo "  ok   Bundler" || FAIL=1
echo "== CLI from the tarball"
./node_modules/.bin/agent-doorman --version >/dev/null && echo "  ok   agent-doorman --version" || FAIL=1
exit $FAIL

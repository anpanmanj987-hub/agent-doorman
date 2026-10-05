// Plain node:http. Run: node server.mjs, then try:
//   curl -i localhost:3000/checkout -A "GPTBot/1.2"
//   curl -i localhost:3000/.well-known/agent-policy.json
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { createDoorman, fileLogger, nodeMiddleware, validatePolicy } from "agent-doorman/node";

const policy = validatePolicy(JSON.parse(readFileSync(new URL("../agent-policy.json", import.meta.url), "utf8")));

const doorman = createDoorman({
  policy,
  // Start with "monitor" (the policy default), read the log, then switch to "enforce".
  mode: process.env.DOORMAN_MODE === "enforce" ? "enforce" : undefined,
  onDecision: fileLogger("agent-decisions.jsonl"),
});
const guard = nodeMiddleware(doorman);

const server = createServer((req, res) =>
  guard(req, res, () => {
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.end(`Hello. You look like: ${req.agentDoorman?.trust.class ?? "n/a"}\n`);
  }),
);
server.listen(Number(process.env.PORT ?? 3000), () => {
  console.log(`listening on http://localhost:${server.address().port} (mode: ${doorman.mode})`);
});

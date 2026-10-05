// Express 4 or 5. Run: npm i express agent-doorman && node server.mjs
import express from "express";
import { readFileSync } from "node:fs";
import { createDoorman, fileLogger, nodeMiddleware, validatePolicy } from "agent-doorman/node";

const policy = validatePolicy(JSON.parse(readFileSync(new URL("../agent-policy.json", import.meta.url), "utf8")));

const doorman = createDoorman({
  policy,
  // Behind a load balancer or CDN that sets X-Forwarded-Host/-Proto. Signatures cover the
  // authority the agent saw, so the doorman must see it too. Only enable behind a trusted proxy.
  trustProxy: process.env.BEHIND_PROXY === "1",
  onDecision: fileLogger("agent-decisions.jsonl"),
});

const app = express();
app.set("trust proxy", process.env.BEHIND_PROXY === "1");
app.use(nodeMiddleware(doorman, { getIp: (req) => req.ip }));

app.get("/", (req, res) => res.send(`Hello. You look like: ${req.agentDoorman?.trust.class}`));
app.post("/cart/items", (req, res) => res.json({ ok: true }));
app.get("/checkout", (req, res) => res.send("Checkout"));

const server = app.listen(Number(process.env.PORT ?? 3000), () => {
  console.log(`listening on http://localhost:${server.address().port} (mode: ${doorman.mode})`);
});

#!/usr/bin/env node
// agent-doorman CLI. Zero runtime dependencies.

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { createReadStream } from "node:fs";
import { renderHtml, renderMarkdown, renderText, badgeUrl } from "../audit/render.js";
import { runAudit } from "../audit/run.js";
import type { Decision } from "../gate/doorman.js";
import { presets, type PresetName, validatePolicy } from "../gate/policy.js";
import { generateKeyPair, type SigAlg, SUPPORTED_ALGS } from "../httpsig/jwk.js";
import { directoryDocument, signRequest } from "../httpsig/sign.js";
import { VERSION } from "../version.js";

const HELP = `agent-doorman ${VERSION}
Check AI agents at the door.

Usage
  agent-doorman audit <url> [options]     How does this site treat AI agents?
  agent-doorman init [options]            Write a starter agent-policy.json
  agent-doorman keygen [options]          Create an Ed25519 key for your own agent
  agent-doorman sign <url> --key <file>   Print Web Bot Auth headers for a request
  agent-doorman report <decisions.jsonl>  Summarise logged gate decisions

Audit options
  --path <path>            Also audit this path (repeatable), e.g. --path /cart --path /checkout
  --active                 Run the door test (sends requests claiming to be AI agents).
                           Only use against sites you operate.
  --sign-key <file>        Private JWK; adds a "verified agent" visitor to the door test
  --signature-agent <url>  Signature-Agent to send with --sign-key
  --json <file|->          Write the JSON report
  --html <file>            Write the HTML report
  --markdown <file>        Write a Markdown summary (e.g. "$GITHUB_STEP_SUMMARY")
  --fail-under <n>         Exit with code 2 when the score is below n
  --timeout <ms>           Per-request timeout (default 15000)
  --delay <ms>             Pause between door-test requests (default 150)
  --no-color               Plain output

Init options
  --preset <name>          ecommerce (default) or content
  --out <file>             Default agent-policy.json
  --force                  Overwrite an existing file

Keygen options
  --out-dir <dir>          Default current directory
  --alg <alg>              ${SUPPORTED_ALGS.join(", ")} (default ed25519)

Sign options
  --key <file>             Private JWK (from keygen)
  --signature-agent <url>  Where verifiers can fetch your public key
  --method <method>        Default GET
  --curl                   Print a ready-to-run curl command

Report options
  --json                   Machine-readable summary
`;

interface Args {
  _: string[];
  flags: Map<string, string[]>;
}

const BOOLEAN_FLAGS = new Set(["active", "force", "curl", "no-color", "help", "version"]);

function parseArgs(argv: string[]): Args {
  const args: Args = { _: [], flags: new Map() };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === "--") {
      args._.push(...argv.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = eq > 0 ? a.slice(2, eq) : a.slice(2);
      let value: string;
      if (eq > 0) value = a.slice(eq + 1);
      else if (BOOLEAN_FLAGS.has(name)) value = "true";
      else if (name === "json" && (argv[i + 1] === undefined || argv[i + 1]!.startsWith("--"))) value = "true";
      else {
        const next = argv[i + 1];
        if (next === undefined) throw new UsageError(`--${name} needs a value`);
        value = next;
        i++;
      }
      args.flags.set(name, [...(args.flags.get(name) ?? []), value]);
    } else if (a === "-h") args.flags.set("help", ["true"]);
    else args._.push(a);
  }
  return args;
}

class UsageError extends Error {}

const flag = (a: Args, name: string) => a.flags.get(name)?.at(-1);
const flags = (a: Args, name: string) => a.flags.get(name) ?? [];
const has = (a: Args, name: string) => a.flags.has(name);

function readJson(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new UsageError(`cannot read JSON from ${path}: ${(e as Error).message}`);
  }
}

function num(a: Args, name: string): number | undefined {
  const v = flag(a, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  if (!Number.isFinite(n) || n < 0) throw new UsageError(`--${name} must be a non-negative number`);
  return n;
}

async function cmdAudit(a: Args): Promise<number> {
  const url = a._[1];
  if (!url) throw new UsageError("audit needs a URL, e.g. agent-doorman audit https://example.com");
  let target: URL;
  try {
    target = new URL(/^https?:\/\//i.test(url) ? url : `https://${url}`);
  } catch {
    throw new UsageError(`not a valid URL: ${url}`);
  }
  const active = has(a, "active");
  const signKeyPath = flag(a, "sign-key");
  if (active) {
    process.stderr.write(
      `Door test: sending requests to ${target.host} that claim to be AI agents and one with a forged signature.\n` +
        `Only run this against sites you operate or are authorised to test.\n\n`,
    );
  }
  const report = await runAudit({
    url: target.href,
    paths: flags(a, "path"),
    active,
    signKey: signKeyPath ? (readJson(signKeyPath) as JsonWebKey) : undefined,
    signatureAgent: flag(a, "signature-agent"),
    timeoutMs: num(a, "timeout"),
    delayMs: num(a, "delay"),
  });
  const json = flag(a, "json");
  if (json === "-" || json === "true") process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  else {
    process.stdout.write(renderText(report, { color: !has(a, "no-color") && process.stdout.isTTY && !process.env.NO_COLOR }));
    if (json) {
      writeFileSync(json, `${JSON.stringify(report, null, 2)}\n`);
      process.stderr.write(`JSON report: ${resolve(json)}\n`);
    }
  }
  const html = flag(a, "html");
  if (html) {
    writeFileSync(html, renderHtml(report));
    process.stderr.write(`HTML report: ${resolve(html)}\n`);
  }
  const md = flag(a, "markdown");
  if (md) {
    writeFileSync(md, `${renderMarkdown(report)}\n`, { flag: md === process.env.GITHUB_STEP_SUMMARY ? "a" : "w" });
    process.stderr.write(`Markdown summary: ${md}\n`);
  }
  process.stderr.write(`Badge: ${badgeUrl(report)}\n`);
  const failUnder = num(a, "fail-under");
  if (failUnder !== undefined && report.score < failUnder) {
    process.stderr.write(`Score ${report.score} is below --fail-under ${failUnder}.\n`);
    return 2;
  }
  return 0;
}

function cmdInit(a: Args): number {
  const preset = (flag(a, "preset") ?? "ecommerce") as PresetName;
  if (!(preset in presets)) throw new UsageError(`unknown preset "${preset}" (choose ${Object.keys(presets).join(" or ")})`);
  const out = flag(a, "out") ?? "agent-policy.json";
  if (existsSync(out) && !has(a, "force")) throw new UsageError(`${out} already exists (use --force to overwrite)`);
  const policy = presets[preset]();
  validatePolicy(policy);
  writeFileSync(out, `${JSON.stringify(policy, null, 2)}\n`);
  process.stdout.write(
    `Wrote ${out} (${preset} preset, mode "monitor").\n` +
      `Start in monitor mode, review decisions with "agent-doorman report", then set "mode": "enforce".\n`,
  );
  return 0;
}

async function cmdKeygen(a: Args): Promise<number> {
  const alg = (flag(a, "alg") ?? "ed25519") as SigAlg;
  if (!SUPPORTED_ALGS.includes(alg)) throw new UsageError(`unsupported --alg ${alg}`);
  const dir = flag(a, "out-dir") ?? ".";
  mkdirSync(dir, { recursive: true });
  const { privateJwk, publicJwk, keyid } = await generateKeyPair(alg);
  const privPath = join(dir, "agent-key.private.jwk.json");
  const dirPath = join(dir, "http-message-signatures-directory.json");
  if (existsSync(privPath) && !has(a, "force")) throw new UsageError(`${privPath} already exists (use --force to overwrite)`);
  writeFileSync(privPath, `${JSON.stringify({ ...privateJwk, kid: keyid }, null, 2)}\n`, { mode: 0o600 });
  writeFileSync(dirPath, `${JSON.stringify(directoryDocument([publicJwk]), null, 2)}\n`);
  process.stdout.write(
    `keyid  ${keyid}\n` +
      `private ${privPath}  (keep secret; never commit)\n` +
      `public  ${dirPath}\n\n` +
      `Serve the public file at https://<your-agent-domain>/.well-known/http-message-signatures-directory\n` +
      `and send Signature-Agent: sig1="https://<your-agent-domain>" with your requests.\n`,
  );
  return 0;
}

async function cmdSign(a: Args): Promise<number> {
  const url = a._[1];
  const keyPath = flag(a, "key");
  if (!url || !keyPath) throw new UsageError("sign needs a URL and --key <file>");
  const method = (flag(a, "method") ?? "GET").toUpperCase();
  const sa = flag(a, "signature-agent");
  const headers = await signRequest(
    { method, url },
    sa ? { privateJwk: readJson(keyPath) as JsonWebKey, signatureAgent: sa } : { privateJwk: readJson(keyPath) as JsonWebKey },
  );
  if (has(a, "curl")) {
    const q = (s: string) => `'${s.replace(/'/g, `'\\''`)}'`;
    const parts = ["curl", "-i", ...(method !== "GET" ? ["-X", method] : [])];
    for (const [k, v] of Object.entries(headers)) parts.push("-H", q(`${k}: ${v}`));
    parts.push(q(url));
    process.stdout.write(`${parts.join(" ")}\n`);
  } else {
    for (const [k, v] of Object.entries(headers)) process.stdout.write(`${k}: ${v}\n`);
  }
  return 0;
}

async function cmdReport(a: Args): Promise<number> {
  const file = a._[1];
  if (!file) throw new UsageError("report needs a JSON Lines file written by jsonLines()/fileLogger()");
  const byClass = new Map<string, number>();
  const byAction = new Map<string, number>();
  const byRule = new Map<string, { total: number; refused: number }>();
  const agents = new Map<string, number>();
  let total = 0;
  let bad = 0;
  const modes = new Set<string>();
  const rl = createInterface({ input: createReadStream(file), crlfDelay: Infinity });
  for await (const line of rl) {
    if (!line.trim()) continue;
    let d: Decision;
    try {
      d = JSON.parse(line) as Decision;
    } catch {
      bad++;
      continue;
    }
    total++;
    modes.add(d.mode);
    byClass.set(d.trust.class, (byClass.get(d.trust.class) ?? 0) + 1);
    byAction.set(d.action, (byAction.get(d.action) ?? 0) + 1);
    const r = byRule.get(d.rule) ?? { total: 0, refused: 0 };
    r.total++;
    if (d.action !== "allow") r.refused++;
    byRule.set(d.rule, r);
    if (d.trust.agent && d.trust.class !== "browser") {
      const k = `${d.trust.agent} (${d.trust.class})`;
      agents.set(k, (agents.get(k) ?? 0) + 1);
    }
  }
  const summary = {
    total,
    unreadableLines: bad,
    modes: [...modes],
    byClass: Object.fromEntries(byClass),
    byAction: Object.fromEntries(byAction),
    byRule: Object.fromEntries(byRule),
    topAgents: Object.fromEntries([...agents].sort((x, y) => y[1] - x[1]).slice(0, 15)),
  };
  if (has(a, "json")) {
    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    return 0;
  }
  const pct = (n: number) => (total ? `${((n / total) * 100).toFixed(1)}%` : "0%");
  const table = (m: Map<string, number>) =>
    [...m].sort((x, y) => y[1] - x[1]).map(([k, v]) => `  ${k.padEnd(28)} ${String(v).padStart(8)}  ${pct(v)}`).join("\n");
  const monitor = modes.has("monitor") && !modes.has("enforce");
  process.stdout.write(
    `${total} decisions${bad ? ` (${bad} unreadable lines skipped)` : ""}${monitor ? ", monitor mode: nothing was blocked" : ""}\n\n` +
      `Visitors by class\n${table(byClass)}\n\n` +
      `${monitor ? "Would have been" : "Outcome"}\n${table(byAction)}\n\n` +
      `By rule (refused / total)\n${[...byRule].map(([k, v]) => `  ${k.padEnd(28)} ${String(v.refused).padStart(8)} / ${v.total}`).join("\n")}\n\n` +
      `Top agents\n${table(agents) || "  (none)"}\n`,
  );
  return 0;
}

export async function main(argv: string[]): Promise<number> {
  let a: Args;
  try {
    a = parseArgs(argv);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n\n${HELP}`);
    return 1;
  }
  if (has(a, "version")) {
    process.stdout.write(`${VERSION}\n`);
    return 0;
  }
  const cmd = a._[0];
  if (!cmd || has(a, "help") || cmd === "help") {
    process.stdout.write(HELP);
    return cmd || has(a, "help") ? 0 : 1;
  }
  try {
    switch (cmd) {
      case "audit":
        return await cmdAudit(a);
      case "init":
        return cmdInit(a);
      case "keygen":
        return await cmdKeygen(a);
      case "sign":
        return await cmdSign(a);
      case "report":
        return await cmdReport(a);
      default:
        throw new UsageError(`unknown command "${cmd}"`);
    }
  } catch (e) {
    if (e instanceof UsageError) {
      process.stderr.write(`error: ${e.message}\n\nRun "agent-doorman help" for usage.\n`);
      return 1;
    }
    process.stderr.write(`error: ${(e as Error).stack ?? e}\n`);
    return 1;
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    process.stderr.write(`${(e as Error).stack ?? e}\n`);
    process.exitCode = 1;
  },
);

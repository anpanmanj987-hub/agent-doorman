// Node.js helpers: http/Express/Connect middleware, a DNS-aware SSRF guard and a file logger.

import { createWriteStream } from "node:fs";
import { lookup } from "node:dns/promises";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createDoorman as createCoreDoorman, type Decision, type Doorman, type DoormanOptions, jsonLines } from "./gate/doorman.js";
import type { RequestLike } from "./httpsig/base.js";
import {
  createDirectoryResolver,
  defaultHostGuard,
  DirectoryError,
  type HostGuard,
  isIpLiteral,
  isPrivateAddress,
} from "./httpsig/directory.js";
import { createVerifier, type Verifier, type VerifyOptions } from "./httpsig/verify.js";

export * from "./index.js";

/** Like defaultHostGuard, but also resolves DNS and refuses names that point at private addresses. */
export const nodeHostGuard: HostGuard = async (url) => {
  await defaultHostGuard(url);
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (isIpLiteral(host)) return;
  let addrs: Array<{ address: string }>;
  try {
    addrs = await lookup(host, { all: true });
  } catch (e) {
    throw new DirectoryError(`cannot resolve ${host}: ${(e as Error).message}`);
  }
  if (addrs.some((a) => isPrivateAddress(a.address))) throw new DirectoryError(`${host} resolves to a private address`);
};

/** createDoorman with Node defaults: directory discovery uses the DNS-aware guard. */
export function createDoorman(options: DoormanOptions): Doorman {
  const v = options.verify;
  const isVerifier = typeof (v as Verifier | undefined)?.verify === "function";
  if (!isVerifier && (v === undefined || (v as VerifyOptions).directory === undefined)) {
    return createCoreDoorman({
      ...options,
      verify: createVerifier({ ...(v as VerifyOptions | undefined), directory: createDirectoryResolver({ hostGuard: nodeHostGuard }) }),
    });
  }
  return createCoreDoorman(options);
}

export interface NodeMiddlewareOptions {
  /** Defaults to the socket address (or the first X-Forwarded-For hop when trustProxy is set on the doorman). */
  getIp?: (req: IncomingMessage) => string | undefined;
  /** Origin to use when the Host header is missing. Default http://localhost. */
  fallbackOrigin?: string;
}

export function toRequestLike(req: IncomingMessage, fallbackOrigin = "http://localhost"): RequestLike {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) for (const v of value) headers.append(name, v);
    else headers.set(name, value);
  }
  const encrypted = (req.socket as { encrypted?: boolean } | undefined)?.encrypted === true;
  const host = req.headers.host;
  const origin = host ? `${encrypted ? "https" : "http"}://${host}` : fallbackOrigin;
  let url: string;
  try {
    url = new URL(req.url ?? "/", origin).href;
  } catch {
    url = new URL("/", fallbackOrigin).href;
  }
  return { method: req.method ?? "GET", url, headers };
}

async function send(res: ServerResponse, response: Response): Promise<void> {
  res.statusCode = response.status;
  response.headers.forEach((value, name) => res.setHeader(name, value));
  res.end(response.body ? Buffer.from(await response.arrayBuffer()) : undefined);
}

type Next = (err?: unknown) => void;

/**
 * Express/Connect/node:http middleware.
 * The decision is attached to `req.agentDoorman` for your handlers and logs.
 */
export function nodeMiddleware(doorman: Doorman, options: NodeMiddlewareOptions = {}) {
  return async function agentDoorman(req: IncomingMessage, res: ServerResponse, next?: Next): Promise<void> {
    try {
      const request = toRequestLike(req, options.fallbackOrigin);
      const ip = options.getIp ? options.getIp(req) : req.socket?.remoteAddress;
      const { decision, response } = await doorman.check(request, ip ? { ip } : undefined);
      if (decision) req.agentDoorman = decision;
      if (response) {
        await send(res, response);
        return;
      }
      next?.();
    } catch (err) {
      if (next) next(err);
      else {
        res.statusCode = 500;
        res.end();
      }
    }
  };
}

/** Append decisions as JSON Lines to a file (for `agent-doorman report`). */
export function fileLogger(path: string): (d: Decision) => void {
  const stream = createWriteStream(path, { flags: "a" });
  return jsonLines((line) => stream.write(line));
}

declare module "node:http" {
  interface IncomingMessage {
    agentDoorman?: Decision;
  }
}

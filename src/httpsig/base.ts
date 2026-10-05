// RFC 9421 §2: deriving component values and building the signature base for a request.

import {
  type InnerList,
  type Item,
  parseDictionary,
  serializeInnerList,
  serializeItem,
  serializeMember,
} from "../sf.js";

/** The subset of the Fetch API Request that signing/verification needs. */
export interface RequestLike {
  method: string;
  url: string;
  headers: Headers;
}

/** Lets deployments behind a trusted proxy supply the externally visible authority/scheme. */
export interface MessageContext {
  authority?: string;
  scheme?: string;
}

export class ComponentError extends Error {
  override name = "ComponentError";
}

interface View {
  method: string;
  scheme: string;
  authority: string;
  path: string;
  query: string;
}

function view(req: RequestLike, ctx: MessageContext = {}): View {
  const u = new URL(req.url);
  const scheme = (ctx.scheme ?? u.protocol.replace(/:$/, "")).toLowerCase();
  let authority = (ctx.authority ?? u.host).toLowerCase();
  // RFC 9421 §2.2.3: default ports are omitted.
  if ((scheme === "https" && authority.endsWith(":443")) || (scheme === "http" && authority.endsWith(":80"))) {
    authority = authority.replace(/:\d+$/, "");
  }
  return {
    method: req.method.toUpperCase(),
    scheme,
    authority,
    path: u.pathname || "/",
    query: u.search || "?",
  };
}

export function componentName(id: Item): string {
  if (typeof id.value !== "string") throw new ComponentError("component identifier must be a string");
  return id.value;
}

export function componentValue(req: RequestLike, id: Item, ctx?: MessageContext): string {
  const name = componentName(id);
  for (const p of id.params.keys()) {
    if (p !== "key") throw new ComponentError(`unsupported component parameter ;${p} on "${name}"`);
  }
  const v = view(req, ctx);
  if (name.startsWith("@")) {
    if (id.params.size) throw new ComponentError(`parameters not allowed on ${name}`);
    switch (name) {
      case "@method":
        return v.method;
      case "@authority":
        return v.authority;
      case "@scheme":
        return v.scheme;
      case "@target-uri":
        return `${v.scheme}://${v.authority}${v.path}${v.query === "?" ? "" : v.query}`;
      case "@path":
        return v.path;
      case "@query":
        return v.query;
      case "@request-target":
        return `${v.path}${v.query === "?" ? "" : v.query}`;
      default:
        throw new ComponentError(`unsupported derived component ${name}`);
    }
  }
  if (name !== name.toLowerCase()) throw new ComponentError(`field names must be lowercase: ${name}`);
  const raw = req.headers.get(name);
  if (raw === null) throw new ComponentError(`missing header: ${name}`);
  const value = raw.trim();
  const key = id.params.get("key");
  if (key === undefined) return value;
  if (typeof key !== "string") throw new ComponentError(";key must be a string");
  let member;
  try {
    member = parseDictionary(value).get(key);
  } catch (e) {
    throw new ComponentError(`header ${name} is not a valid dictionary: ${(e as Error).message}`);
  }
  if (!member) throw new ComponentError(`dictionary member "${key}" missing from ${name}`);
  return serializeMember(member);
}

/** RFC 9421 §2.5 signature base. `inner` is the Signature-Input member for the label. */
export function createSignatureBase(req: RequestLike, inner: InnerList, ctx?: MessageContext): string {
  const seen = new Set<string>();
  const lines: string[] = [];
  for (const id of inner.items) {
    const ident = serializeItem(id);
    if (seen.has(ident)) throw new ComponentError(`duplicate component ${ident}`);
    seen.add(ident);
    const value = componentValue(req, id, ctx);
    if (/[\r\n]/.test(value)) throw new ComponentError(`component ${ident} contains a newline`);
    lines.push(`${ident}: ${value}`);
  }
  lines.push(`"@signature-params": ${serializeInnerList(inner)}`);
  return lines.join("\n");
}

// Minimal, strict implementation of RFC 8941 (Structured Field Values for HTTP).
// Covers what RFC 9421 HTTP Message Signatures needs: dictionaries, inner lists,
// items, parameters, strings, tokens, integers, decimals, booleans, byte sequences.

import { base64ToBytes, bytesToBase64 } from "./b64.js";

export class Token {
  constructor(readonly value: string) {}
  toString(): string {
    return this.value;
  }
}

export type BareItem = number | string | boolean | Uint8Array | Token;
export type Params = Map<string, BareItem>;

export interface Item {
  kind: "item";
  value: BareItem;
  params: Params;
}

export interface InnerList {
  kind: "inner";
  items: Item[];
  params: Params;
}

export type Member = Item | InnerList;
export type Dictionary = Map<string, Member>;

export class SFParseError extends Error {
  override name = "SFParseError";
}

export function item(value: BareItem, params?: Record<string, BareItem> | Params): Item {
  return { kind: "item", value, params: toParams(params) };
}

export function innerList(items: Item[], params?: Record<string, BareItem> | Params): InnerList {
  return { kind: "inner", items, params: toParams(params) };
}

function toParams(p?: Record<string, BareItem> | Params): Params {
  if (!p) return new Map();
  if (p instanceof Map) return p;
  return new Map(Object.entries(p));
}

const isDigit = (c: string | undefined) => c !== undefined && c >= "0" && c <= "9";
const isLcAlpha = (c: string | undefined) => c !== undefined && c >= "a" && c <= "z";
const isAlpha = (c: string | undefined) =>
  c !== undefined && ((c >= "a" && c <= "z") || (c >= "A" && c <= "Z"));
const TCHAR = new Set("!#$%&'*+-.^_`|~".split(""));
const isTchar = (c: string | undefined) => c !== undefined && (TCHAR.has(c) || isDigit(c) || isAlpha(c));

class Parser {
  i = 0;
  constructor(private readonly s: string) {}

  get done(): boolean {
    return this.i >= this.s.length;
  }
  peek(): string | undefined {
    return this.s[this.i];
  }
  fail(msg: string): never {
    throw new SFParseError(`${msg} at offset ${this.i}`);
  }
  skipSP(): void {
    while (this.peek() === " ") this.i++;
  }
  skipOWS(): void {
    while (this.peek() === " " || this.peek() === "\t") this.i++;
  }

  dictionary(): Dictionary {
    const dict: Dictionary = new Map();
    this.skipSP();
    if (this.done) return dict;
    for (;;) {
      const key = this.key();
      let member: Member;
      if (this.peek() === "=") {
        this.i++;
        member = this.itemOrInnerList();
      } else {
        member = { kind: "item", value: true, params: this.parameters() };
      }
      dict.set(key, member);
      this.skipOWS();
      if (this.done) return dict;
      if (this.peek() !== ",") this.fail("expected ','");
      this.i++;
      this.skipOWS();
      if (this.done) this.fail("trailing comma");
    }
  }

  list(): Member[] {
    const out: Member[] = [];
    this.skipSP();
    if (this.done) return out;
    for (;;) {
      out.push(this.itemOrInnerList());
      this.skipOWS();
      if (this.done) return out;
      if (this.peek() !== ",") this.fail("expected ','");
      this.i++;
      this.skipOWS();
      if (this.done) this.fail("trailing comma");
    }
  }

  itemOrInnerList(): Member {
    return this.peek() === "(" ? this.innerList() : this.item();
  }

  innerList(): InnerList {
    if (this.peek() !== "(") this.fail("expected '('");
    this.i++;
    const items: Item[] = [];
    for (;;) {
      this.skipSP();
      if (this.peek() === ")") {
        this.i++;
        return { kind: "inner", items, params: this.parameters() };
      }
      if (this.done) this.fail("unterminated inner list");
      items.push(this.item());
      const c = this.peek();
      if (c !== " " && c !== ")") this.fail("expected SP or ')' in inner list");
    }
  }

  item(): Item {
    const value = this.bareItem();
    return { kind: "item", value, params: this.parameters() };
  }

  bareItem(): BareItem {
    const c = this.peek();
    if (c === "-" || isDigit(c)) return this.number();
    if (c === '"') return this.string();
    if (c === ":") return this.byteSequence();
    if (c === "?") return this.boolean();
    if (isAlpha(c) || c === "*") return this.token();
    return this.fail("unexpected character for bare item");
  }

  parameters(): Params {
    const params: Params = new Map();
    while (this.peek() === ";") {
      this.i++;
      this.skipSP();
      const key = this.key();
      let value: BareItem = true;
      if (this.peek() === "=") {
        this.i++;
        value = this.bareItem();
      }
      params.set(key, value);
    }
    return params;
  }

  key(): string {
    const c = this.peek();
    if (!isLcAlpha(c) && c !== "*") this.fail("invalid key");
    const start = this.i;
    while (!this.done) {
      const ch = this.peek();
      if (isLcAlpha(ch) || isDigit(ch) || ch === "_" || ch === "-" || ch === "." || ch === "*") this.i++;
      else break;
    }
    return this.s.slice(start, this.i);
  }

  number(): number {
    const start = this.i;
    let sign = 1;
    if (this.peek() === "-") {
      sign = -1;
      this.i++;
    }
    if (!isDigit(this.peek())) this.fail("expected digit");
    let intPart = "";
    let frac: string | null = null;
    while (isDigit(this.peek())) intPart += this.s[this.i++];
    if (this.peek() === ".") {
      if (intPart.length > 12) this.fail("decimal integer part too long");
      this.i++;
      frac = "";
      while (isDigit(this.peek())) frac += this.s[this.i++];
      if (frac.length === 0 || frac.length > 3) this.fail("invalid decimal fraction");
    } else if (intPart.length > 15) {
      this.i = start;
      this.fail("integer too long");
    }
    return sign * Number(frac === null ? intPart : `${intPart}.${frac}`);
  }

  string(): string {
    this.i++; // opening quote
    let out = "";
    for (;;) {
      if (this.done) this.fail("unterminated string");
      const c = this.s[this.i++]!;
      if (c === "\\") {
        const n = this.s[this.i++];
        if (n !== '"' && n !== "\\") this.fail("invalid escape in string");
        out += n;
      } else if (c === '"') {
        return out;
      } else {
        const code = c.charCodeAt(0);
        if (code < 0x20 || code > 0x7e) this.fail("invalid character in string");
        out += c;
      }
    }
  }

  token(): Token {
    const start = this.i;
    this.i++;
    while (!this.done) {
      const c = this.peek();
      if (isTchar(c) || c === ":" || c === "/") this.i++;
      else break;
    }
    return new Token(this.s.slice(start, this.i));
  }

  byteSequence(): Uint8Array {
    this.i++; // ':'
    const end = this.s.indexOf(":", this.i);
    if (end < 0) this.fail("unterminated byte sequence");
    const b64 = this.s.slice(this.i, end);
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) this.fail("invalid base64 in byte sequence");
    this.i = end + 1;
    try {
      return base64ToBytes(b64);
    } catch {
      return this.fail("invalid base64 in byte sequence");
    }
  }

  boolean(): boolean {
    this.i++; // '?'
    const c = this.s[this.i++];
    if (c === "1") return true;
    if (c === "0") return false;
    return this.fail("invalid boolean");
  }
}

function finish<T>(p: Parser, value: T): T {
  p.skipSP();
  if (!p.done) p.fail("unexpected trailing characters");
  return value;
}

export function parseDictionary(input: string): Dictionary {
  const p = new Parser(input);
  return finish(p, p.dictionary());
}

export function parseList(input: string): Member[] {
  const p = new Parser(input);
  return finish(p, p.list());
}

export function parseItem(input: string): Item {
  const p = new Parser(input);
  p.skipSP();
  return finish(p, p.item());
}

// ---------------------------------------------------------------- serialize

export function serializeBareItem(v: BareItem): string {
  if (typeof v === "boolean") return v ? "?1" : "?0";
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new TypeError("non-finite number");
    if (Number.isInteger(v)) return String(v);
    const fixed = (Math.round(v * 1000) / 1000).toFixed(3).replace(/0+$/, "");
    return fixed.endsWith(".") ? `${fixed}0` : fixed;
  }
  if (typeof v === "string") {
    for (const ch of v) {
      const code = ch.charCodeAt(0);
      if (code < 0x20 || code > 0x7e) throw new TypeError("string contains non-printable ASCII");
    }
    return `"${v.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
  }
  if (v instanceof Token) return v.value;
  if (v instanceof Uint8Array) return `:${bytesToBase64(v)}:`;
  throw new TypeError("unsupported bare item");
}

export function serializeParams(params: Params): string {
  let out = "";
  for (const [k, v] of params) out += v === true ? `;${k}` : `;${k}=${serializeBareItem(v)}`;
  return out;
}

export function serializeItem(it: Item): string {
  return serializeBareItem(it.value) + serializeParams(it.params);
}

export function serializeInnerList(il: InnerList): string {
  return `(${il.items.map(serializeItem).join(" ")})${serializeParams(il.params)}`;
}

export function serializeMember(m: Member): string {
  return m.kind === "inner" ? serializeInnerList(m) : serializeItem(m);
}

export function serializeDictionary(dict: Dictionary): string {
  const parts: string[] = [];
  for (const [k, m] of dict) {
    if (m.kind === "item" && m.value === true) parts.push(k + serializeParams(m.params));
    else parts.push(`${k}=${serializeMember(m)}`);
  }
  return parts.join(", ");
}

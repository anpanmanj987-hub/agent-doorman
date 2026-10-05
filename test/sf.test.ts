import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  parseDictionary,
  parseItem,
  parseList,
  serializeDictionary,
  serializeInnerList,
  SFParseError,
  Token,
} from "../src/sf.js";

describe("RFC 8941 structured fields", () => {
  it("parses a Signature-Input style dictionary and round-trips it", () => {
    const raw = 'sig1=("@authority" "signature-agent";key="sig1");created=1700000000;keyid="abc";tag="web-bot-auth"';
    const d = parseDictionary(raw);
    const m = d.get("sig1")!;
    assert.equal(m.kind, "inner");
    if (m.kind !== "inner") return;
    assert.equal(m.items.length, 2);
    assert.equal(m.items[1]!.params.get("key"), "sig1");
    assert.equal(m.params.get("created"), 1700000000);
    assert.equal(serializeDictionary(d), raw);
    assert.equal(`sig1=${serializeInnerList(m)}`, raw);
  });

  it("parses byte sequences, tokens, booleans, decimals", () => {
    const d = parseDictionary("a=:aGVsbG8=:, b=tok/en:x, c, d=?0, e=-1.5;p=?1");
    assert.deepEqual([...((d.get("a") as { value: Uint8Array }).value)], [...new TextEncoder().encode("hello")]);
    assert.ok((d.get("b") as { value: unknown }).value instanceof Token);
    assert.equal((d.get("c") as { value: unknown }).value, true);
    assert.equal((d.get("d") as { value: unknown }).value, false);
    assert.equal((d.get("e") as { value: unknown }).value, -1.5);
    assert.equal(serializeDictionary(d), "a=:aGVsbG8=:, b=tok/en:x, c, d=?0, e=-1.5;p");
  });

  it("handles escapes in strings", () => {
    const it1 = parseItem('"a \\"quoted\\" \\\\ value"');
    assert.equal(it1.value, 'a "quoted" \\ value');
  });

  it("parses lists", () => {
    assert.equal(parseList("a, (b c);x=1, ?1").length, 3);
  });

  for (const bad of ['sig1=("a"', "Sig=1", "a=1,", 'a="\u0001"', "a=:not base64!:", "a=?2", "a=1 b", 'a="unterminated']) {
    it(`rejects malformed input: ${JSON.stringify(bad)}`, () => {
      assert.throws(() => parseDictionary(bad), SFParseError);
    });
  }
});

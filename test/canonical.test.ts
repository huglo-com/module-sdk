import { describe, it, expect } from "vitest";
import { canonicalizeObject, canonicalizeToBytes } from "../src/canonical.js";

describe("canonical", () => {
  it("produces deterministic JCS output", () => {
    const obj = { b: 2, a: 1, c: { z: 3, y: 2 } };
    expect(canonicalizeObject(obj)).toBe('{"a":1,"b":2,"c":{"y":2,"z":3}}');
    expect(canonicalizeObject(obj)).toBe(canonicalizeObject({ ...obj }));
  });

  it("returns UTF-8 bytes", () => {
    const bytes = canonicalizeToBytes({ x: 1 });
    expect(bytes.toString("utf8")).toBe('{"x":1}');
  });

  it("throws on non-serializable values", () => {
    const circular: Record<string, unknown> = {};
    circular["self"] = circular;
    expect(() => canonicalizeObject(circular)).toThrow();
  });
});

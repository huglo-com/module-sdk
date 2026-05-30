import { describe, it, expect } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import {
  signObject,
  verifyObject,
  parseSignature,
  encodeSignature,
} from "../src/signing.js";

describe("signing", () => {
  const { publicKey, privateKey } = generateKeyPair();

  it("signs and verifies an object", () => {
    const obj = { payload: "hello", count: 42 };
    const sig = signObject(obj, privateKey);
    expect(verifyObject(obj, sig, publicKey)).toBe(true);
  });

  it("rejects tampered objects", () => {
    const obj = { payload: "hello" };
    const sig = signObject(obj, privateKey);
    expect(verifyObject({ payload: "world" }, sig, publicKey)).toBe(false);
  });

  it("supports ed25519:<base64> encoding", () => {
    const obj = { a: 1 };
    const sig = signObject(obj, privateKey);
    const parsed = parseSignature(sig);
    expect(parsed.algorithm).toBe("ed25519");
    expect(parsed.keyId).toBeUndefined();
    expect(parsed.signature.length).toBeGreaterThan(0);
  });

  it("supports ed25519:<keyId>:<base64> encoding for key rotation stub", () => {
    const obj = { a: 1 };
    const sigBytes = Buffer.from("fake-sig");
    const encoded = encodeSignature(sigBytes, "key-v2");
    const parsed = parseSignature(encoded);
    expect(parsed.keyId).toBe("key-v2");
    expect(parsed.signature.equals(sigBytes)).toBe(true);
  });

  it("signs with optional keyId", () => {
    const obj = { test: true };
    const sig = signObject(obj, privateKey, "key-v1");
    expect(sig.startsWith("ed25519:key-v1:")).toBe(true);
    expect(verifyObject(obj, sig, publicKey)).toBe(true);
  });

  it("rejects invalid signature format", () => {
    expect(() => parseSignature("rsa:abc")).toThrow();
  });
});

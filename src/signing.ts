import { sign, verify, type KeyObject } from "node:crypto";
import { canonicalizeToBytes } from "./canonical.js";

/** Signature wire format: `ed25519:<base64>` or `ed25519:<keyId>:<base64>` for future key rotation. */
export type SignatureString = string;

export interface ParsedSignature {
  algorithm: "ed25519";
  /** Present when using the rotation encoding; undefined for legacy `ed25519:<base64>`. */
  keyId?: string;
  signature: Buffer;
}

/**
 * Parse a signature string.
 * Supports `ed25519:<base64>` and `ed25519:<keyId>:<base64>`.
 *
 * TODO: key rotation — full overlap-window protocol is future work.
 */
export function parseSignature(sig: string): ParsedSignature {
  if (!sig.startsWith("ed25519:")) {
    throw new Error("Invalid signature format: expected ed25519 prefix");
  }
  const rest = sig.slice("ed25519:".length);
  const colonIdx = rest.indexOf(":");
  if (colonIdx === -1) {
    return {
      algorithm: "ed25519",
      signature: Buffer.from(rest, "base64"),
    };
  }
  const keyId = rest.slice(0, colonIdx);
  const b64 = rest.slice(colonIdx + 1);
  return {
    algorithm: "ed25519",
    keyId,
    signature: Buffer.from(b64, "base64"),
  };
}

/** Encode a signature buffer as `ed25519:<base64>` or `ed25519:<keyId>:<base64>`. */
export function encodeSignature(signature: Buffer, keyId?: string): SignatureString {
  const b64 = signature.toString("base64");
  if (keyId) {
    return `ed25519:${keyId}:${b64}`;
  }
  return `ed25519:${b64}`;
}

/** Sign a parsed object using JCS canonicalization. */
export function signObject(
  obj: unknown,
  privateKey: KeyObject,
  keyId?: string,
): SignatureString {
  const data = canonicalizeToBytes(obj);
  const sig = sign(null, data, privateKey);
  return encodeSignature(sig, keyId);
}

/** Verify a parsed object signature using JCS canonicalization. */
export function verifyObject(
  obj: unknown,
  sigString: SignatureString,
  publicKey: KeyObject,
): boolean {
  const parsed = parseSignature(sigString);
  const data = canonicalizeToBytes(obj);
  return verify(null, data, publicKey, parsed.signature);
}

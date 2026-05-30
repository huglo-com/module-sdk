import canonicalize from "canonicalize";

/**
 * Returns the RFC 8785 (JCS) canonical serialization of a parsed object.
 * Both signer and verifier must call this independently — never sign raw wire bytes.
 */
export function canonicalizeObject(obj: unknown): string {
  const result = canonicalize(obj);
  if (result === undefined) {
    throw new Error("Object is not JSON-serializable for canonicalization");
  }
  return result;
}

/** Returns UTF-8 bytes of the JCS string, used as the Ed25519 message. */
export function canonicalizeToBytes(obj: unknown): Buffer {
  return Buffer.from(canonicalizeObject(obj), "utf8");
}

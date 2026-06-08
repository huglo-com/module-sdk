import { describe, it, expect, beforeEach } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import {
  verifyConfigProof,
  CONFIG_PROOF_PURPOSE,
  CONFIG_PROOF_TTL_MS,
} from "../src/config-proof.js";
import { NonceCache } from "../src/verify.js";
import { createSignedConfigProof } from "./helpers/create-signed-config-proof.js";

describe("config-proof", () => {
  const userKeys = generateKeyPair();
  const directory = new InMemoryDirectoryClient();
  const moduleId = "acme-module";
  const nonceCache = new NonceCache();

  beforeEach(() => {
    directory.clear();
    nonceCache.clear();
    directory.registerUser("alice", userKeys.publicKey);
  });

  function verifyOpts(overrides: { now?: number } = {}) {
    return { moduleId, directory, nonceCache, ...overrides };
  }

  function validProof(overrides: Partial<ReturnType<typeof createSignedConfigProof>["assertion"]> = {}) {
    const proof = createSignedConfigProof({
      subject: "huglo:user:alice",
      audience: moduleId,
      privateKey: userKeys.privateKey,
    });
    if (Object.keys(overrides).length > 0) {
      const assertion = { ...proof.assertion, ...overrides };
      return { assertion, signature: signObject(assertion, userKeys.privateKey) };
    }
    return proof;
  }

  it("verifyConfigProof returns subject on valid proof", async () => {
    const proof = validProof();
    const subject = await verifyConfigProof(proof, verifyOpts());
    expect(subject).toBe("huglo:user:alice");
  });

  it("createSignedConfigProof uses config purpose and default TTL", () => {
    const proof = createSignedConfigProof({
      subject: "huglo:user:alice",
      audience: moduleId,
      privateKey: userKeys.privateKey,
    });
    expect(proof.assertion.purpose).toBe(CONFIG_PROOF_PURPOSE);
    const issued = Date.parse(proof.assertion.issued_at);
    const expires = Date.parse(proof.assertion.expires_at);
    expect(expires - issued).toBe(CONFIG_PROOF_TTL_MS);
  });

  it("rejects invalid signature", async () => {
    const proof = validProof();
    proof.signature = signObject(proof.assertion, generateKeyPair().privateKey);
    await expect(verifyConfigProof(proof, verifyOpts())).rejects.toMatchObject({
      code: "config_proof_invalid_signature",
    });
  });

  it("rejects wrong audience", async () => {
    const proof = validProof({ audience: "other-module" });
    await expect(verifyConfigProof(proof, verifyOpts())).rejects.toMatchObject({
      code: "config_proof_audience_mismatch",
    });
  });

  it("rejects wrong purpose", async () => {
    const proof = validProof({ purpose: "grant" as typeof CONFIG_PROOF_PURPOSE });
    await expect(verifyConfigProof(proof, verifyOpts())).rejects.toMatchObject({
      code: "config_proof_purpose_mismatch",
    });
  });

  it("rejects expired proof", async () => {
    const now = Date.now();
    const proof = createSignedConfigProof({
      subject: "huglo:user:alice",
      audience: moduleId,
      privateKey: userKeys.privateKey,
      now: now - 10_000,
      ttlMs: 1_000,
    });
    await expect(
      verifyConfigProof(proof, verifyOpts({ now })),
    ).rejects.toMatchObject({ code: "config_proof_expired" });
  });

  it("rejects unknown subject", async () => {
    const proof = createSignedConfigProof({
      subject: "huglo:user:unknown",
      audience: moduleId,
      privateKey: userKeys.privateKey,
    });
    await expect(verifyConfigProof(proof, verifyOpts())).rejects.toMatchObject({
      code: "config_proof_user_not_found",
    });
  });

  it("rejects replayed nonce", async () => {
    const proof = createSignedConfigProof({
      subject: "huglo:user:alice",
      audience: moduleId,
      privateKey: userKeys.privateKey,
    });
    await verifyConfigProof(proof, verifyOpts());
    await expect(verifyConfigProof(proof, verifyOpts())).rejects.toMatchObject({
      code: "config_proof_nonce_replayed",
    });
  });

  it("rejects malformed proof", async () => {
    await expect(verifyConfigProof(null, verifyOpts())).rejects.toMatchObject({
      code: "invalid_config_proof",
    });
  });
});

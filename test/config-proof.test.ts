import { describe, it, expect, beforeEach, vi } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { HttpDirectoryClient, InMemoryDirectoryClient } from "../src/directory.js";
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

  it("verifyConfigProof accepts an agent subject registered on the subject key map", async () => {
    const agentKeys = generateKeyPair();
    directory.registerSubject("huglo:agent:agt_1", agentKeys.publicKey);
    const proof = createSignedConfigProof({
      subject: "huglo:agent:agt_1",
      audience: moduleId,
      privateKey: agentKeys.privateKey,
    });
    await expect(verifyConfigProof(proof, verifyOpts())).resolves.toBe("huglo:agent:agt_1");
  });

  it("does not verify an agent-subject proof against a user key with the same id suffix", async () => {
    const agentKeys = generateKeyPair();
    const proof = createSignedConfigProof({
      subject: "huglo:agent:alice",
      audience: moduleId,
      privateKey: userKeys.privateKey,
    });
    directory.registerSubject("huglo:agent:alice", agentKeys.publicKey);
    await expect(verifyConfigProof(proof, verifyOpts())).rejects.toMatchObject({
      code: "config_proof_invalid_signature",
    });
  });
});

describe("config-proof HttpDirectoryClient lookup", () => {
  const moduleId = "acme-module";
  const userKeys = generateKeyPair();
  const agentKeys = generateKeyPair();
  const otherKeys = generateKeyPair();

  function httpVerify(
    fetchFn: typeof fetch,
    proof: ReturnType<typeof createSignedConfigProof>,
  ) {
    const directory = new HttpDirectoryClient({
      directoryUrl: "https://directory.example",
      fetch: fetchFn,
    });
    return verifyConfigProof(proof, {
      moduleId,
      directory,
      nonceCache: new NonceCache(),
    });
  }

  it("looks up user subjects on the subjects endpoint and verifies", async () => {
    const subject = "huglo:user:alice";
    const proof = createSignedConfigProof({
      subject,
      audience: moduleId,
      privateKey: userKeys.privateKey,
    });
    const fetchFn = vi.fn().mockResolvedValue(
      Response.json({ subject, publicKey: userKeys.publicKeyBase64 }),
    );

    await expect(httpVerify(fetchFn, proof)).resolves.toBe(subject);
    expect(String(fetchFn.mock.calls[0]?.[0])).toBe(
      `https://directory.example/directory/subjects/${encodeURIComponent(subject)}/key`,
    );
  });

  it("looks up agent and project subjects on the subjects endpoint", async () => {
    const agentSubject = "huglo:agent:agt_1";
    const projectSubject = "huglo:proj1:entity-1";
    const fetchFn = vi.fn().mockImplementation(async (url: string | URL | Request) => {
      const path = String(url);
      if (path.includes(encodeURIComponent(agentSubject))) {
        return Response.json({ subject: agentSubject, publicKey: agentKeys.publicKeyBase64 });
      }
      if (path.includes(encodeURIComponent(projectSubject))) {
        return Response.json({ subject: projectSubject, publicKey: agentKeys.publicKeyBase64 });
      }
      return new Response(null, { status: 404 });
    });

    await expect(
      httpVerify(
        fetchFn,
        createSignedConfigProof({
          subject: agentSubject,
          audience: moduleId,
          privateKey: agentKeys.privateKey,
        }),
      ),
    ).resolves.toBe(agentSubject);

    await expect(
      httpVerify(
        fetchFn,
        createSignedConfigProof({
          subject: projectSubject,
          audience: moduleId,
          privateKey: agentKeys.privateKey,
        }),
      ),
    ).resolves.toBe(projectSubject);

    const requested = fetchFn.mock.calls.map((call) => String(call[0]));
    expect(requested).toEqual([
      `https://directory.example/directory/subjects/${encodeURIComponent(agentSubject)}/key`,
      `https://directory.example/directory/subjects/${encodeURIComponent(projectSubject)}/key`,
    ]);
    expect(requested.some((url) => url.includes("/directory/users/"))).toBe(false);
  });

  it("fails closed when the subject key is missing", async () => {
    const proof = createSignedConfigProof({
      subject: "huglo:agent:agt_missing",
      audience: moduleId,
      privateKey: agentKeys.privateKey,
    });
    const fetchFn = vi.fn().mockResolvedValue(new Response(null, { status: 404 }));
    await expect(httpVerify(fetchFn, proof)).rejects.toMatchObject({
      code: "config_proof_user_not_found",
    });
  });

  it("fails closed when the directory returns another principal's key", async () => {
    const proof = createSignedConfigProof({
      subject: "huglo:agent:agt_1",
      audience: moduleId,
      privateKey: otherKeys.privateKey,
    });
    const fetchFn = vi.fn().mockResolvedValue(
      Response.json({
        subject: "huglo:user:alice",
        publicKey: otherKeys.publicKeyBase64,
      }),
    );
    await expect(httpVerify(fetchFn, proof)).rejects.toMatchObject({
      code: "config_proof_user_not_found",
    });
  });
});

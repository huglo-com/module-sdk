import { describe, it, expect } from "vitest";
import { z } from "zod";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import { callScope } from "../src/client.js";
import type { SignedGrant } from "../src/envelope.js";
import { sig2OpenPayload } from "../src/envelope.js";

describe("client", () => {
  const requesterKeys = generateKeyPair();
  const holderKeys = generateKeyPair();
  const authorKeys = generateKeyPair();
  const directory = new InMemoryDirectoryClient();

  directory.registerModule(
    "trovi",
    "http://localhost:9999",
    holderKeys.publicKey,
    holderKeys.publicKeyBase64,
  );
  directory.registerUser("user-1", authorKeys.publicKey);

  function buildGrant(overrides: Partial<SignedGrant["grant"]> = {}): SignedGrant {
    const grant = {
      grant_id: "g-client-001",
      holder: "trovi",
      scope: "test:scope",
      subject: "huglo:user:user-1",
      requester: "foaf",
      author: "huglo:user:user-1",
      constraints: {},
      issued_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      ...overrides,
    };
    return { grant, signature: signObject(grant, authorKeys.privateKey) };
  }

  it("rejects grant with wrong requester", async () => {
    const grant = buildGrant({ requester: "other" });
    await expect(
      callScope(
        { moduleId: "foaf", privateKey: requesterKeys.privateKey, directory },
        { target: "trovi", scope: "test:scope", input: {}, grant },
      ),
    ).rejects.toMatchObject({ code: "grant_requester_mismatch" });
  });

  it("rejects grant with wrong holder", async () => {
    const grant = buildGrant({ holder: "other" });
    await expect(
      callScope(
        { moduleId: "foaf", privateKey: requesterKeys.privateKey, directory },
        { target: "trovi", scope: "test:scope", input: {}, grant },
      ),
    ).rejects.toMatchObject({ code: "grant_holder_mismatch" });
  });

  it("rejects grant with wrong scope", async () => {
    const grant = buildGrant({ scope: "other:scope" });
    await expect(
      callScope(
        { moduleId: "foaf", privateKey: requesterKeys.privateKey, directory },
        { target: "trovi", scope: "test:scope", input: {}, grant },
      ),
    ).rejects.toMatchObject({ code: "grant_scope_mismatch" });
  });

  it("open call envelope has no grant field", () => {
    const timestamp = new Date().toISOString();
    const envelope = {
      payload: { x: 1 },
      requester: "foaf",
      scope: "status:read",
      timestamp,
      nonce: crypto.randomUUID(),
      requesterSignature: "",
    };
    envelope.requesterSignature = signObject(sig2OpenPayload(envelope), requesterKeys.privateKey);
    const parsed = JSON.parse(JSON.stringify(envelope)) as Record<string, unknown>;
    expect(parsed).not.toHaveProperty("grant");
    expect(parsed.requester).toBe("foaf");
  });
});

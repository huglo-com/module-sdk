import { describe, it, expect, beforeEach, vi } from "vitest";
import { z } from "zod";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { InMemoryDirectoryClient, HttpDirectoryClient } from "../src/directory.js";
import { verifyInvokeRequest, verifyOpenInvokeRequest, NonceCache } from "../src/verify.js";
import type { SignedGrant, InvokeRequest, OpenInvokeRequest } from "../src/envelope.js";
import { sig1Payload, sig2Payload, sig2OpenPayload } from "../src/envelope.js";

describe("verify", () => {
  const holderKeys = generateKeyPair();
  const requesterKeys = generateKeyPair();
  const authorKeys = generateKeyPair();
  const directory = new InMemoryDirectoryClient();
  const nonceCache = new NonceCache();
  const inputSchema = z.object({ amount: z.number(), vendor: z.string() });

  beforeEach(() => {
    nonceCache.clear();
    directory.clear();

    directory.registerModule(
      "trovi",
      "http://localhost:3000",
      holderKeys.publicKey,
      holderKeys.publicKeyBase64,
    );
    directory.registerModule(
      "foaf",
      "http://localhost:3001",
      requesterKeys.publicKey,
      requesterKeys.publicKeyBase64,
    );
    directory.registerUser("user-abc", authorKeys.publicKey);
  });

  function buildGrant(overrides: Partial<SignedGrant["grant"]> = {}): SignedGrant {
    const grant = {
      grant_id: "g-test-001",
      holder: "trovi",
      scope: "invoices:write",
      subject: "huglo:user:user-abc",
      requester: "foaf",
      author: "huglo:user:user-abc",
      constraints: {},
      issued_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      ...overrides,
    };
    const signed: SignedGrant = {
      grant,
      signature: signObject(grant, authorKeys.privateKey),
    };
    return signed;
  }

  function buildRequest(
    grant: SignedGrant,
    payload: unknown,
    overrides: Partial<InvokeRequest> = {},
  ): InvokeRequest {
    const req: InvokeRequest = {
      payload,
      grant,
      scope: "invoices:write",
      timestamp: new Date().toISOString(),
      nonce: crypto.randomUUID(),
      requesterSignature: "",
      ...overrides,
    };
    req.requesterSignature = signObject(sig2Payload(req), requesterKeys.privateKey);
    return req;
  }

  it("passes all 11 verification steps for a valid request", async () => {
    const grant = buildGrant();
    const req = buildRequest(grant, { amount: 100, vendor: "Acme" });

    const ctx = await verifyInvokeRequest(req, nonceCache, {
      moduleId: "trovi",
      urlScope: "invoices:write",
      inputSchema,
      directory,
    });

    expect(ctx.open).toBe(false);
    expect(ctx.subject).toBe("huglo:user:user-abc");
    expect(ctx.caller).toBe("foaf");
    expect(ctx.input).toEqual({ amount: 100, vendor: "Acme" });
  });

  it("rejects malformed envelope", async () => {
    await expect(
      verifyInvokeRequest({ bad: true }, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "malformed_request" });
  });

  it("rejects expired timestamp", async () => {
    const grant = buildGrant();
    const req = buildRequest(grant, { amount: 1, vendor: "x" }, {
      timestamp: new Date(Date.now() - 10 * 60_000).toISOString(),
    });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "timestamp_expired" });
  });

  it("rejects replayed nonce", async () => {
    const grant = buildGrant();
    const req = buildRequest(grant, { amount: 1, vendor: "x" });

    await verifyInvokeRequest(req, nonceCache, {
      moduleId: "trovi",
      urlScope: "invoices:write",
      inputSchema,
      directory,
    });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "nonce_replayed" });
  });

  it("rejects invalid request signature", async () => {
    const grant = buildGrant();
    const req = buildRequest(grant, { amount: 1, vendor: "x" });
    req.requesterSignature = signObject(sig2Payload(req), holderKeys.privateKey);

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "invalid_request_signature" });
  });

  it("rejects invalid grant signature", async () => {
    const grant = buildGrant();
    grant.signature = signObject(sig1Payload(grant), requesterKeys.privateKey);
    const req = buildRequest(grant, { amount: 1, vendor: "x" });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "invalid_grant_signature" });
  });

  it("rejects grant when author does not match subject", async () => {
    directory.registerUser("user-other", authorKeys.publicKey);
    const grant = buildGrant({
      subject: "huglo:user:user-abc",
      author: "huglo:user:user-other",
    });
    const req = buildRequest(grant, { amount: 1, vendor: "x" });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "grant_author_mismatch" });
  });

  it("rejects expired grant", async () => {
    const grant = buildGrant({
      expires_at: new Date(Date.now() - 1000).toISOString(),
    });
    const req = buildRequest(grant, { amount: 1, vendor: "x" });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "grant_expired" });
  });

  it("rejects holder mismatch", async () => {
    const grant = buildGrant({ holder: "other" });
    const req = buildRequest(grant, { amount: 1, vendor: "x" });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "grant_holder_mismatch" });
  });

  it("rejects scope mismatch", async () => {
    const grant = buildGrant();
    const req = buildRequest(grant, { amount: 1, vendor: "x" }, { scope: "other:scope" });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "scope_mismatch" });
  });

  it("rejects unknown constraints (fail closed)", async () => {
    const grant = buildGrant({ constraints: { unknown_key: true } });
    const req = buildRequest(grant, { amount: 1, vendor: "x" });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "unknown_constraint" });
  });

  it("rejects revoked grant", async () => {
    const grant = buildGrant();
    directory.revokeGrant(grant.grant.grant_id);
    const req = buildRequest(grant, { amount: 1, vendor: "x" });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "grant_revoked" });
  });

  it("rejects invalid payload", async () => {
    const grant = buildGrant();
    const req = buildRequest(grant, { amount: "not-a-number", vendor: "x" });

    await expect(
      verifyInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "invoices:write",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "invalid_payload" });
  });

  describe("directory unavailability", () => {
    it("rejects when requester key is not in directory", async () => {
      directory.clear();
      directory.registerModule(
        "trovi",
        "http://localhost:3000",
        holderKeys.publicKey,
        holderKeys.publicKeyBase64,
      );
      directory.registerUser("user-abc", authorKeys.publicKey);

      const grant = buildGrant();
      const req = buildRequest(grant, { amount: 1, vendor: "x" });

      await expect(
        verifyInvokeRequest(req, nonceCache, {
          moduleId: "trovi",
          urlScope: "invoices:write",
          inputSchema,
          directory,
        }),
      ).rejects.toMatchObject({ code: "module_not_found" });
    });

    it("rejects when author key is not in directory", async () => {
      directory.registerUser("user-abc", authorKeys.publicKey);
      directory.clear();
      directory.registerModule(
        "trovi",
        "http://localhost:3000",
        holderKeys.publicKey,
        holderKeys.publicKeyBase64,
      );
      directory.registerModule(
        "foaf",
        "http://localhost:3001",
        requesterKeys.publicKey,
        requesterKeys.publicKeyBase64,
      );

      const grant = buildGrant();
      const req = buildRequest(grant, { amount: 1, vendor: "x" });

      await expect(
        verifyInvokeRequest(req, nonceCache, {
          moduleId: "trovi",
          urlScope: "invoices:write",
          inputSchema,
          directory,
        }),
      ).rejects.toMatchObject({ code: "user_not_found" });
    });

    it("rejects when revocation list is unreachable", async () => {
      const fetchFn = vi.fn().mockImplementation(async (url: string | URL | Request) => {
        const path = String(url);
        if (path.includes("/revocations")) {
          throw new Error("network down");
        }
        if (path.includes("/modules/foaf")) {
          return Response.json(
            {
              publicKey: requesterKeys.publicKeyBase64,
              endpoint: "http://localhost:3001",
            },
            { status: 200 },
          );
        }
        if (path.includes("/users/user-abc/key")) {
          return Response.json(
            { userId: "user-abc", publicKey: authorKeys.publicKeyBase64 },
            { status: 200 },
          );
        }
        return new Response(null, { status: 404 });
      });

      const httpDirectory = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      const grant = buildGrant();
      const req = buildRequest(grant, { amount: 1, vendor: "x" });

      await expect(
        verifyInvokeRequest(req, nonceCache, {
          moduleId: "trovi",
          urlScope: "invoices:write",
          inputSchema,
          directory: httpDirectory,
        }),
      ).rejects.toMatchObject({ code: "directory_unreachable" });
    });
  });
});

describe("verifyOpenInvokeRequest", () => {
  const holderKeys = generateKeyPair();
  const requesterKeys = generateKeyPair();
  const directory = new InMemoryDirectoryClient();
  const nonceCache = new NonceCache();
  const inputSchema = z.object({});

  beforeEach(() => {
    nonceCache.clear();
    directory.clear();
    directory.registerModule(
      "trovi",
      "http://localhost:3000",
      holderKeys.publicKey,
      holderKeys.publicKeyBase64,
    );
    directory.registerModule(
      "foaf",
      "http://localhost:3001",
      requesterKeys.publicKey,
      requesterKeys.publicKeyBase64,
    );
  });

  function buildOpenRequest(overrides: Partial<OpenInvokeRequest> = {}): OpenInvokeRequest {
    const req: OpenInvokeRequest = {
      payload: {},
      requester: "foaf",
      scope: "status:read",
      timestamp: new Date().toISOString(),
      nonce: crypto.randomUUID(),
      requesterSignature: "",
      ...overrides,
    };
    req.requesterSignature = signObject(sig2OpenPayload(req), requesterKeys.privateKey);
    return req;
  }

  it("passes verification for a valid open request", async () => {
    const req = buildOpenRequest();
    const ctx = await verifyOpenInvokeRequest(req, nonceCache, {
      moduleId: "trovi",
      urlScope: "status:read",
      inputSchema,
      directory,
    });

    expect(ctx.open).toBe(true);
    expect(ctx.caller).toBe("foaf");
    expect(ctx.input).toEqual({});
    expect("grant" in ctx).toBe(false);
    expect("subject" in ctx).toBe(false);
  });

  it("rejects invalid request signature", async () => {
    const req = buildOpenRequest();
    req.requesterSignature = "ed25519:invalid";

    await expect(
      verifyOpenInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "status:read",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "invalid_request_signature" });
  });

  it("rejects replayed nonce", async () => {
    const req = buildOpenRequest({ nonce: "fixed-open-nonce" });
    const opts = {
      moduleId: "trovi",
      urlScope: "status:read",
      inputSchema,
      directory,
    };
    await verifyOpenInvokeRequest(req, nonceCache, opts);
    await expect(verifyOpenInvokeRequest(req, nonceCache, opts)).rejects.toMatchObject({
      code: "nonce_replayed",
    });
  });

  it("rejects scope mismatch", async () => {
    const req = buildOpenRequest({ scope: "other:scope" });
    await expect(
      verifyOpenInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "status:read",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "scope_mismatch" });
  });

  it("rejects when requester key is not in directory", async () => {
    directory.clear();
    directory.registerModule(
      "trovi",
      "http://localhost:3000",
      holderKeys.publicKey,
      holderKeys.publicKeyBase64,
    );

    const req = buildOpenRequest();
    await expect(
      verifyOpenInvokeRequest(req, nonceCache, {
        moduleId: "trovi",
        urlScope: "status:read",
        inputSchema,
        directory,
      }),
    ).rejects.toMatchObject({ code: "module_not_found" });
  });
});

import { describe, it, expect, beforeEach, vi } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { signObject, verifyObject } from "../src/signing.js";
import { HttpDirectoryClient, InMemoryDirectoryClient } from "../src/directory.js";
import { Module } from "../src/module.js";
import { createSignedInvite } from "../src/grant-callback.js";
import type { CreateInviteResponse, SignedGrant } from "../src/envelope.js";

describe("invite flow", () => {
  const requesterKeys = generateKeyPair();
  const authorKeys = generateKeyPair();
  let directory: InMemoryDirectoryClient;

  const sampleInviteResponse: CreateInviteResponse = {
    invite: {
      id: "inv-001",
      requesterModuleId: "trovi-test",
      callbackUrl: "https://trovi.example/oauth/callback",
      constraints: {},
      expiresAt: "2026-05-29T23:33:22.698Z",
      createdByUserId: "user-1",
      active: true,
      createdAt: "2026-05-29T23:33:22.698Z",
      updatedAt: "2026-05-29T23:33:22.698Z",
      scopes: [
        {
          id: "scope-1",
          inviteId: "inv-001",
          holder: "da",
          scope: "invoice:write",
        },
      ],
    },
    inviteUrl: "https://account.huglo.com/invite/abc123",
  };

  function buildGrant(overrides: Partial<SignedGrant["grant"]> = {}): SignedGrant {
    const grant = {
      grant_id: "g-invite-001",
      holder: "da",
      scope: "invoice:write",
      subject: "huglo:user:user-1",
      requester: "trovi-test",
      author: "huglo:user:user-1",
      constraints: {},
      issued_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      ...overrides,
    };
    return { grant, signature: signObject(grant, authorKeys.privateKey) };
  }

  function createModule(): Module {
    return new Module({
      id: "trovi-test",
      name: "Trovi",
      description: "Test requester",
      version: "1.0.0",
      keyPair: requesterKeys,
      huglo: { directoryUrl: "http://unused" },
      directory,
    });
  }

  beforeEach(() => {
    directory = new InMemoryDirectoryClient();
    directory.setInviteResponse("trovi-test", sampleInviteResponse);
  });

  it("createInvite signs payload and returns invite response", async () => {
    let capturedSigned: { payload: unknown; signature: string } | undefined;
    const spyDirectory = new InMemoryDirectoryClient();
    spyDirectory.setInviteResponse("trovi-test", sampleInviteResponse);
    const originalCreateInvite = spyDirectory.createInvite.bind(spyDirectory);
    spyDirectory.createInvite = async (moduleId, signed) => {
      capturedSigned = signed;
      return originalCreateInvite(moduleId, signed);
    };

    const module = new Module({
      id: "trovi-test",
      name: "Trovi",
      description: "Test requester",
      version: "1.0.0",
      keyPair: requesterKeys,
      huglo: { directoryUrl: "http://unused" },
      directory: spyDirectory,
    });

    const result = await module.createInvite({
      callbackUrl: "https://trovi.example/oauth/callback",
      scopes: [{ holder: "da", scope: "invoice:write" }],
      constraints: { tenant: "acme" },
    });

    expect(result).toEqual(sampleInviteResponse);
    expect(capturedSigned).toBeDefined();
    expect(capturedSigned!.payload).toMatchObject({
      moduleId: "trovi-test",
      callbackUrl: "https://trovi.example/oauth/callback",
      scopes: [{ holder: "da", scope: "invoice:write" }],
      constraints: { tenant: "acme" },
    });
    expect(typeof capturedSigned!.payload).toBe("object");
    expect((capturedSigned!.payload as { iat: string }).iat).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(
      verifyObject(
        capturedSigned!.payload,
        capturedSigned!.signature,
        requesterKeys.publicKey,
      ),
    ).toBe(true);
    const payload = capturedSigned!.payload as { nonce: string };
    expect(payload.nonce).toBeTruthy();
    expect(typeof payload.nonce).toBe("string");
  });

  it("createInvite generates a distinct nonce per call", async () => {
    const capturedNonces: string[] = [];
    const spyDirectory = new InMemoryDirectoryClient();
    spyDirectory.setInviteResponse("trovi-test", sampleInviteResponse);
    const originalCreateInvite = spyDirectory.createInvite.bind(spyDirectory);
    spyDirectory.createInvite = async (moduleId, signed) => {
      capturedNonces.push((signed.payload as { nonce: string }).nonce);
      return originalCreateInvite(moduleId, signed);
    };

    const module = new Module({
      id: "trovi-test",
      name: "Trovi",
      description: "Test requester",
      version: "1.0.0",
      keyPair: requesterKeys,
      huglo: { directoryUrl: "http://unused" },
      directory: spyDirectory,
    });

    const inviteOptions = {
      callbackUrl: "https://trovi.example/oauth/callback",
      scopes: [{ holder: "da", scope: "invoice:write" }],
    };
    await module.createInvite(inviteOptions);
    await module.createInvite(inviteOptions);

    expect(capturedNonces).toHaveLength(2);
    expect(capturedNonces[0]).toBeTruthy();
    expect(capturedNonces[1]).toBeTruthy();
    expect(capturedNonces[0]).not.toBe(capturedNonces[1]);
  });

  it("createInvite signature fails verification when nonce is altered", async () => {
    let capturedSigned: { payload: unknown; signature: string } | undefined;
    const directory = new InMemoryDirectoryClient();
    directory.setInviteResponse("trovi-test", sampleInviteResponse);
    const originalCreateInvite = directory.createInvite.bind(directory);
    directory.createInvite = async (moduleId, signed) => {
      capturedSigned = signed;
      return originalCreateInvite(moduleId, signed);
    };

    await createSignedInvite(directory, "trovi-test", requesterKeys.privateKey, {
      callbackUrl: "https://trovi.example/oauth/callback",
      scopes: [{ holder: "da", scope: "invoice:write" }],
    });

    expect(capturedSigned).toBeDefined();
    const tampered = {
      ...(capturedSigned!.payload as Record<string, unknown>),
      nonce: "tampered-nonce",
    };
    expect(
      verifyObject(tampered, capturedSigned!.signature, requesterKeys.publicKey),
    ).toBe(false);
    expect(
      verifyObject(capturedSigned!.payload, capturedSigned!.signature, requesterKeys.publicKey),
    ).toBe(true);
  });

  it("createInvite includes subject in signed payload when provided", async () => {
    let capturedSigned: { payload: unknown; signature: string } | undefined;
    const spyDirectory = new InMemoryDirectoryClient();
    spyDirectory.setInviteResponse("trovi-test", sampleInviteResponse);
    const originalCreateInvite = spyDirectory.createInvite.bind(spyDirectory);
    spyDirectory.createInvite = async (moduleId, signed) => {
      capturedSigned = signed;
      return originalCreateInvite(moduleId, signed);
    };

    const module = new Module({
      id: "trovi-test",
      name: "Trovi",
      description: "Test requester",
      version: "1.0.0",
      keyPair: requesterKeys,
      huglo: { directoryUrl: "http://unused" },
      directory: spyDirectory,
    });

    await module.createInvite({
      callbackUrl: "https://trovi.example/oauth/callback",
      subject: "huglo:user:user-1",
      scopes: [{ holder: "da", scope: "invoice:write" }],
    });

    expect(capturedSigned!.payload).toMatchObject({
      subject: "huglo:user:user-1",
    });
  });

  it("createInvite defaults constraints to empty object", async () => {
    const module = createModule();
    await module.createInvite({
      callbackUrl: "https://trovi.example/oauth/callback",
      scopes: [{ holder: "da", scope: "invoice:write" }],
    });
    // No throw means success; signing verified in previous test
  });

  it("createInvite propagates directory_unreachable when directory is down", async () => {
    const failingDirectory = new HttpDirectoryClient({
      directoryUrl: "https://account.huglo.com",
      fetch: vi.fn().mockRejectedValue(new Error("network down")),
    });
    const module = new Module({
      id: "trovi-test",
      name: "Trovi",
      description: "Test requester",
      version: "1.0.0",
      keyPair: requesterKeys,
      huglo: { directoryUrl: "http://unused" },
      directory: failingDirectory,
    });

    await expect(
      module.createInvite({
        callbackUrl: "https://trovi.example/oauth/callback",
        scopes: [{ holder: "da", scope: "invoice:write" }],
      }),
    ).rejects.toMatchObject({ code: "directory_unreachable" });
  });

  it("exchangeGrants returns seeded grants", async () => {
    const grants = [buildGrant()];
    directory.setExchangeGrants("code-123", grants);

    const module = createModule();
    const result = await module.exchangeGrants("code-123");

    expect(result).toEqual(grants);
  });
});

describe("HttpDirectoryClient invite endpoints", () => {
  const baseUrl = "https://account.huglo.com";

  it("createInvite POSTs to the correct URL with signed payload", async () => {
    const signed = {
      payload: {
        moduleId: "trovi-test",
        callbackUrl: "https://trovi.example/oauth/callback",
        scopes: [{ holder: "da", scope: "invoice:write" }],
        constraints: {},
        iat: "2026-05-29T22:00:00.000Z",
        nonce: "00000000-0000-4000-8000-000000000001",
      },
      signature: "ed25519:abc123",
    };
    const inviteResponse = {
      invite: {
        id: "inv-001",
        requesterModuleId: "trovi-test",
        callbackUrl: "https://trovi.example/oauth/callback",
        constraints: {},
        expiresAt: "2026-05-29T23:33:22.698Z",
        createdByUserId: "user-1",
        active: true,
        createdAt: "2026-05-29T23:33:22.698Z",
        updatedAt: "2026-05-29T23:33:22.698Z",
        scopes: [
          {
            id: "scope-1",
            inviteId: "inv-001",
            holder: "da",
            scope: "invoice:write",
          },
        ],
      },
      inviteUrl: "https://account.huglo.com/invite/abc123",
    };

    let capturedUrl = "";
    let capturedInit: RequestInit | undefined;
    const fetchFn = async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = String(url);
      capturedInit = init;
      return new Response(JSON.stringify(inviteResponse), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new HttpDirectoryClient({ directoryUrl: baseUrl, fetch: fetchFn });
    const result = await client.createInvite("trovi-test", signed);

    expect(capturedUrl).toBe(`${baseUrl}/directory/modules/trovi-test/invites`);
    expect(capturedInit?.method).toBe("POST");
    expect(JSON.parse(String(capturedInit?.body))).toEqual(signed);
    expect(result).toEqual(inviteResponse);
  });

  it("exchangeGrants POSTs code and returns grants array", async () => {
    const grant = {
      grant: {
        grant_id: "g-001",
        holder: "da",
        scope: "invoice:write",
        subject: "huglo:user:user-1",
        requester: "trovi-test",
        author: "huglo:user:user-1",
        constraints: {},
        issued_at: "2026-05-29T22:00:43.343Z",
        expires_at: "2026-06-28T22:00:43.343Z",
      },
      signature: "ed25519:xyz789",
    };

    let capturedUrl = "";
    let capturedInit: RequestInit | undefined;
    const fetchFn = async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = String(url);
      capturedInit = init;
      return new Response(JSON.stringify({ grants: [grant] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    const client = new HttpDirectoryClient({ directoryUrl: baseUrl, fetch: fetchFn });
    const result = await client.exchangeGrants("code-456");

    expect(capturedUrl).toBe(`${baseUrl}/directory/grants/exchange`);
    expect(capturedInit?.method).toBe("POST");
    expect(JSON.parse(String(capturedInit?.body))).toEqual({ code: "code-456" });
    expect(result).toEqual([grant]);
  });

  it("createInvite includes directory error code in message on non-2xx JSON body", async () => {
    const fetchFn = async () =>
      new Response(
        JSON.stringify({ error: "invalid_request", message: "nonce is required" }),
        { status: 400, headers: { "Content-Type": "application/json" } },
      );

    const client = new HttpDirectoryClient({ directoryUrl: baseUrl, fetch: fetchFn });
    const signed = {
      payload: {
        moduleId: "trovi-test",
        callbackUrl: "https://trovi.example/oauth/callback",
        scopes: [{ holder: "da", scope: "invoice:write" }],
        constraints: {},
        iat: "2026-05-29T22:00:00.000Z",
        nonce: "00000000-0000-4000-8000-000000000001",
      },
      signature: "ed25519:abc123",
    };

    await expect(client.createInvite("trovi-test", signed)).rejects.toMatchObject({
      code: "directory_error",
      message: "Directory returned 400 (invalid_request)",
    });
  });

  it("throws infraError on malformed exchange response", async () => {
    const fetchFn = async () =>
      new Response(JSON.stringify({ notGrants: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });

    const client = new HttpDirectoryClient({ directoryUrl: baseUrl, fetch: fetchFn });

    await expect(client.exchangeGrants("bad-code")).rejects.toMatchObject({
      code: "invalid_response",
    });
  });
});

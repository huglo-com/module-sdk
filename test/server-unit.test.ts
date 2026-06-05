import { randomUUID } from "node:crypto";
import { describe, it, expect, vi } from "vitest";
import { z } from "zod";
import { generateKeyPair, type ModuleKeyPair } from "../src/keys.js";
import { InMemoryDirectoryClient, HttpDirectoryClient } from "../src/directory.js";
import { createModuleServer } from "../src/server.js";
import { ModuleError } from "../src/errors.js";
import { signObject } from "../src/signing.js";
import { sig2OpenPayload, type OpenInvokeRequest } from "../src/envelope.js";

function buildOpenInvoke(
  requesterKeys: ModuleKeyPair,
  scope: string,
  input: Record<string, unknown> = {},
): OpenInvokeRequest {
  const req: OpenInvokeRequest = {
    payload: input,
    requester: "requester-mod",
    scope,
    timestamp: new Date().toISOString(),
    nonce: randomUUID(),
    requesterSignature: "",
  };
  req.requesterSignature = signObject(sig2OpenPayload(req), requesterKeys.privateKey);
  return req;
}

function createTestServer(
  overrides: Partial<Parameters<typeof createModuleServer>[0]> = {},
) {
  const keys = generateKeyPair();
  const requesterKeys = generateKeyPair();
  const directory = new InMemoryDirectoryClient();
  directory.registerModule("test-mod", "http://127.0.0.1:8080", keys.publicKey, keys.publicKeyBase64);
  directory.registerModule(
    "requester-mod",
    "http://127.0.0.1:8081",
    requesterKeys.publicKey,
    requesterKeys.publicKeyBase64,
  );

  const scopes = new Map<
    string,
    {
      description: string;
      open?: boolean;
      input: z.ZodType;
      output: z.ZodType;
      handler: (ctx: { input: unknown }) => Promise<unknown>;
    }
  >();

  scopes.set("echo:read", {
    description: "Echo",
    input: z.object({ message: z.string() }),
    output: z.object({ message: z.string() }),
    handler: async (ctx) => ({ message: (ctx.input as { message: string }).message }),
  });

  scopes.set("fail:read", {
    description: "Fails",
    open: true,
    input: z.object({}),
    output: z.object({ ok: z.boolean() }),
    handler: async () => {
      throw new ModuleError({ code: "handler_failed", message: "boom", retryable: false });
    },
  });

  scopes.set("bad-output:read", {
    description: "Bad output",
    open: true,
    input: z.object({}),
    output: z.object({ ok: z.boolean() }),
    handler: async () => ({ ok: "not-a-boolean" }),
  });

  const app = createModuleServer({
    moduleId: "test-mod",
    name: "Test",
    description: "Test module",
    version: "1.0.0",
    publicKeyBase64: keys.publicKeyBase64,
    privateKey: keys.privateKey,
    directory,
    scopes,
    ...overrides,
  });

  return { app, requesterKeys };
}

describe("server unit", () => {
  it("GET /health returns module status", async () => {
    const { app } = createTestServer();
    const res = await app.request("/health");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok", module: "test-mod" });
  });

  it("GET /.well-known/huglo-challenge returns 503 when unconfigured", async () => {
    const { app } = createTestServer();
    const res = await app.request("/.well-known/huglo-challenge");
    expect(res.status).toBe(503);
  });

  it("GET /.well-known/huglo-challenge returns signed payload when configured", async () => {
    const { app } = createTestServer({
      challenge: "challenge-token",
      endpoint: "http://127.0.0.1:8080",
    });
    const res = await app.request("/.well-known/huglo-challenge");
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      payload: { challenge: string; moduleId: string; endpoint: string; publicKey: string };
      signature: string;
    };
    expect(body.payload.challenge).toBe("challenge-token");
    expect(body.signature).toBeTruthy();
  });

  it("POST /invoke/:scope returns 400 for malformed JSON", async () => {
    const { app } = createTestServer();
    const res = await app.request("/invoke/echo:read", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not-json",
    });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("malformed_request");
  });

  it("POST /invoke/:scope returns 400 when handler throws non-retryable error", async () => {
    const { app, requesterKeys } = createTestServer();
    const invokeBody = buildOpenInvoke(requesterKeys, "fail:read");

    const res = await app.request("/invoke/fail:read", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(invokeBody),
    });
    expect(res.status).toBe(400);
  });

  it("POST /invoke/:scope returns 500 for invalid handler output", async () => {
    const { app, requesterKeys } = createTestServer();
    const invokeBody = buildOpenInvoke(requesterKeys, "bad-output:read");

    const res = await app.request("/invoke/bad-output:read", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(invokeBody),
    });
    expect(res.status).toBe(500);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("invalid_output");
  });

  it("POST /invoke/:scope returns 503 when directory is unreachable during verification", async () => {
    const failingDirectory = new HttpDirectoryClient({
      directoryUrl: "https://directory.example",
      fetch: vi.fn().mockRejectedValue(new Error("network down")),
    });
    const { app, requesterKeys } = createTestServer({ directory: failingDirectory });
    const invokeBody = buildOpenInvoke(requesterKeys, "fail:read");

    const res = await app.request("/invoke/fail:read", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(invokeBody),
    });

    expect(res.status).toBe(503);
    const body = (await res.json()) as { error: { code: string } };
    expect(body.error.code).toBe("directory_unreachable");
  });
});

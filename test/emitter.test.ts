import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { z } from "zod";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import { Module } from "../src/module.js";
import type { SignedGrant } from "../src/envelope.js";
import type { ModuleManifest } from "../src/manifest.js";

const EmailReceived = z.object({
  sender: z.string(),
  recipient: z.string(),
  subject: z.string(),
  body: z.string(),
});

describe("emitters", () => {
  const holderKeys = generateKeyPair();
  const emitterKeys = generateKeyPair();
  const authorKeys = generateKeyPair();
  const directory = new InMemoryDirectoryClient();

  const holderPort = 9200 + Math.floor(Math.random() * 1000);
  const emitterPort = holderPort + 1;

  const holderEndpoint = `http://127.0.0.1:${holderPort}`;

  let handlerCalled = false;
  let receivedInput: z.infer<typeof EmailReceived> | undefined;

  const holder = new Module({
    id: "module-a",
    name: "Module A",
    description: "Receiver",
    version: "1.0.0",
    keyPair: holderKeys,
    huglo: { directoryUrl: "http://unused" },
    directory,
  });

  holder.scope("on-email", {
    description: "Handle an email event",
    input: EmailReceived,
    output: z.object({ ok: z.boolean() }),
    handler: async (ctx) => {
      handlerCalled = true;
      receivedInput = ctx.input;
      return { ok: true };
    },
  });

  const emitter = new Module({
    id: "email-trigger",
    name: "Email Trigger",
    description: "Emits email events",
    version: "1.0.0",
    keyPair: emitterKeys,
    huglo: { directoryUrl: "http://unused" },
    directory,
  });

  emitter.emitter("email.received", {
    description: "Fires when an email is received",
    output: EmailReceived,
  });

  directory.registerModule(
    "module-a",
    holderEndpoint,
    holderKeys.publicKey,
    holderKeys.publicKeyBase64,
  );
  directory.registerModule(
    "email-trigger",
    `http://127.0.0.1:${emitterPort}`,
    emitterKeys.publicKey,
    emitterKeys.publicKeyBase64,
  );
  directory.registerUser("user-abc", authorKeys.publicKey);

  function buildGrant(overrides: Partial<SignedGrant["grant"]> = {}): SignedGrant {
    const grant = {
      grant_id: "g-emitter-001",
      holder: "module-a",
      scope: "on-email",
      subject: "huglo:user:user-abc",
      requester: "email-trigger",
      author: "huglo:user:user-abc",
      constraints: {},
      issued_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
      ...overrides,
    };
    return {
      grant,
      signature: signObject(grant, authorKeys.privateKey),
    };
  }

  const emailData = {
    sender: "alice@example.com",
    recipient: "bob@example.com",
    subject: "Hello",
    body: "Test message",
  };

  beforeAll(async () => {
    await holder.listen(holderPort, "127.0.0.1");
    await emitter.listen(emitterPort, "127.0.0.1");
  });

  afterAll(() => {
    holder.close();
    emitter.close();
  });

  it("lists emitters in /manifest", async () => {
    const res = await emitter.getApp().request("/manifest");
    expect(res.status).toBe(200);
    const manifest = (await res.json()) as ModuleManifest;
    expect(manifest.emitters).toHaveLength(1);
    expect(manifest.emitters[0]).toMatchObject({
      name: "email.received",
      description: "Fires when an email is received",
    });
    expect(manifest.emitters[0]!.output).toBeDefined();
  });

  it("emit validates and calls the grant holder scope", async () => {
    handlerCalled = false;
    receivedInput = undefined;

    const grant = buildGrant();
    const result = await emitter.emit("email.received", emailData, grant);

    expect(result).toEqual({ ok: true });
    expect(handlerCalled).toBe(true);
    expect(receivedInput).toEqual(emailData);
  });

  it("emit throws when data violates the output schema", async () => {
    const grant = buildGrant({ grant_id: "g-emitter-invalid" });
    await expect(
      emitter.emit("email.received", { sender: "only-one-field" }, grant),
    ).rejects.toThrow();
  });

  it("emit throws for unknown emitter name", async () => {
    const grant = buildGrant({ grant_id: "g-emitter-unknown" });
    await expect(emitter.emit("unknown.emitter", emailData, grant)).rejects.toThrow(
      "Unknown emitter: unknown.emitter",
    );
  });
});

import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { z } from "zod";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import { Module, ModuleError } from "../src/module.js";
import type { SignedGrant } from "../src/envelope.js";
import { sig3Payload } from "../src/envelope.js";
import { verifyObject } from "../src/signing.js";

export interface TestModules {
  holder: Module;
  requester: Module;
  directory: InMemoryDirectoryClient;
  authorKeys: ReturnType<typeof generateKeyPair>;
  holderPort: number;
  buildGrant: () => SignedGrant;
  cleanup: () => Promise<void>;
}

/**
 * Integration-test harness: spins up two in-process modules and exercises
 * a full signed module.call round trip with an in-memory directory.
 */
export async function createTestModules(): Promise<TestModules> {
  const holderKeys = generateKeyPair();
  const requesterKeys = generateKeyPair();
  const authorKeys = generateKeyPair();
  const directory = new InMemoryDirectoryClient();

  const holderPort = 9100 + Math.floor(Math.random() * 1000);
  const requesterPort = holderPort + 1;

  const holderEndpoint = `http://127.0.0.1:${holderPort}`;
  const requesterEndpoint = `http://127.0.0.1:${requesterPort}`;

  directory.registerModule("trovi", holderEndpoint, holderKeys.publicKey, holderKeys.publicKeyBase64);
  directory.registerModule("foaf", requesterEndpoint, requesterKeys.publicKey, requesterKeys.publicKeyBase64);
  directory.registerUser("user-abc", authorKeys.publicKey);

  let handlerCalled = false;

  const holder = new Module({
    id: "trovi",
    name: "Trovi",
    description: "Test holder",
    version: "1.0.0",
    keyPair: holderKeys,
    huglo: { directoryUrl: "http://unused" },
    directory,
  });

  holder.scope("invoices:write", {
    description: "Create invoice",
    input: z.object({ vendor: z.string(), amount: z.number() }),
    output: z.object({ id: z.string(), vendor: z.string(), amount: z.number() }),
    handler: async (ctx) => {
      handlerCalled = true;
      if (ctx.dryRun) {
        return { id: "dry-run", vendor: ctx.input.vendor, amount: ctx.input.amount };
      }
      return { id: "inv-001", vendor: ctx.input.vendor, amount: ctx.input.amount };
    },
  });

  const requester = new Module({
    id: "foaf",
    name: "Foaf",
    description: "Test requester",
    version: "1.0.0",
    keyPair: requesterKeys,
    huglo: { directoryUrl: "http://unused" },
    directory,
  });

  await holder.listen(holderPort, "127.0.0.1");
  await requester.listen(requesterPort, "127.0.0.1");

  function buildGrant(overrides: Partial<SignedGrant["grant"]> = {}): SignedGrant {
    const grant = {
      grant_id: "g-integration-001",
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
    return {
      grant,
      signature: signObject(grant, authorKeys.privateKey),
    };
  }

  return {
    holder,
    requester,
    directory,
    authorKeys,
    holderPort,
    buildGrant,
    cleanup: async () => {
      holder.close();
      requester.close();
      expect(handlerCalled).toBe(true);
    },
  };
}

describe("integration", () => {
  let testEnv: TestModules;

  beforeAll(async () => {
    testEnv = await createTestModules();
  });

  afterAll(async () => {
    await testEnv.cleanup();
  });

  it("completes a full signed module.call round trip", async () => {
    const grant = testEnv.buildGrant();
    const result = await testEnv.requester.call({
      target: "trovi",
      scope: "invoices:write",
      input: { vendor: "Acme Corp", amount: 500 },
      grant,
    });

    expect(result).toEqual({ id: "inv-001", vendor: "Acme Corp", amount: 500 });
  });

  it("honors dryRun flag", async () => {
    const grant = testEnv.buildGrant({ grant_id: "g-dryrun-001" });
    const result = await testEnv.requester.call({
      target: "trovi",
      scope: "invoices:write",
      input: { vendor: "Dry Co", amount: 100 },
      grant,
      dryRun: true,
    });

    expect(result).toEqual({ id: "dry-run", vendor: "Dry Co", amount: 100 });
  });

  it("rejects tampered grant", async () => {
    const grant = testEnv.buildGrant({ holder: "evil-module", grant_id: "g-tamper-001" });

    await expect(
      testEnv.requester.call({
        target: "trovi",
        scope: "invoices:write",
        input: { vendor: "X", amount: 1 },
        grant,
      }),
    ).rejects.toMatchObject({ code: "grant_holder_mismatch" });
  });

  it("returns signed error responses from holder", async () => {
    const endpoint = await testEnv.directory.getEndpoint("trovi");
    const response = await fetch(`${endpoint}/invoke/nonexistent:scope`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ invalid: true }),
    });
    const body = await response.json();
    expect(body.error).toBeDefined();
    expect(body.holderSignature).toBeDefined();

    const holderKey = await testEnv.directory.getModuleKey("trovi");
    expect(verifyObject(sig3Payload(body), body.holderSignature, holderKey)).toBe(true);
  });

  it("throws ModuleError on holder business errors", async () => {
    // Register a scope that throws ModuleError
    const errorHolder = new Module({
      id: "error-mod",
      name: "Error Mod",
      description: "Throws errors",
      version: "1.0.0",
      keyPair: generateKeyPair(),
      huglo: { directoryUrl: "http://unused" },
      directory: testEnv.directory,
    });

    const port = testEnv.holderPort + 10;
    testEnv.directory.registerModule(
      "error-mod",
      `http://127.0.0.1:${port}`,
      errorHolder.getKeyPair().publicKey,
      errorHolder.getKeyPair().publicKeyBase64,
    );

    errorHolder.scope("fail:scope", {
      description: "Always fails",
      input: z.object({}),
      output: z.object({}),
      handler: async () => {
        throw new ModuleError({ code: "test_error", message: "Expected failure", retryable: false });
      },
    });

    await errorHolder.listen(port, "127.0.0.1");

    const grant = testEnv.buildGrant({
      grant_id: "g-biz-error",
      holder: "error-mod",
      scope: "fail:scope",
    });

    await expect(
      testEnv.requester.call({
        target: "error-mod",
        scope: "fail:scope",
        input: {},
        grant,
      }),
    ).rejects.toMatchObject({ code: "test_error", retryable: false });

    errorHolder.close();
  });
});

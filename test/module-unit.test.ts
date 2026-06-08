import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { z } from "zod";
import { Hono } from "hono";
import { generateKeyPair } from "../src/keys.js";
import { InMemoryDirectoryClient, HttpDirectoryClient } from "../src/directory.js";
import {
  Module,
  DEFAULT_HUGLO_DIRECTORY_URL,
} from "../src/module.js";
import { InMemoryConfigStore } from "../src/config-store.js";
import { InMemoryFileStore } from "../src/file-store.js";
import { InMemoryHugloOAuthClient } from "../src/oauth.js";
import { signObject } from "../src/signing.js";
import type { SignedGrant } from "../src/envelope.js";
import type { ModuleManifest } from "../src/manifest.js";

function createModule(
  overrides: Partial<ConstructorParameters<typeof Module>[0]> = {},
): Module {
  const keys = generateKeyPair();
  const directory = overrides.directory ?? new InMemoryDirectoryClient();
  return new Module({
    id: "test-mod",
    name: "Test Module",
    description: "Unit test module",
    version: "1.0.0",
    keyPair: keys,
    huglo: { directoryUrl: "http://unused" },
    directory,
    ...overrides,
  });
}

describe("Module unit", () => {
  describe("constructor and accessors", () => {
    it("exposes id, directory, and keypair", () => {
      const keys = generateKeyPair();
      const directory = new InMemoryDirectoryClient();
      const module = new Module({
        id: "my-mod",
        name: "My Module",
        description: "desc",
        version: "2.0.0",
        keyPair: keys,
        directory,
      });

      expect(module.id).toBe("my-mod");
      expect(module.getDirectory()).toBe(directory);
      expect(module.getKeyPair()).toBe(keys);
    });

    it("creates HttpDirectoryClient when directory is not overridden", () => {
      const keys = generateKeyPair();
      const module = new Module({
        id: "http-dir-mod",
        name: "HTTP Dir",
        description: "desc",
        version: "1.0.0",
        keyPair: keys,
        huglo: { directoryUrl: "https://custom-directory.example" },
      });

      expect(module.getDirectory()).toBeInstanceOf(HttpDirectoryClient);
    });

    it("exports DEFAULT_HUGLO_DIRECTORY_URL", () => {
      expect(DEFAULT_HUGLO_DIRECTORY_URL).toBe("https://account.huglo.com");
    });

    it("disables metrics when metrics: false", () => {
      const module = createModule({ metrics: false });
      expect(module.getMetrics()).toBeUndefined();
    });

    it("enables metrics by default", () => {
      const module = createModule();
      expect(module.getMetrics()).toBeDefined();
    });
  });

  describe("environment fallbacks", () => {
    const envKeys = ["MODULE_ENDPOINT", "MODULE_CHALLENGE"] as const;

    beforeEach(() => {
      vi.stubEnv("MODULE_ENDPOINT", "https://env-endpoint.example/");
      vi.stubEnv("MODULE_CHALLENGE", "env-challenge-token");
    });

    afterEach(() => {
      for (const key of envKeys) {
        vi.unstubAllEnvs();
      }
    });

    it("reads MODULE_ENDPOINT for getCallbackUrl", () => {
      const module = createModule();
      expect(module.getCallbackUrl()).toBe("https://env-endpoint.example/grant/callback");
    });

    it("reads MODULE_CHALLENGE for huglo-challenge route", async () => {
      const module = createModule();
      const res = await module.getApp().request("/.well-known/huglo-challenge");
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        payload: { challenge: string; endpoint: string };
      };
      expect(body.payload.challenge).toBe("env-challenge-token");
      expect(body.payload.endpoint).toBe("https://env-endpoint.example/");
    });

    it("setChallenge updates endpoint and challenge at runtime", async () => {
      const module = createModule();
      module.setChallenge("runtime-challenge", "https://runtime.example");

      const res = await module.getApp().request("/.well-known/huglo-challenge");
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        payload: { challenge: string; endpoint: string };
      };
      expect(body.payload.challenge).toBe("runtime-challenge");
      expect(body.payload.endpoint).toBe("https://runtime.example");
    });
  });

  describe("fluent registration API", () => {
    it("scope, emitter, config, and api return the module instance", () => {
      const module = createModule({ endpoint: "https://example.com" });
      const oauthClient = new InMemoryHugloOAuthClient({
        defaultSubject: "huglo:user:test",
      });

      const result = module
        .scope("echo:read", {
          description: "Echo",
          input: z.object({ message: z.string() }),
          output: z.object({ message: z.string() }),
          handler: async (ctx) => ({ message: ctx.input.message }),
        })
        .emitter("event.sent", {
          description: "An event",
          output: z.object({ id: z.string() }),
        })
        .config({
          schema: z.object({ label: z.string() }),
          fields: { label: "userEntered" },
        })
        .api(new Hono());

      expect(result).toBe(module);
      expect(module.getConfigStore()).toBeDefined();
    });
  });

  describe("getConfigStore", () => {
    it("returns undefined before config() is called", () => {
      const module = createModule();
      expect(module.getConfigStore()).toBeUndefined();
    });

    it("returns injected configStore when config() is used", () => {
      const configStore = new InMemoryConfigStore();
      const oauthClient = new InMemoryHugloOAuthClient({
        defaultSubject: "huglo:user:test",
      });
      const module = createModule({ configStore, oauthClient, oauth: oauthOptions() });
      module.config({
        schema: z.object({ label: z.string() }),
        fields: { label: "userEntered" },
      });

      expect(module.getConfigStore()).toBe(configStore);
    });

    it("creates a default InMemoryConfigStore when config() is used without configStore", () => {
      const oauthClient = new InMemoryHugloOAuthClient({
        defaultSubject: "huglo:user:test",
      });
      const module = createModule({ oauthClient, oauth: oauthOptions() });
      module.config({
        schema: z.object({ label: z.string() }),
        fields: { label: "userEntered" },
      });

      const store = module.getConfigStore();
      expect(store).toBeDefined();
      expect(store).toBe(module.getConfigStore());
    });

    it("throws when config() is used without OAuth options on getApp()", () => {
      const module = createModule();
      module.config({
        schema: z.object({ label: z.string() }),
        fields: { label: "userEntered" },
      });

      expect(() => module.getApp()).toThrow(/Config requires OAuth/);
    });
  });

  describe("getCallbackUrl", () => {
    it("throws when endpoint is not configured", () => {
      const module = createModule();
      expect(() => module.getCallbackUrl()).toThrow(/MODULE_ENDPOINT or config.endpoint is required/);
    });

    it("builds callback URL from endpoint and custom callbackPath", () => {
      const module = createModule({
        endpoint: "https://trovi.example/",
        callbackPath: "/oauth/grant/callback",
      });

      expect(module.getCallbackUrl()).toBe("https://trovi.example/oauth/grant/callback");
    });
  });

  describe("getFileStore and createFile", () => {
    it("returns injected fileStore", () => {
      const fileStore = new InMemoryFileStore();
      const module = createModule({ fileStore, endpoint: "https://example.com" });
      expect(module.getFileStore()).toBe(fileStore);
    });

    it("creates a default InMemoryFileStore lazily", () => {
      const module = createModule({ endpoint: "https://example.com" });
      const first = module.getFileStore();
      const second = module.getFileStore();
      expect(first).toBeInstanceOf(InMemoryFileStore);
      expect(second).toBe(first);
    });

    it("createFile throws when endpoint is missing", async () => {
      const module = createModule();
      await expect(
        module.createFile({
          data: Buffer.from("x"),
          content_type: "text/plain",
        }),
      ).rejects.toThrow(/MODULE_ENDPOINT or config.endpoint is required/);
    });

    it("createFile stores data and exposes download route after getApp()", async () => {
      const module = createModule({ endpoint: "https://files.example" });
      const file = await module.createFile({
        data: Buffer.from("module unit file"),
        content_type: "text/plain",
        filename: "unit.txt",
        expires_at: new Date(Date.now() + 3600_000),
      });

      expect(file.url).toMatch(/^https:\/\/files\.example\/file\//);
      expect(file.filename).toBe("unit.txt");

      const res = await module.getApp().request(new URL(file.url).pathname);
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("module unit file");
    });
  });

  describe("getApp", () => {
    it("returns the same Hono instance on repeated calls", () => {
      const module = createModule();
      expect(module.getApp()).toBe(module.getApp());
    });

    it("includes registered scopes and emitters in manifest", async () => {
      const module = createModule();
      module
        .scope("items:read", {
          description: "Read items",
          input: z.object({}),
          output: z.object({ items: z.array(z.string()) }),
          handler: async () => ({ items: [] }),
        })
        .emitter("item.created", {
          description: "Item created",
          output: z.object({ id: z.string() }),
        });

      const res = await module.getApp().request("/manifest");
      const manifest = (await res.json()) as ModuleManifest;

      expect(manifest.scopes.map((s) => s.name)).toContain("items:read");
      expect(manifest.emitters.map((e) => e.name)).toContain("item.created");
    });

    it("mounts custom api routes at /api/*", async () => {
      const routes = new Hono();
      routes.get("/hello", (c) => c.text("custom-api"));
      const module = createModule().api(routes);

      const res = await module.getApp().request("/api/hello");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("custom-api");
    });

    it("rebuilds the app after config() invalidates cached app", async () => {
      const oauthClient = new InMemoryHugloOAuthClient({
        defaultSubject: "huglo:user:test",
      });
      const module = createModule({ oauthClient, oauth: oauthOptions() });
      const before = module.getApp();

      module.config({
        schema: z.object({ label: z.string() }),
        fields: { label: "userEntered" },
      });

      const after = module.getApp();
      expect(after).not.toBe(before);

      const res = await after.request("/manifest");
      const manifest = (await res.json()) as ModuleManifest;
      expect(manifest.config).toBe(true);
    });

    it("customConfig returns the module instance", () => {
      const handler = new Hono();
      handler.get("/", (c) => c.text("custom"));
      const module = createModule();
      expect(module.customConfig(handler)).toBe(module);
    });

    it("customConfig module exposes config true in manifest without OAuth", async () => {
      const handler = new Hono();
      handler.get("/", (c) => c.text("custom"));
      const module = createModule().customConfig(handler);

      const res = await module.getApp().request("/manifest");
      const manifest = (await res.json()) as ModuleManifest;
      expect(manifest.config).toBe(true);
      expect(manifest).not.toHaveProperty("fields");
    });

    it("customConfig mounts handler at GET /config", async () => {
      const handler = new Hono();
      handler.get("/", (c) => c.text("custom-config-page"));
      const module = createModule().customConfig(handler);

      const res = await module.getApp().request("/config");
      expect(res.status).toBe(200);
      expect(await res.text()).toBe("custom-config-page");
    });
  });

  describe("call and exchangeGrants", () => {
    const requesterKeys = generateKeyPair();
    const holderKeys = generateKeyPair();
    const authorKeys = generateKeyPair();
    let directory: InMemoryDirectoryClient;

    beforeEach(() => {
      directory = new InMemoryDirectoryClient();
      directory.registerModule(
        "holder-mod",
        "http://127.0.0.1:59999",
        holderKeys.publicKey,
        holderKeys.publicKeyBase64,
      );
      directory.registerUser("user-1", authorKeys.publicKey);
    });

    function buildGrant(overrides: Partial<SignedGrant["grant"]> = {}): SignedGrant {
      const grant = {
        grant_id: "g-module-unit",
        holder: "holder-mod",
        scope: "echo:read",
        subject: "huglo:user:user-1",
        requester: "test-mod",
        author: "huglo:user:user-1",
        constraints: {},
        issued_at: new Date(Date.now() - 60_000).toISOString(),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        ...overrides,
      };
      return { grant, signature: signObject(grant, authorKeys.privateKey) };
    }

    it("call rejects grant requester mismatch before reaching directory", async () => {
      const module = new Module({
        id: "test-mod",
        name: "Test",
        description: "Test",
        version: "1.0.0",
        keyPair: requesterKeys,
        directory,
      });

      await expect(
        module.call({
          target: "holder-mod",
          scope: "echo:read",
          input: {},
          grant: buildGrant({ requester: "other-requester" }),
        }),
      ).rejects.toMatchObject({ code: "grant_requester_mismatch" });
    });

    it("exchangeGrants delegates to directory client", async () => {
      const grants = [buildGrant()];
      directory.setExchangeGrants("unit-code", grants);

      const module = new Module({
        id: "test-mod",
        name: "Test",
        description: "Test",
        version: "1.0.0",
        keyPair: requesterKeys,
        directory,
      });

      await expect(module.exchangeGrants("unit-code")).resolves.toEqual(grants);
    });
  });

  describe("emit and createInvite", () => {
    it("emit throws for unknown emitter names", async () => {
      const module = createModule();
      const grant = {
        grant: {
          grant_id: "g-1",
          holder: "holder",
          scope: "scope",
          subject: "huglo:user:u",
          requester: "test-mod",
          author: "huglo:user:u",
          constraints: {},
          issued_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        },
        signature: "ed25519:unused",
      };

      await expect(module.emit("missing.event", {}, grant)).rejects.toThrow(
        "Unknown emitter: missing.event",
      );
    });

    it("createInvite delegates to directory client", async () => {
      const keys = generateKeyPair();
      const directory = new InMemoryDirectoryClient();
      const inviteResponse = {
        invite: {
          id: "inv-unit",
          requesterModuleId: "test-mod",
          callbackUrl: "https://example/cb",
          constraints: {},
          expiresAt: "2026-06-01T00:00:00.000Z",
          createdByUserId: "user-1",
          active: true,
          createdAt: "2026-06-01T00:00:00.000Z",
          updatedAt: "2026-06-01T00:00:00.000Z",
          scopes: [],
        },
        inviteUrl: "https://account.huglo.com/invite/unit",
      };
      directory.setInviteResponse("test-mod", inviteResponse);

      const module = new Module({
        id: "test-mod",
        name: "Test",
        description: "Test",
        version: "1.0.0",
        keyPair: keys,
        directory,
        endpoint: "https://example.com",
      });

      const result = await module.createInvite({
        callbackUrl: "https://example/cb",
        scopes: [{ holder: "da", scope: "invoice:write" }],
      });

      expect(result).toEqual(inviteResponse);
    });
  });

  describe("getApp with explicit fileStore", () => {
    it("uses injected fileStore without lazy initialization", async () => {
      const fileStore = new InMemoryFileStore();
      const module = createModule({ fileStore, endpoint: "https://example.com" });
      await module.getApp().request("/health");
      expect(module.getFileStore()).toBe(fileStore);
    });
  });

  describe("listen and close", () => {
    it("starts and stops an HTTP server", async () => {
      const module = createModule();
      module.scope("status:read", {
        open: true,
        description: "Status",
        input: z.object({}),
        output: z.object({ ok: z.boolean() }),
        handler: async () => ({ ok: true }),
      });

      const port = 9400 + Math.floor(Math.random() * 1000);
      await module.listen(port, "127.0.0.1");

      try {
        const res = await fetch(`http://127.0.0.1:${port}/health`);
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ status: "ok", module: "test-mod" });
      } finally {
        module.close();
      }
    });
  });
});

function oauthOptions() {
  return {
    clientId: "test-client",
    clientSecret: "test-secret",
    redirectUri: "http://127.0.0.1:8080/config/callback",
    authorizeUrl: "https://oauth.test/authorize",
    tokenUrl: "https://oauth.test/token",
    userInfoUrl: "https://oauth.test/userinfo",
  };
}

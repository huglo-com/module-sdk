import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { z } from "zod";
import { generateKeyPair } from "../src/keys.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import { Module } from "../src/module.js";
import {
  assembleConfigValues,
  ConfigAssemblyError,
} from "../src/config.js";
import { InMemoryConfigStore } from "../src/config-store.js";
import { InMemoryHugloOAuthClient } from "../src/oauth.js";
import {
  createConfigSession,
  readConfigSession,
  CONFIG_SESSION_COOKIE,
} from "../src/oauth.js";
import type { ModuleManifest } from "../src/manifest.js";

const ConfigSchema = z.object({
  target: z.string().default("module-fixed-target"),
  scope: z.string().default("fixed-scope"),
  label: z.string(),
  hostRef: z.string(),
});

describe("config", () => {
  describe("assembleConfigValues", () => {
    const definition = {
      schema: ConfigSchema,
      fields: {
        target: "locked" as const,
        scope: "locked" as const,
        label: "userEntered" as const,
        hostRef: "hostProvided" as const,
      },
      lockedValues: {
        target: "override-target",
      },
    };

    it("locked discards incoming user/host values", () => {
      const result = assembleConfigValues({
        definition,
        userValues: {
          label: "my-label",
          target: "user-attempt",
          scope: "user-scope",
        },
        hostValues: {
          hostRef: "host-123",
          target: "host-attempt",
        },
      });

      expect(result.values.target).toBe("override-target");
      expect(result.values.scope).toBe("fixed-scope");
      expect(result.values.label).toBe("my-label");
      expect(result.values.hostRef).toBe("host-123");
    });

    it("hostProvided accepted from hostValues", () => {
      const result = assembleConfigValues({
        definition,
        userValues: { label: "x" },
        hostValues: { hostRef: "opaque-host-value" },
      });
      expect(result.values.hostRef).toBe("opaque-host-value");
    });

    it("userEntered accepted from userValues", () => {
      const result = assembleConfigValues({
        definition,
        userValues: { label: "user-value" },
        hostValues: { hostRef: "h" },
      });
      expect(result.values.label).toBe("user-value");
    });

    it("schema validation rejects bad assembled values", () => {
      expect(() =>
        assembleConfigValues({
          definition,
          userValues: { label: 123 as unknown as string },
          hostValues: { hostRef: "h" },
        }),
      ).toThrow();
    });

    it("throws when hostProvided field is missing", () => {
      expect(() =>
        assembleConfigValues({
          definition,
          userValues: { label: "x" },
          hostValues: {},
        }),
      ).toThrow(ConfigAssemblyError);
    });
  });

  describe("ConfigStore", () => {
    it("get(instanceId) returns subject-bearing config", async () => {
      const store = new InMemoryConfigStore();
      await store.set({
        instanceId: "inst-1",
        subject: "huglo:user:alice",
        values: { label: "test" },
      });

      const got = await store.get("inst-1");
      expect(got).toEqual({
        instanceId: "inst-1",
        subject: "huglo:user:alice",
        values: { label: "test" },
      });

      expect(await store.get("unknown")).toBeNull();
    });

    it("listBySubject filters by subject", async () => {
      const store = new InMemoryConfigStore();
      await store.set({
        instanceId: "a",
        subject: "huglo:user:alice",
        values: {},
      });
      await store.set({
        instanceId: "b",
        subject: "huglo:user:bob",
        values: {},
      });

      const list = await store.listBySubject("huglo:user:alice");
      expect(list).toHaveLength(1);
      expect(list[0]!.instanceId).toBe("a");
    });
  });

  describe("config session", () => {
    it("creates and reads signed session", () => {
      const secret = "test-secret";
      const cookie = createConfigSession("huglo:user:alice", secret);
      expect(readConfigSession(cookie, secret)).toBe("huglo:user:alice");
      expect(readConfigSession(cookie, "wrong")).toBeNull();
    });
  });

  describe("config routes", () => {
    const keys = generateKeyPair();
    const directory = new InMemoryDirectoryClient();
    const configStore = new InMemoryConfigStore();
    const oauthClient = new InMemoryHugloOAuthClient({
      defaultSubject: "huglo:user:config-user",
    });
    const port = 9300 + Math.floor(Math.random() * 1000);

    const mod = new Module({
      id: "config-module",
      name: "Config Module",
      description: "Has config",
      version: "1.0.0",
      keyPair: keys,
      directory,
      configStore,
      oauthClient,
      oauth: {
        clientId: "test-client",
        clientSecret: "test-secret",
        redirectUri: `http://127.0.0.1:${port}/config/callback`,
        authorizeUrl: "https://oauth.test/authorize",
        tokenUrl: "https://oauth.test/token",
        userInfoUrl: "https://oauth.test/userinfo",
      },
    });

    mod.config({
      schema: ConfigSchema,
      fields: {
        target: "locked",
        scope: "locked",
        label: "userEntered",
        hostRef: "hostProvided",
      },
      lockedValues: { target: "locked-target", scope: "locked-scope" },
    });

    beforeAll(async () => {
      directory.registerModule(
        "config-module",
        `http://127.0.0.1:${port}`,
        keys.publicKey,
        keys.publicKeyBase64,
      );
      await mod.listen(port, "127.0.0.1");
    });

    afterAll(() => {
      mod.close();
    });

    it("lists config in /manifest", async () => {
      const res = await mod.getApp().request("/manifest");
      const manifest = (await res.json()) as ModuleManifest;
      expect(manifest.config).toBeDefined();
      expect(manifest.config!.fields).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ name: "target", source: "locked" }),
          expect.objectContaining({ name: "label", source: "userEntered" }),
          expect.objectContaining({ name: "hostRef", source: "hostProvided" }),
        ]),
      );
    });

    it("intake rejects without authenticated session", async () => {
      const res = await mod.getApp().request("/config/intake", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userValues: { label: "x" },
          hostValues: { hostRef: "h" },
        }),
      });
      expect(res.status).toBe(401);
    });

    it("mints instanceId on create and reuses on edit", async () => {
      const sessionCookie = createConfigSession(
        "huglo:user:config-user",
        "test-secret",
      );

      const createRes = await mod.getApp().request("/config/intake", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}`,
        },
        body: JSON.stringify({
          userValues: { label: "first" },
          hostValues: { hostRef: "host-1" },
        }),
      });
      expect(createRes.status).toBe(200);
      const created = (await createRes.json()) as { instanceId: string };
      expect(created.instanceId).toBeTruthy();

      const stored = await configStore.get(created.instanceId);
      expect(stored?.subject).toBe("huglo:user:config-user");
      expect(stored?.values).toMatchObject({
        target: "locked-target",
        scope: "locked-scope",
        label: "first",
        hostRef: "host-1",
      });

      const editRes = await mod.getApp().request("/config/intake", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}`,
        },
        body: JSON.stringify({
          instanceId: created.instanceId,
          userValues: { label: "updated" },
          hostValues: { hostRef: "host-2" },
        }),
      });
      expect(editRes.status).toBe(200);
      const edited = (await editRes.json()) as { instanceId: string };
      expect(edited.instanceId).toBe(created.instanceId);

      const afterEdit = await configStore.get(created.instanceId);
      expect(afterEdit?.values.label).toBe("updated");
      expect(afterEdit?.values.hostRef).toBe("host-2");
    });
  });
});

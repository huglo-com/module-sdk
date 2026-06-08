import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { z } from "zod";
import { Hono } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { generateKeyPair } from "../src/keys.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import { Module } from "../src/module.js";
import {
  assembleConfigValues,
  ConfigAssemblyError,
  formatInstanceLabel,
  truncateInstanceId,
} from "../src/config.js";
import { buildConfigManifest } from "../src/manifest.js";
import { InMemoryConfigStore } from "../src/config-store.js";
import {
  InMemoryHugloOAuthClient,
  HttpHugloOAuthClient,
  createConfigSession,
  readConfigSession,
  createPkceCookie,
  readPkceCookie,
  generateCodeVerifier,
  generateCodeChallenge,
  CONFIG_SESSION_COOKIE,
  OAUTH_PKCE_COOKIE,
  OAUTH_STATE_COOKIE,
} from "../src/oauth.js";
import {
  CONFIG_READY_MESSAGE,
  CONFIG_SAVED_MESSAGE,
} from "../src/config-opener.js";
import { createSignedConfigProof } from "./helpers/create-signed-config-proof.js";
import { signObject } from "../src/signing.js";
import type { SignedGrant } from "../src/envelope.js";
import { sig2Payload } from "../src/envelope.js";
import type { ModuleManifest } from "../src/manifest.js";

const DEV_SESSION_COOKIE = "dev_session";

function createFullCustomConfigHandler() {
  const store = new Map<string, { apiKey: string }>();
  const handler = new Hono();

  handler.get("/", (c) => {
    const instanceId = c.req.query("instanceId") ?? "";
    const existing = instanceId ? store.get(instanceId) : undefined;
    return c.html(`<!DOCTYPE html>
<html><body>
<div id="instance-id">${instanceId}</div>
<div id="api-key">${existing?.apiKey ?? ""}</div>
<script>
  const CONFIG_READY = ${JSON.stringify(CONFIG_READY_MESSAGE)};
  const CONFIG_SAVED = ${JSON.stringify(CONFIG_SAVED_MESSAGE)};
  function notifyReady() {
    const msg = { type: CONFIG_READY };
    if (window.opener) window.opener.postMessage(msg, "*");
  }
  notifyReady();
</script>
</body></html>`);
  });

  handler.post("/login", async (c) => {
    const body = (await c.req.json()) as { apiKey?: string };
    if (body.apiKey !== "secret-key") {
      return c.json({ error: "Invalid credentials" }, 401);
    }
    setCookie(c, DEV_SESSION_COOKIE, "authenticated", {
      httpOnly: true,
      path: "/",
      maxAge: 86400,
    });
    return c.json({ ok: true });
  });

  handler.get("/me", (c) => {
    if (getCookie(c, DEV_SESSION_COOKIE) !== "authenticated") {
      return c.json({ error: "Unauthorized" }, 401);
    }
    return c.json({ ok: true });
  });

  handler.post("/save", async (c) => {
    if (getCookie(c, DEV_SESSION_COOKIE) !== "authenticated") {
      return c.json({ error: "Authentication required" }, 401);
    }
    const body = (await c.req.json()) as { instanceId?: string; apiKey: string };
    if (body.instanceId && !store.has(body.instanceId)) {
      return c.json({ error: "Instance not found" }, 404);
    }
    const instanceId = body.instanceId ?? crypto.randomUUID();
    store.set(instanceId, { apiKey: body.apiKey });
    return c.json({ instanceId });
  });

  return { handler, store };
}

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

  describe("formatInstanceLabel", () => {
    const definition = {
      schema: ConfigSchema,
      fields: {
        target: "locked" as const,
        scope: "locked" as const,
        label: "userEntered" as const,
        hostRef: "hostProvided" as const,
      },
    };
    const manifest = buildConfigManifest(definition);

    it("uses the first schema field value", () => {
      expect(
        formatInstanceLabel(
          { target: "my-target", label: "ignored" },
          "inst-abcdefgh",
          manifest.fields,
        ),
      ).toBe("my-target");
    });

    it("falls back to truncated instanceId when first field is empty", () => {
      expect(
        formatInstanceLabel({ target: "" }, "inst-abcdefgh", manifest.fields),
      ).toBe("inst-abc…");
    });

    it("truncateInstanceId leaves short ids unchanged", () => {
      expect(truncateInstanceId("short")).toBe("short");
    });
  });

  describe("ConfigStore", () => {
    it("get(instanceId) returns subject-bearing config", async () => {
      const store = new InMemoryConfigStore();
      await store.set({
        instanceId: "inst-1",
        subject: "huglo:user:alice",
        directorySubject: "huglo:user:alice",
        values: { label: "test" },
      });

      const got = await store.get("inst-1");
      expect(got).toEqual({
        instanceId: "inst-1",
        subject: "huglo:user:alice",
        directorySubject: "huglo:user:alice",
        values: { label: "test" },
      });

      expect(await store.get("unknown")).toBeNull();
    });

    it("listBySubject filters by subject", async () => {
      const store = new InMemoryConfigStore();
      await store.set({
        instanceId: "a",
        subject: "huglo:user:alice",
        directorySubject: "huglo:user:alice",
        values: {},
      });
      await store.set({
        instanceId: "b",
        subject: "huglo:user:bob",
        directorySubject: "huglo:user:bob",
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

  describe("PKCE", () => {
    const secret = "test-secret";

    it("generateCodeChallenge is S256 base64url of verifier", () => {
      const verifier = "test-verifier-value";
      const challenge = generateCodeChallenge(verifier);
      const expected = generateCodeChallenge(verifier);
      expect(challenge).toBe(expected);
      expect(challenge).not.toBe(verifier);
    });

    it("signed PKCE cookie round-trips verifier for matching state", () => {
      const verifier = generateCodeVerifier();
      const state = "state-abc";
      const cookie = createPkceCookie(verifier, state, secret);
      expect(readPkceCookie(cookie, state, secret)).toBe(verifier);
    });

    it("rejects PKCE cookie when state does not match", () => {
      const cookie = createPkceCookie("verifier", "state-a", secret);
      expect(readPkceCookie(cookie, "state-b", secret)).toBeNull();
    });

    it("rejects PKCE cookie with wrong secret", () => {
      const cookie = createPkceCookie("verifier", "state-a", secret);
      expect(readPkceCookie(cookie, "state-a", "wrong")).toBeNull();
    });
  });

  describe("HttpHugloOAuthClient PKCE", () => {
    const oauthOptions = {
      clientId: "client-id",
      clientSecret: "client-secret",
      redirectUri: "https://module.example/config/callback",
      authorizeUrl: "https://auth.example/oauth2/authorize",
      tokenUrl: "https://auth.example/oauth2/token",
      userInfoUrl: "https://auth.example/oauth2/userinfo",
    };

    it("buildAuthorizeUrl includes code_challenge and S256 method", () => {
      const client = new HttpHugloOAuthClient(oauthOptions);
      const url = new URL(
        client.buildAuthorizeUrl("state-1", { codeChallenge: "challenge-xyz" }),
      );
      expect(url.searchParams.get("code_challenge")).toBe("challenge-xyz");
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      expect(url.searchParams.get("state")).toBe("state-1");
    });

    it("exchangeCode sends code_verifier in token request", async () => {
      let tokenBody = "";
      const fetchFn = async (input: string | URL | Request, init?: RequestInit) => {
        const url = input instanceof Request ? input.url : String(input);
        if (url.includes("/token")) {
          tokenBody = String(init?.body ?? "");
          return new Response(
            JSON.stringify({ access_token: "access-token" }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (url.includes("/userinfo")) {
          return new Response(JSON.stringify({ sub: "user-123" }), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        return new Response("not found", { status: 404 });
      };

      const client = new HttpHugloOAuthClient({ ...oauthOptions, fetch: fetchFn });
      const result = await client.exchangeCode("auth-code", "verifier-secret");
      expect(result.subject).toBe("huglo:user:user-123");
      const params = new URLSearchParams(tokenBody);
      expect(params.get("code_verifier")).toBe("verifier-secret");
      expect(params.get("code")).toBe("auth-code");
    });
  });

  describe("config routes", () => {
    const keys = generateKeyPair();
    const proofUserKeys = generateKeyPair();
    const directory = new InMemoryDirectoryClient();
    const configStore = new InMemoryConfigStore();
    const oauthClient = new InMemoryHugloOAuthClient({
      defaultSubject: "huglo:user:config-user",
    });
    const port = 9300 + Math.floor(Math.random() * 1000);

    function configProof(subject = "huglo:user:config-user") {
      return createSignedConfigProof({
        subject,
        audience: "config-module",
        privateKey: proofUserKeys.privateKey,
      });
    }

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
      directory.registerUser("config-user", proofUserKeys.publicKey);
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
      expect(manifest.config).toBe(true);
    });

    it("config page notifies opener on ready and save", async () => {
      const res = await mod.getApp().request("/config");
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain("notifyReady");
      expect(html).toContain("huglo:config:ready");
      expect(html).toContain("window.opener");
      expect(html).toContain('key === "type"');
      expect(html).toContain("HOST_PROVIDED_FIELDS.has(key)");
      expect(html).toContain("huglo:config:saved");
      expect(html).toContain("window.close");
    });

    it("config page includes selector when authenticated with instances", async () => {
      const sessionCookie = createConfigSession(
        "huglo:user:config-user",
        "test-secret",
      );
      await configStore.set({
        instanceId: "inst-a",
        subject: "huglo:user:config-user",
        directorySubject: "huglo:user:config-user",
        values: {
          target: "locked-target",
          scope: "locked-scope",
          label: "Alpha",
          hostRef: "h1",
        },
      });
      await configStore.set({
        instanceId: "inst-b",
        subject: "huglo:user:config-user",
        directorySubject: "huglo:user:config-user",
        values: {
          target: "locked-target",
          scope: "locked-scope",
          label: "Beta",
          hostRef: "h2",
        },
      });

      const res = await mod.getApp().request("/config", {
        headers: { Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}` },
      });
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('id="config-select"');
      expect(html).toContain('value="__new__"');
      expect(html).toContain("New configuration");
      expect(html).toContain('id="delete-btn"');
      expect(html).toContain("disableSelector");
      expect(html).toContain("HOST_PROVIDED_FIELDS");
      expect(html).toContain("configProof");
      expect(html).toContain("inst-a");
      expect(html).toContain("inst-b");
    });

    it("DELETE /config/instances/:id requires authentication", async () => {
      const res = await mod.getApp().request("/config/instances/inst-a", {
        method: "DELETE",
      });
      expect(res.status).toBe(401);
    });

    it("DELETE /config/instances/:id returns 404 for unknown instance", async () => {
      const sessionCookie = createConfigSession(
        "huglo:user:config-user",
        "test-secret",
      );
      const res = await mod.getApp().request("/config/instances/unknown-id", {
        method: "DELETE",
        headers: { Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}` },
      });
      expect(res.status).toBe(404);
    });

    it("DELETE /config/instances/:id returns 403 for wrong subject", async () => {
      await configStore.set({
        instanceId: "inst-other",
        subject: "huglo:user:someone-else",
        directorySubject: "huglo:user:someone-else",
        values: {
          target: "locked-target",
          scope: "locked-scope",
          label: "Other",
          hostRef: "h",
        },
      });
      const sessionCookie = createConfigSession(
        "huglo:user:config-user",
        "test-secret",
      );
      const res = await mod.getApp().request("/config/instances/inst-other", {
        method: "DELETE",
        headers: { Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}` },
      });
      expect(res.status).toBe(403);
    });

    it("DELETE /config/instances/:id removes owned instance", async () => {
      await configStore.set({
        instanceId: "inst-delete-me",
        subject: "huglo:user:config-user",
        directorySubject: "huglo:user:config-user",
        values: {
          target: "locked-target",
          scope: "locked-scope",
          label: "Delete me",
          hostRef: "h",
        },
      });
      const sessionCookie = createConfigSession(
        "huglo:user:config-user",
        "test-secret",
      );
      const res = await mod.getApp().request("/config/instances/inst-delete-me", {
        method: "DELETE",
        headers: { Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}` },
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { ok: boolean };
      expect(body.ok).toBe(true);
      expect(await configStore.get("inst-delete-me")).toBeNull();
    });

    it("login redirect includes code_challenge", async () => {
      const res = await mod.getApp().request("/config/login", {
        redirect: "manual",
      });
      expect(res.status).toBe(302);
      const location = res.headers.get("Location");
      expect(location).toBeTruthy();
      const url = new URL(location!);
      expect(url.searchParams.get("code_challenge")).toBeTruthy();
      expect(url.searchParams.get("code_challenge_method")).toBe("S256");
      const setCookie = res.headers.get("Set-Cookie") ?? "";
      expect(setCookie).toContain(OAUTH_STATE_COOKIE);
      expect(setCookie).toContain(OAUTH_PKCE_COOKIE);
    });

    it("callback returns error when OAuth redirects with error", async () => {
      const res = await mod.getApp().request(
        "/config/callback?error=invalid_request&error_description=pkce+is+required&state=x",
      );
      expect(res.status).toBe(400);
      const text = await res.text();
      expect(text).toContain("pkce is required");
    });

    it("intake rejects without authenticated session", async () => {
      const res = await mod.getApp().request("/config/intake", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          userValues: { label: "x" },
          hostValues: { hostRef: "h" },
          configProof: configProof(),
        }),
      });
      expect(res.status).toBe(401);
    });

    it("intake rejects without config proof", async () => {
      const sessionCookie = createConfigSession(
        "huglo:user:config-user",
        "test-secret",
      );
      const res = await mod.getApp().request("/config/intake", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}`,
        },
        body: JSON.stringify({
          userValues: { label: "x" },
          hostValues: { hostRef: "h" },
        }),
      });
      expect(res.status).toBe(400);
    });

    it("intake rejects invalid config proof", async () => {
      const sessionCookie = createConfigSession(
        "huglo:user:config-user",
        "test-secret",
      );
      const badProof = configProof();
      badProof.signature = signObject(badProof.assertion, generateKeyPair().privateKey);
      const res = await mod.getApp().request("/config/intake", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}`,
        },
        body: JSON.stringify({
          userValues: { label: "x" },
          hostValues: { hostRef: "h" },
          configProof: badProof,
        }),
      });
      expect(res.status).toBe(403);
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
          configProof: configProof(),
        }),
      });
      expect(createRes.status).toBe(200);
      const created = (await createRes.json()) as { instanceId: string };
      expect(created.instanceId).toBeTruthy();

      const stored = await configStore.get(created.instanceId);
      expect(stored?.subject).toBe("huglo:user:config-user");
      expect(stored?.directorySubject).toBe("huglo:user:config-user");
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
          configProof: configProof("huglo:user:config-user"),
        }),
      });
      expect(editRes.status).toBe(200);
      const edited = (await editRes.json()) as { instanceId: string };
      expect(edited.instanceId).toBe(created.instanceId);

      const afterEdit = await configStore.get(created.instanceId);
      expect(afterEdit?.values.label).toBe("updated");
      expect(afterEdit?.values.hostRef).toBe("host-2");
      expect(afterEdit?.directorySubject).toBe("huglo:user:config-user");
    });

    it("OAuth callback happy path sets session and redirects to config", async () => {
      const loginRes = await mod.getApp().request("/config/login", { redirect: "manual" });
      expect(loginRes.status).toBe(302);

      const location = new URL(loginRes.headers.get("Location")!);
      const state = location.searchParams.get("state");
      expect(state).toBeTruthy();

      const setCookies = loginRes.headers.getSetCookie?.() ?? [loginRes.headers.get("Set-Cookie") ?? ""];
      const cookieHeader = setCookies
        .flatMap((c) => c.split(/,(?=[^;]+=)/))
        .map((c) => c.trim().split(";")[0])
        .join("; ");

      oauthClient.setCode("oauth-success-code", "huglo:user:config-user");

      const callbackRes = await mod.getApp().request(
        `/config/callback?code=oauth-success-code&state=${state}`,
        {
          redirect: "manual",
          headers: { Cookie: cookieHeader },
        },
      );

      expect(callbackRes.status).toBe(302);
      expect(callbackRes.headers.get("Location")).toBe("/config");
      const sessionCookies = callbackRes.headers.getSetCookie?.() ?? [
        callbackRes.headers.get("Set-Cookie") ?? "",
      ];
      expect(sessionCookies.join("; ")).toContain(CONFIG_SESSION_COOKIE);
    });

    it("login redirects to config when session already exists", async () => {
      const sessionCookie = createConfigSession("huglo:user:config-user", "test-secret");
      const res = await mod.getApp().request("/config/login", {
        redirect: "manual",
        headers: { Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}` },
      });
      expect(res.status).toBe(302);
      expect(res.headers.get("Location")).toBe("/config");
    });

    it("intake edit returns 404 for unknown instance", async () => {
      const sessionCookie = createConfigSession("huglo:user:config-user", "test-secret");
      const res = await mod.getApp().request("/config/intake", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}`,
        },
        body: JSON.stringify({
          instanceId: "does-not-exist",
          userValues: { label: "x" },
          hostValues: { hostRef: "h" },
          configProof: configProof(),
        }),
      });
      expect(res.status).toBe(404);
    });

    it("intake edit returns 403 for instance owned by another subject", async () => {
      await configStore.set({
        instanceId: "inst-other-user",
        subject: "huglo:user:someone-else",
        directorySubject: "huglo:user:someone-else",
        values: {
          target: "locked-target",
          scope: "locked-scope",
          label: "Other",
          hostRef: "h",
        },
      });

      const sessionCookie = createConfigSession("huglo:user:config-user", "test-secret");
      const res = await mod.getApp().request("/config/intake", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}`,
        },
        body: JSON.stringify({
          instanceId: "inst-other-user",
          userValues: { label: "stolen" },
          hostValues: { hostRef: "h" },
          configProof: configProof(),
        }),
      });
      expect(res.status).toBe(403);
    });
  });

  describe("onConfigSaved hook", () => {
    const keys = generateKeyPair();
    const hookProofKeys = generateKeyPair();
    const directory = new InMemoryDirectoryClient();
    const configStore = new InMemoryConfigStore();
    const oauthClient = new InMemoryHugloOAuthClient({
      defaultSubject: "huglo:user:hook-user",
    });
    const port = 9400 + Math.floor(Math.random() * 1000);
    const savedCalls: Array<{
      isNew: boolean;
      instanceId: string;
      subject: string;
      directorySubject: string;
    }> = [];

    const hookMod = new Module({
      id: "hook-module",
      name: "Hook Module",
      description: "Config hook test",
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
      onConfigSaved: async ({ isNew, instanceId, subject, directorySubject }) => {
        savedCalls.push({ isNew, instanceId, subject, directorySubject });
      },
    });

    hookMod.config({
      schema: ConfigSchema,
      fields: {
        target: "locked",
        scope: "locked",
        label: "userEntered",
        hostRef: "hostProvided",
      },
      lockedValues: { target: "t", scope: "s" },
    });

    beforeAll(async () => {
      directory.registerUser("hook-user", hookProofKeys.publicKey);
      directory.registerModule("hook-module", `http://127.0.0.1:${port}`, keys.publicKey, keys.publicKeyBase64);
      await hookMod.listen(port, "127.0.0.1");
    });

    afterAll(() => {
      hookMod.close();
    });

    it("invokes onConfigSaved with isNew true on create and false on edit", async () => {
      savedCalls.length = 0;
      const sessionCookie = createConfigSession("huglo:user:hook-user", "test-secret");

      const createRes = await hookMod.getApp().request("/config/intake", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}`,
        },
        body: JSON.stringify({
          userValues: { label: "new" },
          hostValues: { hostRef: "h1" },
          configProof: createSignedConfigProof({
            subject: "huglo:user:hook-user",
            audience: "hook-module",
            privateKey: hookProofKeys.privateKey,
          }),
        }),
      });
      const created = (await createRes.json()) as { instanceId: string };

      await hookMod.getApp().request("/config/intake", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}`,
        },
        body: JSON.stringify({
          instanceId: created.instanceId,
          userValues: { label: "edited" },
          hostValues: { hostRef: "h2" },
          configProof: createSignedConfigProof({
            subject: "huglo:user:hook-user",
            audience: "hook-module",
            privateKey: hookProofKeys.privateKey,
          }),
        }),
      });

      expect(savedCalls).toEqual([
        {
          isNew: true,
          instanceId: created.instanceId,
          subject: "huglo:user:hook-user",
          directorySubject: "huglo:user:hook-user",
        },
        {
          isNew: false,
          instanceId: created.instanceId,
          subject: "huglo:user:hook-user",
          directorySubject: "huglo:user:hook-user",
        },
      ]);
    });
  });

  describe("renderConfigPage hook", () => {
    const keys = generateKeyPair();
    const directory = new InMemoryDirectoryClient();
    const configStore = new InMemoryConfigStore();
    const oauthClient = new InMemoryHugloOAuthClient({
      defaultSubject: "huglo:user:render-user",
    });
    const port = 9500 + Math.floor(Math.random() * 1000);

    const customMod = new Module({
      id: "render-module",
      name: "Render Module",
      description: "Custom config page",
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
      renderConfigPage: (ctx) =>
        `<html><body>custom:${ctx.subject ?? "anon"}</body></html>`,
    });

    customMod.config({
      schema: ConfigSchema,
      fields: {
        target: "locked",
        scope: "locked",
        label: "userEntered",
        hostRef: "hostProvided",
      },
      lockedValues: { target: "t", scope: "s" },
    });

    beforeAll(async () => {
      directory.registerModule(
        "render-module",
        `http://127.0.0.1:${port}`,
        keys.publicKey,
        keys.publicKeyBase64,
      );
      await customMod.listen(port, "127.0.0.1");
    });

    afterAll(() => {
      customMod.close();
    });

    it("serves custom HTML from renderConfigPage at GET /config", async () => {
      const res = await customMod.getApp().request("/config");
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toBe("<html><body>custom:anon</body></html>");
    });

    it("passes authenticated subject to renderConfigPage", async () => {
      const sessionCookie = createConfigSession(
        "huglo:user:render-user",
        "test-secret",
      );
      const res = await customMod.getApp().request("/config", {
        headers: { Cookie: `${CONFIG_SESSION_COOKIE}=${sessionCookie}` },
      });
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toBe("<html><body>custom:huglo:user:render-user</body></html>");
    });
  });

  describe("renderConfigPage void fallback", () => {
    const keys = generateKeyPair();
    const directory = new InMemoryDirectoryClient();
    const oauthClient = new InMemoryHugloOAuthClient({
      defaultSubject: "huglo:user:fallback-user",
    });
    const port = 9600 + Math.floor(Math.random() * 1000);

    const fallbackMod = new Module({
      id: "fallback-module",
      name: "Fallback Module",
      description: "Falls back to default page",
      version: "1.0.0",
      keyPair: keys,
      directory,
      oauthClient,
      oauth: {
        clientId: "test-client",
        clientSecret: "test-secret",
        redirectUri: `http://127.0.0.1:${port}/config/callback`,
        authorizeUrl: "https://oauth.test/authorize",
        tokenUrl: "https://oauth.test/token",
        userInfoUrl: "https://oauth.test/userinfo",
      },
      renderConfigPage: () => undefined,
    });

    fallbackMod.config({
      schema: z.object({ label: z.string() }),
      fields: { label: "userEntered" },
    });

    beforeAll(async () => {
      directory.registerModule(
        "fallback-module",
        `http://127.0.0.1:${port}`,
        keys.publicKey,
        keys.publicKeyBase64,
      );
      await fallbackMod.listen(port, "127.0.0.1");
    });

    afterAll(() => {
      fallbackMod.close();
    });

    it("uses default config page when hook returns void", async () => {
      const res = await fallbackMod.getApp().request("/config");
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain("Sign in with Huglo");
      expect(html).toContain("notifyReady");
    });
  });

  describe("full custom config (customConfig)", () => {
    const keys = generateKeyPair();
    const directory = new InMemoryDirectoryClient();
    const port = 9700 + Math.floor(Math.random() * 1000);
    const { handler: customHandler, store } = createFullCustomConfigHandler();

    const fullCustomMod = new Module({
      id: "full-custom-module",
      name: "Full Custom Module",
      description: "Developer-owned config",
      version: "1.0.0",
      keyPair: keys,
      directory,
    });

    fullCustomMod.customConfig(customHandler);

    beforeAll(async () => {
      directory.registerModule(
        "full-custom-module",
        `http://127.0.0.1:${port}`,
        keys.publicKey,
        keys.publicKeyBase64,
      );
      await fullCustomMod.listen(port, "127.0.0.1");
    });

    afterAll(() => {
      fullCustomMod.close();
    });

    it("getApp() does not require OAuth", () => {
      expect(() => fullCustomMod.getApp()).not.toThrow();
    });

    it("manifest.config is true with no fields property", async () => {
      const res = await fullCustomMod.getApp().request("/manifest");
      const manifest = (await res.json()) as ModuleManifest;
      expect(manifest.config).toBe(true);
      expect(manifest).not.toHaveProperty("fields");
      expect(Object.keys(manifest)).not.toContain("fields");
    });

    it("GET /config is served by developer handler, not SDK default page", async () => {
      const res = await fullCustomMod.getApp().request("/config");
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).not.toContain("Sign in with Huglo");
      expect(html).toContain(CONFIG_READY_MESSAGE);
      expect(html).toContain(CONFIG_SAVED_MESSAGE);
    });

    it("GET /config?instanceId= echoes instance id and prefills stored values", async () => {
      store.set("inst-edit", { apiKey: "stored-key" });
      const res = await fullCustomMod.getApp().request("/config?instanceId=inst-edit");
      expect(res.status).toBe(200);
      const html = await res.text();
      expect(html).toContain('id="instance-id">inst-edit');
      expect(html).toContain('id="api-key">stored-key');
    });

    it("developer login sets session cookie and /me succeeds", async () => {
      const loginRes = await fullCustomMod.getApp().request("/config/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: "secret-key" }),
      });
      expect(loginRes.status).toBe(200);
      const setCookie = loginRes.headers.get("Set-Cookie") ?? "";
      expect(setCookie).toContain(DEV_SESSION_COOKIE);

      const meRes = await fullCustomMod.getApp().request("/config/me", {
        headers: { Cookie: setCookie.split(";")[0]! },
      });
      expect(meRes.status).toBe(200);
    });

    it("POST /config/save mints instanceId on create", async () => {
      store.clear();
      const loginRes = await fullCustomMod.getApp().request("/config/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: "secret-key" }),
      });
      const cookie = loginRes.headers.get("Set-Cookie")?.split(";")[0] ?? "";

      const saveRes = await fullCustomMod.getApp().request("/config/save", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ apiKey: "my-api-key" }),
      });
      expect(saveRes.status).toBe(200);
      const body = (await saveRes.json()) as { instanceId: string };
      expect(body.instanceId).toBeTruthy();
      expect(store.get(body.instanceId)?.apiKey).toBe("my-api-key");
    });

    it("POST /config/save updates existing instance", async () => {
      store.clear();
      store.set("inst-update", { apiKey: "old-key" });
      const loginRes = await fullCustomMod.getApp().request("/config/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: "secret-key" }),
      });
      const cookie = loginRes.headers.get("Set-Cookie")?.split(";")[0] ?? "";

      const saveRes = await fullCustomMod.getApp().request("/config/save", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ instanceId: "inst-update", apiKey: "new-key" }),
      });
      expect(saveRes.status).toBe(200);
      const body = (await saveRes.json()) as { instanceId: string };
      expect(body.instanceId).toBe("inst-update");
      expect(store.get("inst-update")?.apiKey).toBe("new-key");
    });

    it("POST /config/save returns 404 for unknown instance", async () => {
      const loginRes = await fullCustomMod.getApp().request("/config/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: "secret-key" }),
      });
      const cookie = loginRes.headers.get("Set-Cookie")?.split(";")[0] ?? "";

      const saveRes = await fullCustomMod.getApp().request("/config/save", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Cookie: cookie,
        },
        body: JSON.stringify({ instanceId: "missing", apiKey: "x" }),
      });
      expect(saveRes.status).toBe(404);
    });

    it("GET /config/me without session returns 401", async () => {
      const res = await fullCustomMod.getApp().request("/config/me");
      expect(res.status).toBe(401);
    });

    it("SDK managed routes are not mounted", async () => {
      const intakeRes = await fullCustomMod.getApp().request("/config/intake", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ userValues: {}, hostValues: {} }),
      });
      expect(intakeRes.status).toBe(404);

      const callbackRes = await fullCustomMod.getApp().request(
        "/config/callback?code=x&state=y",
      );
      expect(callbackRes.status).toBe(404);
      expect(callbackRes.headers.get("Set-Cookie") ?? "").not.toContain(
        OAUTH_STATE_COOKIE,
      );
    });

    it("lifecycle: login, create, reopen with instanceId, update", async () => {
      store.clear();
      const loginRes = await fullCustomMod.getApp().request("/config/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ apiKey: "secret-key" }),
      });
      const cookie = loginRes.headers.get("Set-Cookie")?.split(";")[0] ?? "";

      const createRes = await fullCustomMod.getApp().request("/config/save", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify({ apiKey: "lifecycle-key" }),
      });
      const created = (await createRes.json()) as { instanceId: string };

      const reopenRes = await fullCustomMod.getApp().request(
        `/config?instanceId=${created.instanceId}`,
      );
      expect(await reopenRes.text()).toContain("lifecycle-key");

      const updateRes = await fullCustomMod.getApp().request("/config/save", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: cookie },
        body: JSON.stringify({
          instanceId: created.instanceId,
          apiKey: "lifecycle-updated",
        }),
      });
      expect(updateRes.status).toBe(200);
      expect(store.get(created.instanceId)?.apiKey).toBe("lifecycle-updated");
    });
  });

  describe("config invoke enforcement", () => {
    const holderKeys = generateKeyPair();
    const requesterKeys = generateKeyPair();
    const authorKeys = generateKeyPair();
    const directory = new InMemoryDirectoryClient();
    const configStore = new InMemoryConfigStore();
    const oauthClient = new InMemoryHugloOAuthClient({
      defaultSubject: "huglo:user:invoke-user",
    });
    const port = 9600 + Math.floor(Math.random() * 1000);

    const invokeMod = new Module({
      id: "invoke-config-module",
      name: "Invoke Config",
      description: "Config invoke test",
      version: "1.0.0",
      keyPair: holderKeys,
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

    const InputSchema = z.object({
      context: z.object({
        configInstanceId: z.string().optional(),
      }),
    });

    invokeMod.config({
      schema: z.object({ label: z.string() }),
      fields: { label: "userEntered" },
    });

    invokeMod.scope("run:check", {
      description: "Uses config at invoke",
      input: InputSchema,
      output: z.object({ hasConfig: z.boolean(), label: z.string().optional() }),
      handler: async (ctx) => ({
        hasConfig: ctx.config !== undefined,
        label: ctx.config?.values.label as string | undefined,
      }),
    });

    function buildGrant(subject = "huglo:user:invoke-user"): SignedGrant {
      const grant = {
        grant_id: "g-invoke-config",
        holder: "invoke-config-module",
        scope: "run:check",
        subject,
        requester: "foaf",
        author: subject,
        constraints: {},
        issued_at: new Date(Date.now() - 60_000).toISOString(),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      };
      return { grant, signature: signObject(grant, authorKeys.privateKey) };
    }

    function buildInvoke(grant: SignedGrant, configInstanceId?: string) {
      const payload = {
        context: configInstanceId ? { configInstanceId } : {},
      };
      const req = {
        payload,
        grant,
        scope: "run:check",
        timestamp: new Date().toISOString(),
        nonce: crypto.randomUUID(),
        requesterSignature: "",
      };
      req.requesterSignature = signObject(sig2Payload(req), requesterKeys.privateKey);
      return req;
    }

    beforeAll(async () => {
      directory.registerModule(
        "invoke-config-module",
        `http://127.0.0.1:${port}`,
        holderKeys.publicKey,
        holderKeys.publicKeyBase64,
      );
      directory.registerModule(
        "foaf",
        "http://127.0.0.1:59998",
        requesterKeys.publicKey,
        requesterKeys.publicKeyBase64,
      );
      directory.registerUser("invoke-user", authorKeys.publicKey);
      await invokeMod.listen(port, "127.0.0.1");
    });

    afterAll(() => {
      invokeMod.close();
    });

    it("allows invoke when directorySubject matches grant subject and injects ctx.config", async () => {
      await configStore.set({
        instanceId: "inst-match",
        subject: "huglo:user:invoke-user",
        directorySubject: "huglo:user:invoke-user",
        values: { label: "matched" },
      });

      const res = await invokeMod.getApp().request("/invoke/run:check", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-Id": crypto.randomUUID() },
        body: JSON.stringify(buildInvoke(buildGrant(), "inst-match")),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { result: { hasConfig: boolean; label: string } };
      expect(body.result.hasConfig).toBe(true);
      expect(body.result.label).toBe("matched");
    });

    it("rejects invoke when directorySubject mismatches grant subject", async () => {
      await configStore.set({
        instanceId: "inst-mismatch",
        subject: "huglo:user:invoke-user",
        directorySubject: "huglo:user:someone-else",
        values: { label: "stolen" },
      });

      const res = await invokeMod.getApp().request("/invoke/run:check", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-Id": crypto.randomUUID() },
        body: JSON.stringify(buildInvoke(buildGrant(), "inst-mismatch")),
      });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: { code: string } };
      expect(body.error.code).toBe("config_subject_mismatch");
    });

    it("rejects invoke when configInstanceId is missing", async () => {
      const res = await invokeMod.getApp().request("/invoke/run:check", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-Id": crypto.randomUUID() },
        body: JSON.stringify(buildInvoke(buildGrant())),
      });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: { code: string } };
      expect(body.error.code).toBe("config_instance_required");
    });

    it("rejects invoke when config instance is missing", async () => {
      const res = await invokeMod.getApp().request("/invoke/run:check", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Request-Id": crypto.randomUUID() },
        body: JSON.stringify(buildInvoke(buildGrant(), "inst-missing")),
      });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error: { code: string } };
      expect(body.error.code).toBe("config_not_found");
    });
  });

  describe("customConfig mutual exclusion", () => {
    const keys = generateKeyPair();

    it("config() then customConfig() throws", () => {
      const mod = new Module({
        id: "excl-1",
        name: "Excl",
        description: "d",
        version: "1.0.0",
        keyPair: keys,
      });
      mod.config({
        schema: z.object({ label: z.string() }),
        fields: { label: "userEntered" },
      });
      expect(() => mod.customConfig(new Hono())).toThrow(
        /cannot be combined with config\(\)/,
      );
    });

    it("customConfig() then config() throws", () => {
      const mod = new Module({
        id: "excl-2",
        name: "Excl",
        description: "d",
        version: "1.0.0",
        keyPair: keys,
      });
      mod.customConfig(new Hono());
      expect(() =>
        mod.config({
          schema: z.object({ label: z.string() }),
          fields: { label: "userEntered" },
        }),
      ).toThrow(/cannot be combined with customConfig\(\)/);
    });
  });
});

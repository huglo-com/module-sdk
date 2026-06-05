import { describe, it, expect, beforeEach, vi } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { HttpDirectoryClient, InMemoryDirectoryClient } from "../src/directory.js";
import { InMemoryGrantStore } from "../src/store.js";
import { Module, exchangeAndSaveGrants } from "../src/module.js";
import {
  DEFAULT_CALLBACK_PATH,
  DEFAULT_GRANT_INIT_PATH,
  grantInitPath,
} from "../src/server.js";
import type { SignedGrant } from "../src/envelope.js";
import type { GrantCallbackErrorContext } from "../src/grant-callback.js";

describe("grant callback route", () => {
  const keys = generateKeyPair();
  const authorKeys = generateKeyPair();
  let directory: InMemoryDirectoryClient;
  let grantStore: InMemoryGrantStore;

  function buildGrant(overrides: Partial<SignedGrant["grant"]> = {}): SignedGrant {
    const grant = {
      grant_id: "g-callback-001",
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

  function createModule(
    withStore = true,
    overrides: Partial<ConstructorParameters<typeof Module>[0]> = {},
  ): Module {
    return new Module({
      id: "trovi-test",
      name: "Trovi",
      description: "Test",
      version: "1.0.0",
      keyPair: keys,
      huglo: { directoryUrl: "http://unused" },
      directory,
      endpoint: "https://trovi.example",
      ...(withStore ? { grantStore } : {}),
      ...overrides,
    });
  }

  beforeEach(() => {
    directory = new InMemoryDirectoryClient();
    grantStore = new InMemoryGrantStore();
  });

  it("exchanges code, saves grants, and returns auto-close HTML", async () => {
    const grants = [buildGrant()];
    directory.setExchangeGrants("code-abc", grants);

    const module = createModule();
    const app = module.getApp();
    const res = await app.request(`${DEFAULT_CALLBACK_PATH}?code=code-abc`);

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("huglo:grant:authorized");
    expect(html).toContain("window.opener");
    expect(html).toContain("Authorization complete");

    const stored = await grantStore.find({
      subject: "huglo:user:user-1",
      holder: "da",
      scope: "invoice:write",
      requester: "trovi-test",
    });
    expect(stored).toEqual(grants[0]);
  });

  it("returns 400 when code is missing", async () => {
    const module = createModule();
    const app = module.getApp();
    const res = await app.request(DEFAULT_CALLBACK_PATH);

    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Missing authorization code");
    expect(grantStore.size()).toBe(0);
  });

  it("returns 502 when exchange fails and does not save", async () => {
    const module = createModule();
    const app = module.getApp();
    const res = await app.request(`${DEFAULT_CALLBACK_PATH}?code=unknown`);

    expect(res.status).toBe(502);
    expect(await res.text()).toContain("Could not complete authorization");
    expect(grantStore.size()).toBe(0);
  });

  it("returns 502 when directory is unreachable during exchange", async () => {
    const failingDirectory = new HttpDirectoryClient({
      directoryUrl: "https://directory.example",
      fetch: vi.fn().mockRejectedValue(new Error("network down")),
    });
    const onGrantCallbackError = vi.fn();
    const module = createModule(true, {
      directory: failingDirectory,
      onGrantCallbackError,
    });
    const app = module.getApp();
    const res = await app.request(`${DEFAULT_CALLBACK_PATH}?code=code-abc`);

    expect(res.status).toBe(502);
    expect(await res.text()).toContain("Could not complete authorization");
    expect(grantStore.size()).toBe(0);
    expect(onGrantCallbackError).toHaveBeenCalledWith(
      expect.objectContaining({
        stage: "exchange",
        code: "code-abc",
        error: expect.objectContaining({ code: "directory_unreachable" }),
      }),
    );
  });

  it("onGrantCallbackError invoked when grant save fails with stage save", async () => {
    const grants = [buildGrant()];
    directory.setExchangeGrants("code-save-fail", grants);
    const onGrantCallbackError = vi.fn();

    const failingStore = {
      save: vi.fn().mockRejectedValue(new Error("db down")),
      find: grantStore.find.bind(grantStore),
      list: grantStore.list.bind(grantStore),
      delete: grantStore.delete.bind(grantStore),
    };

    const module = createModule(true, { onGrantCallbackError, grantStore: failingStore });
    const app = module.getApp();
    const res = await app.request(`${DEFAULT_CALLBACK_PATH}?code=code-save-fail`);

    expect(res.status).toBe(502);
    expect(onGrantCallbackError).toHaveBeenCalledWith(
      expect.objectContaining({ stage: "save" }),
    );
  });

  it("does not register callback route without grantStore or onGrantCallback", async () => {
    const module = createModule(false);
    const app = module.getApp();
    const res = await app.request(`${DEFAULT_CALLBACK_PATH}?code=code-abc`);

    expect(res.status).toBe(404);
  });

  it("onGrantCallback returning string uses custom HTML", async () => {
    const grants = [buildGrant()];
    directory.setExchangeGrants("code-custom", grants);

    const module = createModule(true, {
      onGrantCallback: () => "<html><body>popup</body></html>",
    });
    const res = await module.getApp().request(`${DEFAULT_CALLBACK_PATH}?code=code-custom`);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("<html><body>popup</body></html>");
  });

  it("onGrantCallback returning Response uses that response", async () => {
    const grants = [buildGrant()];
    directory.setExchangeGrants("code-resp", grants);

    const module = createModule(true, {
      onGrantCallback: ({ c }) =>
        c.json({ ok: true }, 201),
    });
    const res = await module.getApp().request(`${DEFAULT_CALLBACK_PATH}?code=code-resp`);

    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ ok: true });
  });

  it("onGrantCallback returning void falls back to default success page", async () => {
    const grants = [buildGrant()];
    directory.setExchangeGrants("code-void", grants);

    const module = createModule(true, {
      onGrantCallback: () => undefined,
    });
    const res = await module.getApp().request(`${DEFAULT_CALLBACK_PATH}?code=code-void`);

    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("huglo:grant:authorized");
    expect(html).toContain("window.opener");
  });

  it("onGrantCallback receives exchanged grants and code", async () => {
    const grants = [buildGrant({ grant_id: "g-hook-1" })];
    directory.setExchangeGrants("code-hook", grants);
    const hook = vi.fn(() => "<html>ok</html>");

    const module = createModule(true, { onGrantCallback: hook });
    await module.getApp().request(`${DEFAULT_CALLBACK_PATH}?code=code-hook`);

    expect(hook).toHaveBeenCalledOnce();
    expect(hook.mock.calls[0]![0].code).toBe("code-hook");
    expect(hook.mock.calls[0]![0].grants).toEqual(grants);
  });

  it("registers callback with onGrantCallback only and skips save", async () => {
    const grants = [buildGrant()];
    directory.setExchangeGrants("code-no-store", grants);
    const hook = vi.fn(() => "<html>saved elsewhere</html>");

    const module = createModule(false, { onGrantCallback: hook });
    const res = await module.getApp().request(`${DEFAULT_CALLBACK_PATH}?code=code-no-store`);

    expect(res.status).toBe(200);
    expect(await res.text()).toBe("<html>saved elsewhere</html>");
    expect(grantStore.size()).toBe(0);
    expect(hook.mock.calls[0]![0].grants).toEqual(grants);
  });

  it("callbackMiddleware runs on the callback route", async () => {
    const grants = [buildGrant()];
    directory.setExchangeGrants("code-mw", grants);

    const module = createModule(true, {
      callbackMiddleware: async (c, next) => {
        await next();
        c.res.headers.set("X-Callback-Middleware", "1");
      },
    });
    const res = await module.getApp().request(`${DEFAULT_CALLBACK_PATH}?code=code-mw`);

    expect(res.status).toBe(200);
    expect(res.headers.get("X-Callback-Middleware")).toBe("1");
  });

  it("onGrantCallbackError invoked on missing code with stage missing_code", async () => {
    const onGrantCallbackError = vi.fn(
      ({ stage }: GrantCallbackErrorContext) => `<html>${stage}</html>`,
    );
    const module = createModule(true, { onGrantCallbackError });
    const res = await module.getApp().request(DEFAULT_CALLBACK_PATH);

    expect(res.status).toBe(400);
    expect(await res.text()).toBe("<html>missing_code</html>");
    expect(onGrantCallbackError).toHaveBeenCalledWith(
      expect.objectContaining({ stage: "missing_code" }),
    );
  });

  it("onGrantCallbackError invoked on exchange failure with stage exchange", async () => {
    const onGrantCallbackError = vi.fn(
      ({ stage }: GrantCallbackErrorContext) => `<html>${stage}</html>`,
    );
    const module = createModule(true, { onGrantCallbackError });
    const res = await module.getApp().request(`${DEFAULT_CALLBACK_PATH}?code=bad-code`);

    expect(res.status).toBe(502);
    expect(await res.text()).toBe("<html>exchange</html>");
    expect(onGrantCallbackError).toHaveBeenCalledWith(
      expect.objectContaining({ stage: "exchange", code: "bad-code" }),
    );
  });

  it("onGrantCallback throw invokes onGrantCallbackError with stage render", async () => {
    const grants = [buildGrant()];
    directory.setExchangeGrants("code-render-err", grants);
    const boom = new Error("render failed");
    const onGrantCallbackError = vi.fn(
      ({ stage }: GrantCallbackErrorContext) => `<html>${stage}</html>`,
    );

    const module = createModule(true, {
      onGrantCallback: () => {
        throw boom;
      },
      onGrantCallbackError,
    });
    const res = await module.getApp().request(`${DEFAULT_CALLBACK_PATH}?code=code-render-err`);

    expect(res.status).toBe(500);
    expect(await res.text()).toBe("<html>render</html>");
    expect(onGrantCallbackError).toHaveBeenCalledWith(
      expect.objectContaining({ stage: "render", error: boom, code: "code-render-err" }),
    );
  });

  it("getCallbackUrl returns endpoint plus callback path", () => {
    const module = createModule();
    expect(module.getCallbackUrl()).toBe("https://trovi.example/grant/callback");
  });
});

describe("grant init route", () => {
  const keys = generateKeyPair();
  const authorKeys = generateKeyPair();
  let directory: InMemoryDirectoryClient;
  let grantStore: InMemoryGrantStore;

  const sampleInviteResponse = {
    invite: {
      id: "inv-init-1",
      requesterModuleId: "trovi-test",
      callbackUrl: "https://trovi.example/grant/callback",
      constraints: {},
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      createdByUserId: "user-1",
      active: true,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      scopes: [
        {
          id: "scope-1",
          inviteId: "inv-init-1",
          holder: "da",
          scope: "invoice:write",
        },
      ],
    },
    inviteUrl: "https://account.huglo.test/invite/init-test",
  };

  function buildGrant(overrides: Partial<{ grant_id: string }> = {}) {
    const grant = {
      grant_id: overrides.grant_id ?? "g-init-001",
      holder: "da",
      scope: "invoice:write",
      subject: "huglo:user:user-1",
      requester: "trovi-test",
      author: "huglo:user:user-1",
      constraints: {},
      issued_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
    };
    return { grant, signature: signObject(grant, authorKeys.privateKey) };
  }

  function createModule(
    withStore = true,
    overrides: Partial<ConstructorParameters<typeof Module>[0]> = {},
  ): Module {
    return new Module({
      id: "trovi-test",
      name: "Trovi",
      description: "Test",
      version: "1.0.0",
      keyPair: keys,
      huglo: { directoryUrl: "http://unused" },
      directory,
      endpoint: "https://trovi.example",
      ...(withStore ? { grantStore } : {}),
      ...overrides,
    });
  }

  beforeEach(() => {
    directory = new InMemoryDirectoryClient();
    grantStore = new InMemoryGrantStore();
    directory.setInviteResponse("trovi-test", sampleInviteResponse);
  });

  it("grantInitPath maps callback path to init path", () => {
    expect(grantInitPath("/grant/callback")).toBe("/grant/init");
    expect(grantInitPath("/oauth/grant/callback")).toBe("/oauth/grant/init");
    expect(grantInitPath("/custom")).toBe(DEFAULT_GRANT_INIT_PATH);
  });

  it("does not register init without grantStore", async () => {
    const module = createModule(false);
    const res = await module.getApp().request(DEFAULT_GRANT_INIT_PATH);
    expect(res.status).toBe(404);
  });

  it("returns 400 when query params are missing", async () => {
    const module = createModule();
    const res = await module.getApp().request(DEFAULT_GRANT_INIT_PATH);
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("Missing subject");
  });

  it("returns notify HTML when grant already exists", async () => {
    await grantStore.save(buildGrant());
    const module = createModule();
    const res = await module.getApp().request(
      `${DEFAULT_GRANT_INIT_PATH}?subject=huglo:user:user-1&holder=da&scope=invoice:write`,
    );
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("huglo:grant:authorized");
    expect(html).toContain("huglo:user:user-1");
    expect(html).toContain("window.opener");
  });

  it("redirects to inviteUrl when grant is missing", async () => {
    let capturedModuleId: string | undefined;
    const originalCreateInvite = directory.createInvite.bind(directory);
    directory.createInvite = async (moduleId, signed) => {
      capturedModuleId = moduleId;
      expect(signed.payload).toMatchObject({
        moduleId: "trovi-test",
        callbackUrl: "https://trovi.example/grant/callback",
        scopes: [{ holder: "da", scope: "invoice:write" }],
      });
      return originalCreateInvite(moduleId, signed);
    };

    const module = createModule();
    const res = await module.getApp().request(
      `${DEFAULT_GRANT_INIT_PATH}?subject=huglo:user:user-1&holder=da&scope=invoice:write`,
      { redirect: "manual" },
    );
    expect(res.status).toBe(302);
    expect(res.headers.get("Location")).toBe(sampleInviteResponse.inviteUrl);
    expect(capturedModuleId).toBe("trovi-test");
  });

  it("returns 503 when endpoint is missing and grant is missing", async () => {
    const module = createModule(true, { endpoint: undefined });
    const res = await module.getApp().request(
      `${DEFAULT_GRANT_INIT_PATH}?subject=huglo:user:user-1&holder=da&scope=invoice:write`,
    );
    expect(res.status).toBe(503);
    expect(await res.text()).toContain("endpoint not configured");
  });

  it("registers init under custom callback path prefix", async () => {
    const module = createModule(true, {
      callbackPath: "/oauth/grant/callback",
    });
    const initPath = grantInitPath("/oauth/grant/callback");
    const res = await module.getApp().request(
      `${initPath}?subject=huglo:user:user-1&holder=da&scope=invoice:write`,
      { redirect: "manual" },
    );
    expect(res.status).toBe(302);
    expect(initPath).toBe("/oauth/grant/init");
  });
});

describe("exchangeAndSaveGrants", () => {
  const authorKeys = generateKeyPair();

  it("exchanges code then saves each grant", async () => {
    const directory = new InMemoryDirectoryClient();
    const store = new InMemoryGrantStore();
    const grant: SignedGrant = {
      grant: {
        grant_id: "g-exchange-1",
        holder: "da",
        scope: "invoice:write",
        subject: "huglo:user:alice",
        requester: "trovi",
        author: "huglo:user:alice",
        constraints: {},
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      },
      signature: signObject(
        {
          grant_id: "g-exchange-1",
          holder: "da",
          scope: "invoice:write",
          subject: "huglo:user:alice",
          requester: "trovi",
          author: "huglo:user:alice",
          constraints: {},
          issued_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        },
        authorKeys.privateKey,
      ),
    };
    directory.setExchangeGrants("code-save", [grant]);

    const grants = await exchangeAndSaveGrants(directory, store, "code-save");

    expect(grants).toEqual([grant]);
    expect(
      await store.find({
        subject: "huglo:user:alice",
        holder: "da",
        scope: "invoice:write",
        requester: "trovi",
      }),
    ).toEqual(grant);
  });

  it("propagates directory_unreachable without saving grants", async () => {
    const directory = new HttpDirectoryClient({
      directoryUrl: "https://directory.example",
      fetch: vi.fn().mockRejectedValue(new Error("network down")),
    });
    const store = new InMemoryGrantStore();

    await expect(exchangeAndSaveGrants(directory, store, "code-save")).rejects.toMatchObject({
      code: "directory_unreachable",
    });
    expect(store.size()).toBe(0);
  });
});

describe("InMemoryGrantStore", () => {
  const authorKeys = generateKeyPair();

  it("find, list, and delete grants", async () => {
    const store = new InMemoryGrantStore();
    const grant: SignedGrant = {
      grant: {
        grant_id: "g-1",
        holder: "da",
        scope: "invoice:write",
        subject: "huglo:user:alice",
        requester: "trovi",
        author: "huglo:user:alice",
        constraints: {},
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      },
      signature: signObject(
        {
          grant_id: "g-1",
          holder: "da",
          scope: "invoice:write",
          subject: "huglo:user:alice",
          requester: "trovi",
          author: "huglo:user:alice",
          constraints: {},
          issued_at: new Date().toISOString(),
          expires_at: new Date(Date.now() + 3600_000).toISOString(),
        },
        authorKeys.privateKey,
      ),
    };

    await store.save(grant);
    expect(
      await store.find({
        subject: "huglo:user:alice",
        holder: "da",
        scope: "invoice:write",
        requester: "trovi",
      }),
    ).toEqual(grant);

    expect(await store.list({ subject: "huglo:user:alice" })).toEqual([grant]);
    await store.delete("g-1");
    expect(store.size()).toBe(0);
  });
});

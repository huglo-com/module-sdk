import { describe, it, expect, beforeEach, vi } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import { InMemoryGrantStore } from "../src/store.js";
import { Module, exchangeAndSaveGrants } from "../src/module.js";
import { DEFAULT_CALLBACK_PATH } from "../src/server.js";
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
    expect(html).toContain("window.close");
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
    expect(html).toContain("window.close");
    expect(html).toContain("Authorization complete");
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

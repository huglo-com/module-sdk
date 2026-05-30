import { describe, it, expect, beforeEach } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import { InMemoryGrantStore } from "../src/store.js";
import { Module } from "../src/module.js";
import { DEFAULT_CALLBACK_PATH } from "../src/server.js";
import type { SignedGrant } from "../src/envelope.js";

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

  function createModule(withStore = true): Module {
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

  it("does not register callback route without grantStore", async () => {
    const module = createModule(false);
    const app = module.getApp();
    const res = await app.request(`${DEFAULT_CALLBACK_PATH}?code=code-abc`);

    expect(res.status).toBe(404);
  });

  it("getCallbackUrl returns endpoint plus callback path", () => {
    const module = createModule();
    expect(module.getCallbackUrl()).toBe("https://trovi.example/grant/callback");
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

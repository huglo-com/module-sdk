import { describe, it, expect, vi, afterEach } from "vitest";
import { InMemoryConfigStore } from "../src/config-store.js";
import { InMemoryFileStore } from "../src/file-store.js";
import { InMemoryGrantStore } from "../src/store.js";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import type { SignedGrant } from "../src/envelope.js";

describe("store unit", () => {
  describe("InMemoryConfigStore", () => {
    it("delete removes instance from listBySubject", async () => {
      const store = new InMemoryConfigStore();
      await store.set({
        instanceId: "inst-1",
        subject: "huglo:user:a",
        values: { label: "A" },
      });
      expect(store.size()).toBe(1);

      await store.delete("inst-1");
      expect(store.size()).toBe(0);
      expect(await store.listBySubject("huglo:user:a")).toEqual([]);
    });

    it("clear removes all configs", async () => {
      const store = new InMemoryConfigStore();
      await store.set({
        instanceId: "inst-1",
        subject: "huglo:user:a",
        values: {},
      });
      store.clear();
      expect(store.size()).toBe(0);
    });
  });

  describe("InMemoryFileStore", () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    it("delete removes stored file", async () => {
      const store = new InMemoryFileStore();
      await store.put({
        token: "tok-1",
        body: new Uint8Array([1]),
        content_type: "text/plain",
        filename: "a.txt",
        size: 1,
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
      });
      await store.delete("tok-1");
      expect(await store.get("tok-1")).toBeNull();
      expect(store.size()).toBe(0);
    });

    it("purgeExpired removes expired files on interval", async () => {
      vi.useFakeTimers();
      const store = new InMemoryFileStore();
      await store.put({
        token: "expired",
        body: new Uint8Array([1]),
        content_type: "text/plain",
        filename: "a.txt",
        size: 1,
        expires_at: new Date(Date.now() + 1000).toISOString(),
      });

      vi.advanceTimersByTime(61_000);
      expect(store.size()).toBe(0);
    });
  });

  describe("InMemoryGrantStore", () => {
    const authorKeys = generateKeyPair();

    function buildGrant(overrides: Partial<SignedGrant["grant"]> = {}): SignedGrant {
      const grant = {
        grant_id: "g-store-1",
        holder: "holder",
        scope: "scope:read",
        subject: "huglo:user:alice",
        requester: "requester",
        author: "huglo:user:alice",
        constraints: {},
        issued_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 3600_000).toISOString(),
        ...overrides,
      };
      return { grant, signature: signObject(grant, authorKeys.privateKey) };
    }

    it("find returns null when no matching grant", async () => {
      const store = new InMemoryGrantStore();
      expect(
        await store.find({
          subject: "huglo:user:alice",
          holder: "holder",
          scope: "scope:read",
          requester: "requester",
        }),
      ).toBeNull();
    });

    it("list without filter returns all grants", async () => {
      const store = new InMemoryGrantStore();
      const g1 = buildGrant({ grant_id: "g-1", subject: "huglo:user:a" });
      const g2 = buildGrant({ grant_id: "g-2", subject: "huglo:user:b" });
      await store.save(g1);
      await store.save(g2);

      const all = await store.list();
      expect(all).toHaveLength(2);
    });

    it("clear removes all grants", async () => {
      const store = new InMemoryGrantStore();
      await store.save(buildGrant());
      store.clear();
      expect(store.size()).toBe(0);
    });
  });
});

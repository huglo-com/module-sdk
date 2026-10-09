import { describe, it, expect, vi } from "vitest";
import { generateKeyPair } from "../src/keys.js";
import { HttpDirectoryClient, InMemoryDirectoryClient } from "../src/directory.js";
import { ModuleError } from "../src/errors.js";

describe("directory unit", () => {
  describe("InMemoryDirectoryClient errors", () => {
    it("getModuleKey throws module_not_found", async () => {
      const directory = new InMemoryDirectoryClient();
      await expect(directory.getModuleKey("missing")).rejects.toMatchObject({
        code: "module_not_found",
      });
    });

    it("getEndpoint throws module_not_found", async () => {
      const directory = new InMemoryDirectoryClient();
      await expect(directory.getEndpoint("missing")).rejects.toMatchObject({
        code: "module_not_found",
      });
    });

    it("getSubjectKey throws subject_not_found for missing user subject", async () => {
      const directory = new InMemoryDirectoryClient();
      await expect(directory.getSubjectKey("huglo:user:missing")).rejects.toMatchObject({
        code: "subject_not_found",
      });
    });

    it("getSubjectKey throws subject_not_found", async () => {
      const directory = new InMemoryDirectoryClient();
      await expect(directory.getSubjectKey("huglo:agent:missing")).rejects.toMatchObject({
        code: "subject_not_found",
      });
    });

    it("resolves user and agent subjects independently", async () => {
      const userKeys = generateKeyPair();
      const agentKeys = generateKeyPair();
      const directory = new InMemoryDirectoryClient();
      directory.registerUser("huglo:user:agt_1", userKeys.publicKey);
      directory.registerSubject("huglo:agent:agt_1", agentKeys.publicKey);

      await expect(directory.getSubjectKey("huglo:agent:agt_1")).resolves.toBe(agentKeys.publicKey);
      await expect(directory.getSubjectKey("huglo:user:agt_1")).resolves.toBe(userKeys.publicKey);
    });

    it("createInvite throws invite_not_configured", async () => {
      const directory = new InMemoryDirectoryClient();
      await expect(
        directory.createInvite("mod-1", {} as never),
      ).rejects.toMatchObject({ code: "invite_not_configured" });
    });

    it("exchangeGrants throws code_not_found", async () => {
      const directory = new InMemoryDirectoryClient();
      await expect(directory.exchangeGrants("missing-code")).rejects.toMatchObject({
        code: "code_not_found",
      });
    });

    it("registerUser stores the full huglo:user subject", async () => {
      const keys = generateKeyPair();
      const directory = new InMemoryDirectoryClient();
      directory.registerUser("huglo:user:bare-id", keys.publicKey);

      await expect(directory.getSubjectKey("huglo:user:bare-id")).resolves.toBe(keys.publicKey);
    });
  });

  describe("HttpDirectoryClient", () => {
    const keys = generateKeyPair();

    it("getSubjectKey fetches GET /directory/subjects/{encoded-subject}/key", async () => {
      const subject = "huglo:agent:agt_1";
      const fetchFn = vi.fn().mockResolvedValue(
        Response.json(
          { subject, publicKey: keys.publicKeyBase64 },
          { status: 200 },
        ),
      );
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await client.getSubjectKey(subject);
      expect(fetchFn).toHaveBeenCalledTimes(1);
      expect(String(fetchFn.mock.calls[0]?.[0])).toBe(
        `https://directory.example/directory/subjects/${encodeURIComponent(subject)}/key`,
      );
    });

    it("getSubjectKey fails closed when the directory binds a different subject", async () => {
      const fetchFn = vi.fn().mockResolvedValue(
        Response.json(
          { subject: "huglo:user:alice", publicKey: keys.publicKeyBase64 },
          { status: 200 },
        ),
      );
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await expect(client.getSubjectKey("huglo:agent:agt_1")).rejects.toMatchObject({
        code: "invalid_response",
        message: "Directory subject key does not match requested subject",
      });
    });

    it("getSubjectKey throws invalid_response when body is not JSON", async () => {
      const fetchFn = vi.fn().mockResolvedValue(
        new Response("not json", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        }),
      );
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await expect(client.getSubjectKey("huglo:user:alice")).rejects.toMatchObject({
        code: "invalid_response",
        message: "Directory returned non-JSON response",
      });
    });

    it("getSubjectKey fails closed on 404", async () => {
      const fetchFn = vi.fn().mockResolvedValue(new Response(null, { status: 404 }));
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await expect(client.getSubjectKey("huglo:agent:agt_1")).rejects.toMatchObject({
        code: "subject_not_found",
      });
    });

    it("getSubjectKey rejects invalid namespace before fetch", async () => {
      const fetchFn = vi.fn();
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await expect(client.getSubjectKey("huglo:USR:abc")).rejects.toMatchObject({
        code: "invalid_subject",
      });
      expect(fetchFn).not.toHaveBeenCalled();
    });

    it("getSubjectKey rejects wrong-length module publicKey from directory", async () => {
      const shortKey = Buffer.alloc(31).toString("base64");
      const fetchFn = vi.fn().mockResolvedValue(
        Response.json(
          {
            publicKey: shortKey,
            endpoint: "https://module.example",
          },
          { status: 200 },
        ),
      );
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await expect(client.getModuleKey("mod-1")).rejects.toMatchObject({
        code: "invalid_response",
      });
    });

    it("getSubjectKey rejects wrong-length subject publicKey from directory", async () => {
      const longKey = Buffer.alloc(64).toString("base64");
      const subject = "huglo:user:alice";
      const fetchFn = vi.fn().mockResolvedValue(
        Response.json({ subject, publicKey: longKey }, { status: 200 }),
      );
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await expect(client.getSubjectKey(subject)).rejects.toMatchObject({
        code: "invalid_response",
      });
    });

    it("subject key cache expires after TTL", async () => {
      const subject = "huglo:user:alice";
      const fetchFn = vi.fn().mockImplementation(async () =>
        Response.json({ subject, publicKey: keys.publicKeyBase64 }, { status: 200 }),
      );
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        ttlMs: 50,
        fetch: fetchFn,
      });

      await client.getSubjectKey(subject);
      await new Promise((resolve) => setTimeout(resolve, 60));
      await client.getSubjectKey(subject);
      expect(fetchFn).toHaveBeenCalledTimes(2);
    });

    it("caches module key across repeated getModuleKey calls", async () => {
      const fetchFn = vi.fn().mockResolvedValue(
        Response.json(
          {
            publicKey: keys.publicKeyBase64,
            endpoint: "https://module.example",
          },
          { status: 200 },
        ),
      );

      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await client.getModuleKey("mod-1");
      await client.getModuleKey("mod-1");
      expect(fetchFn).toHaveBeenCalledTimes(1);
    });

    it("throws directory_unreachable when fetch fails", async () => {
      const fetchFn = vi.fn().mockRejectedValue(new Error("network down"));
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await expect(client.getModuleKey("mod-1")).rejects.toBeInstanceOf(ModuleError);
      await expect(client.getModuleKey("mod-1")).rejects.toMatchObject({
        code: "directory_unreachable",
      });
    });

    it("throws directory_error when response is not ok", async () => {
      const fetchFn = vi.fn().mockResolvedValue(new Response(null, { status: 503 }));
      const client = new HttpDirectoryClient({
        directoryUrl: "https://directory.example",
        fetch: fetchFn,
      });

      await expect(client.getModuleKey("mod-1")).rejects.toMatchObject({
        code: "directory_error",
      });
    });

    describe("directory unavailability on every method", () => {
      const baseUrl = "https://directory.example";
      const signedInvite = {
        payload: {
          moduleId: "mod-1",
          callbackUrl: "https://example/cb",
          scopes: [{ holder: "da", scope: "invoice:write" }],
          constraints: {},
          iat: "2026-01-01T00:00:00.000Z",
          nonce: "00000000-0000-4000-8000-000000000001",
        },
        signature: `ed25519:${keys.publicKeyBase64}`,
      };

      type DirectoryCall = (client: HttpDirectoryClient) => Promise<unknown>;

      const directoryCalls: [string, DirectoryCall][] = [
        ["getModuleKey", (c) => c.getModuleKey("mod-1")],
        ["getSubjectKey", (c) => c.getSubjectKey("huglo:user:user-1")],
        ["getSubjectKey (agent)", (c) => c.getSubjectKey("huglo:agent:agt_1")],
        ["getEndpoint", (c) => c.getEndpoint("mod-1")],
        ["isRevoked", (c) => c.isRevoked("g-1")],
        ["createInvite", (c) => c.createInvite("mod-1", signedInvite)],
        ["exchangeGrants", (c) => c.exchangeGrants("code-1")],
      ];

      it.each(directoryCalls)(
        "%s throws directory_unreachable when fetch fails",
        async (_name, invoke) => {
          const fetchFn = vi.fn().mockRejectedValue(new Error("network down"));
          const client = new HttpDirectoryClient({ directoryUrl: baseUrl, fetch: fetchFn });

          await expect(invoke(client)).rejects.toBeInstanceOf(ModuleError);
          await expect(invoke(client)).rejects.toMatchObject({
            code: "directory_unreachable",
          });
        },
      );

      it.each(directoryCalls)(
        "%s throws directory_error when response is not ok",
        async (_name, invoke) => {
          const fetchFn = vi.fn().mockResolvedValue(new Response(null, { status: 503 }));
          const client = new HttpDirectoryClient({ directoryUrl: baseUrl, fetch: fetchFn });

          await expect(invoke(client)).rejects.toMatchObject({
            code: "directory_error",
          });
        },
      );

      it("createInvite throws invalid_response on non-JSON body", async () => {
        const fetchFn = vi.fn().mockResolvedValue(
          new Response("not json", {
            status: 200,
            headers: { "Content-Type": "text/plain" },
          }),
        );
        const client = new HttpDirectoryClient({ directoryUrl: baseUrl, fetch: fetchFn });

        await expect(client.createInvite("mod-1", signedInvite)).rejects.toMatchObject({
          code: "invalid_response",
          message: "Directory returned non-JSON response",
        });
      });

      it("createInvite throws invalid_response on malformed JSON body", async () => {
        const fetchFn = vi.fn().mockResolvedValue(
          Response.json({ notAnInvite: true }, { status: 200 }),
        );
        const client = new HttpDirectoryClient({ directoryUrl: baseUrl, fetch: fetchFn });

        await expect(client.createInvite("mod-1", signedInvite)).rejects.toMatchObject({
          code: "invalid_response",
          message: "Directory response is malformed",
        });
      });

      it("exchangeGrants throws invalid_response on non-JSON body", async () => {
        const fetchFn = vi.fn().mockResolvedValue(
          new Response("not json", {
            status: 200,
            headers: { "Content-Type": "text/plain" },
          }),
        );
        const client = new HttpDirectoryClient({ directoryUrl: baseUrl, fetch: fetchFn });

        await expect(client.exchangeGrants("code-1")).rejects.toMatchObject({
          code: "invalid_response",
          message: "Directory returned non-JSON response",
        });
      });
    });
  });
});

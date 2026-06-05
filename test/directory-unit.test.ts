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

    it("getUserKey throws user_not_found", async () => {
      const directory = new InMemoryDirectoryClient();
      await expect(directory.getUserKey("huglo:user:missing")).rejects.toMatchObject({
        code: "user_not_found",
      });
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

    it("registerUser strips huglo:user: prefix", async () => {
      const keys = generateKeyPair();
      const directory = new InMemoryDirectoryClient();
      directory.registerUser("huglo:user:bare-id", keys.publicKey);

      await expect(directory.getUserKey("bare-id")).resolves.toBeDefined();
      await expect(directory.getUserKey("huglo:user:bare-id")).resolves.toBeDefined();
    });
  });

  describe("HttpDirectoryClient", () => {
    const keys = generateKeyPair();

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
        },
        signature: `ed25519:${keys.publicKeyBase64}`,
      };

      type DirectoryCall = (client: HttpDirectoryClient) => Promise<unknown>;

      const directoryCalls: [string, DirectoryCall][] = [
        ["getModuleKey", (c) => c.getModuleKey("mod-1")],
        ["getUserKey", (c) => c.getUserKey("user-1")],
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

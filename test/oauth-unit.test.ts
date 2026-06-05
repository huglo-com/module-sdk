import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  HttpHugloOAuthClient,
  InMemoryHugloOAuthClient,
  OAuthError,
  createConfigSession,
  createPkceCookie,
  readConfigSession,
  readPkceCookie,
  resolveOAuthOptions,
} from "../src/oauth.js";

const oauthOptions = {
  clientId: "client-id",
  clientSecret: "client-secret",
  redirectUri: "http://localhost/config/callback",
  authorizeUrl: "https://oauth.test/authorize",
  tokenUrl: "https://oauth.test/token",
  userInfoUrl: "https://oauth.test/userinfo",
};

describe("oauth unit", () => {
  describe("HttpHugloOAuthClient.exchangeCode", () => {
    it("throws OAuthError when token exchange fails", async () => {
      const fetchFn = vi.fn().mockResolvedValue(new Response(null, { status: 401 }));
      const client = new HttpHugloOAuthClient({ ...oauthOptions, fetch: fetchFn });

      await expect(client.exchangeCode("code", "verifier")).rejects.toThrow(OAuthError);
      await expect(client.exchangeCode("code", "verifier")).rejects.toThrow(/Token exchange failed/);
    });

    it("throws when token response missing access_token", async () => {
      const fetchFn = vi.fn().mockResolvedValue(
        Response.json({}, { status: 200 }),
      );
      const client = new HttpHugloOAuthClient({ ...oauthOptions, fetch: fetchFn });

      await expect(client.exchangeCode("code", "verifier")).rejects.toThrow(
        /missing access_token/,
      );
    });

    it("throws when userinfo request fails", async () => {
      const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(Response.json({ access_token: "tok" }, { status: 200 }))
        .mockResolvedValueOnce(new Response(null, { status: 500 }));

      const client = new HttpHugloOAuthClient({ ...oauthOptions, fetch: fetchFn });
      await expect(client.exchangeCode("code", "verifier")).rejects.toThrow(/User info failed/);
    });

    it("throws when userinfo missing sub", async () => {
      const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(Response.json({ access_token: "tok" }, { status: 200 }))
        .mockResolvedValueOnce(Response.json({}, { status: 200 }));

      const client = new HttpHugloOAuthClient({ ...oauthOptions, fetch: fetchFn });
      await expect(client.exchangeCode("code", "verifier")).rejects.toThrow(/missing sub/);
    });

    it("does not double-prefix huglo:user: subject", async () => {
      const fetchFn = vi
        .fn()
        .mockResolvedValueOnce(Response.json({ access_token: "tok" }, { status: 200 }))
        .mockResolvedValueOnce(
          Response.json({ sub: "huglo:user:already-prefixed" }, { status: 200 }),
        );

      const client = new HttpHugloOAuthClient({ ...oauthOptions, fetch: fetchFn });
      const result = await client.exchangeCode("code", "verifier");
      expect(result.subject).toBe("huglo:user:already-prefixed");
    });
  });

  describe("signed cookies", () => {
    const secret = "test-secret";

    it("returns null for tampered session cookie", () => {
      const cookie = createConfigSession("huglo:user:u1", secret);
      const tampered = `${cookie.slice(0, -1)}x`;
      expect(readConfigSession(tampered, secret)).toBeNull();
    });

    it("returns null for PKCE cookie with wrong secret", () => {
      const cookie = createPkceCookie("verifier", "state-1", secret);
      expect(readPkceCookie(cookie, "state-1", "wrong-secret")).toBeNull();
    });
  });

  describe("resolveOAuthOptions", () => {
    beforeEach(() => {
      vi.stubEnv("HUGLO_OAUTH_CLIENT_ID", "env-client");
      vi.stubEnv("HUGLO_OAUTH_CLIENT_SECRET", "env-secret");
      vi.stubEnv("HUGLO_OAUTH_REDIRECT_URI", "http://localhost/cb");
    });

    afterEach(() => {
      vi.unstubAllEnvs();
    });

    it("returns options from environment when partial args missing", () => {
      const resolved = resolveOAuthOptions();
      expect(resolved).toMatchObject({
        clientId: "env-client",
        clientSecret: "env-secret",
        redirectUri: "http://localhost/cb",
      });
    });

    it("returns undefined when required env vars are missing", () => {
      vi.unstubAllEnvs();
      expect(resolveOAuthOptions()).toBeUndefined();
    });
  });

  describe("InMemoryHugloOAuthClient", () => {
    it("uses setCode mapping over default subject", async () => {
      const client = new InMemoryHugloOAuthClient({ defaultSubject: "huglo:user:default" });
      client.setCode("custom-code", "huglo:user:mapped");
      const result = await client.exchangeCode("custom-code", "verifier");
      expect(result.subject).toBe("huglo:user:mapped");
    });
  });
});

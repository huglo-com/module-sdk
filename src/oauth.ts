import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

export const CONFIG_SESSION_COOKIE = "huglo_config_session";
export const OAUTH_STATE_COOKIE = "huglo_oauth_state";

export interface OAuthClientOptions {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  authorizeUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
}

export interface OAuthExchangeResult {
  subject: string;
}

export interface HugloOAuthClient {
  buildAuthorizeUrl(state: string): string;
  exchangeCode(code: string): Promise<OAuthExchangeResult>;
}

export interface HttpHugloOAuthClientOptions extends OAuthClientOptions {
  fetch?: typeof globalThis.fetch;
}

interface TokenResponse {
  access_token: string;
  token_type?: string;
}

interface UserInfoResponse {
  sub: string;
}

/**
 * HTTP-backed Huglo OAuth client for config login.
 * Separate from the federation keypair / directory client.
 */
export class HttpHugloOAuthClient implements HugloOAuthClient {
  private readonly options: HttpHugloOAuthClientOptions;
  private readonly fetchFn: typeof globalThis.fetch;

  constructor(options: HttpHugloOAuthClientOptions) {
    this.options = options;
    this.fetchFn = options.fetch ?? globalThis.fetch;
  }

  buildAuthorizeUrl(state: string): string {
    const url = new URL(this.options.authorizeUrl);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("client_id", this.options.clientId);
    url.searchParams.set("redirect_uri", this.options.redirectUri);
    url.searchParams.set("state", state);
    return url.toString();
  }

  async exchangeCode(code: string): Promise<OAuthExchangeResult> {
    const tokenBody = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: this.options.redirectUri,
      client_id: this.options.clientId,
      client_secret: this.options.clientSecret,
    });

    const tokenRes = await this.fetchFn(this.options.tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: tokenBody.toString(),
    });
    if (!tokenRes.ok) {
      throw new OAuthError(`Token exchange failed: ${tokenRes.status}`);
    }

    const tokenJson = (await tokenRes.json()) as TokenResponse;
    if (!tokenJson.access_token) {
      throw new OAuthError("Token response missing access_token");
    }

    const userRes = await this.fetchFn(this.options.userInfoUrl, {
      headers: { Authorization: `Bearer ${tokenJson.access_token}` },
    });
    if (!userRes.ok) {
      throw new OAuthError(`User info failed: ${userRes.status}`);
    }

    const userJson = (await userRes.json()) as UserInfoResponse;
    if (!userJson.sub) {
      throw new OAuthError("User info response missing sub");
    }

    const subject = userJson.sub.startsWith("huglo:user:")
      ? userJson.sub
      : `huglo:user:${userJson.sub}`;

    return { subject };
  }
}

/** In-memory OAuth client for tests. */
export class InMemoryHugloOAuthClient implements HugloOAuthClient {
  private readonly subjectsByCode = new Map<string, string>();
  private readonly defaultSubject: string;

  constructor(options: { defaultSubject?: string } = {}) {
    this.defaultSubject = options.defaultSubject ?? "huglo:user:test-user";
  }

  /** Seed a code -> subject mapping for tests. */
  setCode(code: string, subject: string): void {
    this.subjectsByCode.set(code, subject);
  }

  buildAuthorizeUrl(state: string): string {
    return `https://oauth.test/authorize?state=${encodeURIComponent(state)}`;
  }

  async exchangeCode(code: string): Promise<OAuthExchangeResult> {
    const subject = this.subjectsByCode.get(code) ?? this.defaultSubject;
    return { subject };
  }

  clear(): void {
    this.subjectsByCode.clear();
  }
}

export class OAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "OAuthError";
  }
}

interface SessionPayload {
  subject: string;
  exp: number;
}

const SESSION_TTL_MS = 24 * 60 * 60 * 1000;

function sessionSecret(clientSecret: string): string {
  return createHmac("sha256", "huglo-config-session").update(clientSecret).digest("hex");
}

function signPayload(payloadB64: string, secret: string): string {
  return createHmac("sha256", secret).update(payloadB64).digest("base64url");
}

/** Create a signed session cookie value for the authenticated config subject. */
export function createConfigSession(subject: string, clientSecret: string): string {
  const payload: SessionPayload = {
    subject,
    exp: Date.now() + SESSION_TTL_MS,
  };
  const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = signPayload(payloadB64, sessionSecret(clientSecret));
  return `${payloadB64}.${sig}`;
}

/** Read and verify a signed config session cookie. Returns subject or null. */
export function readConfigSession(
  cookieValue: string | undefined,
  clientSecret: string,
): string | null {
  if (!cookieValue) return null;

  const dot = cookieValue.lastIndexOf(".");
  if (dot === -1) return null;

  const payloadB64 = cookieValue.slice(0, dot);
  const sig = cookieValue.slice(dot + 1);
  const expected = signPayload(payloadB64, sessionSecret(clientSecret));

  try {
    const sigBuf = Buffer.from(sig, "base64url");
    const expectedBuf = Buffer.from(expected, "base64url");
    if (sigBuf.length !== expectedBuf.length || !timingSafeEqual(sigBuf, expectedBuf)) {
      return null;
    }
  } catch {
    return null;
  }

  let payload: SessionPayload;
  try {
    payload = JSON.parse(
      Buffer.from(payloadB64, "base64url").toString("utf8"),
    ) as SessionPayload;
  } catch {
    return null;
  }

  if (!payload.subject || typeof payload.exp !== "number" || Date.now() > payload.exp) {
    return null;
  }

  return payload.subject;
}

/** Generate OAuth state + store in cookie. */
export function createOAuthState(): string {
  return randomBytes(16).toString("base64url");
}

export function resolveOAuthOptions(
  partial?: Partial<OAuthClientOptions>,
): OAuthClientOptions | undefined {
  const clientId = partial?.clientId ?? process.env["HUGLO_OAUTH_CLIENT_ID"];
  const clientSecret = partial?.clientSecret ?? process.env["HUGLO_OAUTH_CLIENT_SECRET"];
  const redirectUri = partial?.redirectUri ?? process.env["HUGLO_OAUTH_REDIRECT_URI"];
  const authorizeUrl =
    partial?.authorizeUrl ??
    process.env["HUGLO_OAUTH_AUTHORIZE_URL"] ??
    "https://account.huglo.com/oauth/authorize";
  const tokenUrl =
    partial?.tokenUrl ??
    process.env["HUGLO_OAUTH_TOKEN_URL"] ??
    "https://account.huglo.com/oauth/token";
  const userInfoUrl =
    partial?.userInfoUrl ??
    process.env["HUGLO_OAUTH_USERINFO_URL"] ??
    "https://account.huglo.com/oauth/userinfo";

  if (!clientId || !clientSecret || !redirectUri) {
    return undefined;
  }

  return {
    clientId,
    clientSecret,
    redirectUri,
    authorizeUrl,
    tokenUrl,
    userInfoUrl,
  };
}

import type { KeyObject } from "node:crypto";
import { importPublicKeyBase64 } from "./keys.js";
import { infraError } from "./errors.js";
import type {
  CreateInviteResponse,
  SignedGrant,
  SignedInvitePayload,
} from "./envelope.js";
import {
  CreateInviteResponseSchema,
  GrantExchangeResponseSchema,
} from "./envelope.js";
import type { z } from "zod";

export interface DirectoryClient {
  /** Fetch a module's Ed25519 public key (cached). */
  getModuleKey(moduleId: string, keyId?: string): Promise<KeyObject>;
  /** Fetch a user's Ed25519 public key (cached). userId is the bare id without prefix. */
  getUserKey(userId: string, keyId?: string): Promise<KeyObject>;
  /** Fetch a module's base endpoint URL (cached). */
  getEndpoint(moduleId: string): Promise<string>;
  /** Check whether a grant_id is on the revocation list. */
  isRevoked(grantId: string): Promise<boolean>;
  /** Create a grant invite at Huglo (requester module signs the payload). */
  createInvite(
    moduleId: string,
    signed: SignedInvitePayload,
  ): Promise<CreateInviteResponse>;
  /** Exchange a single-use code for signed grants. */
  exchangeGrants(code: string): Promise<SignedGrant[]>;
}

interface CacheEntry<T> {
  value: T;
  expiresAt: number;
}

export interface HttpDirectoryClientOptions {
  directoryUrl: string;
  /** Cache TTL in milliseconds. Default: 5 minutes. */
  ttlMs?: number;
  /** Revocation list refresh interval in milliseconds. Default: 1 minute. */
  revocationRefreshMs?: number;
  /** Custom fetch implementation (for testing). */
  fetch?: typeof globalThis.fetch;
}

interface ModuleDirectoryEntry {
  moduleId: string;
  endpoint: string;
  publicKey: string;
}

interface UserKeyEntry {
  userId: string;
  publicKey: string;
}

interface RevocationList {
  grantIds: string[];
}

/**
 * Default HTTP-backed directory client with TTL caching.
 * Fail-closed: on cache miss + unreachable Huglo, throws so callers reject the request.
 */
export class HttpDirectoryClient implements DirectoryClient {
  private readonly baseUrl: string;
  private readonly ttlMs: number;
  private readonly revocationRefreshMs: number;
  private readonly fetchFn: typeof globalThis.fetch;

  private readonly moduleKeyCache = new Map<string, CacheEntry<KeyObject>>();
  private readonly userKeyCache = new Map<string, CacheEntry<KeyObject>>();
  private readonly endpointCache = new Map<string, CacheEntry<string>>();
  private revocationSet: Set<string> = new Set();
  private revocationLastFetch = 0;

  constructor(options: HttpDirectoryClientOptions) {
    this.baseUrl = options.directoryUrl.replace(/\/$/, "");
    this.ttlMs = options.ttlMs ?? 5 * 60 * 1000;
    this.revocationRefreshMs = options.revocationRefreshMs ?? 60 * 1000;
    this.fetchFn = options.fetch ?? globalThis.fetch;
  }

  async getModuleKey(moduleId: string, keyId?: string): Promise<KeyObject> {
    const cacheKey = keyId ? `${moduleId}:${keyId}` : moduleId;
    const cached = this.getCached(this.moduleKeyCache, cacheKey);
    if (cached) return cached;

    const url = keyId
      ? `${this.baseUrl}/directory/modules/${encodeURIComponent(moduleId)}/keys/${encodeURIComponent(keyId)}`
      : `${this.baseUrl}/directory/modules/${encodeURIComponent(moduleId)}`;

    const entry = await this.fetchJson<ModuleDirectoryEntry>(url);
    const key = importPublicKeyBase64(entry.publicKey);
    this.setCached(this.moduleKeyCache, cacheKey, key);
    if (!keyId) {
      this.setCached(this.endpointCache, moduleId, entry.endpoint.replace(/\/$/, ""));
    }
    return key;
  }

  async getUserKey(userId: string, keyId?: string): Promise<KeyObject> {
    const bareId = userId.startsWith("huglo:user:")
      ? userId.slice("huglo:user:".length)
      : userId;
    const cacheKey = keyId ? `${bareId}:${keyId}` : bareId;
    const cached = this.getCached(this.userKeyCache, cacheKey);
    if (cached) return cached;

    const url = keyId
      ? `${this.baseUrl}/directory/users/${encodeURIComponent(bareId)}/keys/${encodeURIComponent(keyId)}`
      : `${this.baseUrl}/directory/users/${encodeURIComponent(bareId)}/key`;

    const entry = await this.fetchJson<UserKeyEntry>(url);
    const key = importPublicKeyBase64(entry.publicKey);
    this.setCached(this.userKeyCache, cacheKey, key);
    return key;
  }

  async getEndpoint(moduleId: string): Promise<string> {
    const cached = this.getCached(this.endpointCache, moduleId);
    if (cached) return cached;

    const url = `${this.baseUrl}/directory/modules/${encodeURIComponent(moduleId)}`;
    const entry = await this.fetchJson<ModuleDirectoryEntry>(url);
    const endpoint = entry.endpoint.replace(/\/$/, "");
    this.setCached(this.endpointCache, moduleId, endpoint);
    this.setCached(
      this.moduleKeyCache,
      moduleId,
      importPublicKeyBase64(entry.publicKey),
    );
    return endpoint;
  }

  async isRevoked(grantId: string): Promise<boolean> {
    await this.refreshRevocationList();
    return this.revocationSet.has(grantId);
  }

  async createInvite(
    moduleId: string,
    signed: SignedInvitePayload,
  ): Promise<CreateInviteResponse> {
    const url = `${this.baseUrl}/directory/modules/${encodeURIComponent(moduleId)}/invites`;
    return this.postJson(url, signed, CreateInviteResponseSchema);
  }

  async exchangeGrants(code: string): Promise<SignedGrant[]> {
    const url = `${this.baseUrl}/directory/grants/exchange`;
    const response = await this.postJson(
      url,
      { code },
      GrantExchangeResponseSchema,
    );
    return response.grants;
  }

  private async refreshRevocationList(): Promise<void> {
    const now = Date.now();
    if (now - this.revocationLastFetch < this.revocationRefreshMs) {
      return;
    }
    const url = `${this.baseUrl}/directory/revocations`;
    const list = await this.fetchJson<RevocationList>(url);
    this.revocationSet = new Set(list.grantIds);
    this.revocationLastFetch = now;
  }

  private getCached<T>(cache: Map<string, CacheEntry<T>>, key: string): T | undefined {
    const entry = cache.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expiresAt) {
      cache.delete(key);
      return undefined;
    }
    return entry.value;
  }

  private setCached<T>(cache: Map<string, CacheEntry<T>>, key: string, value: T): void {
    cache.set(key, { value, expiresAt: Date.now() + this.ttlMs });
  }

  private async fetchJson<T>(url: string): Promise<T> {
    let response: Response;
    try {
      response = await this.fetchFn(url, {
        headers: { Accept: "application/json" },
      });
    } catch {
      throw infraError(
        "directory_unreachable",
        "Unable to reach Huglo directory",
      );
    }
    if (!response.ok) {
      throw infraError(
        "directory_error",
        `Directory returned ${response.status}`,
      );
    }
    return (await response.json()) as T;
  }

  private async postJson<T>(
    url: string,
    body: unknown,
    schema: z.ZodType<T>,
  ): Promise<T> {
    let response: Response;
    try {
      response = await this.fetchFn(url, {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(body),
      });
    } catch {
      throw infraError(
        "directory_unreachable",
        "Unable to reach Huglo directory",
      );
    }
    if (!response.ok) {
      throw infraError(
        "directory_error",
        `Directory returned ${response.status}`,
      );
    }
    let json: unknown;
    try {
      json = await response.json();
    } catch {
      throw infraError("invalid_response", "Directory returned non-JSON response");
    }
    try {
      return schema.parse(json);
    } catch {
      throw infraError("invalid_response", "Directory response is malformed");
    }
  }
}

/** In-memory directory client for testing. */
export class InMemoryDirectoryClient implements DirectoryClient {
  private readonly modules = new Map<
    string,
    { endpoint: string; publicKey: KeyObject; publicKeyBase64: string }
  >();
  private readonly users = new Map<string, KeyObject>();
  private readonly revoked = new Set<string>();
  private readonly inviteResponses = new Map<string, CreateInviteResponse>();
  private readonly exchangeGrantsByCode = new Map<string, SignedGrant[]>();

  registerModule(
    moduleId: string,
    endpoint: string,
    publicKey: KeyObject,
    publicKeyBase64: string,
  ): void {
    this.modules.set(moduleId, { endpoint, publicKey, publicKeyBase64 });
  }

  registerUser(userId: string, publicKey: KeyObject): void {
    const bareId = userId.startsWith("huglo:user:")
      ? userId.slice("huglo:user:".length)
      : userId;
    this.users.set(bareId, publicKey);
  }

  revokeGrant(grantId: string): void {
    this.revoked.add(grantId);
  }

  /** Seed createInvite response for tests. */
  setInviteResponse(moduleId: string, response: CreateInviteResponse): void {
    this.inviteResponses.set(moduleId, response);
  }

  /** Seed exchangeGrants response for tests. */
  setExchangeGrants(code: string, grants: SignedGrant[]): void {
    this.exchangeGrantsByCode.set(code, grants);
  }

  /** Clear all registered modules, users, and revocations (for tests). */
  clear(): void {
    this.modules.clear();
    this.users.clear();
    this.revoked.clear();
    this.inviteResponses.clear();
    this.exchangeGrantsByCode.clear();
  }

  async getModuleKey(moduleId: string, _keyId?: string): Promise<KeyObject> {
    const entry = this.modules.get(moduleId);
    if (!entry) {
      throw infraError("module_not_found", `Module ${moduleId} not in directory`);
    }
    return entry.publicKey;
  }

  async getUserKey(userId: string, _keyId?: string): Promise<KeyObject> {
    const bareId = userId.startsWith("huglo:user:")
      ? userId.slice("huglo:user:".length)
      : userId;
    const key = this.users.get(bareId);
    if (!key) {
      throw infraError("user_not_found", `User ${userId} not in directory`);
    }
    return key;
  }

  async getEndpoint(moduleId: string): Promise<string> {
    const entry = this.modules.get(moduleId);
    if (!entry) {
      throw infraError("module_not_found", `Module ${moduleId} not in directory`);
    }
    return entry.endpoint;
  }

  async isRevoked(grantId: string): Promise<boolean> {
    return this.revoked.has(grantId);
  }

  async createInvite(
    moduleId: string,
    _signed: SignedInvitePayload,
  ): Promise<CreateInviteResponse> {
    const response = this.inviteResponses.get(moduleId);
    if (!response) {
      throw infraError("invite_not_configured", `No invite response for ${moduleId}`);
    }
    return response;
  }

  async exchangeGrants(code: string): Promise<SignedGrant[]> {
    const grants = this.exchangeGrantsByCode.get(code);
    if (!grants) {
      throw infraError("code_not_found", `No grants configured for code ${code}`);
    }
    return grants;
  }
}

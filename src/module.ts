import { Hono } from "hono";
import { serve } from "@hono/node-server";
import type { z } from "zod";
import type { ModuleKeyPair } from "./keys.js";
import type { DirectoryClient } from "./directory.js";
import { HttpDirectoryClient } from "./directory.js";
import type { ScopeDefinition, EmitterDefinition } from "./manifest.js";
import { createModuleServer, DEFAULT_CALLBACK_PATH, type ScopeHandler } from "./server.js";
import { callScope, type CallOptions } from "./client.js";
import { signObject } from "./signing.js";
import type { GrantStore } from "./store.js";
import type { ProtectedCtx, OpenCtx } from "./context.js";
import type {
  CreateInviteResponse,
  InviteScopeRequest,
  SignedGrant,
} from "./envelope.js";

export { ModuleError } from "./errors.js";
export type { Ctx, ProtectedCtx, OpenCtx } from "./context.js";
export type { SignedGrant, InvokeRequest, InvokeResponse } from "./envelope.js";
export type {
  InvitePayload,
  InviteScopeRequest,
  Invite,
  CreateInviteResponse,
} from "./envelope.js";
export type { DirectoryClient } from "./directory.js";
export type { GrantStore } from "./store.js";
export { loadKeyPair, generateKeyPair } from "./keys.js";

/** Production Huglo directory URL used when none is configured. */
export const DEFAULT_HUGLO_DIRECTORY_URL = "https://account.huglo.com";

function resolveDirectoryUrl(config: ModuleConfig): string {
  return (
    config.huglo?.directoryUrl ??
    process.env["HUGLO_DIRECTORY_URL"] ??
    DEFAULT_HUGLO_DIRECTORY_URL
  );
}

export interface ModuleConfig {
  id: string;
  name: string;
  description: string;
  version: string;
  keyPair: ModuleKeyPair;
  /** Huglo directory (optional; defaults to https://account.huglo.com or HUGLO_DIRECTORY_URL). */
  huglo?: {
    directoryUrl?: string;
  };
  /** Registration challenge token from Huglo (optional; falls back to MODULE_CHALLENGE env). */
  challenge?: string;
  /** This module's public endpoint base URL (optional; falls back to MODULE_ENDPOINT env). */
  endpoint?: string;
  /** Optional directory client override (extension point). */
  directory?: DirectoryClient;
  /** Optional path to static assets served at /assets/*. */
  assetsDir?: string;
  /** Grant persistence for invite callback (enables GET /grant/callback by default). */
  grantStore?: GrantStore;
  /** Invite callback path when grantStore is set. Default: /grant/callback */
  callbackPath?: string;
}

/** Protected scope (default): requires subject grant; handler receives subject + grant. */
export interface ProtectedScopeOptions<I extends z.ZodType, O extends z.ZodType> {
  description: string;
  open?: false;
  input: I;
  output: O;
  handler: (ctx: ProtectedCtx<z.infer<I>>) => Promise<z.infer<O>>;
}

/** Open scope: Sig 2 only; no subject or grant in handler context. */
export interface OpenScopeOptions<I extends z.ZodType, O extends z.ZodType> {
  description: string;
  open: true;
  input: I;
  output: O;
  handler: (ctx: OpenCtx<z.infer<I>>) => Promise<z.infer<O>>;
}

export type ScopeOptions<I extends z.ZodType, O extends z.ZodType> =
  | ProtectedScopeOptions<I, O>
  | OpenScopeOptions<I, O>;

export interface EmitterOptions<O extends z.ZodType> {
  description: string;
  output: O;
}

export interface CreateInviteOptions {
  callbackUrl: string;
  scopes: InviteScopeRequest[];
  constraints?: Record<string, unknown>;
}

interface RegisteredScope<I extends z.ZodType, O extends z.ZodType>
  extends ScopeDefinition {
  handler: ScopeHandler<z.infer<I>, z.infer<O>>;
}

export class Module {
  readonly id: string;
  private readonly config: ModuleConfig;
  private readonly directory: DirectoryClient;
  private readonly scopes = new Map<string, RegisteredScope<z.ZodType, z.ZodType>>();
  private readonly emitters = new Map<string, EmitterDefinition>();
  private app: Hono | null = null;
  private server: ReturnType<typeof serve> | null = null;
  customRoutes: Hono | undefined;

  constructor(config: ModuleConfig) {
    this.id = config.id;
    this.config = {
      ...config,
      challenge: config.challenge ?? process.env["MODULE_CHALLENGE"],
      endpoint: config.endpoint ?? process.env["MODULE_ENDPOINT"],
      callbackPath: config.callbackPath ?? DEFAULT_CALLBACK_PATH,
    };
    this.directory =
      config.directory ??
      new HttpDirectoryClient({ directoryUrl: resolveDirectoryUrl(config) });
  }

  /**
   * Register a protected scope handler (default). Requires a subject grant on invoke.
   */
  scope<I extends z.ZodType, O extends z.ZodType>(
    name: string,
    options: ProtectedScopeOptions<I, O>,
  ): this;
  /**
   * Register an open scope handler. No grant; authenticated requester module only.
   */
  scope<I extends z.ZodType, O extends z.ZodType>(
    name: string,
    options: OpenScopeOptions<I, O>,
  ): this;
  scope<I extends z.ZodType, O extends z.ZodType>(
    name: string,
    options: ScopeOptions<I, O>,
  ): this {
    this.scopes.set(name, {
      description: options.description,
      open: options.open,
      input: options.input,
      output: options.output,
      handler: options.handler as ScopeHandler<unknown, unknown>,
    });
    return this;
  }

  /**
   * Register an emitter — a named outbound event with a declared output schema.
   * Published in the manifest; use emit() to validate data and call a subscriber scope.
   */
  emitter<O extends z.ZodType>(name: string, options: EmitterOptions<O>): this {
    this.emitters.set(name, {
      description: options.description,
      output: options.output,
    });
    return this;
  }

  /**
   * Validate data against an emitter's output schema and call the grant's holder scope.
   */
  async emit(name: string, data: unknown, grant: SignedGrant): Promise<unknown> {
    const def = this.emitters.get(name);
    if (!def) {
      throw new Error(`Unknown emitter: ${name}`);
    }
    const event = def.output.parse(data);
    return this.call({
      target: grant.grant.holder,
      scope: grant.grant.scope,
      input: event,
      grant,
    });
  }

  /** Attach custom routes mounted at /api/*. */
  api(routes: Hono): this {
    this.customRoutes = routes;
    return this;
  }

  /** Outbound call to another module's scope. */
  async call(options: CallOptions): Promise<unknown> {
    return callScope(
      {
        moduleId: this.id,
        privateKey: this.config.keyPair.privateKey,
        directory: this.directory,
      },
      options,
    );
  }

  /**
   * Create a grant invite at Huglo. Returns invite metadata and a URL
   * the user must open in a browser to approve.
   */
  async createInvite(options: CreateInviteOptions): Promise<CreateInviteResponse> {
    const payload = {
      moduleId: this.id,
      callbackUrl: options.callbackUrl,
      scopes: options.scopes,
      constraints: options.constraints ?? {},
      iat: new Date().toISOString(),
    };
    const signature = signObject(payload, this.config.keyPair.privateKey);
    return this.directory.createInvite(this.id, { payload, signature });
  }

  /** Exchange a single-use code from the invite callback for signed grants. */
  async exchangeGrants(code: string): Promise<SignedGrant[]> {
    return this.directory.exchangeGrants(code);
  }

  /** Get the underlying Hono app (useful for testing). */
  getApp(): Hono {
    this.app ??= createModuleServer({
      moduleId: this.id,
      name: this.config.name,
      description: this.config.description,
      version: this.config.version,
      publicKeyBase64: this.config.keyPair.publicKeyBase64,
      privateKey: this.config.keyPair.privateKey,
      directory: this.directory,
      scopes: this.scopes,
      emitters: this.emitters,
      challenge: this.config.challenge,
      endpoint: this.config.endpoint,
      assetsDir: this.config.assetsDir,
      customRoutes: this.customRoutes,
      grantStore: this.config.grantStore,
      callbackPath: this.config.callbackPath,
    });
    return this.app;
  }

  /** Expose directory client (for testing harness). */
  getDirectory(): DirectoryClient {
    return this.directory;
  }

  /** Expose keypair (for testing harness). */
  getKeyPair(): ModuleKeyPair {
    return this.config.keyPair;
  }

  /** Full callback URL for createInvite (endpoint + callbackPath). */
  getCallbackUrl(): string {
    const endpoint = this.config.endpoint?.replace(/\/$/, "");
    if (!endpoint) {
      throw new Error("MODULE_ENDPOINT or config.endpoint is required for getCallbackUrl()");
    }
    const path = this.config.callbackPath ?? DEFAULT_CALLBACK_PATH;
    const normalizedPath = path.startsWith("/") ? path : `/${path}`;
    return `${endpoint}${normalizedPath}`;
  }

  /** Start listening on the given port. */
  listen(port: number, host = "0.0.0.0"): Promise<void> {
    const app = this.getApp();
    return new Promise((resolve) => {
      this.server = serve({ fetch: app.fetch, port, hostname: host }, () => {
        resolve();
      });
    });
  }

  /** Stop the HTTP server (for testing). */
  close(): void {
    if (this.server && "close" in this.server) {
      (this.server as { close: (cb?: () => void) => void }).close();
      this.server = null;
    }
  }

  /** Update registration challenge config at runtime. */
  setChallenge(challenge: string, endpoint: string): void {
    this.config.challenge = challenge;
    this.config.endpoint = endpoint;
    this.app = null;
  }
}

export type { CallOptions };

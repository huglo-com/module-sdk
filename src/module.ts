import { Hono } from "hono";
import { serve } from "@hono/node-server";
import type { z } from "zod";
import type { ModuleKeyPair } from "./keys.js";
import type { DirectoryClient } from "./directory.js";
import { HttpDirectoryClient } from "./directory.js";
import type { ScopeDefinition, EmitterDefinition } from "./manifest.js";
import type { GrantCallbackOptions } from "./grant-callback.js";
import { createModuleServer, DEFAULT_CALLBACK_PATH, type ScopeHandler } from "./server.js";
import { callScope, type CallOptions } from "./client.js";
import { signObject } from "./signing.js";
import type { GrantStore } from "./store.js";
import type { ConfigStore } from "./config-store.js";
import { InMemoryConfigStore } from "./config-store.js";
import type { ConfigDefinition } from "./config.js";
import type { ProtectedCtx, OpenCtx } from "./context.js";
import {
  HttpHugloOAuthClient,
  resolveOAuthOptions,
  type HugloOAuthClient,
  type OAuthClientOptions,
} from "./oauth.js";
import type { OnConfigSaved } from "./config-routes.js";
import { DEFAULT_CONFIG_PATH } from "./config-routes.js";
import type { ConfigPageTheme } from "./config-page.js";
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
export type { ConfigStore, InstanceConfig } from "./config-store.js";
export { InMemoryConfigStore } from "./config-store.js";
export type { ConfigDefinition, ConfigOptions, FieldSource } from "./config.js";
export { assembleConfigValues, ConfigAssemblyError } from "./config.js";
export type {
  HugloOAuthClient,
  OAuthClientOptions,
} from "./oauth.js";
export {
  HttpHugloOAuthClient,
  InMemoryHugloOAuthClient,
  resolveOAuthOptions,
  DEFAULT_HUGLO_OAUTH_ISSUER,
  DEFAULT_HUGLO_OAUTH_SCOPES,
  OAUTH_PKCE_COOKIE,
  generateCodeVerifier,
  generateCodeChallenge,
  createPkceCookie,
  readPkceCookie,
} from "./oauth.js";
export type { OAuthPkceParams } from "./oauth.js";
export type { OnConfigSaved, OnConfigSavedContext } from "./config-routes.js";
export { DEFAULT_CONFIG_PATH } from "./config-routes.js";
export type { ConfigPageTheme } from "./config-page.js";
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

export interface ModuleConfig extends GrantCallbackOptions {
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
  /** Grant persistence for invite callback (enables GET /grant/callback when set). */
  grantStore?: GrantStore;
  /**
   * Invite callback path (default: /grant/callback). Controls the registered route
   * and `getCallbackUrl()`.
   */
  callbackPath?: string;
  /** OAuth client for config login (separate from federation keypair). */
  oauth?: Partial<OAuthClientOptions>;
  /** Override OAuth client (e.g. in-memory for tests). */
  oauthClient?: HugloOAuthClient;
  /** Per-instance config persistence (required when using config()). */
  configStore?: ConfigStore;
  /** Config UI path (default: /config). */
  configPath?: string;
  /** Override default SDK config page URL (published in manifest). */
  configPageUrl?: string;
  /** Light theming for the default config page. */
  theme?: ConfigPageTheme;
  /** Hook after config intake saves an instance (provisioning, grant invites, etc.). */
  onConfigSaved?: OnConfigSaved;
}

export type {
  GrantCallbackContext,
  GrantCallbackErrorContext,
  GrantCallbackResult,
  GrantCallbackStage,
  OnGrantCallback,
  OnGrantCallbackError,
} from "./grant-callback.js";
export { exchangeAndSaveGrants } from "./grant-callback.js";

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
  private readonly init: ModuleConfig;
  private readonly directory: DirectoryClient;
  private readonly scopes = new Map<string, RegisteredScope<z.ZodType, z.ZodType>>();
  private readonly emitters = new Map<string, EmitterDefinition>();
  private configDefinition: ConfigDefinition | undefined;
  private defaultConfigStore: ConfigStore | undefined;
  private app: Hono | null = null;
  private server: ReturnType<typeof serve> | null = null;
  customRoutes: Hono | undefined;

  constructor(config: ModuleConfig) {
    this.id = config.id;
    this.init = {
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
   * Declare per-instance configuration schema and field sources.
   * Enables config routes, Huglo OAuth login, and /manifest config output.
   */
  config(options: ConfigDefinition): this {
    this.configDefinition = options;
    this.app = null;
    return this;
  }

  /** Expose the config store (for module logic that reads stored instances). */
  getConfigStore(): ConfigStore | undefined {
    return this.init.configStore ?? (this.configDefinition ? this.resolveConfigStore() : undefined);
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
        privateKey: this.init.keyPair.privateKey,
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
    const signature = signObject(payload, this.init.keyPair.privateKey);
    return this.directory.createInvite(this.id, { payload, signature });
  }

  /** Exchange a single-use code from the invite callback for signed grants. */
  async exchangeGrants(code: string): Promise<SignedGrant[]> {
    return this.directory.exchangeGrants(code);
  }

  /** Get the underlying Hono app (useful for testing). */
  getApp(): Hono {
    const configRuntime = this.resolveConfigRuntime();
    this.app ??= createModuleServer({
      moduleId: this.id,
      name: this.init.name,
      description: this.init.description,
      version: this.init.version,
      publicKeyBase64: this.init.keyPair.publicKeyBase64,
      privateKey: this.init.keyPair.privateKey,
      directory: this.directory,
      scopes: this.scopes,
      emitters: this.emitters,
      challenge: this.init.challenge,
      endpoint: this.init.endpoint,
      assetsDir: this.init.assetsDir,
      customRoutes: this.customRoutes,
      grantStore: this.init.grantStore,
      callbackPath: this.init.callbackPath,
      onGrantCallback: this.init.onGrantCallback,
      onGrantCallbackError: this.init.onGrantCallbackError,
      callbackMiddleware: this.init.callbackMiddleware,
      configDefinition: this.configDefinition,
      configStore: configRuntime?.configStore,
      oauth: configRuntime?.oauth,
      oauthOptions: configRuntime?.oauthOptions,
      configPath: this.init.configPath ?? DEFAULT_CONFIG_PATH,
      configPageUrl: this.init.configPageUrl,
      configTheme: this.init.theme,
      onConfigSaved: this.init.onConfigSaved,
    });
    return this.app;
  }

  private resolveConfigStore(): ConfigStore {
    if (this.init.configStore) {
      return this.init.configStore;
    }
    this.defaultConfigStore ??= new InMemoryConfigStore();
    return this.defaultConfigStore;
  }

  private resolveConfigRuntime():
    | {
        configStore: ConfigStore;
        oauth: HugloOAuthClient;
        oauthOptions: OAuthClientOptions;
      }
    | undefined {
    if (!this.configDefinition) {
      return undefined;
    }

    const oauthOptions = resolveOAuthOptions(this.init.oauth);
    if (!oauthOptions) {
      throw new Error(
        "Config requires OAuth. Set oauth in ModuleConfig or HUGLO_OAUTH_CLIENT_ID, HUGLO_OAUTH_CLIENT_SECRET, HUGLO_OAUTH_REDIRECT_URI.",
      );
    }

    const oauth =
      this.init.oauthClient ?? new HttpHugloOAuthClient(oauthOptions);

    return {
      configStore: this.resolveConfigStore(),
      oauth,
      oauthOptions,
    };
  }

  /** Expose directory client (for testing harness). */
  getDirectory(): DirectoryClient {
    return this.directory;
  }

  /** Expose keypair (for testing harness). */
  getKeyPair(): ModuleKeyPair {
    return this.init.keyPair;
  }

  /** Full callback URL for createInvite (endpoint + callbackPath). */
  getCallbackUrl(): string {
    const endpoint = this.init.endpoint?.replace(/\/$/, "");
    if (!endpoint) {
      throw new Error("MODULE_ENDPOINT or config.endpoint is required for getCallbackUrl()");
    }
    const path = this.init.callbackPath ?? DEFAULT_CALLBACK_PATH;
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
    this.init.challenge = challenge;
    this.init.endpoint = endpoint;
    this.app = null;
  }
}

export type { CallOptions };

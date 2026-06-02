import { Hono } from "hono";
import type { Context, MiddlewareHandler } from "hono";
import { serveStatic } from "@hono/node-server/serve-static";
import type { KeyObject } from "node:crypto";
import { randomUUID } from "node:crypto";
import type { DirectoryClient } from "./directory.js";
import type { InvokeResponse, SignedGrant } from "./envelope.js";
import { sig3Payload , isGrantInvokeBody } from "./envelope.js";
import { normalizeError, ModuleError } from "./errors.js";
import { signObject } from "./signing.js";
import {
  verifyInvokeRequest,
  verifyOpenInvokeRequest,
  NonceCache,
  type VerifiedInvokeContext,
  type VerifyOptions,
} from "./verify.js";
import { buildManifest, type ModuleManifest, type ScopeDefinition, type EmitterDefinition } from "./manifest.js";
import { buildSignedChallenge } from "./challenge.js";
import type { Ctx, ProtectedCtx, OpenCtx } from "./context.js";
import type { GrantStore } from "./store.js";
import { grantCallbackHtml } from "./callback.js";
import type {
  GrantCallbackErrorContext,
  OnGrantCallback,
  OnGrantCallbackError,
} from "./grant-callback.js";
import type { ConfigDefinition } from "./config.js";
import type { ConfigStore } from "./config-store.js";
import { mountConfigRoutes, type OnConfigSaved } from "./config-routes.js";
import type { ConfigPageTheme } from "./config-page.js";
import type { HugloOAuthClient, OAuthClientOptions } from "./oauth.js";

export const DEFAULT_CALLBACK_PATH = "/grant/callback";

export interface ServerConfig {
  moduleId: string;
  name: string;
  description: string;
  version: string;
  publicKeyBase64: string;
  privateKey: KeyObject;
  directory: DirectoryClient;
  scopes: Map<string, ScopeDefinition & { handler: ScopeHandler<unknown, unknown> }>;
  emitters?: Map<string, EmitterDefinition>;
  challenge?: string;
  endpoint?: string;
  assetsDir?: string;
  customRoutes?: Hono;
  grantStore?: GrantStore;
  callbackPath?: string;
  onGrantCallback?: OnGrantCallback;
  onGrantCallbackError?: OnGrantCallbackError;
  callbackMiddleware?: MiddlewareHandler | MiddlewareHandler[];
  configDefinition?: ConfigDefinition;
  configStore?: ConfigStore;
  oauth?: HugloOAuthClient;
  oauthOptions?: OAuthClientOptions;
  configPath?: string;
  configPageUrl?: string;
  configTheme?: ConfigPageTheme;
  onConfigSaved?: OnConfigSaved;
}

export type ProtectedScopeHandler<I, O> = (ctx: ProtectedCtx<I>) => Promise<O>;
export type OpenScopeHandler<I, O> = (ctx: OpenCtx<I>) => Promise<O>;
/** Internal runtime handler (protected or open invoke). */
export type ScopeHandler<I, O> = (ctx: Ctx<I>) => Promise<O>;

export interface CreateServerOptions extends ServerConfig {
  nonceCache?: NonceCache;
}

export function createModuleServer(options: CreateServerOptions): Hono {
  const app = new Hono();
  const nonceCache = options.nonceCache ?? new NonceCache();

  app.get("/health", (c) => c.json({ status: "ok", module: options.moduleId }));

  app.get("/manifest", (c) => {
    const manifest: ModuleManifest = buildManifest(
      {
        id: options.moduleId,
        name: options.name,
        description: options.description,
        version: options.version,
        publicKey: options.publicKeyBase64,
        configDefinition: options.configDefinition,
        configPageUrl: options.configPageUrl,
      },
      options.scopes,
      options.emitters ?? new Map(),
    );
    return c.json(manifest);
  });

  app.get("/.well-known/huglo-challenge", (c) => {
    if (!options.challenge || !options.endpoint) {
      return c.json(
        { error: "Registration challenge not configured" },
        503,
      );
    }
    const signed = buildSignedChallenge({
      challenge: options.challenge,
      moduleId: options.moduleId,
      endpoint: options.endpoint,
      publicKey: options.publicKeyBase64,
      privateKey: options.privateKey,
    });
    return c.json(signed);
  });

  if (options.assetsDir) {
    app.use("/assets/*", serveStatic({ root: options.assetsDir }));
  }

  if (options.grantStore || options.onGrantCallback) {
    const callbackPath = options.callbackPath ?? DEFAULT_CALLBACK_PATH;
    const callbackMiddleware = normalizeMiddleware(options.callbackMiddleware);
    const handler = createGrantCallbackHandler(options);
    const callbackRoute = new Hono();
    for (const middleware of callbackMiddleware) {
      callbackRoute.use("*", middleware);
    }
    callbackRoute.get("/", handler);
    app.route(callbackPath, callbackRoute);
  }

  if (options.customRoutes) {
    app.route("/api", options.customRoutes);
  }

  if (
    options.configDefinition &&
    options.configStore &&
    options.oauth &&
    options.oauthOptions
  ) {
    mountConfigRoutes(app, {
      configDefinition: options.configDefinition,
      configStore: options.configStore,
      oauth: options.oauth,
      oauthOptions: options.oauthOptions,
      configPath: options.configPath,
      configPageUrl: options.configPageUrl,
      theme: options.configTheme,
      onConfigSaved: options.onConfigSaved,
    });
  }

  app.post("/invoke/:scope", async (c) => {
    const urlScope = c.req.param("scope");
    const scopeDef = options.scopes.get(urlScope);
    if (!scopeDef) {
      return c.json(
        buildSignedErrorResponse(
          c.req.header("X-Request-Id") ?? randomUUID(),
          authModuleError("scope_not_found", `Scope '${urlScope}' not found`),
          options.privateKey,
        ),
        404,
      );
    }

    let rawBody: unknown;
    try {
      rawBody = await c.req.json();
    } catch {
      return c.json(
        buildSignedErrorResponse(
          c.req.header("X-Request-Id") ?? randomUUID(),
          authModuleError("malformed_request", "Invalid JSON body"),
          options.privateKey,
        ),
        400,
      );
    }

    const requestId = c.req.header("X-Request-Id") ?? randomUUID();
    const dryRun = c.req.header("X-Dry-Run") === "true";

    const verifyOpts = {
      moduleId: options.moduleId,
      urlScope,
      inputSchema: scopeDef.input,
      directory: options.directory,
      dryRun,
      requestId,
    };

    let verified: VerifiedInvokeContext<unknown>;
    try {
      verified = await verifyInvokeForScope(rawBody, scopeDef, nonceCache, verifyOpts);
    } catch (err) {
      const normalized = err instanceof ModuleError ? err : authModuleError("verification_failed", "Verification failed");
      const status = normalized.retryable ? 503 : 401;
      return c.json(buildSignedErrorResponse(requestId, normalized, options.privateKey), status);
    }

    try {
      const result = await scopeDef.handler(verified);

      const parsed = scopeDef.output.safeParse(result);
      if (!parsed.success) {
        return c.json(
          buildSignedErrorResponse(
            requestId,
            authModuleError("invalid_output", "Handler output does not match scope output schema"),
            options.privateKey,
          ),
          500,
        );
      }

      return c.json(
        buildSignedSuccessResponse(requestId, parsed.data, options.privateKey),
      );
    } catch (err) {
      const normalized = normalizeError(err);
      const status = normalized.retryable ? 503 : 400;
      return c.json(
        buildSignedErrorResponse(requestId, normalized, options.privateKey),
        status,
      );
    }
  });

  return app;
}

function normalizeMiddleware(
  middleware: MiddlewareHandler | MiddlewareHandler[] | undefined,
): MiddlewareHandler[] {
  if (!middleware) {
    return [];
  }
  return Array.isArray(middleware) ? middleware : [middleware];
}

function createGrantCallbackHandler(options: CreateServerOptions) {
  return async (c: Context) => {
    const code = c.req.query("code");
    if (!code) {
      return resolveGrantCallbackError(c, options.onGrantCallbackError, {
        error: new Error("Missing authorization code"),
        stage: "missing_code",
      }, 400, grantCallbackHtml("Missing authorization code.", false));
    }

    let grants: SignedGrant[];
    try {
      grants = await options.directory.exchangeGrants(code);
    } catch (err) {
      return resolveGrantCallbackError(c, options.onGrantCallbackError, {
        code,
        error: err,
        stage: "exchange",
      }, 502, grantCallbackHtml("Could not complete authorization.", false));
    }

    if (options.grantStore) {
      try {
        for (const grant of grants) {
          await options.grantStore.save(grant);
        }
      } catch (err) {
        return resolveGrantCallbackError(c, options.onGrantCallbackError, {
          code,
          error: err,
          stage: "save",
        }, 502, grantCallbackHtml("Could not complete authorization.", false));
      }
    }

    if (options.onGrantCallback) {
      try {
        const result = await options.onGrantCallback({ c, code, grants });
        if (result !== undefined) {
          return toGrantCallbackResponse(c, result, 200);
        }
      } catch (err) {
        return resolveGrantCallbackError(c, options.onGrantCallbackError, {
          code,
          error: err,
          stage: "render",
        }, 500, grantCallbackHtml("Could not complete authorization.", false));
      }
    }

    return c.html(
      grantCallbackHtml("Authorization complete. You can close this tab.", true),
    );
  };
}

async function resolveGrantCallbackError(
  c: Context,
  onError: OnGrantCallbackError | undefined,
  ctx: Omit<GrantCallbackErrorContext, "c">,
  defaultStatus: number,
  defaultHtml: string,
): Promise<Response> {
  if (onError) {
    const result = await onError({ c, ...ctx });
    if (result !== undefined) {
      return toGrantCallbackResponse(c, result, defaultStatus);
    }
  }
  return c.html(defaultHtml, defaultStatus as 400 | 500 | 502);
}

function toGrantCallbackResponse(
  c: Context,
  result: Response | string,
  defaultStatus: number,
): Response {
  if (typeof result === "string") {
    return c.html(result, defaultStatus as 200 | 400 | 500 | 502);
  }
  return result;
}

async function verifyInvokeForScope(
  rawBody: unknown,
  scopeDef: Pick<ScopeDefinition, "open">,
  nonceCache: NonceCache,
  verifyOpts: VerifyOptions,
): Promise<VerifiedInvokeContext<unknown>> {
  if (scopeDef.open) {
    if (isGrantInvokeBody(rawBody)) {
      throw authModuleError(
        "grant_not_expected",
        "Open scope does not accept a grant envelope",
      );
    }
    return verifyOpenInvokeRequest(rawBody, nonceCache, verifyOpts);
  }
  if (!isGrantInvokeBody(rawBody)) {
    throw authModuleError(
      "grant_required",
      "Protected scope requires a grant envelope",
    );
  }
  return verifyInvokeRequest(rawBody, nonceCache, verifyOpts);
}

function authModuleError(code: string, message: string): ModuleError {
  return new ModuleError({ code, message, retryable: false });
}

function buildSignedSuccessResponse(
  requestId: string,
  result: unknown,
  privateKey: KeyObject,
): InvokeResponse {
  const timestamp = new Date().toISOString();
  const partial: InvokeResponse = {
    requestId,
    result,
    timestamp,
    holderSignature: "",
  };
  partial.holderSignature = signObject(sig3Payload(partial), privateKey);
  return partial;
}

function buildSignedErrorResponse(
  requestId: string,
  error: { code: string; message: string; retryable: boolean },
  privateKey: KeyObject,
): InvokeResponse {
  const timestamp = new Date().toISOString();
  const partial: InvokeResponse = {
    requestId,
    error,
    timestamp,
    holderSignature: "",
  };
  partial.holderSignature = signObject(sig3Payload(partial), privateKey);
  return partial;
}

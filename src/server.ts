import { Hono } from "hono";
import type { Context, MiddlewareHandler } from "hono";
import { routePath } from "hono/route";
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
import type { TypeManifestEntry } from "./type-system.js";
import { buildSignedChallenge } from "./challenge.js";
import type { Ctx, ProtectedCtx, OpenCtx } from "./context.js";
import type { GrantStore } from "./store.js";
import { grantAuthorizedNotifyHtml, grantCallbackHtml } from "./callback.js";
import type {
  GrantCallbackErrorContext,
  OnGrantCallback,
  OnGrantCallbackError,
} from "./grant-callback.js";
import {
  buildGrantCallbackUrl,
  createSignedInvite,
} from "./grant-callback.js";
import type { ConfigDefinition } from "./config.js";
import type { ConfigStore } from "./config-store.js";
import { mountConfigRoutes, DEFAULT_CONFIG_PATH, type OnConfigSaved, type RenderConfigPage } from "./config-routes.js";
import type { ConfigPageTheme } from "./config-page.js";
import type { HugloOAuthClient, OAuthClientOptions } from "./oauth.js";
import type { FileStore } from "./file-store.js";
import { mountFileRoutes } from "./file-routes.js";
import type { ModuleMetrics } from "./metrics.js";
import { mountMetricsRoutes } from "./metrics-routes.js";

export const DEFAULT_CALLBACK_PATH = "/grant/callback";
export const DEFAULT_GRANT_INIT_PATH = "/grant/init";

/** Derive grant init path from callback path (e.g. /grant/callback → /grant/init). */
export function grantInitPath(callbackPath: string): string {
  const normalized = callbackPath.replaceAll(/\/$/g, "");
  if (normalized.endsWith("/callback")) {
    return `${normalized.slice(0, -"/callback".length)}/init`;
  }
  return DEFAULT_GRANT_INIT_PATH;
}

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
  types?: Map<string, TypeManifestEntry>;
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
  hasConfig?: boolean;
  customConfigHandler?: Hono;
  configTheme?: ConfigPageTheme;
  renderConfigPage?: RenderConfigPage;
  onConfigSaved?: OnConfigSaved;
  fileStore?: FileStore;
  metrics?: ModuleMetrics;
}

export type ProtectedScopeHandler<I, O> = (ctx: ProtectedCtx<I>) => Promise<O>;
export type OpenScopeHandler<I, O> = (ctx: OpenCtx<I>) => Promise<O>;
/** Internal runtime handler (protected or open invoke). */
export type ScopeHandler<I, O> = (ctx: Ctx<I>) => Promise<O>;

export interface CreateServerOptions extends ServerConfig {
  nonceCache?: NonceCache;
  configProofNonceCache?: NonceCache;
}

export function createModuleServer(options: CreateServerOptions): Hono {
  const app = new Hono();
  const nonceCache = options.nonceCache ?? new NonceCache();
  const configProofNonceCache = options.configProofNonceCache ?? new NonceCache();

  app.get("/health", (c) => c.json({ status: "ok", module: options.moduleId }));

  if (options.metrics) {
    mountMetricsRoutes(app, { metrics: options.metrics });
    app.use("*", createMetricsMiddleware(options.metrics));
  }

  app.get("/manifest", (c) => {
    const manifest: ModuleManifest = buildManifest(
      {
        id: options.moduleId,
        name: options.name,
        description: options.description,
        version: options.version,
        publicKey: options.publicKeyBase64,
        hasConfig: options.hasConfig,
      },
      options.scopes,
      options.emitters ?? new Map(),
      options.types ?? new Map(),
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

  if (options.grantStore) {
    const callbackPath = options.callbackPath ?? DEFAULT_CALLBACK_PATH;
    app.get(grantInitPath(callbackPath), createGrantInitHandler(options));
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

  if (options.fileStore) {
    mountFileRoutes(app, {
      fileStore: options.fileStore,
      metrics: options.metrics,
    });
  }

  if (options.customConfigHandler) {
    app.route(DEFAULT_CONFIG_PATH, options.customConfigHandler);
  } else if (
    options.configDefinition &&
    options.configStore &&
    options.oauth &&
    options.oauthOptions
  ) {
    mountConfigRoutes(app, {
      moduleId: options.moduleId,
      directory: options.directory,
      configDefinition: options.configDefinition,
      configStore: options.configStore,
      oauth: options.oauth,
      oauthOptions: options.oauthOptions,
      theme: options.configTheme,
      renderConfigPage: options.renderConfigPage,
      onConfigSaved: options.onConfigSaved,
      configProofNonceCache,
    });
  }

  app.post("/invoke/:scope", async (c) => {
    const urlScope = c.req.param("scope");
    const scopeDef = options.scopes.get(urlScope);
    if (!scopeDef) {
      options.metrics?.recordInvoke(urlScope, "scope_not_found");
      return c.json(
        buildSignedErrorResponse(
          c.req.header("X-Request-Id") ?? randomUUID(),
          authModuleError("scope_not_found", `Scope '${urlScope}' not found`),
          options.privateKey,
        ),
        404,
      );
    }

    const endInvokeTimer = options.metrics?.startInvokeTimer(urlScope);

    let rawBody: unknown;
    try {
      rawBody = await c.req.json();
    } catch {
      endInvokeTimer?.();
      options.metrics?.recordInvoke(urlScope, "malformed_request");
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
      endInvokeTimer?.();
      options.metrics?.recordInvoke(urlScope, "verification_failed");
      const normalized = err instanceof ModuleError ? err : authModuleError("verification_failed", "Verification failed");
      const status = normalized.retryable ? 503 : 401;
      return c.json(buildSignedErrorResponse(requestId, normalized, options.privateKey), status);
    }

    // TODO(module-sdk-extensions): Move invoke-time config resolution to a separate
    // flowbuilder-oriented extension package. Core SDK should not assume
    // input.context.configInstanceId host payload shape.
    if (options.configStore) {
      const configResolved = await resolveInvokeConfigContext(options.configStore, verified);
      if (!configResolved.ok) {
        endInvokeTimer?.();
        options.metrics?.recordInvoke(urlScope, configResolved.outcome);
        return c.json(
          buildSignedErrorResponse(requestId, configResolved.error, options.privateKey),
          403,
        );
      }
      verified = configResolved.verified;
    }

    try {
      const result = await scopeDef.handler(verified);

      const parsed = scopeDef.output.safeParse(result);
      if (!parsed.success) {
        endInvokeTimer?.();
        options.metrics?.recordInvoke(urlScope, "invalid_output");
        return c.json(
          buildSignedErrorResponse(
            requestId,
            authModuleError("invalid_output", "Handler output does not match scope output schema"),
            options.privateKey,
          ),
          500,
        );
      }

      endInvokeTimer?.();
      options.metrics?.recordInvoke(urlScope, "success");
      return c.json(
        buildSignedSuccessResponse(requestId, parsed.data, options.privateKey),
      );
    } catch (err) {
      endInvokeTimer?.();
      options.metrics?.recordInvoke(urlScope, "handler_error");
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

function createMetricsMiddleware(metrics: ModuleMetrics): MiddlewareHandler {
  return async (c, next) => {
    const start = performance.now();
    await next();
    const durationSeconds = (performance.now() - start) / 1000;
    const route = routePath(c) || c.req.path;
    metrics.recordHttpRequest(c.req.method, route, String(c.res.status), durationSeconds);
  };
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

    const first = grants[0]?.grant;
    if (first) {
      return c.html(
        grantAuthorizedNotifyHtml({
          subject: first.subject,
          holder: first.holder,
          scope: first.scope,
        }),
      );
    }

    return c.html(
      grantCallbackHtml("Authorization complete. You can close this tab.", true),
    );
  };
}

function createGrantInitHandler(options: CreateServerOptions) {
  return async (c: Context) => {
    const subject = c.req.query("subject");
    const holder = c.req.query("holder");
    const scope = c.req.query("scope");

    if (!subject || !holder || !scope) {
      return c.text("Missing subject, holder, or scope query parameter", 400);
    }

    const grantStore = options.grantStore;
    if (!grantStore) {
      return c.text("Grant store not configured", 503);
    }

    const existing = await grantStore.find({
      subject,
      holder,
      scope,
      requester: options.moduleId,
    });

    if (existing) {
      return c.html(
        grantAuthorizedNotifyHtml({ subject, holder, scope }),
      );
    }

    const endpoint = options.endpoint?.replaceAll(/\/$/g, "");
    if (!endpoint) {
      return c.text("Module endpoint not configured", 503);
    }

    const callbackPath = options.callbackPath ?? DEFAULT_CALLBACK_PATH;
    const callbackUrl = buildGrantCallbackUrl(endpoint, callbackPath);

    try {
      const { inviteUrl } = await createSignedInvite(
        options.directory,
        options.moduleId,
        options.privateKey,
        {
          callbackUrl,
          scopes: [{ holder, scope }],
        },
      );
      return c.redirect(inviteUrl);
    } catch {
      return c.html(
        grantCallbackHtml("Could not start authorization.", false),
        502,
      );
    }
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

type InvokeConfigOutcome = "config_not_found" | "config_subject_mismatch" | "config_instance_required";

type InvokeConfigResolveResult =
  | { ok: true; verified: VerifiedInvokeContext<unknown> }
  | { ok: false; outcome: InvokeConfigOutcome; error: ModuleError };

// TODO(module-sdk-extensions): Relocate to flowbuilder extension — auto-resolves
// context.configInstanceId and enforces directorySubject vs grant subject.
async function resolveInvokeConfigContext(
  configStore: ConfigStore,
  verified: VerifiedInvokeContext<unknown>,
): Promise<InvokeConfigResolveResult> {
  if (verified.open) {
    return { ok: true, verified };
  }

  const configInstanceId = extractConfigInstanceId(verified.input);
  if (!configInstanceId) {
    return {
      ok: false,
      outcome: "config_instance_required",
      error: authModuleError(
        "config_instance_required",
        "Protected invoke on a config-enabled module requires context.configInstanceId",
      ),
    };
  }

  const inst = await configStore.get(configInstanceId);
  if (!inst) {
    return {
      ok: false,
      outcome: "config_not_found",
      error: authModuleError(
        "config_not_found",
        "No configuration found for this config instance",
      ),
    };
  }

  if (inst.directorySubject !== verified.subject) {
    return {
      ok: false,
      outcome: "config_subject_mismatch",
      error: authModuleError(
        "config_subject_mismatch",
        "Config instance does not belong to grant subject",
      ),
    };
  }

  return {
    ok: true,
    verified: {
      ...verified,
      config: { instanceId: inst.instanceId, values: inst.values },
    },
  };
}

// TODO(module-sdk-extensions): Relocate to flowbuilder extension — hardcoded
// convention that host injects configInstanceId at input.context.configInstanceId.
function extractConfigInstanceId(input: unknown): string | undefined {
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return undefined;
  }
  const context = (input as { context?: unknown }).context;
  if (typeof context !== "object" || context === null || Array.isArray(context)) {
    return undefined;
  }
  const id = (context as { configInstanceId?: unknown }).configInstanceId;
  return typeof id === "string" && id.length > 0 ? id : undefined;
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

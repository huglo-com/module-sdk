import { Hono } from "hono";
import { serveStatic } from "@hono/node-server/serve-static";
import type { KeyObject } from "node:crypto";
import { randomUUID } from "node:crypto";
import type { DirectoryClient } from "./directory.js";
import type { InvokeResponse } from "./envelope.js";
import { sig3Payload } from "./envelope.js";
import { normalizeError, ModuleError } from "./errors.js";
import { signObject } from "./signing.js";
import { verifyInvokeRequest, NonceCache, type VerifiedInvokeContext } from "./verify.js";
import { buildManifest, type ModuleManifest, type ScopeDefinition } from "./manifest.js";
import { buildSignedChallenge } from "./challenge.js";
import type { Ctx } from "./context.js";
import type { GrantStore } from "./store.js";
import { grantCallbackHtml } from "./callback.js";

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
  challenge?: string;
  endpoint?: string;
  assetsDir?: string;
  customRoutes?: Hono;
  grantStore?: GrantStore;
  callbackPath?: string;
}

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
      },
      options.scopes,
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
    app.get(callbackPath, async (c) => {
      const code = c.req.query("code");
      if (!code) {
        return c.html(grantCallbackHtml("Missing authorization code.", false), 400);
      }
      try {
        const grants = await options.directory.exchangeGrants(code);
        for (const grant of grants) {
          await options.grantStore!.save(grant);
        }
      } catch {
        return c.html(
          grantCallbackHtml("Could not complete authorization.", false),
          502,
        );
      }
      return c.html(
        grantCallbackHtml("Authorization complete. You can close this tab.", true),
      );
    });
  }

  if (options.customRoutes) {
    app.route("/api", options.customRoutes);
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

    let verified: VerifiedInvokeContext<unknown>;
    try {
      verified = await verifyInvokeRequest(rawBody, nonceCache, {
        moduleId: options.moduleId,
        urlScope,
        inputSchema: scopeDef.input,
        directory: options.directory,
        dryRun,
        requestId,
      });
    } catch (err) {
      const normalized = err instanceof ModuleError ? err : authModuleError("verification_failed", "Verification failed");
      const status = normalized.retryable ? 503 : 401;
      return c.json(buildSignedErrorResponse(requestId, normalized, options.privateKey), status);
    }

    try {
      const ctx: Ctx<unknown> = {
        subject: verified.subject,
        input: verified.input,
        grant: verified.grant,
        caller: verified.caller,
        scope: verified.scope,
        requestId: verified.requestId,
        dryRun: verified.dryRun,
      };

      const result = await scopeDef.handler(ctx);

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

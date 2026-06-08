import { Hono } from "hono";
import type { Context } from "hono";
import { randomUUID } from "node:crypto";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import type { ConfigDefinition } from "./config.js";
import { assembleConfigValues, ConfigAssemblyError, formatInstanceLabel } from "./config.js";
import type { ConfigStore } from "./config-store.js";
import type { DirectoryClient } from "./directory.js";
import { verifyConfigProof } from "./config-proof.js";
import { ModuleError } from "./errors.js";
import type { NonceCache } from "./verify.js";
import type { ConfigManifestEntry } from "./manifest.js";
import { buildConfigManifest } from "./manifest.js";
import { configPageHtml } from "./config-page.js";
import type { ConfigInstanceEntry, ConfigPageTheme } from "./config-page.js";
import {
  CONFIG_SESSION_COOKIE,
  OAUTH_STATE_COOKIE,
  OAUTH_PKCE_COOKIE,
  createConfigSession,
  readConfigSession,
  createPkceCookie,
  readPkceCookie,
  createOAuthState,
  generateCodeVerifier,
  generateCodeChallenge,
  type HugloOAuthClient,
  type OAuthClientOptions,
} from "./oauth.js";

export const DEFAULT_CONFIG_PATH = "/config";

export interface OnConfigSavedContext {
  c: Context;
  instanceId: string;
  /** Session A — module OAuth login; UI tenancy (list/edit/delete). Not federation identity. */
  subject: string;
  /** Session B — verified configProof subject; use for host sync, grants, audit, invoke binding. */
  directorySubject: string;
  values: Record<string, unknown>;
  isNew: boolean;
}

export type OnConfigSaved = (
  ctx: OnConfigSavedContext,
) => void | Promise<void>;

export interface RenderConfigPageContext {
  c: Context;
  manifest: ConfigManifestEntry;
  configPath: string;
  subject: string | null;
  instanceId?: string;
  existingValues?: Record<string, unknown>;
  instances: ConfigInstanceEntry[];
  labelField: string | null;
  theme?: ConfigPageTheme;
}

export type RenderConfigPageResult = Response | string | void;

export type RenderConfigPage = (
  ctx: RenderConfigPageContext,
) => RenderConfigPageResult | Promise<RenderConfigPageResult>;

export interface ConfigRoutesOptions {
  moduleId: string;
  directory: DirectoryClient;
  configDefinition: ConfigDefinition;
  configStore: ConfigStore;
  oauth: HugloOAuthClient;
  oauthOptions: OAuthClientOptions;
  theme?: ConfigPageTheme;
  renderConfigPage?: RenderConfigPage;
  onConfigSaved?: OnConfigSaved;
  configProofNonceCache: NonceCache;
}

export function mountConfigRoutes(app: Hono, options: ConfigRoutesOptions): void {
  const configPath = DEFAULT_CONFIG_PATH;
  const manifest: ConfigManifestEntry = buildConfigManifest(options.configDefinition);

  app.get(configPath, (c) => serveConfigPage(c, options, manifest, configPath));

  app.get(`${configPath}/login`, (c) => {
    const existing = readConfigSession(
      getCookie(c, CONFIG_SESSION_COOKIE),
      options.oauthOptions.clientSecret,
    );
    if (existing) {
      return c.redirect(configPath);
    }

    const state = createOAuthState();
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    const cookieOpts = {
      httpOnly: true,
      secure: true,
      sameSite: "Lax" as const,
      path: "/",
      maxAge: 600,
    };
    setCookie(c, OAUTH_STATE_COOKIE, state, cookieOpts);
    setCookie(
      c,
      OAUTH_PKCE_COOKIE,
      createPkceCookie(codeVerifier, state, options.oauthOptions.clientSecret),
      cookieOpts,
    );
    return c.redirect(
      options.oauth.buildAuthorizeUrl(state, { codeChallenge }),
    );
  });

  app.get(`${configPath}/callback`, async (c) => {
    const oauthError = c.req.query("error");
    if (oauthError) {
      const description =
        c.req.query("error_description") ?? oauthError;
      clearOAuthCookies(c);
      return c.html(oauthCallbackErrorHtml(description), 400);
    }

    const code = c.req.query("code");
    const state = c.req.query("state");
    const savedState = getCookie(c, OAUTH_STATE_COOKIE);
    const codeVerifier =
      state && savedState && state === savedState
        ? readPkceCookie(
            getCookie(c, OAUTH_PKCE_COOKIE),
            state,
            options.oauthOptions.clientSecret,
          )
        : null;

    clearOAuthCookies(c);

    if (!code || !state || !savedState || state !== savedState || !codeVerifier) {
      return c.text("Invalid OAuth callback", 400);
    }

    let subject: string;
    try {
      const result = await options.oauth.exchangeCode(code, codeVerifier);
      subject = result.subject;
    } catch {
      return c.text("OAuth exchange failed", 502);
    }

    setCookie(c, CONFIG_SESSION_COOKIE, createConfigSession(subject, options.oauthOptions.clientSecret), {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
      maxAge: 86400,
    });

    return c.redirect(configPath);
  });

  app.post(`${configPath}/intake`, async (c) => handleIntake(c, options));
  app.delete(`${configPath}/instances/:instanceId`, async (c) =>
    handleDeleteInstance(c, options),
  );
}

async function buildRenderConfigPageContext(
  c: Context,
  options: ConfigRoutesOptions,
  manifest: ConfigManifestEntry,
  configPath: string,
): Promise<RenderConfigPageContext> {
  const subject = readConfigSession(
    getCookie(c, CONFIG_SESSION_COOKIE),
    options.oauthOptions.clientSecret,
  );

  const editId = c.req.query("instanceId");
  let existingValues: Record<string, unknown> | undefined;
  if (editId && subject) {
    const existing = await options.configStore.get(editId);
    if (existing?.subject === subject) {
      existingValues = existing.values;
    }
  }

  let instances: ConfigInstanceEntry[] = [];
  if (subject) {
    const raw = await options.configStore.listBySubject(subject);
    instances = raw
      .map((inst) => ({
        instanceId: inst.instanceId,
        label: formatInstanceLabel(inst.values, inst.instanceId, manifest.fields),
        values: inst.values,
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }

  const labelField = manifest.fields[0]?.name ?? null;

  return {
    c,
    manifest,
    configPath,
    subject,
    instanceId: editId,
    existingValues,
    instances,
    labelField,
    theme: options.theme,
  };
}

function defaultConfigPageHtml(ctx: RenderConfigPageContext): string {
  return configPageHtml({
    manifest: ctx.manifest,
    configPath: ctx.configPath,
    authenticated: ctx.subject !== null,
    instanceId: ctx.instanceId,
    existingValues: ctx.existingValues,
    instances: ctx.instances,
    labelField: ctx.labelField,
    theme: ctx.theme,
  });
}

function toConfigPageResponse(c: Context, result: Response | string): Response {
  if (typeof result === "string") {
    return c.html(result);
  }
  return result;
}

async function serveConfigPage(
  c: Context,
  options: ConfigRoutesOptions,
  manifest: ConfigManifestEntry,
  configPath: string,
): Promise<Response> {
  const ctx = await buildRenderConfigPageContext(c, options, manifest, configPath);

  if (options.renderConfigPage) {
    const result = await options.renderConfigPage(ctx);
    if (result !== undefined) {
      return toConfigPageResponse(c, result);
    }
  }

  return c.html(defaultConfigPageHtml(ctx));
}

type IntakeBody = {
  userValues?: Record<string, unknown>;
  hostValues?: Record<string, unknown>;
  instanceId?: string;
  configProof?: unknown;
};

async function parseIntakeBody(c: Context): Promise<IntakeBody | Response> {
  try {
    return await c.req.json<IntakeBody>();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }
}

function proofVerificationErrorResponse(c: Context, err: unknown): Response {
  if (err instanceof ModuleError) {
    const status = err.code.startsWith("config_proof_") ? 403 : 400;
    return c.json({ error: err.message, code: err.code }, status);
  }
  return c.json({ error: "Invalid config proof" }, 403);
}

function assemblyErrorResponse(c: Context, err: unknown): Response {
  if (err instanceof ConfigAssemblyError) {
    return c.json({ error: err.message }, 400);
  }
  return c.json({ error: "Validation failed" }, 400);
}

function assembleIntakeValues(
  options: ConfigRoutesOptions,
  userValues: Record<string, unknown>,
  hostValues: Record<string, unknown>,
): Record<string, unknown> {
  const assembled = assembleConfigValues({
    definition: options.configDefinition,
    userValues,
    hostValues,
  });
  return assembled.values;
}

async function validateIntakeEditAccess(
  c: Context,
  configStore: ConfigStore,
  instanceId: string,
  subject: string,
): Promise<Response | null> {
  const existing = await configStore.get(instanceId);
  if (!existing) {
    return c.json({ error: "Instance not found" }, 404);
  }
  if (existing.subject !== subject) {
    return c.json({ error: "Forbidden" }, 403);
  }
  return null;
}

async function handleIntake(
  c: Context,
  options: ConfigRoutesOptions,
): Promise<Response> {
  const subject = readConfigSession(
    getCookie(c, CONFIG_SESSION_COOKIE),
    options.oauthOptions.clientSecret,
  );
  if (!subject) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const body = await parseIntakeBody(c);
  if (body instanceof Response) {
    return body;
  }

  if (body.configProof === undefined) {
    return c.json({ error: "Config proof required" }, 400);
  }

  let directorySubject: string;
  try {
    directorySubject = await verifyConfigProof(body.configProof, {
      moduleId: options.moduleId,
      directory: options.directory,
      nonceCache: options.configProofNonceCache,
    });
  } catch (err) {
    return proofVerificationErrorResponse(c, err);
  }

  let values: Record<string, unknown>;
  try {
    values = assembleIntakeValues(
      options,
      body.userValues ?? {},
      body.hostValues ?? {},
    );
  } catch (err) {
    return assemblyErrorResponse(c, err);
  }

  const isNew = !body.instanceId;
  const instanceId = body.instanceId ?? randomUUID();

  if (!isNew) {
    const editError = await validateIntakeEditAccess(
      c,
      options.configStore,
      instanceId,
      subject,
    );
    if (editError) {
      return editError;
    }
  }

  await options.configStore.set({ instanceId, subject, directorySubject, values });

  if (options.onConfigSaved) {
    await options.onConfigSaved({
      c,
      instanceId,
      subject,
      directorySubject,
      values,
      isNew,
    });
  }

  return c.json({ instanceId });
}

async function handleDeleteInstance(
  c: Context,
  options: ConfigRoutesOptions,
): Promise<Response> {
  const subject = readConfigSession(
    getCookie(c, CONFIG_SESSION_COOKIE),
    options.oauthOptions.clientSecret,
  );
  if (!subject) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const instanceId = c.req.param("instanceId");
  if (!instanceId) {
    return c.json({ error: "Instance not found" }, 404);
  }

  const existing = await options.configStore.get(instanceId);
  if (!existing) {
    return c.json({ error: "Instance not found" }, 404);
  }
  if (existing.subject !== subject) {
    return c.json({ error: "Forbidden" }, 403);
  }

  await options.configStore.delete(instanceId);
  return c.json({ ok: true });
}

function clearOAuthCookies(c: Context): void {
  deleteCookie(c, OAUTH_STATE_COOKIE, { path: "/" });
  deleteCookie(c, OAUTH_PKCE_COOKIE, { path: "/" });
}

function oauthCallbackErrorHtml(message: string): string {
  const escaped = message
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Login failed</title>
</head>
<body>
  <p>Could not sign in with Huglo: ${escaped}</p>
</body>
</html>`;
}

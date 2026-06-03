import { Hono } from "hono";
import type { Context } from "hono";
import { randomUUID } from "node:crypto";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import type { ConfigDefinition } from "./config.js";
import { assembleConfigValues, ConfigAssemblyError, formatInstanceLabel } from "./config.js";
import type { ConfigStore } from "./config-store.js";
import type { ConfigManifestEntry } from "./manifest.js";
import { buildConfigManifest } from "./manifest.js";
import { configPageHtml } from "./config-page.js";
import type { ConfigPageTheme } from "./config-page.js";
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
  subject: string;
  values: Record<string, unknown>;
  isNew: boolean;
}

export type OnConfigSaved = (
  ctx: OnConfigSavedContext,
) => void | Promise<void>;

export interface ConfigRoutesOptions {
  configDefinition: ConfigDefinition;
  configStore: ConfigStore;
  oauth: HugloOAuthClient;
  oauthOptions: OAuthClientOptions;
  configPath?: string;
  /** When set, the default page is not served; manifest exposes this URL instead. */
  configPageUrl?: string;
  theme?: ConfigPageTheme;
  onConfigSaved?: OnConfigSaved;
}

export function mountConfigRoutes(app: Hono, options: ConfigRoutesOptions): void {
  const configPath = normalizePath(options.configPath ?? DEFAULT_CONFIG_PATH);
  const manifest: ConfigManifestEntry = buildConfigManifest(options.configDefinition);

  if (!options.configPageUrl) {
    app.get(configPath, (c) => serveConfigPage(c, options, manifest, configPath));
  }

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

async function serveConfigPage(
  c: Context,
  options: ConfigRoutesOptions,
  manifest: ConfigManifestEntry,
  configPath: string,
): Promise<Response> {
  const subject = readConfigSession(
    getCookie(c, CONFIG_SESSION_COOKIE),
    options.oauthOptions.clientSecret,
  );

  const editId = c.req.query("instanceId");
  let existingValues: Record<string, unknown> | undefined;
  if (editId && subject) {
    const existing = await options.configStore.get(editId);
    if (existing && existing.subject === subject) {
      existingValues = existing.values;
    }
  }

  let instances: Array<{
    instanceId: string;
    label: string;
    values: Record<string, unknown>;
  }> = [];
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

  return c.html(
    configPageHtml({
      manifest,
      configPath,
      authenticated: !!subject,
      instanceId: editId,
      existingValues,
      instances,
      labelField,
      theme: options.theme,
    }),
  );
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

  let body: {
    userValues?: Record<string, unknown>;
    hostValues?: Record<string, unknown>;
    instanceId?: string;
  };
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Invalid JSON body" }, 400);
  }

  const userValues = body.userValues ?? {};
  const hostValues = body.hostValues ?? {};

  let values: Record<string, unknown>;
  try {
    const assembled = assembleConfigValues({
      definition: options.configDefinition,
      userValues,
      hostValues,
    });
    values = assembled.values;
  } catch (err) {
    if (err instanceof ConfigAssemblyError) {
      return c.json({ error: err.message }, 400);
    }
    return c.json({ error: "Validation failed" }, 400);
  }

  const isNew = !body.instanceId;
  const instanceId = body.instanceId ?? randomUUID();

  if (!isNew) {
    const existing = await options.configStore.get(instanceId);
    if (!existing) {
      return c.json({ error: "Instance not found" }, 404);
    }
    if (existing.subject !== subject) {
      return c.json({ error: "Forbidden" }, 403);
    }
  }

  await options.configStore.set({ instanceId, subject, values });

  if (options.onConfigSaved) {
    await options.onConfigSaved({
      c,
      instanceId,
      subject,
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

function normalizePath(path: string): string {
  return path.startsWith("/") ? path : `/${path}`;
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

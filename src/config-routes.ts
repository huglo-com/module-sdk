import { Hono } from "hono";
import type { Context } from "hono";
import { randomUUID } from "node:crypto";
import { getCookie, setCookie, deleteCookie } from "hono/cookie";
import type { ConfigDefinition } from "./config.js";
import { assembleConfigValues, ConfigAssemblyError } from "./config.js";
import type { ConfigStore } from "./config-store.js";
import type { ConfigManifestEntry } from "./manifest.js";
import { buildConfigManifest } from "./manifest.js";
import { configPageHtml } from "./config-page.js";
import type { ConfigPageTheme } from "./config-page.js";
import {
  CONFIG_SESSION_COOKIE,
  OAUTH_STATE_COOKIE,
  createConfigSession,
  readConfigSession,
  createOAuthState,
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
    setCookie(c, OAUTH_STATE_COOKIE, state, {
      httpOnly: true,
      secure: true,
      sameSite: "Lax",
      path: "/",
      maxAge: 600,
    });
    return c.redirect(options.oauth.buildAuthorizeUrl(state));
  });

  app.get(`${configPath}/callback`, async (c) => {
    const code = c.req.query("code");
    const state = c.req.query("state");
    const savedState = getCookie(c, OAUTH_STATE_COOKIE);

    deleteCookie(c, OAUTH_STATE_COOKIE, { path: "/" });

    if (!code || !state || !savedState || state !== savedState) {
      return c.text("Invalid OAuth callback", 400);
    }

    let subject: string;
    try {
      const result = await options.oauth.exchangeCode(code);
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

  return c.html(
    configPageHtml({
      manifest,
      configPath,
      authenticated: !!subject,
      instanceId: editId,
      existingValues,
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

function normalizePath(path: string): string {
  return path.startsWith("/") ? path : `/${path}`;
}

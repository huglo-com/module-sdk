/**
 * Custom config example — session A: demo login; session B: configProof from host.
 *
 * Demo users: alice / demo-alice, bob / demo-bob
 *
 *   npm run build
 *   node examples/custom-config/index.ts
 *
 * Open host.html to configure (must be logged into Huglo on the directory for mint).
 *
 * Set MODULE_PRIVATE_KEY_PATH (or MODULE_PRIVATE_KEY) before running — see .env.
 */
import { Hono } from "hono";
import type { Context } from "hono";
import { getCookie, setCookie } from "hono/cookie";
import { randomUUID } from "node:crypto";
import { z } from "zod";
import {
  Module,
  ModuleError,
  InMemoryGrantStore,
  HttpDirectoryClient,
  loadKeyPair,
  verifyConfigProof,
  CONFIG_READY_MESSAGE,
  CONFIG_SAVED_MESSAGE,
} from "../../dist/index.js";
import { NonceCache } from "../../dist/verify.js";

/* =============================================================================
 * Example constants
 *
 * Real modules would read these from config or env without fallbacks sprinkled through the code.
 * ============================================================================= */

const MODULE_ID = "acme-connector";
const PORT = 3201;
const ENDPOINT = `http://127.0.0.1:${PORT}`;
const DIRECTORY_URL = "https://account.huglo.com";
const SESSION_COOKIE = "demo_config_session";

/* =============================================================================
 * Session A — module account (your auth, not Huglo)
 *
 * Custom config means you own the login UI and tenancy rules. Here we use a
 * tiny in-memory user list. Session A controls who can open the config form and
 * which saved instances they may edit (subject field).
 * 
 * This does NOT prove which Huglo user is configuring — that is session B (configProof).
 * ============================================================================= */

const USERS = [
  { username: "alice", password: "demo-alice" },
  { username: "bob", password: "demo-bob" },
];

function accountSubject(username: string): string {
  return `demo:user:${username}`;
}

function loggedInUser(c: Context): string | null {
  const username = getCookie(c, SESSION_COOKIE);
  if (!username || !USERS.some((u) => u.username === username)) {
    return null;
  }
  return username;
}

/* =============================================================================
 * Session B — config proof verification (Huglo federation)
 *
 * Account linked to session A does not have to be the same as the Huglo user.
 * Custom config needs to stamp the Huglo user's subject on the config instance.
 * this stamp is a cryptographic proof that the Huglo user is the owner of the config instance.
 *
 * directory client + nonce cache are shared by verifyConfigProof on every save.
 * The directory signs configProof with the Huglo user's key; we verify signature,
 * audience, expiry, and single-use nonce before stamping directorySubject.
 *
 * With customConfig() the SDK does NOT call verifyConfigProof for you — unlike
 * managed module.config() which verifies on POST /config/intake automatically.
 * ============================================================================= */

const configProofNonceCache = new NonceCache();
const directory = new HttpDirectoryClient({ directoryUrl: DIRECTORY_URL });

/* =============================================================================
 * Config storage
 *
 * In production use your database. Each instance stores:
 *   subject          — session A owner (module account)
 *   directorySubject — session B owner (verified Huglo user from configProof)
 *
 * Invoke enforcement compares directorySubject to ctx.subject (grant subject).
 * ============================================================================= */

interface StoredConfig {
  apiKey: string;
  webhookUrl: string;
  subject: string;
  directorySubject: string;
}

const configStore = new Map<string, StoredConfig>();

/* =============================================================================
 * Helpers
 *
 * escapeHtml — inline HTML template for the config page; must escape user data.
 * ============================================================================= */

function escapeHtml(value: string): string {
  return value
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

/* =============================================================================
 * Config page (HTML + client script)
 *
 * Served at GET /config. The popup must:
 *   1. postMessage huglo:config:ready so the host sends configProof (session B)
 *   2. let the user sign in (session A) then POST /config/save with both
 *   3. postMessage huglo:config:saved + instanceId back to the host
 *
 * In production you might serve a SPA or separate static assets instead of one
 * template string — the handshake messages stay the same.
 * ============================================================================= */

function buildConfigPageHtml(options: {
  instanceId: string;
  existing?: StoredConfig;
  authenticated: boolean;
}): string {
  const apiKey = escapeHtml(options.existing?.apiKey ?? "");
  const webhookUrl = escapeHtml(options.existing?.webhookUrl ?? "");
  const instanceId = escapeHtml(options.instanceId);
  const ready = JSON.stringify(CONFIG_READY_MESSAGE);
  const saved = JSON.stringify(CONFIG_SAVED_MESSAGE);

  const loginBlock = options.authenticated
    ? ""
    : `<section>
  <h2>Sign in</h2>
  <form id="login-form">
    <label for="username">Username</label>
    <input type="text" id="username" required>
    <label for="password">Password</label>
    <input type="password" id="password" required>
    <button type="submit">Sign in</button>
    <p id="login-error" class="error" hidden></p>
  </form>
</section>`;

  const configBlock = options.authenticated
    ? `<section>
  <h2>Settings</h2>
  <form id="config-form">
    <input type="hidden" id="instance-id" value="${instanceId}">
    <label for="api-key">API key</label>
    <input type="text" id="api-key" value="${apiKey}" required>
    <label for="webhook-url">Webhook URL</label>
    <input type="url" id="webhook-url" value="${webhookUrl}" required>
    <button type="submit" id="save-btn">Save</button>
    <p id="config-message" class="message" hidden></p>
  </form>
</section>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>${MODULE_ID} config</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 28rem; margin: 2rem auto; padding: 0 1rem; }
    label { display: block; margin-top: 0.75rem; font-size: 0.875rem; }
    input { width: 100%; padding: 0.5rem; margin-top: 0.25rem; }
    button { margin-top: 1rem; padding: 0.5rem 1rem; }
    .error { color: #b91c1c; }
    .message.success { color: #15803d; }
    .message.error { color: #b91c1c; }
    #host-warn { color: #71717a; font-size: 0.875rem; }
  </style>
</head>
<body>
  <h1>${MODULE_ID}</h1>
  <p id="host-warn" hidden>Open from host.html so the host can send configProof.</p>
  ${loginBlock}
  ${configBlock}
  <script>
    const CONFIG_READY = ${ready};
    const CONFIG_SAVED = ${saved};
    let configProof = null;

    window.addEventListener("message", (event) => {
      const data = event.data;
      if (data && typeof data === "object" && "configProof" in data) {
        configProof = data.configProof;
      }
    });

    function notifyReady() {
      const msg = { type: CONFIG_READY };
      if (window.opener) window.opener.postMessage(msg, "*");
      else if (window.parent !== window) window.parent.postMessage(msg, "*");
    }
    notifyReady();

    if (!window.opener && window.parent === window) {
      document.getElementById("host-warn").hidden = false;
    }

    document.getElementById("login-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const errEl = document.getElementById("login-error");
      errEl.hidden = true;
      const res = await fetch("/config/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({
          username: document.getElementById("username").value.trim(),
          password: document.getElementById("password").value,
        }),
      });
      if (!res.ok) {
        errEl.textContent = "Invalid username or password";
        errEl.hidden = false;
        return;
      }
      location.reload();
    });

    document.getElementById("config-form")?.addEventListener("submit", async (e) => {
      e.preventDefault();
      const msgEl = document.getElementById("config-message");
      const btn = document.getElementById("save-btn");
      msgEl.hidden = true;
      btn.disabled = true;
      try {
        if (!configProof) {
          msgEl.textContent = "Missing configProof from host";
          msgEl.className = "message error";
          msgEl.hidden = false;
          return;
        }
        const body = {
          apiKey: document.getElementById("api-key").value.trim(),
          webhookUrl: document.getElementById("webhook-url").value.trim(),
          configProof,
        };
        const instanceId = document.getElementById("instance-id").value.trim();
        if (instanceId) body.instanceId = instanceId;

        const res = await fetch("/config/save", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify(body),
        });
        const json = await res.json();
        if (!res.ok) {
          msgEl.textContent = json.error || "Save failed";
          msgEl.className = "message error";
          msgEl.hidden = false;
          return;
        }

        msgEl.textContent = "Saved: " + json.instanceId;
        msgEl.className = "message success";
        msgEl.hidden = false;
        document.getElementById("instance-id").value = json.instanceId;

        const savedMsg = { type: CONFIG_SAVED, instanceId: json.instanceId };
        if (window.opener) {
          window.opener.postMessage(savedMsg, "*");
          window.close();
        } else if (window.parent !== window) {
          window.parent.postMessage(savedMsg, "*");
        }
      } finally {
        btn.disabled = false;
      }
    });
  </script>
</body>
</html>`;
}

/* =============================================================================
 * Config routes (mounted at /config by module.customConfig)
 *
 * GET  /        — config page (session A gate for edit ownership)
 * POST /login   — session A: set module-account cookie
 * POST /save    — session A required + session B verifyConfigProof → store instance
 *
 * This is the main difference from managed config: you implement these handlers
 * and must call verifyConfigProof yourself on save.
 * ============================================================================= */

const configRoutes = new Hono();

configRoutes.get("/", (c) => {
  const instanceId = c.req.query("instanceId") ?? "";
  const username = loggedInUser(c);
  const existing = instanceId ? configStore.get(instanceId) : undefined;
  if (existing && username && existing.subject !== accountSubject(username)) {
    return c.text("Forbidden", 403);
  }
  return c.html(
    buildConfigPageHtml({
      instanceId,
      existing,
      authenticated: username !== null,
    }),
  );
});

configRoutes.post("/login", async (c) => {
  const body = (await c.req.json());
  const user = USERS.find((u) => u.username === body.username && u.password === body.password);
  if (!user) {
    return c.json({ error: "Invalid credentials" }, 401);
  }
  setCookie(c, SESSION_COOKIE, user.username, {
    httpOnly: true,
    secure: false,
    path: "/",
    maxAge: 86400,
    sameSite: "Lax",
  });
  return c.json({ ok: true });
});

configRoutes.post("/save", async (c) => {
  const username = loggedInUser(c);
  if (!username) {
    return c.json({ error: "Authentication required" }, 401);
  }

  const body = (await c.req.json());

  if (body.configProof === undefined) {
    return c.json({ error: "Config proof required" }, 400);
  }

  let directorySubject: string;
  try {
    directorySubject = await verifyConfigProof(body.configProof, {
      moduleId: MODULE_ID,
      directory,
      nonceCache: configProofNonceCache,
    });
  } catch (err) {
    const message = err instanceof ModuleError ? err.message : "Invalid config proof";
    return c.json({ error: message }, 403);
  }

  if (!body.apiKey?.trim() || !body.webhookUrl?.trim()) {
    return c.json({ error: "apiKey and webhookUrl are required" }, 400);
  }

  const subject = accountSubject(username);
  const instanceId = body.instanceId ?? randomUUID();

  if (body.instanceId) {
    const existing = configStore.get(body.instanceId);
    if (!existing) {
      return c.json({ error: "Instance not found" }, 404);
    }
    if (existing.subject !== subject) {
      return c.json({ error: "Forbidden" }, 403);
    }
  }

  configStore.set(instanceId, {
    apiKey: body.apiKey.trim(),
    webhookUrl: body.webhookUrl.trim(),
    subject,
    directorySubject,
  });

  return c.json({ instanceId });
});

/* =============================================================================
 * Module setup
 *
 * Module wires manifest, invoke, grants, and mounts customConfig routes.
 * customConfig() and config() are mutually exclusive — pick one per module.
 * ============================================================================= */

const keyPair = loadKeyPair();

const module = new Module({
  id: MODULE_ID,
  name: "Acme Connector",
  description: "Custom config example",
  version: "1.0.0",
  keyPair,
  directory,
  endpoint: ENDPOINT,
  grantStore: new InMemoryGrantStore(),
});

module.customConfig(configRoutes);

/* =============================================================================
 * Scopes (invoke)
 *
 * Host passes configInstanceId in the request context. We load the stored config
 * and reject if directorySubject !== ctx.subject so user A's grant cannot invoke
 * user B's instance. Managed config enforces this in the SDK; custom config must
 * do it in each handler that reads stored settings.
 * ============================================================================= */

module.scope("webhook:ping", {
  description: "Return stored webhook settings",
  input: z.object({
    context: z.object({ configInstanceId: z.string() }),
  }),
  output: z.object({
    webhookUrl: z.url(),
    apiKeyHint: z.string(),
  }),
  handler: async (ctx) => {
    const stored = configStore.get(ctx.input.context.configInstanceId);
    if (!stored) {
      throw new ModuleError({
        code: "config_not_found",
        message: "Config instance not found",
        retryable: false,
      });
    }
    if (stored.directorySubject !== ctx.subject) {
      throw new ModuleError({
        code: "config_subject_mismatch",
        message: "Config instance does not belong to grant subject",
        retryable: false,
      });
    }
    return {
      webhookUrl: stored.webhookUrl,
      apiKeyHint: `${stored.apiKey.slice(0, 4)}…`,
    };
  },
});

/* =============================================================================
 * Start
 * ============================================================================= */

await module.listen(PORT, "127.0.0.1");

console.log(`Listening on ${ENDPOINT}`);
console.log(`  Config: ${ENDPOINT}/config`);

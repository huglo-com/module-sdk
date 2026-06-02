import type { ConfigManifestEntry } from "./manifest.js";

export interface ConfigPageTheme {
  logoUrl?: string;
  accentColor?: string;
}

export interface ConfigPageOptions {
  manifest: ConfigManifestEntry;
  configPath: string;
  authenticated: boolean;
  instanceId?: string;
  existingValues?: Record<string, unknown>;
  theme?: ConfigPageTheme;
}

/** Default SDK config page: schema-rendered form, login, host-prefill via postMessage. */
export function configPageHtml(options: ConfigPageOptions): string {
  const accent = options.theme?.accentColor ?? "#4f46e5";
  const logo = options.theme?.logoUrl
    ? `<img src="${escapeAttr(options.theme.logoUrl)}" alt="" class="logo" />`
    : "";

  const fieldsJson = escapeScriptJson(JSON.stringify(options.manifest.fields));
  const existingJson = escapeScriptJson(
    JSON.stringify(options.existingValues ?? {}),
  );
  const instanceIdJson = escapeScriptJson(
    JSON.stringify(options.instanceId ?? null),
  );

  const loginSection = options.authenticated
    ? ""
    : `<p class="login-prompt"><a href="${escapeAttr(options.configPath)}/login">Sign in with Huglo</a> to configure this module.</p>`;

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Module configuration</title>
  <style>
    :root { --accent: ${escapeAttr(accent)}; }
    * { box-sizing: border-box; }
    body { font-family: system-ui, sans-serif; margin: 0; padding: 1.5rem; max-width: 32rem; color: #111; }
    .logo { max-height: 2.5rem; margin-bottom: 1rem; }
    h1 { font-size: 1.25rem; margin: 0 0 1rem; }
    label { display: block; font-size: 0.875rem; font-weight: 500; margin-bottom: 0.25rem; }
    .field { margin-bottom: 1rem; }
    input, select { width: 100%; padding: 0.5rem; border: 1px solid #ccc; border-radius: 0.375rem; font-size: 1rem; }
    input:disabled, select:disabled { background: #f4f4f5; color: #71717a; }
    input[type="checkbox"] { width: auto; }
    button { background: var(--accent); color: #fff; border: none; padding: 0.625rem 1.25rem; border-radius: 0.375rem; font-size: 1rem; cursor: pointer; }
    button:disabled { opacity: 0.5; cursor: not-allowed; }
    .login-prompt { margin-bottom: 1rem; }
    .login-prompt a { color: var(--accent); }
    .message { margin-top: 1rem; font-size: 0.875rem; }
    .message.error { color: #b91c1c; }
    .message.success { color: #15803d; }
    .locked-readonly { font-size: 0.875rem; color: #71717a; padding: 0.5rem 0; }
  </style>
</head>
<body>
  ${logo}
  <h1>Configuration</h1>
  ${loginSection}
  <form id="config-form" ${options.authenticated ? "" : 'style="display:none"'}>
    <div id="fields"></div>
    <button type="submit" id="submit-btn">Save</button>
    <p id="message" class="message" hidden></p>
  </form>
  <script>
    const FIELDS = ${fieldsJson};
    const EXISTING = ${existingJson};
    const INSTANCE_ID = ${instanceIdJson};
    const INTAKE_URL = ${escapeScriptJson(JSON.stringify(options.configPath + "/intake"))};
    const AUTHENTICATED = ${options.authenticated ? "true" : "false"};

    const hostValues = {};

    function fieldInputType(field) {
      const t = field.type;
      if (t && t.type === "boolean") return "checkbox";
      if (t && Array.isArray(t.enum)) return "select";
      if (t && t.type === "number" || t && t.type === "integer") return "number";
      return "text";
    }

    function renderFields() {
      const container = document.getElementById("fields");
      container.innerHTML = "";
      for (const field of FIELDS) {
        if (field.source === "locked") continue;

        const wrap = document.createElement("div");
        wrap.className = "field";
        const label = document.createElement("label");
        label.textContent = field.name;
        label.setAttribute("for", "f-" + field.name);
        wrap.appendChild(label);

        const inputType = fieldInputType(field);
        const existing = EXISTING[field.name];
        const hostVal = hostValues[field.name];

        if (field.source === "hostProvided") {
          const ro = document.createElement("input");
          ro.type = "text";
          ro.id = "f-" + field.name;
          ro.name = field.name;
          ro.value = hostVal !== undefined ? String(hostVal) : (existing !== undefined ? String(existing) : "");
          ro.disabled = true;
          ro.dataset.source = "hostProvided";
          wrap.appendChild(ro);
        } else if (inputType === "checkbox") {
          const cb = document.createElement("input");
          cb.type = "checkbox";
          cb.id = "f-" + field.name;
          cb.name = field.name;
          cb.checked = existing === true || existing === "true";
          cb.dataset.source = "userEntered";
          wrap.appendChild(cb);
        } else if (inputType === "select") {
          const sel = document.createElement("select");
          sel.id = "f-" + field.name;
          sel.name = field.name;
          sel.dataset.source = "userEntered";
          for (const opt of field.type.enum) {
            const o = document.createElement("option");
            o.value = String(opt);
            o.textContent = String(opt);
            if (String(existing) === String(opt)) o.selected = true;
            sel.appendChild(o);
          }
          wrap.appendChild(sel);
        } else {
          const inp = document.createElement("input");
          inp.type = inputType;
          inp.id = "f-" + field.name;
          inp.name = field.name;
          inp.value = existing !== undefined ? String(existing) : "";
          inp.dataset.source = "userEntered";
          wrap.appendChild(inp);
        }
        container.appendChild(wrap);
      }
    }

    function collectUserValues() {
      const user = {};
      const form = document.getElementById("config-form");
      for (const el of form.querySelectorAll("[name]")) {
        if (el.dataset.source !== "userEntered") continue;
        if (el.type === "checkbox") {
          user[el.name] = el.checked;
        } else if (el.type === "number") {
          user[el.name] = el.value === "" ? undefined : Number(el.value);
        } else {
          user[el.name] = el.value;
        }
      }
      return user;
    }

    function showMessage(text, kind) {
      const msg = document.getElementById("message");
      msg.textContent = text;
      msg.className = "message " + (kind || "");
      msg.hidden = false;
    }

    window.addEventListener("message", (event) => {
      const data = event.data;
      if (!data || typeof data !== "object" || Array.isArray(data)) return;
      for (const [key, value] of Object.entries(data)) {
        hostValues[key] = value;
      }
      renderFields();
    });

    if (window.parent !== window) {
      window.parent.postMessage({ type: "huglo:config:ready" }, "*");
    }

    document.getElementById("config-form").addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = document.getElementById("submit-btn");
      btn.disabled = true;
      try {
        const body = {
          userValues: collectUserValues(),
          hostValues: { ...hostValues },
        };
        if (INSTANCE_ID) body.instanceId = INSTANCE_ID;

        const res = await fetch(INTAKE_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
          body: JSON.stringify(body),
        });
        const json = await res.json();
        if (!res.ok) {
          showMessage(json.error || "Save failed", "error");
          return;
        }
        showMessage("Saved. Instance: " + json.instanceId, "success");
        if (window.opener) {
          window.opener.postMessage(
            { type: "huglo:config:saved", instanceId: json.instanceId },
            "*",
          );
          window.close();
        } else if (window.parent !== window) {
          window.parent.postMessage({ type: "huglo:config:saved", instanceId: json.instanceId }, "*");
        }
      } catch (err) {
        showMessage("Save failed", "error");
      } finally {
        btn.disabled = false;
      }
    });

    if (AUTHENTICATED) {
      renderFields();
    }
  </script>
</body>
</html>`;
}

function escapeHtml(text: string): string {
  return text
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function escapeAttr(text: string): string {
  return escapeHtml(text);
}

/** Escape JSON for safe embedding in a script tag. */
function escapeScriptJson(json: string): string {
  return json
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026");
}

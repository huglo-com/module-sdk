import type { ConfigManifestEntry } from "./manifest.js";

export interface ConfigPageTheme {
  logoUrl?: string;
  accentColor?: string;
}

export interface ConfigInstanceEntry {
  instanceId: string;
  label: string;
  values: Record<string, unknown>;
}

export interface ConfigPageOptions {
  manifest: ConfigManifestEntry;
  configPath: string;
  authenticated: boolean;
  instanceId?: string;
  existingValues?: Record<string, unknown>;
  instances?: ConfigInstanceEntry[];
  labelField?: string | null;
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
  const instancesJson = escapeScriptJson(
    JSON.stringify(options.instances ?? []),
  );
  const labelFieldJson = escapeScriptJson(
    JSON.stringify(options.labelField ?? null),
  );

  const instances = options.instances ?? [];
  const selectedId = options.instanceId;
  const hasSelectedInstance =
    selectedId !== undefined &&
    instances.some((inst) => inst.instanceId === selectedId);

  const instanceOptions = instances
    .map(
      (inst) =>
        `<option value="${escapeAttr(inst.instanceId)}"${inst.instanceId === selectedId ? " selected" : ""}>${escapeHtml(inst.label)}</option>`,
    )
    .join("");

  const loginSection = options.authenticated
    ? ""
    : `<p class="login-prompt"><a href="${escapeAttr(options.configPath)}/login">Sign in with Huglo</a> to configure this module.</p>`;

  const pickerSection = options.authenticated
    ? `<div class="field" id="config-picker">
    <label for="config-select">Configuration</label>
    <select id="config-select">
      ${instanceOptions}
      <option value="__new__"${hasSelectedInstance ? "" : " selected"}>New configuration</option>
    </select>
    <button type="button" id="delete-btn"${hasSelectedInstance ? "" : " hidden"}>Delete</button>
  </div>`
    : "";

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
    #delete-btn { background: transparent; color: #b91c1c; border: 1px solid #fecaca; margin-top: 0.5rem; width: auto; }
    #delete-btn:hover { background: #fef2f2; }
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
    ${pickerSection}
    <div id="fields"></div>
    <button type="submit" id="submit-btn">Save</button>
    <p id="message" class="message" hidden></p>
  </form>
  <script>
    const FIELDS = ${fieldsJson};
    const EXISTING = ${existingJson};
    const INSTANCE_ID = ${instanceIdJson};
    const INSTANCES_LIST = ${instancesJson};
    const LABEL_FIELD = ${labelFieldJson};
    const INTAKE_URL = ${escapeScriptJson(JSON.stringify(options.configPath + "/intake"))};
    const CONFIG_PATH = ${escapeScriptJson(JSON.stringify(options.configPath))};
    const DELETE_URL_BASE = ${escapeScriptJson(JSON.stringify(options.configPath + "/instances/"))};
    const AUTHENTICATED = ${options.authenticated ? "true" : "false"};

    const INSTANCES = {};
    for (const inst of INSTANCES_LIST) {
      INSTANCES[inst.instanceId] = { label: inst.label, values: inst.values };
    }

    const HOST_PROVIDED_FIELDS = new Set(
      FIELDS.filter(function (f) { return f.source === "hostProvided"; }).map(function (f) { return f.name; }),
    );

    const hostValues = {};
    let instanceId = INSTANCE_ID;
    let currentValues = Object.assign({}, EXISTING);
    let selectorEnabled = true;

    function fieldInputType(field) {
      const t = field.type;
      if (t && t.type === "boolean") return "checkbox";
      if (t && Array.isArray(t.enum)) return "select";
      if (t && t.type === "number" || t && t.type === "integer") return "number";
      return "text";
    }

    function getFieldValues() {
      return selectorEnabled ? currentValues : EXISTING;
    }

    function truncateId(id) {
      return id.length <= 8 ? id : id.slice(0, 8) + "\\u2026";
    }

    function formatLabel(values, id) {
      if (!LABEL_FIELD) return truncateId(id);
      const v = values[LABEL_FIELD];
      if (typeof v === "string" && v.trim() !== "") return v;
      return truncateId(id);
    }

    function renderFields() {
      const container = document.getElementById("fields");
      container.innerHTML = "";
      const fieldValues = getFieldValues();
      for (const field of FIELDS) {
        if (field.source === "locked") continue;

        const wrap = document.createElement("div");
        wrap.className = "field";
        const label = document.createElement("label");
        label.textContent = field.name;
        label.setAttribute("for", "f-" + field.name);
        wrap.appendChild(label);

        const inputType = fieldInputType(field);
        const existing = fieldValues[field.name];
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

    function disableSelector() {
      if (!selectorEnabled) return;
      selectorEnabled = false;
      instanceId = INSTANCE_ID;
      const picker = document.getElementById("config-picker");
      if (picker) picker.hidden = true;
      renderFields();
    }

    function updateDeleteButton() {
      const btn = document.getElementById("delete-btn");
      if (!btn || !selectorEnabled) return;
      const sel = document.getElementById("config-select");
      btn.hidden = !sel || sel.value === "__new__";
    }

    function rebuildSelectorOptions() {
      const sel = document.getElementById("config-select");
      if (!sel) return;
      const current = sel.value;
      sel.innerHTML = "";
      const entries = Object.entries(INSTANCES)
        .map(function (entry) { return { id: entry[0], label: entry[1].label }; })
        .sort(function (a, b) { return a.label.localeCompare(b.label); });
      for (const entry of entries) {
        const opt = document.createElement("option");
        opt.value = entry.id;
        opt.textContent = entry.label;
        sel.appendChild(opt);
      }
      const newOpt = document.createElement("option");
      newOpt.value = "__new__";
      newOpt.textContent = "New configuration";
      sel.appendChild(newOpt);
      if (current && (current === "__new__" || INSTANCES[current])) {
        sel.value = current;
      }
      updateDeleteButton();
    }

    function selectNewConfig() {
      instanceId = null;
      currentValues = {};
      history.replaceState(null, "", CONFIG_PATH);
      const sel = document.getElementById("config-select");
      if (sel) sel.value = "__new__";
      updateDeleteButton();
      renderFields();
    }

    function selectExistingConfig(id) {
      instanceId = id;
      currentValues = Object.assign({}, INSTANCES[id].values);
      history.replaceState(null, "", CONFIG_PATH + "?instanceId=" + encodeURIComponent(id));
      updateDeleteButton();
      renderFields();
    }

    window.addEventListener("message", function (event) {
      const data = event.data;
      if (!data || typeof data !== "object" || Array.isArray(data)) return;
      for (const entry of Object.entries(data)) {
        if (entry[0] === "type") continue;
        hostValues[entry[0]] = entry[1];
      }
      const hostContext = Object.keys(hostValues).some(function (k) {
        return HOST_PROVIDED_FIELDS.has(k);
      });
      if (hostContext) disableSelector();
      renderFields();
    });

    function notifyReady() {
      var msg = { type: "huglo:config:ready" };
      if (window.opener) {
        window.opener.postMessage(msg, "*");
      } else if (window.parent !== window) {
        window.parent.postMessage(msg, "*");
      }
    }
    notifyReady();

    const configSelect = document.getElementById("config-select");
    if (configSelect) {
      configSelect.addEventListener("change", function () {
        if (!selectorEnabled) return;
        if (configSelect.value === "__new__") {
          selectNewConfig();
        } else {
          selectExistingConfig(configSelect.value);
        }
      });
    }

    const deleteBtn = document.getElementById("delete-btn");
    if (deleteBtn) {
      deleteBtn.addEventListener("click", async function () {
        if (!selectorEnabled || !instanceId) return;
        if (!confirm("Delete this configuration?")) return;
        deleteBtn.disabled = true;
        try {
          const res = await fetch(DELETE_URL_BASE + encodeURIComponent(instanceId), {
            method: "DELETE",
            credentials: "same-origin",
          });
          const json = await res.json();
          if (!res.ok) {
            showMessage(json.error || "Delete failed", "error");
            return;
          }
          delete INSTANCES[instanceId];
          rebuildSelectorOptions();
          selectNewConfig();
          showMessage("Configuration deleted.", "success");
        } catch (err) {
          showMessage("Delete failed", "error");
        } finally {
          deleteBtn.disabled = false;
        }
      });
    }

    document.getElementById("config-form").addEventListener("submit", async function (e) {
      e.preventDefault();
      const btn = document.getElementById("submit-btn");
      btn.disabled = true;
      try {
        const body = {
          userValues: collectUserValues(),
          hostValues: Object.assign({}, hostValues),
        };
        const saveId = selectorEnabled ? instanceId : INSTANCE_ID;
        if (saveId) body.instanceId = saveId;

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

        if (selectorEnabled) {
          const userVals = collectUserValues();
          instanceId = json.instanceId;
          currentValues = Object.assign({}, currentValues, userVals);
          const label = formatLabel(currentValues, instanceId);
          INSTANCES[instanceId] = { label: label, values: Object.assign({}, currentValues) };
          rebuildSelectorOptions();
          const sel = document.getElementById("config-select");
          if (sel) sel.value = instanceId;
          updateDeleteButton();
          history.replaceState(null, "", CONFIG_PATH + "?instanceId=" + encodeURIComponent(instanceId));
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
      updateDeleteButton();
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

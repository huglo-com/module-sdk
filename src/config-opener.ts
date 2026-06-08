/** Minimal popup handle (browser `Window` without requiring DOM lib in tsc). */
export interface ConfigPopupWindow {
  readonly closed: boolean;
  postMessage(message: unknown, targetOrigin: string): void;
}

interface ConfigMessageEvent {
  readonly source: unknown;
  readonly origin: string;
  readonly data: unknown;
}

interface ConfigOpenerGlobal {
  open(
    url: string,
    target: string,
    features: string,
  ): ConfigPopupWindow | null;
  addEventListener(
    type: "message",
    listener: (event: ConfigMessageEvent) => void,
  ): void;
  removeEventListener(
    type: "message",
    listener: (event: ConfigMessageEvent) => void,
  ): void;
}

function openerGlobal(): ConfigOpenerGlobal {
  return globalThis as unknown as ConfigOpenerGlobal;
}

export const CONFIG_READY_MESSAGE = "huglo:config:ready" as const;
export const CONFIG_SAVED_MESSAGE = "huglo:config:saved" as const;

export const DEFAULT_CONFIG_POPUP_FEATURES =
  "width=480,height=720,left=200,top=100";

const POPUP_CLOSED_POLL_MS = 800;

export interface OpenConfigPopupOptions {
  configUrl: string;
  /** Directory-signed config identity proof from the host. */
  configProof: unknown;
  configInstanceId?: string;
  /** Optional values for schema fields with source hostProvided. */
  hostValues?: Record<string, unknown>;
  onSaved: (instanceId: string) => void;
  /** Optional; default 480×720 centered. */
  popupFeatures?: string;
}

/** Append `?instanceId=` when editing an existing config instance. */
export function buildConfigUrl(
  configUrl: string,
  configInstanceId?: string,
): string {
  if (!configInstanceId) {
    return configUrl;
  }
  const url = new URL(configUrl);
  url.searchParams.set("instanceId", configInstanceId);
  return url.toString();
}

export function isConfigReadyMessage(data: unknown): boolean {
  return (
    typeof data === "object" &&
    data !== null &&
    !Array.isArray(data) &&
    (data as { type?: unknown }).type === CONFIG_READY_MESSAGE
  );
}

export function parseConfigSavedMessage(
  data: unknown,
): { instanceId: string } | null {
  if (
    typeof data !== "object" ||
    data === null ||
    Array.isArray(data)
  ) {
    return null;
  }
  const record = data as { type?: unknown; instanceId?: unknown };
  if (record.type !== CONFIG_SAVED_MESSAGE) {
    return null;
  }
  if (typeof record.instanceId !== "string" || record.instanceId.length === 0) {
    return null;
  }
  return { instanceId: record.instanceId };
}

/**
 * Open a module config page in a centered popup and run the ready → prefill → saved handshake.
 * Browser-only; validates `event.origin` against the config URL origin.
 */
export function openConfigPopup(
  options: OpenConfigPopupOptions,
  browser: ConfigOpenerGlobal = openerGlobal(),
): ConfigPopupWindow | null {
  const url = buildConfigUrl(options.configUrl, options.configInstanceId);
  const configOrigin = new URL(options.configUrl).origin;
  const hostPayload: Record<string, unknown> = {
    configProof: options.configProof,
    ...options.hostValues,
  };
  const g = browser;

  const popup = g.open(
    url,
    "_blank",
    options.popupFeatures ?? DEFAULT_CONFIG_POPUP_FEATURES,
  );
  if (!popup) {
    return null;
  }

  let closedPoll: ReturnType<typeof setInterval> | undefined;

  const cleanup = (): void => {
    g.removeEventListener("message", onMessage);
    if (closedPoll !== undefined) {
      clearInterval(closedPoll);
      closedPoll = undefined;
    }
  };

  const onMessage = (event: ConfigMessageEvent): void => {
    if (event.source !== popup || event.origin !== configOrigin) {
      return;
    }
    const data = event.data;
    if (isConfigReadyMessage(data)) {
      popup.postMessage(hostPayload, configOrigin);
      return;
    }
    const saved = parseConfigSavedMessage(data);
    if (saved) {
      options.onSaved(saved.instanceId);
      cleanup();
    }
  };

  g.addEventListener("message", onMessage);

  closedPoll = setInterval(() => {
    if (popup.closed) {
      cleanup();
    }
  }, POPUP_CLOSED_POLL_MS);

  return popup;
}

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  buildConfigUrl,
  isConfigReadyMessage,
  parseConfigSavedMessage,
  openConfigPopup,
  CONFIG_READY_MESSAGE,
  CONFIG_SAVED_MESSAGE,
  DEFAULT_CONFIG_POPUP_FEATURES,
} from "../src/config-opener.js";

describe("config-opener", () => {
  describe("buildConfigUrl", () => {
    it("returns base URL when no instanceId", () => {
      expect(buildConfigUrl("https://mod.example/config")).toBe(
        "https://mod.example/config",
      );
    });

    it("appends instanceId query param when editing", () => {
      expect(
        buildConfigUrl("https://mod.example/config", "inst-abc"),
      ).toBe("https://mod.example/config?instanceId=inst-abc");
    });

    it("preserves existing query params", () => {
      expect(
        buildConfigUrl("https://mod.example/config?foo=1", "inst-abc"),
      ).toBe("https://mod.example/config?foo=1&instanceId=inst-abc");
    });
  });

  describe("isConfigReadyMessage", () => {
    it("accepts huglo:config:ready", () => {
      expect(isConfigReadyMessage({ type: CONFIG_READY_MESSAGE })).toBe(true);
    });

    it("rejects other types and non-objects", () => {
      expect(isConfigReadyMessage({ type: CONFIG_SAVED_MESSAGE })).toBe(false);
      expect(isConfigReadyMessage(null)).toBe(false);
      expect(isConfigReadyMessage("ready")).toBe(false);
      expect(isConfigReadyMessage([])).toBe(false);
    });
  });

  describe("parseConfigSavedMessage", () => {
    it("parses valid saved message", () => {
      expect(
        parseConfigSavedMessage({
          type: CONFIG_SAVED_MESSAGE,
          instanceId: "uuid-1",
        }),
      ).toEqual({ instanceId: "uuid-1" });
    });

    it("rejects missing or empty instanceId", () => {
      expect(
        parseConfigSavedMessage({ type: CONFIG_SAVED_MESSAGE }),
      ).toBeNull();
      expect(
        parseConfigSavedMessage({
          type: CONFIG_SAVED_MESSAGE,
          instanceId: "",
        }),
      ).toBeNull();
      expect(parseConfigSavedMessage({ type: CONFIG_READY_MESSAGE })).toBeNull();
    });
  });

  describe("openConfigPopup", () => {
    type MessageHandler = (event: {
      source: unknown;
      origin: string;
      data: unknown;
    }) => void;

    function mockBrowser(popup: { closed: boolean; postMessage: ReturnType<typeof vi.fn> } | null) {
      const listeners: MessageHandler[] = [];
      return {
        open: vi.fn(() => popup),
        addEventListener: vi.fn(
          (_type: string, handler: MessageHandler) => {
            listeners.push(handler);
          },
        ),
        removeEventListener: vi.fn(
          (_type: string, handler: MessageHandler) => {
            const index = listeners.indexOf(handler);
            if (index >= 0) {
              listeners.splice(index, 1);
            }
          },
        ),
        listeners,
      };
    }

    beforeEach(() => {
      vi.useFakeTimers();
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("returns null when popup is blocked", () => {
      const browser = mockBrowser(null);
      expect(
        openConfigPopup(
          {
            configUrl: "https://mod.example/config",
            flowId: "flow-1",
            nodeId: "node-1",
            onSaved: () => {},
          },
          browser,
        ),
      ).toBeNull();
    });

    it("posts host values on ready and calls onSaved", () => {
      const postMessage = vi.fn();
      const popup = { closed: false, postMessage };
      const browser = mockBrowser(popup);

      const onSaved = vi.fn();
      const result = openConfigPopup(
        {
          configUrl: "https://mod.example/config",
          flowId: "flow-1",
          nodeId: "node-1",
          onSaved,
        },
        browser,
      );

      expect(result).toBe(popup);

      browser.listeners[0]!({
        source: popup,
        origin: "https://mod.example",
        data: { type: CONFIG_READY_MESSAGE },
      });
      expect(postMessage).toHaveBeenCalledWith(
        { flowId: "flow-1", nodeId: "node-1" },
        "https://mod.example",
      );

      browser.listeners[0]!({
        source: popup,
        origin: "https://mod.example",
        data: { type: CONFIG_SAVED_MESSAGE, instanceId: "inst-99" },
      });
      expect(onSaved).toHaveBeenCalledWith("inst-99");
      expect(browser.removeEventListener).toHaveBeenCalled();
    });

    it("ignores messages from wrong origin or source", () => {
      const postMessage = vi.fn();
      const popup = { closed: false, postMessage };
      const browser = mockBrowser(popup);

      const onSaved = vi.fn();
      openConfigPopup(
        {
          configUrl: "https://mod.example/config",
          flowId: "f",
          nodeId: "n",
          onSaved,
        },
        browser,
      );

      browser.listeners[0]!({
        source: {},
        origin: "https://mod.example",
        data: { type: CONFIG_READY_MESSAGE },
      });
      browser.listeners[0]!({
        source: popup,
        origin: "https://evil.example",
        data: { type: CONFIG_READY_MESSAGE },
      });

      expect(postMessage).not.toHaveBeenCalled();
      expect(onSaved).not.toHaveBeenCalled();
    });

    it("opens edit URL when configInstanceId is provided", () => {
      const popup = { closed: false, postMessage: vi.fn() };
      const browser = mockBrowser(popup);

      openConfigPopup(
        {
          configUrl: "https://mod.example/config",
          flowId: "flow-1",
          nodeId: "node-1",
          configInstanceId: "inst-edit",
          onSaved: () => {},
        },
        browser,
      );

      expect(browser.open).toHaveBeenCalledWith(
        "https://mod.example/config?instanceId=inst-edit",
        "_blank",
        DEFAULT_CONFIG_POPUP_FEATURES,
      );
    });

    it("uses custom popupFeatures when provided", () => {
      const popup = { closed: false, postMessage: vi.fn() };
      const browser = mockBrowser(popup);
      const features = "width=800,height=600";

      openConfigPopup(
        {
          configUrl: "https://mod.example/config",
          flowId: "flow-1",
          nodeId: "node-1",
          onSaved: () => {},
          popupFeatures: features,
        },
        browser,
      );

      expect(browser.open).toHaveBeenCalledWith(
        "https://mod.example/config",
        "_blank",
        features,
      );
    });

    it("cleans up listener when popup is closed without saved message", () => {
      const popup = { closed: false, postMessage: vi.fn() };
      const browser = mockBrowser(popup);
      const onSaved = vi.fn();

      openConfigPopup(
        {
          configUrl: "https://mod.example/config",
          flowId: "flow-1",
          nodeId: "node-1",
          onSaved,
        },
        browser,
      );

      expect(browser.listeners).toHaveLength(1);

      popup.closed = true;
      vi.advanceTimersByTime(800);

      expect(browser.removeEventListener).toHaveBeenCalled();
      expect(browser.listeners).toHaveLength(0);
      expect(onSaved).not.toHaveBeenCalled();
    });
  });
});

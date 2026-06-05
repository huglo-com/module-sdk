import { describe, it, expect } from "vitest";
import { z } from "zod";
import { configPageHtml } from "../src/config-page.js";
import { buildConfigManifest } from "../src/manifest.js";

const definition = {
  schema: z.object({
    label: z.string(),
    evil: z.string(),
  }),
  fields: {
    label: "userEntered" as const,
    evil: "userEntered" as const,
  },
};

const manifest = buildConfigManifest(definition);

describe("config-page unit", () => {
  it("shows login prompt and hides form when unauthenticated", () => {
    const html = configPageHtml({
      manifest,
      configPath: "/config",
      authenticated: false,
    });

    expect(html).toContain('href="/config/login"');
    expect(html).toContain('style="display:none"');
  });

  it("escapes XSS in field names embedded in script JSON", () => {
    const xssManifest = buildConfigManifest({
      schema: z.object({ "label</script>": z.string() }),
      fields: { "label</script>": "userEntered" },
    });

    const html = configPageHtml({
      manifest: xssManifest,
      configPath: "/config",
      authenticated: true,
    });

    const fieldsAssignment = html.match(/const FIELDS = (\[[\s\S]*?\]);/)?.[1];
    expect(fieldsAssignment).toBeDefined();
    expect(fieldsAssignment).toContain('"name":"label\\u003c/script\\u003e"');
    expect(fieldsAssignment).not.toContain("</script>");
  });

  it("escapes theme logoUrl and accentColor", () => {
    const html = configPageHtml({
      manifest,
      configPath: "/config",
      authenticated: true,
      theme: {
        logoUrl: 'https://example.com/logo" onload="alert(1)',
        accentColor: '#000"><script>alert(1)</script>',
      },
    });

    expect(html).not.toContain('onload="alert(1)"');
    expect(html).toContain("&quot;");
    expect(html).toContain("&lt;script&gt;");
  });

  it("marks selected instance and hides delete for new configuration", () => {
    const html = configPageHtml({
      manifest,
      configPath: "/config",
      authenticated: true,
      instanceId: "inst-selected",
      instances: [
        { instanceId: "inst-selected", label: "Selected", values: {} },
        { instanceId: "inst-other", label: "Other", values: {} },
      ],
    });

    expect(html).toContain('value="inst-selected" selected');
    expect(html).toContain('id="delete-btn"');
    expect(html).not.toMatch(/id="delete-btn" hidden/);
  });

  it("selects new configuration and hides delete when no instance selected", () => {
    const html = configPageHtml({
      manifest,
      configPath: "/config",
      authenticated: true,
      instances: [{ instanceId: "inst-a", label: "A", values: {} }],
    });

    expect(html).toContain('value="__new__" selected');
    expect(html).toContain('id="delete-btn" hidden');
  });
});

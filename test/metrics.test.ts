import { describe, it, expect, beforeAll, afterAll } from "vitest";
import { z } from "zod";
import { generateKeyPair } from "../src/keys.js";
import { signObject } from "../src/signing.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import { Module } from "../src/module.js";
import type { SignedGrant } from "../src/envelope.js";

function createMetricsTestEnv(options?: { metrics?: boolean }) {
  const holderKeys = generateKeyPair();
  const requesterKeys = generateKeyPair();
  const authorKeys = generateKeyPair();
  const directory = new InMemoryDirectoryClient();

  const holderPort = 9300 + Math.floor(Math.random() * 1000);
  const requesterPort = holderPort + 1;
  const holderEndpoint = `http://127.0.0.1:${holderPort}`;
  const requesterEndpoint = `http://127.0.0.1:${requesterPort}`;

  directory.registerModule("metrics-holder", holderEndpoint, holderKeys.publicKey, holderKeys.publicKeyBase64);
  directory.registerModule("metrics-requester", requesterEndpoint, requesterKeys.publicKey, requesterKeys.publicKeyBase64);
  directory.registerUser("user-metrics", authorKeys.publicKey);

  const holder = new Module({
    id: "metrics-holder",
    name: "Metrics Holder",
    description: "Metrics test holder",
    version: "1.0.0",
    keyPair: holderKeys,
    huglo: { directoryUrl: "http://unused" },
    directory,
    endpoint: holderEndpoint,
    metrics: options?.metrics,
  });

  holder.scope("echo:read", {
    description: "Echo input",
    input: z.object({ message: z.string() }),
    output: z.object({ message: z.string() }),
    handler: async (ctx) => ({ message: ctx.input.message }),
  });

  const requester = new Module({
    id: "metrics-requester",
    name: "Metrics Requester",
    description: "Metrics test requester",
    version: "1.0.0",
    keyPair: requesterKeys,
    huglo: { directoryUrl: "http://unused" },
    directory,
    metrics: options?.metrics,
  });

  function buildGrant(): SignedGrant {
    const grant = {
      grant_id: "g-metrics-001",
      holder: "metrics-holder",
      scope: "echo:read",
      subject: "huglo:user:user-metrics",
      requester: "metrics-requester",
      author: "huglo:user:user-metrics",
      constraints: {},
      issued_at: new Date(Date.now() - 60_000).toISOString(),
      expires_at: new Date(Date.now() + 3600_000).toISOString(),
    };
    return {
      grant,
      signature: signObject(grant, authorKeys.privateKey),
    };
  }

  return { holder, requester, buildGrant, holderPort, requesterPort };
}

describe("metrics", () => {
  describe("default (enabled)", () => {
    const env = createMetricsTestEnv();

    beforeAll(async () => {
      await env.holder.listen(env.holderPort, "127.0.0.1");
      await env.requester.listen(env.requesterPort, "127.0.0.1");
    });

    afterAll(() => {
      env.holder.close();
      env.requester.close();
    });

    it("exposes GET /metrics with Prometheus format", async () => {
      const res = await env.holder.getApp().fetch(new Request("http://localhost/metrics"));
      expect(res.status).toBe(200);
      expect(res.headers.get("Content-Type")).toContain("text/plain");
      const body = await res.text();
      expect(body).toContain("huglo_module_");
      expect(body).toContain('module_id="metrics-holder"');
    });

    it("returns getMetrics() registry", () => {
      expect(env.holder.getMetrics()).toBeDefined();
      expect(env.holder.getMetrics()?.registry).toBeDefined();
    });

    it("records successful invoke outcomes", async () => {
      await env.requester.call({
        target: "metrics-holder",
        scope: "echo:read",
        input: { message: "hello metrics" },
        grant: env.buildGrant(),
      });

      const res = await env.holder.getApp().fetch(new Request("http://localhost/metrics"));
      const body = await res.text();
      expect(body).toContain("huglo_module_invoke_total");
      expect(body).toContain('scope="echo:read"');
      expect(body).toContain('outcome="success"');
    });

    it("records scope_not_found invoke outcomes", async () => {
      const res = await env.holder.getApp().fetch(
        new Request("http://localhost/invoke/unknown:scope", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        }),
      );
      expect(res.status).toBe(404);

      const metricsRes = await env.holder.getApp().fetch(new Request("http://localhost/metrics"));
      const body = await metricsRes.text();
      expect(body).toContain('outcome="scope_not_found"');
      expect(body).toContain('scope="unknown:scope"');
    });

    it("includes custom metrics registered via getMetrics()", async () => {
      const metrics = env.holder.getMetrics();
      expect(metrics).toBeDefined();
      const created = metrics!.counter({
        name: "invoices_created_total",
        help: "Invoices created in tests",
      });
      created.inc();

      const res = await env.holder.getApp().fetch(new Request("http://localhost/metrics"));
      const body = await res.text();
      expect(body).toContain("invoices_created_total");
    });
  });

  describe("opt-out (metrics: false)", () => {
    const env = createMetricsTestEnv({ metrics: false });

    beforeAll(async () => {
      await env.holder.listen(env.holderPort, "127.0.0.1");
    });

    afterAll(() => {
      env.holder.close();
    });

    it("does not expose GET /metrics", async () => {
      const res = await env.holder.getApp().fetch(new Request("http://localhost/metrics"));
      expect(res.status).toBe(404);
    });

    it("returns undefined from getMetrics()", () => {
      expect(env.holder.getMetrics()).toBeUndefined();
    });
  });
});

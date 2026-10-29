import { describe, it, expect } from "vitest";
import { Writable } from "node:stream";
import { Hono } from "hono";
import pino from "pino";
import { generateKeyPair } from "../src/keys.js";
import { Module } from "../src/module.js";
import { InMemoryDirectoryClient } from "../src/directory.js";
import { createRequestLogMiddleware } from "../src/server.js";

function createInMemoryLogger(moduleId: string): {
  logger: pino.Logger;
  lines: string[];
} {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      lines.push(chunk.toString());
      callback();
    },
  });
  const logger = pino({ level: "info" }, stream).child({ module_id: moduleId });
  return { logger, lines };
}

interface RequestLogEntry {
  level: number;
  method: string;
  path: string;
  status: number;
  durationMs: number;
  module_id: string;
  msg: string;
}

function isRequestLogEntry(value: unknown): value is RequestLogEntry {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  if (
    !("level" in value) ||
    !("method" in value) ||
    !("path" in value) ||
    !("status" in value) ||
    !("durationMs" in value) ||
    !("module_id" in value) ||
    !("msg" in value)
  ) {
    return false;
  }
  return (
    typeof value.level === "number" &&
    typeof value.method === "string" &&
    typeof value.path === "string" &&
    typeof value.status === "number" &&
    typeof value.durationMs === "number" &&
    typeof value.module_id === "string" &&
    typeof value.msg === "string"
  );
}

function requireLogLine(lines: string[], index: number): { raw: string; entry: RequestLogEntry } {
  const raw = lines[index];
  if (raw === undefined) {
    throw new Error(`missing log line at index ${index}`);
  }
  const parsed: unknown = JSON.parse(raw);
  if (!isRequestLogEntry(parsed)) {
    throw new Error(`log line ${index} is not a request log entry`);
  }
  return { raw, entry: parsed };
}

describe("request logging", () => {
  it("logs 2xx at info without headers or query string", async () => {
    const { logger, lines } = createInMemoryLogger("test-mod");
    const app = new Hono();
    app.use("*", createRequestLogMiddleware(logger));
    app.get("/health", (c) => c.json({ ok: true }));

    const res = await app.request("/health?foo=1", {
      headers: { Authorization: "Bearer secret" },
    });
    expect(res.status).toBe(200);
    expect(lines).toHaveLength(1);
    const { raw, entry } = requireLogLine(lines, 0);
    expect(entry.level).toBe(30);
    expect(entry.method).toBe("GET");
    expect(entry.path).toBe("/health");
    expect(entry.status).toBe(200);
    expect(entry.durationMs).toBeGreaterThanOrEqual(0);
    expect(entry.module_id).toBe("test-mod");
    expect(entry.msg).toBe("request");
    expect(raw).not.toContain("Authorization");
    expect(raw).not.toContain("foo=1");
  });

  it("logs 4xx at warn and 5xx at error", async () => {
    const { logger, lines } = createInMemoryLogger("test-mod");
    const app = new Hono();
    app.use("*", createRequestLogMiddleware(logger));
    app.get("/missing", (c) => c.text("nope", 404));
    app.get("/broken", (c) => c.text("fail", 500));

    await app.request("/missing");
    await app.request("/broken");
    expect(lines).toHaveLength(2);
    expect(requireLogLine(lines, 0).entry.level).toBe(40);
    expect(requireLogLine(lines, 1).entry.level).toBe(50);
  });

  it("disables logger when logging: false", async () => {
    const keys = generateKeyPair();
    const module = new Module({
      id: "log-mod",
      name: "Log Module",
      description: "desc",
      version: "1.0.0",
      keyPair: keys,
      directory: new InMemoryDirectoryClient(),
      logging: false,
    });
    expect(module.getLogger()).toBeUndefined();
    const res = await module.getApp().request("/health");
    expect(res.status).toBe(200);
  });

  it("enables logger by default", () => {
    const keys = generateKeyPair();
    const module = new Module({
      id: "log-mod",
      name: "Log Module",
      description: "desc",
      version: "1.0.0",
      keyPair: keys,
      directory: new InMemoryDirectoryClient(),
    });
    expect(module.getLogger()).toBeDefined();
  });
});

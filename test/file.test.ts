import { describe, it, expect, beforeAll, afterAll, vi } from "vitest";
import { z } from "zod";
import { generateKeyPair } from "../src/keys.js";
import { Module } from "../src/module.js";
import { FileSchema } from "../src/file.js";
import { InMemoryFileStore } from "../src/file-store.js";
import type { ModuleManifest } from "../src/manifest.js";

describe("file storage", () => {
  let module: Module;
  let port: number;
  let endpoint: string;

  beforeAll(async () => {
    const keys = generateKeyPair();
    port = 9200 + Math.floor(Math.random() * 1000);
    endpoint = `http://127.0.0.1:${port}`;

    module = new Module({
      id: "files-mod",
      name: "Files",
      description: "File test module",
      version: "1.0.0",
      keyPair: keys,
      endpoint,
    });

    await module.listen(port);
  });

  afterAll(() => {
    module.close();
  });

  it("emits { type: file } in toJSONSchema", () => {
    const jsonSchema = z.toJSONSchema(FileSchema, { io: "output" });
    expect(jsonSchema).toMatchObject({ type: "file" });
    expect(jsonSchema).not.toHaveProperty("properties");
  });

  it("lists file type in /manifest when used as scope output", async () => {
    const keys = generateKeyPair();
    const p = port + 4;
    const mod = new Module({
      id: "file-manifest",
      name: "File manifest",
      description: "Test",
      version: "1.0.0",
      keyPair: keys,
      endpoint: `http://127.0.0.1:${p}`,
    });

    mod.scope("files:upload", {
      description: "Upload a file",
      input: z.object({}),
      output: FileSchema,
      handler: async () => {
        throw new Error("not invoked in this test");
      },
    });

    await mod.listen(p);
    try {
      const res = await fetch(`http://127.0.0.1:${p}/manifest`);
      expect(res.status).toBe(200);
      const manifest = (await res.json()) as ModuleManifest;
      const scope = manifest.scopes.find((s) => s.name === "files:upload");
      expect(scope?.output).toMatchObject({ type: "file" });
      expect(scope?.output).not.toHaveProperty("properties");
    } finally {
      mod.close();
    }
  });

  it("creates a file from data and serves it", async () => {
    const expires_at = new Date(Date.now() + 3600_000);
    const file = await module.createFile({
      data: Buffer.from("hello file"),
      content_type: "text/plain",
      filename: "hello.txt",
      expires_at,
    });

    expect(FileSchema.safeParse(file).success).toBe(true);
    expect(file.url).toBe(`${endpoint}/file/${file.url.split("/").pop()}`);
    expect(file.size).toBe(10);
    expect(file.content_type).toBe("text/plain");
    expect(file.filename).toBe("hello.txt");

    const token = file.url.split("/file/")[1];
    const res = await fetch(file.url);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toBe("text/plain");
    expect(res.headers.get("content-disposition")).toBe("inline; filename=hello.txt");
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(await res.text()).toBe("hello file");

    const store = module.getFileStore();
    const stored = await store.get(token!);
    expect(stored?.filename).toBe("hello.txt");
  });

  it("serves unicode filename via filename* in Content-Disposition", async () => {
    const file = await module.createFile({
      data: Buffer.from("unicode"),
      content_type: "text/plain",
      filename: "résumé.pdf",
      expires_at: new Date(Date.now() + 3600_000),
    });

    const res = await fetch(file.url);
    expect(res.status).toBe(200);
    const disposition = res.headers.get("content-disposition");
    expect(disposition).toContain("inline");
    expect(disposition).toContain("filename*=UTF-8''");
    expect(disposition).toContain("r%C3%A9sum%C3%A9.pdf");
  });

  it("returns 404 for expired files", async () => {
    const file = await module.createFile({
      data: new Uint8Array([1, 2, 3]),
      content_type: "application/octet-stream",
      filename: "x.bin",
      expires_at: new Date(Date.now() + 50),
    });

    await new Promise((r) => setTimeout(r, 80));

    const res = await fetch(file.url);
    expect(res.status).toBe(404);

    const token = file.url.split("/file/")[1];
    expect(await module.getFileStore().get(token!)).toBeNull();
  });

  it("creates a file from url via injected fetch", async () => {
    const mockFetch = vi.fn().mockResolvedValue(
      new Response(new Uint8Array([0x25, 0x50, 0x44, 0x46]), {
        status: 200,
        headers: {
          "content-type": "application/pdf",
          "content-disposition": 'attachment; filename="doc.pdf"',
        },
      }),
    );

    const { createFileRecord } = await import("../src/file.js");
    const store = new InMemoryFileStore();
    const file = await createFileRecord(
      store,
      endpoint,
      {
        url: "https://example.com/doc.pdf",
        expires_at: new Date(Date.now() + 3600_000),
      },
      { fetch: mockFetch as typeof fetch },
    );

    expect(file.content_type).toBe("application/pdf");
    expect(file.filename).toBe("doc.pdf");
    expect(file.size).toBe(4);
    expect(mockFetch).toHaveBeenCalledWith("https://example.com/doc.pdf");
  });

  it("throws when endpoint is missing", async () => {
    const keys = generateKeyPair();
    const noEndpoint = new Module({
      id: "no-endpoint",
      name: "No endpoint",
      description: "Test",
      version: "1.0.0",
      keyPair: keys,
    });

    await expect(
      noEndpoint.createFile({
        data: Buffer.from("x"),
        content_type: "text/plain",
        filename: "x.txt",
        expires_at: new Date(Date.now() + 1000),
      }),
    ).rejects.toThrow(/endpoint/i);
  });

  it("throws when expires_at is in the past", async () => {
    await expect(
      module.createFile({
        data: Buffer.from("x"),
        content_type: "text/plain",
        filename: "x.txt",
        expires_at: new Date(Date.now() - 1000),
      }),
    ).rejects.toThrow(/future/i);
  });

  it("mounts file routes when fileStore is set at startup", async () => {
    const keys = generateKeyPair();
    const p = 9300 + Math.floor(Math.random() * 1000);
    const ep = `http://127.0.0.1:${p}`;
    const store = new InMemoryFileStore();
    const mod = new Module({
      id: "preconfigured-files",
      name: "Preconfigured",
      description: "Test",
      version: "1.0.0",
      keyPair: keys,
      endpoint: ep,
      fileStore: store,
    });

    await mod.listen(p, "127.0.0.1");
    try {
      const res = await fetch(`${ep}/file/nonexistent-token`);
      expect(res.status).toBe(404);
    } finally {
      mod.close();
    }
  });
});

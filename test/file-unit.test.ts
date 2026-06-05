import { describe, it, expect, vi } from "vitest";
import { parse } from "content-disposition";
import {
  buildContentDisposition,
  createFileRecord,
  DEFAULT_MAX_FILE_BYTES,
} from "../src/file.js";
import { InMemoryFileStore } from "../src/file-store.js";

describe("file unit", () => {
  describe("buildContentDisposition", () => {
    it("builds inline disposition for safe ASCII filenames", () => {
      expect(buildContentDisposition("report.pdf")).toBe("inline; filename=report.pdf");
    });

    it("escapes double quotes in filenames", () => {
      expect(buildContentDisposition('report "final".pdf')).toBe(
        'inline; filename="report \\"final\\".pdf"',
      );
    });

    it("builds inline disposition for filenames with spaces", () => {
      expect(buildContentDisposition("Q4 Report (draft).pdf")).toBe(
        'inline; filename="Q4 Report (draft).pdf"',
      );
    });

    it("includes filename* for non-ASCII filenames", () => {
      const header = buildContentDisposition("résumé.pdf");
      expect(header).toContain("filename*=UTF-8''");
      expect(parse(header).parameters.filename).toBe("résumé.pdf");
    });
  });

  describe("createFileRecord", () => {
    const endpoint = "http://127.0.0.1:8080";
    const future = new Date(Date.now() + 3600_000);

    it("throws TypeError for invalid expires_at string", async () => {
      const store = new InMemoryFileStore();
      await expect(
        createFileRecord(store, endpoint, {
          data: Buffer.from("x"),
          content_type: "text/plain",
          filename: "x.txt",
          expires_at: "not-a-date",
        }),
      ).rejects.toThrow(TypeError);
    });

    it("throws when neither data nor url is provided", async () => {
      const store = new InMemoryFileStore();
      await expect(
        createFileRecord(store, endpoint, {
          expires_at: future,
        } as never),
      ).rejects.toThrow(/data or url/i);
    });

    it("throws when fetch returns non-OK status", async () => {
      const store = new InMemoryFileStore();
      const mockFetch = vi.fn().mockResolvedValue(new Response(null, { status: 404 }));

      await expect(
        createFileRecord(
          store,
          endpoint,
          { url: "https://example.com/missing.bin", expires_at: future },
          { fetch: mockFetch as typeof fetch },
        ),
      ).rejects.toThrow(/Failed to fetch file URL: 404/);
    });

    it("throws when content-length exceeds maxBytes", async () => {
      const store = new InMemoryFileStore();
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(new Uint8Array([1]), {
          status: 200,
          headers: { "content-length": String(DEFAULT_MAX_FILE_BYTES + 1) },
        }),
      );

      await expect(
        createFileRecord(
          store,
          endpoint,
          { url: "https://example.com/big.bin", expires_at: future, maxBytes: 100 },
          { fetch: mockFetch as typeof fetch },
        ),
      ).rejects.toThrow(/maxBytes/);
    });

    it("throws when response body exceeds maxBytes", async () => {
      const store = new InMemoryFileStore();
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(new Uint8Array([1, 2, 3, 4, 5]), { status: 200 }),
      );

      await expect(
        createFileRecord(
          store,
          endpoint,
          { url: "https://example.com/body.bin", expires_at: future, maxBytes: 2 },
          { fetch: mockFetch as typeof fetch },
        ),
      ).rejects.toThrow(/maxBytes/);
    });

    it("derives filename from URL pathname when header absent", async () => {
      const store = new InMemoryFileStore();
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(new Uint8Array([1]), {
          status: 200,
          headers: { "content-type": "application/octet-stream" },
        }),
      );

      const file = await createFileRecord(
        store,
        endpoint,
        { url: "https://example.com/files/archive.zip", expires_at: future },
        { fetch: mockFetch as typeof fetch },
      );

      expect(file.filename).toBe("archive.zip");
    });

    it("derives filename from Content-Disposition header", async () => {
      const store = new InMemoryFileStore();
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(new Uint8Array([1]), {
          status: 200,
          headers: { "content-disposition": 'attachment; filename="named.bin"' },
        }),
      );

      const file = await createFileRecord(
        store,
        endpoint,
        { url: "https://example.com/download", expires_at: future },
        { fetch: mockFetch as typeof fetch },
      );

      expect(file.filename).toBe("named.bin");
    });

    it("derives unicode filename from filename* in Content-Disposition", async () => {
      const store = new InMemoryFileStore();
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(new Uint8Array([1]), {
          status: 200,
          headers: {
            "content-disposition":
              "attachment; filename=\"r?sum?.pdf\"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf",
          },
        }),
      );

      const file = await createFileRecord(
        store,
        endpoint,
        { url: "https://example.com/download", expires_at: future },
        { fetch: mockFetch as typeof fetch },
      );

      expect(file.filename).toBe("résumé.pdf");
    });

    it("falls back to download for invalid URL", async () => {
      const store = new InMemoryFileStore();
      const mockFetch = vi.fn().mockResolvedValue(
        new Response(new Uint8Array([1]), { status: 200 }),
      );

      const file = await createFileRecord(
        store,
        endpoint,
        { url: "not-a-valid-url", expires_at: future },
        { fetch: mockFetch as typeof fetch },
      );

      expect(file.filename).toBe("download");
    });

    it("strips trailing slash from endpoint", async () => {
      const store = new InMemoryFileStore();
      const file = await createFileRecord(store, "http://127.0.0.1:8080/", {
        data: Buffer.from("x"),
        content_type: "text/plain",
        filename: "x.txt",
        expires_at: future,
      });

      expect(file.url).toMatch(/^http:\/\/127\.0\.0\.1:8080\/file\//);
    });
  });
});

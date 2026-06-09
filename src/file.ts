import { randomBytes } from "node:crypto";
import { create, parse } from "content-disposition";
import type { z } from "zod";
import type { FileStore } from "./file-store.js";
import { fileObjectSchema } from "./builtin-types/file.js";

export type File = z.infer<typeof fileObjectSchema>;

export const DEFAULT_MAX_FILE_BYTES = 10 * 1024 * 1024;

export type CreateFileDataOptions = {
  data: Buffer | Uint8Array;
  content_type: string;
  filename: string;
  expires_at: Date | string;
};

export type CreateFileUrlOptions = {
  url: string;
  expires_at: Date | string;
  content_type?: string;
  filename?: string;
  maxBytes?: number;
};

export type CreateFileOptions = CreateFileDataOptions | CreateFileUrlOptions;

export type FetchFn = typeof globalThis.fetch;

function normalizeExpiresAt(expires_at: Date | string): string {
  const date = expires_at instanceof Date ? expires_at : new Date(expires_at);
  if (Number.isNaN(date.getTime())) {
    throw new TypeError("Invalid expires_at");
  }
  const iso = date.toISOString();
  if (Date.parse(iso) <= Date.now()) {
    throw new Error("expires_at must be in the future");
  }
  return iso;
}

function generateToken(): string {
  return randomBytes(16).toString("base64url");
}

function filenameFromUrl(url: string): string {
  try {
    const pathname = new URL(url).pathname;
    const base = pathname.split("/").pop();
    if (base) {
      return base;
    }
  } catch {
    // fall through
  }
  return "download";
}

function filenameFromContentDisposition(header: string | null): string | undefined {
  if (!header) {
    return undefined;
  }
  try {
    return parse(header).parameters.filename;
  } catch {
    return undefined;
  }
}

/** Build an inline Content-Disposition header value (RFC 6266 / RFC 8187). */
function buildContentDisposition(filename: string): string {
  return create(filename, { type: "inline" });
}

async function loadFromUrl(
  url: string,
  fetchFn: FetchFn,
  maxBytes: number,
  overrides: { content_type?: string; filename?: string },
): Promise<{ body: Uint8Array; content_type: string; filename: string; size: number }> {
  const response = await fetchFn(url);
  if (!response.ok) {
    throw new Error(`Failed to fetch file URL: ${response.status}`);
  }

  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > maxBytes) {
    throw new Error(`File exceeds maxBytes (${maxBytes})`);
  }

  const arrayBuffer = await response.arrayBuffer();
  if (arrayBuffer.byteLength > maxBytes) {
    throw new Error(`File exceeds maxBytes (${maxBytes})`);
  }

  const body = new Uint8Array(arrayBuffer);
  const content_type =
    overrides.content_type ??
    response.headers.get("content-type")?.split(";")[0]?.trim() ??
    "application/octet-stream";
  const filename =
    overrides.filename ??
    filenameFromContentDisposition(response.headers.get("content-disposition")) ??
    filenameFromUrl(url);

  return { body, content_type, filename, size: body.byteLength };
}

export interface CreateFileRecordOptions {
  fetch?: FetchFn;
}

export async function createFileRecord(
  store: FileStore,
  endpoint: string,
  options: CreateFileOptions,
  recordOptions: CreateFileRecordOptions = {},
): Promise<File> {
  const expires_at = normalizeExpiresAt(options.expires_at);
  const fetchFn = recordOptions.fetch ?? globalThis.fetch;

  let body: Uint8Array;
  let content_type: string;
  let filename: string;
  let size: number;

  if ("data" in options) {
    body = options.data instanceof Uint8Array ? options.data : new Uint8Array(options.data);
    content_type = options.content_type;
    filename = options.filename;
    size = body.byteLength;
  } else if ("url" in options) {
    const loaded = await loadFromUrl(
      options.url,
      fetchFn,
      options.maxBytes ?? DEFAULT_MAX_FILE_BYTES,
      { content_type: options.content_type, filename: options.filename },
    );
    body = loaded.body;
    content_type = loaded.content_type;
    filename = loaded.filename;
    size = loaded.size;
  } else {
    throw new Error("createFile requires either data or url");
  }

  const token = generateToken();
  await store.put({
    token,
    body,
    content_type,
    filename,
    size,
    expires_at,
  });

  const base = endpoint.replaceAll(/\/$/g, "");
  return fileObjectSchema.parse({
    url: `${base}/file/${token}`,
    content_type,
    filename,
    size,
    expires_at,
  });
}

export { buildContentDisposition };

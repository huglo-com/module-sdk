import type { Hono } from "hono";
import type { FileStore } from "./file-store.js";
import { contentDispositionFilename } from "./file.js";

export interface FileRoutesOptions {
  fileStore: FileStore;
}

export function mountFileRoutes(app: Hono, options: FileRoutesOptions): void {
  app.get("/file/:token", async (c) => {
    const token = c.req.param("token");
    const file = await options.fileStore.get(token);
    if (!file) {
      return c.text("Not found", 404);
    }

    const safeName = contentDispositionFilename(file.filename);
    return new Response(file.body, {
      status: 200,
      headers: {
        "Content-Type": file.content_type,
        "Content-Disposition": `inline; filename="${safeName}"`,
        "Cache-Control": "no-store",
      },
    });
  });
}

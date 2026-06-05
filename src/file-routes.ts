import type { Hono } from "hono";
import type { FileStore } from "./file-store.js";
import { buildContentDisposition } from "./file.js";
import type { ModuleMetrics } from "./metrics.js";

export interface FileRoutesOptions {
  fileStore: FileStore;
  metrics?: ModuleMetrics;
}

export function mountFileRoutes(app: Hono, options: FileRoutesOptions): void {
  app.get("/file/:token", async (c) => {
    const token = c.req.param("token");
    const file = await options.fileStore.get(token);
    if (!file) {
      options.metrics?.recordFileDownload("not_found");
      return c.text("Not found", 404);
    }

    options.metrics?.recordFileDownload("success");

    return new Response(file.body, {
      status: 200,
      headers: {
        "Content-Type": file.content_type,
        "Content-Disposition": buildContentDisposition(file.filename),
        "Cache-Control": "no-store",
      },
    });
  });
}

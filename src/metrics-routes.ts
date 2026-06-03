import type { Hono } from "hono";
import type { ModuleMetrics } from "./metrics.js";

export interface MetricsRoutesOptions {
  metrics: ModuleMetrics;
}

export function mountMetricsRoutes(app: Hono, options: MetricsRoutesOptions): void {
  app.get("/metrics", async (c) => {
    c.header("Content-Type", options.metrics.registry.contentType);
    return c.text(await options.metrics.registry.metrics());
  });
}

import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";
import { dirname } from "node:path";

const root = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  root,
  test: {
    globals: true,
    environment: "node",
    include: ["test/**/*.test.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "lcov"],
      include: [
        "src/signing.ts",
        "src/canonical.ts",
        "src/verify.ts",
        "src/client.ts",
        "src/config.ts",
        "src/config-routes.ts",
        "src/config-page.ts",
        "src/config-store.ts",
        "src/config-opener.ts",
        "src/file.ts",
        "src/file-routes.ts",
        "src/file-store.ts",
        "src/store.ts",
        "src/directory.ts",
        "src/oauth.ts",
        "src/server.ts",
        "src/module.ts",
      ],
      thresholds: {
        lines: 70,
        functions: 70,
        branches: 70,
        statements: 70,
      },
    },
  },
});

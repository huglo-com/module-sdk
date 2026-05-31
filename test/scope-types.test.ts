import { describe, it, expectTypeOf } from "vitest";
import { z } from "zod";
import { Module, type ProtectedCtx, type OpenCtx } from "../src/module.js";
import { generateKeyPair } from "../src/keys.js";
import { InMemoryDirectoryClient } from "../src/directory.js";

describe("scope handler types", () => {
  const keys = generateKeyPair();
  const directory = new InMemoryDirectoryClient();

  const module = new Module({
    id: "type-test",
    name: "Type Test",
    description: "test",
    version: "1.0.0",
    keyPair: keys,
    directory,
  });

  it("protected scope handler ctx includes subject", () => {
    module.scope("protected:scope", {
      description: "protected",
      input: z.object({ id: z.string() }),
      output: z.object({ id: z.string() }),
      handler: async (ctx) => {
        expectTypeOf(ctx).toMatchTypeOf<ProtectedCtx<{ id: string }>>();
        expectTypeOf(ctx.subject).toBeString();
        expectTypeOf(ctx.grant).toBeObject();
        return { id: ctx.input.id };
      },
    });
  });

  it("open scope handler ctx excludes subject", () => {
    module.scope("open:scope", {
      open: true,
      description: "open",
      input: z.object({}),
      output: z.object({ ok: z.boolean() }),
      handler: async (ctx) => {
        expectTypeOf(ctx).toMatchTypeOf<OpenCtx<Record<string, never>>>();
        expectTypeOf(ctx.caller).toBeString();
        return { ok: true };
      },
    });
  });
});

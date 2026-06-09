import { describe, it, expect } from "vitest";
import { z } from "zod";
import { computeSchemaHash } from "../src/type-system.js";

describe("computeSchemaHash", () => {
  it("returns a stable sha256-v1 hash for a flat schema", () => {
    const schema = {
      type: "object",
      properties: {
        name: { type: "string" },
        count: { type: "integer" },
      },
      required: ["name", "count"],
    };

    const hash1 = computeSchemaHash(schema);
    const hash2 = computeSchemaHash(schema);

    expect(hash1).toBe(hash2);
    expect(hash1).toMatch(/^sha256-v1:[a-f0-9]{64}$/);
  });

  it("replaces registered child type refs with schemaHash before hashing", () => {
    const childSchema = {
      type: "object",
      properties: { id: { type: "string" } },
      required: ["id"],
    };
    const childHash = computeSchemaHash(childSchema);

    const parentWithChildRef = {
      type: "object",
      properties: {
        item: { type: "test:child" },
      },
      required: ["item"],
    };

    const parentWithExpandedChild = {
      type: "object",
      properties: {
        item: childSchema,
      },
      required: ["item"],
    };

    const hashWithRef = computeSchemaHash(parentWithChildRef, (id) =>
      id === "test:child" ? childHash : undefined,
    );
    const hashWithExpanded = computeSchemaHash(parentWithExpandedChild);

    expect(hashWithRef).not.toBe(hashWithExpanded);
    expect(hashWithRef).toMatch(/^sha256-v1:/);

    const parentWithResolvedChild = {
      type: "object",
      properties: {
        item: { type: "test:child", schemaHash: childHash },
      },
      required: ["item"],
    };
    const hashWithResolved = computeSchemaHash(parentWithResolvedChild);
    expect(hashWithRef).toBe(hashWithResolved);
  });

  it("does not replace JSON Schema primitive type strings", () => {
    const schema = {
      type: "object",
      properties: {
        name: { type: "string" },
        items: { type: "array", items: { type: "string" } },
      },
    };

    const hashWithoutResolver = computeSchemaHash(schema);
    const hashWithResolver = computeSchemaHash(schema, () => "should-not-apply");

    expect(hashWithoutResolver).toBe(hashWithResolver);
  });
});

describe("registerType nested types", () => {
  it("parent schema hash includes child schemaHash when child is registered first", async () => {
    const { Module } = await import("../src/module.js");
    const { generateKeyPair } = await import("../src/keys.js");

    const keys = generateKeyPair();
    const mod = new Module({
      id: "nested-types",
      name: "Nested",
      description: "Test",
      version: "1.0.0",
      keyPair: keys,
    });

    const Child = mod.registerType({
      id: "test:child",
      schema: z.object({ id: z.string() }),
      display: { label: "child", background: "#fff", border: "#000", color: "#000" },
    });

    const Parent = mod.registerType({
      id: "test:parent",
      schema: z.object({ item: Child }),
      display: { label: "parent", background: "#fff", border: "#000", color: "#000" },
    });

    mod.scope("nested:read", {
      description: "Read nested",
      input: z.object({}),
      output: Parent,
      handler: async () => ({ item: { id: "x" } }),
    });

    const res = await mod.getApp().request("/manifest");
    const manifest = (await res.json()) as {
      types?: Array<{ id: string; schemaHash: string; schema: Record<string, unknown> }>;
    };

    const childEntry = manifest.types?.find((t) => t.id === "test:child");
    const parentEntry = manifest.types?.find((t) => t.id === "test:parent");

    expect(childEntry).toBeDefined();
    expect(parentEntry).toBeDefined();

    const parentProps = parentEntry!.schema["properties"] as Record<string, unknown>;
    expect(parentProps["item"]).toEqual({ type: "test:child" });

    const parentHashWithChildRef = computeSchemaHash(
      parentEntry!.schema,
      (id) => (id === "test:child" ? childEntry!.schemaHash : undefined),
    );

    expect(parentEntry!.schemaHash).toBe(parentHashWithChildRef);
    expect(parentEntry!.schemaHash).not.toBe(computeSchemaHash(parentEntry!.schema));
  });
});

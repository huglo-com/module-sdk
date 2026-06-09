import { createHash } from "node:crypto";
import type { z } from "zod";
import { canonicalizeToBytes } from "./canonical.js";

export interface TypeDisplay {
  label: string;
  background: string;
  border: string;
  color: string;
}

export interface TypeOperator {
  id: string;
  label: string;
  field: string;
  compare: string;
  op: string;
}

export interface TypeDefinition<T extends z.ZodType = z.ZodType> {
  id: string;
  schema: T;
  display: TypeDisplay;
  operators?: TypeOperator[];
}

export interface TypeManifestEntry {
  id: string;
  schema: Record<string, unknown>;
  schemaHash: string;
  display: TypeDisplay;
  operators: TypeOperator[];
}

const JSON_SCHEMA_PRIMITIVE_TYPES = new Set([
  "object",
  "array",
  "string",
  "number",
  "integer",
  "boolean",
  "null",
]);

/** Tag a Zod schema so z.toJSONSchema emits { type: id } instead of expanded properties. */
export function tagSchema<T extends z.ZodType>(schema: T, id: string): T {
  schema._zod.toJSONSchema = () => ({ type: id });
  return schema;
}

function isRegisteredTypeRef(value: unknown): value is { type: string } {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as { type?: unknown }).type === "string" &&
    Object.keys(value).length === 1
  );
}

function resolveChildRefs(
  node: unknown,
  resolveChildHash: (id: string) => string | undefined,
): unknown {
  if (node === null || typeof node !== "object") {
    return node;
  }

  if (Array.isArray(node)) {
    return node.map((item) => resolveChildRefs(item, resolveChildHash));
  }

  if (isRegisteredTypeRef(node)) {
    const childHash = resolveChildHash(node.type);
    if (childHash !== undefined) {
      return { type: node.type, schemaHash: childHash };
    }
    return node;
  }

  const obj = node as Record<string, unknown>;
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    result[key] = resolveChildRefs(value, resolveChildHash);
  }
  return result;
}

/**
 * Compute a canonical schema hash. When resolveChildHash is provided, registered
 * child type refs ({ type: childId }) are replaced with { type, schemaHash }
 * before hashing.
 */
export function computeSchemaHash(
  schema: Record<string, unknown>,
  resolveChildHash?: (id: string) => string | undefined,
): string {
  const forHash =
    resolveChildHash !== undefined
      ? (resolveChildRefs(schema, (id) => {
          if (JSON_SCHEMA_PRIMITIVE_TYPES.has(id)) {
            return undefined;
          }
          return resolveChildHash(id);
        }) as Record<string, unknown>)
      : schema;

  const bytes = canonicalizeToBytes(forHash);
  const hex = createHash("sha256").update(bytes).digest("hex");
  return `sha256-v1:${hex}`;
}

import { z } from "zod";
import type { ConfigManifestFieldEntry } from "./manifest.js";

export type FieldSource = "locked" | "hostProvided" | "userEntered";

export interface ConfigDefinition {
  schema: z.ZodObject;
  fields: Record<string, FieldSource>;
  /** Explicit locked values; otherwise locked fields use schema .default(). */
  lockedValues?: Record<string, unknown>;
}

/** Alias for config declaration options (used by module.config()). */
export type ConfigOptions = ConfigDefinition;

export interface AssembleConfigInput {
  definition: ConfigDefinition;
  userValues: Record<string, unknown>;
  hostValues: Record<string, unknown>;
}

export interface AssembleConfigResult {
  values: Record<string, unknown>;
  parsed: z.infer<ConfigDefinition["schema"]>;
}

function fieldSource(
  definition: ConfigDefinition,
  fieldName: string,
): FieldSource {
  return definition.fields[fieldName] ?? "userEntered";
}

function lockedValueForField(
  definition: ConfigDefinition,
  fieldName: string,
  fieldSchema: z.ZodType,
): unknown {
  if (fieldName in (definition.lockedValues ?? {})) {
    return definition.lockedValues![fieldName];
  }
  if (fieldSchema instanceof z.ZodDefault) {
    return fieldSchema.parse(undefined);
  }
  throw new Error(
    `Locked field '${fieldName}' has no lockedValues entry and no schema default`,
  );
}

/**
 * Enforce field sources server-side, then validate against the declared schema.
 * - locked: module fixed value (incoming discarded)
 * - hostProvided: host-supplied value
 * - userEntered: submitted user value
 */
export function assembleConfigValues(
  input: AssembleConfigInput,
): AssembleConfigResult {
  const { definition, userValues, hostValues } = input;
  const shape = definition.schema.shape;
  const assembled: Record<string, unknown> = {};

  for (const fieldName of Object.keys(shape)) {
    const source = fieldSource(definition, fieldName);
    const fieldSchema = shape[fieldName]!;

    switch (source) {
      case "locked":
        assembled[fieldName] = lockedValueForField(
          definition,
          fieldName,
          fieldSchema,
        );
        break;
      case "hostProvided":
        if (!(fieldName in hostValues)) {
          throw new ConfigAssemblyError(
            `hostProvided field '${fieldName}' is missing from host values`,
          );
        }
        assembled[fieldName] = hostValues[fieldName];
        break;
      case "userEntered":
        if (!(fieldName in userValues)) {
          throw new ConfigAssemblyError(
            `userEntered field '${fieldName}' is missing from user values`,
          );
        }
        assembled[fieldName] = userValues[fieldName];
        break;
    }
  }

  const parsed = definition.schema.parse(assembled);
  return { values: assembled, parsed };
}

export class ConfigAssemblyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigAssemblyError";
  }
}

/** Short display id when the label field is empty. */
export function truncateInstanceId(instanceId: string): string {
  if (instanceId.length <= 8) return instanceId;
  return `${instanceId.slice(0, 8)}…`;
}

/** Deterministic label from the first schema field, else truncated instanceId. */
export function formatInstanceLabel(
  values: Record<string, unknown>,
  instanceId: string,
  fields: ConfigManifestFieldEntry[],
): string {
  const first = fields[0];
  if (!first) return truncateInstanceId(instanceId);
  const v = values[first.name];
  if (typeof v === "string" && v.trim() !== "") return v;
  return truncateInstanceId(instanceId);
}

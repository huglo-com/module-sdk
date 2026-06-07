import { z } from "zod";
import type { ConfigDefinition, FieldSource } from "./config.js";

export interface ScopeManifestEntry {
  name: string;
  description: string;
  /** When true, invoke does not require a grant (Sig 2 only). Omitted when false. */
  open?: boolean;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
}

export interface EmitterManifestEntry {
  name: string;
  description: string;
  output: Record<string, unknown>;
}

export interface ConfigManifestFieldEntry {
  name: string;
  type: Record<string, unknown>;
  source: FieldSource;
}

export interface ConfigManifestEntry {
  fields: ConfigManifestFieldEntry[];
}

export interface ModuleManifest {
  id: string;
  name: string;
  description: string;
  version: string;
  publicKey: string;
  scopes: ScopeManifestEntry[];
  emitters: EmitterManifestEntry[];
  config?: ConfigManifestEntry;
}

export interface ScopeDefinition {
  description: string;
  /** When true, invoke does not require a grant (Sig 2 only). Default false. */
  open?: boolean;
  input: z.ZodType;
  output: z.ZodType;
}

export interface EmitterDefinition {
  description: string;
  output: z.ZodType;
}

export function buildConfigManifest(definition: ConfigDefinition): ConfigManifestEntry {
  const shape = definition.schema.shape;
  const fields: ConfigManifestFieldEntry[] = [];
  for (const [name, fieldSchema] of Object.entries(shape)) {
    fields.push({
      name,
      type: z.toJSONSchema(fieldSchema, { io: "input" }) as Record<string, unknown>,
      source: definition.fields[name] ?? "userEntered",
    });
  }
  return { fields };
}

export function buildManifest(
  config: {
    id: string;
    name: string;
    description: string;
    version: string;
    publicKey: string;
    configDefinition?: ConfigDefinition;
  },
  scopes: Map<string, ScopeDefinition>,
  emitters: Map<string, EmitterDefinition> = new Map(),
): ModuleManifest {
  const scopeEntries: ScopeManifestEntry[] = [];
  for (const [name, def] of scopes) {
    const entry: ScopeManifestEntry = {
      name,
      description: def.description,
      input: z.toJSONSchema(def.input, { io: "input" }) as Record<string, unknown>,
      output: z.toJSONSchema(def.output, { io: "output" }) as Record<string, unknown>,
    };
    if (def.open) {
      entry.open = true;
    }
    scopeEntries.push(entry);
  }
  const emitterEntries: EmitterManifestEntry[] = [];
  for (const [name, def] of emitters) {
    emitterEntries.push({
      name,
      description: def.description,
      output: z.toJSONSchema(def.output, { io: "output" }) as Record<string, unknown>,
    });
  }
  const manifest: ModuleManifest = {
    id: config.id,
    name: config.name,
    description: config.description,
    version: config.version,
    publicKey: config.publicKey,
    scopes: scopeEntries,
    emitters: emitterEntries,
  };

  if (config.configDefinition) {
    manifest.config = buildConfigManifest(config.configDefinition);
  }

  return manifest;
}

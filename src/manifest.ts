import { z } from "zod";

export interface ScopeManifestEntry {
  name: string;
  description: string;
  input: Record<string, unknown>;
  output: Record<string, unknown>;
}

export interface ModuleManifest {
  id: string;
  name: string;
  description: string;
  version: string;
  publicKey: string;
  scopes: ScopeManifestEntry[];
}

export interface ScopeDefinition {
  description: string;
  input: z.ZodType;
  output: z.ZodType;
}

export function buildManifest(
  config: {
    id: string;
    name: string;
    description: string;
    version: string;
    publicKey: string;
  },
  scopes: Map<string, ScopeDefinition>,
): ModuleManifest {
  const scopeEntries: ScopeManifestEntry[] = [];
  for (const [name, def] of scopes) {
    scopeEntries.push({
      name,
      description: def.description,
      input: z.toJSONSchema(def.input, { io: "input" }) as Record<string, unknown>,
      output: z.toJSONSchema(def.output, { io: "output" }) as Record<string, unknown>,
    });
  }
  return {
    id: config.id,
    name: config.name,
    description: config.description,
    version: config.version,
    publicKey: config.publicKey,
    scopes: scopeEntries,
  };
}

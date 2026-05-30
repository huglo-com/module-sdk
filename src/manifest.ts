import { z } from "zod";

export interface ScopeManifestEntry {
  name: string;
  description: string;
  /** When true, invoke does not require a grant (Sig 2 only). Omitted when false. */
  open?: boolean;
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
  /** When true, invoke does not require a grant (Sig 2 only). Default false. */
  open?: boolean;
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
  return {
    id: config.id,
    name: config.name,
    description: config.description,
    version: config.version,
    publicKey: config.publicKey,
    scopes: scopeEntries,
  };
}

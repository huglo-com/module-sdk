export interface InstanceConfig {
  instanceId: string;
  /** WHOSE config — a value, not a lookup key. */
  subject: string;
  values: Record<string, unknown>;
}

export interface ConfigStore {
  /** Keyed by instanceId alone. Subject is retrieved from the stored record. */
  get(instanceId: string): Promise<InstanceConfig | null>;
  set(config: InstanceConfig): Promise<void>;
  /** List all configs for a subject ("show me my configs"). */
  listBySubject(subject: string): Promise<InstanceConfig[]>;
  delete(instanceId: string): Promise<void>;
}

/** In-memory config store for development, tests, and examples. */
export class InMemoryConfigStore implements ConfigStore {
  private readonly configs = new Map<string, InstanceConfig>();

  async get(instanceId: string): Promise<InstanceConfig | null> {
    return this.configs.get(instanceId) ?? null;
  }

  async set(config: InstanceConfig): Promise<void> {
    this.configs.set(config.instanceId, config);
  }

  async listBySubject(subject: string): Promise<InstanceConfig[]> {
    return [...this.configs.values()].filter((c) => c.subject === subject);
  }

  async delete(instanceId: string): Promise<void> {
    this.configs.delete(instanceId);
  }

  /** Clear all stored configs (for tests). */
  clear(): void {
    this.configs.clear();
  }

  /** Number of stored configs (for tests). */
  size(): number {
    return this.configs.size;
  }
}

import type { SignedGrant } from "./envelope.js";

export interface GrantStore {
  save(grant: SignedGrant): Promise<void>;
  find(key: {
    subject: string;
    holder: string;
    scope: string;
    requester: string;
  }): Promise<SignedGrant | null>;
  list?(filter: { subject?: string }): Promise<SignedGrant[]>;
  delete?(grantId: string): Promise<void>;
}

export interface GrantLookupKey {
  subject: string;
  holder: string;
  scope: string;
  requester: string;
}

/** In-memory grant store for development, tests, and examples. */
export class InMemoryGrantStore implements GrantStore {
  private readonly grants = new Map<string, SignedGrant>();

  async save(grant: SignedGrant): Promise<void> {
    this.grants.set(grant.grant.grant_id, grant);
  }

  async find(key: GrantLookupKey): Promise<SignedGrant | null> {
    for (const grant of this.grants.values()) {
      const { grant: g } = grant;
      if (
        g.subject === key.subject &&
        g.holder === key.holder &&
        g.scope === key.scope &&
        g.requester === key.requester
      ) {
        return grant;
      }
    }
    return null;
  }

  async list(filter: { subject?: string } = {}): Promise<SignedGrant[]> {
    const all = [...this.grants.values()];
    if (filter.subject === undefined) {
      return all;
    }
    return all.filter((g) => g.grant.subject === filter.subject);
  }

  async delete(grantId: string): Promise<void> {
    this.grants.delete(grantId);
  }

  /** Clear all stored grants (for tests). */
  clear(): void {
    this.grants.clear();
  }

  /** Number of stored grants (for tests). */
  size(): number {
    return this.grants.size;
  }
}

export interface StoredFile {
  token: string;
  body: Uint8Array;
  content_type: string;
  filename: string;
  size: number;
  expires_at: string;
}

export interface FileStore {
  put(file: StoredFile): Promise<void>;
  get(token: string): Promise<StoredFile | null>;
  delete(token: string): Promise<void>;
}

const SWEEP_INTERVAL_MS = 60_000;

/** In-memory file store for development, tests, and examples. */
export class InMemoryFileStore implements FileStore {
  private readonly files = new Map<string, StoredFile>();
  private readonly sweeper: ReturnType<typeof setInterval>;

  constructor() {
    this.sweeper = setInterval(() => this.purgeExpired(), SWEEP_INTERVAL_MS);
    this.sweeper.unref();
  }

  async put(file: StoredFile): Promise<void> {
    this.files.set(file.token, file);
  }

  async get(token: string): Promise<StoredFile | null> {
    const file = this.files.get(token);
    if (!file) {
      return null;
    }
    if (Date.now() > Date.parse(file.expires_at)) {
      this.files.delete(token);
      return null;
    }
    return file;
  }

  async delete(token: string): Promise<void> {
    this.files.delete(token);
  }

  /** Clear all stored files (for tests). */
  clear(): void {
    this.files.clear();
  }

  /** Number of stored files (for tests). */
  size(): number {
    return this.files.size;
  }

  private purgeExpired(): void {
    const now = Date.now();
    for (const [token, file] of this.files) {
      if (now > Date.parse(file.expires_at)) {
        this.files.delete(token);
      }
    }
  }
}

export interface ModuleErrorOptions {
  code: string;
  message: string;
  retryable: boolean;
}

export class ModuleError extends Error {
  readonly code: string;
  readonly retryable: boolean;

  constructor(options: ModuleErrorOptions) {
    super(options.message);
    this.name = "ModuleError";
    this.code = options.code;
    this.retryable = options.retryable;
  }

  toJSON(): { code: string; message: string; retryable: boolean } {
    return {
      code: this.code,
      message: this.message,
      retryable: this.retryable,
    };
  }
}

export interface NormalizedError {
  code: string;
  message: string;
  retryable: boolean;
}

/** Convert any thrown value into a safe, client-facing error shape. */
export function normalizeError(err: unknown): NormalizedError {
  if (err instanceof ModuleError) {
    return err.toJSON();
  }
  return {
    code: "internal_error",
    message: "An internal error occurred",
    retryable: false,
  };
}

/** Create a ModuleError for verification / auth failures (non-retryable). */
export function authError(code: string, message: string): ModuleError {
  return new ModuleError({ code, message, retryable: false });
}

/** Create a ModuleError for transient infrastructure failures (retryable). */
export function infraError(code: string, message: string): ModuleError {
  return new ModuleError({ code, message, retryable: true });
}

import type { DirectoryClient } from "./directory.js";
import { ModuleError } from "./errors.js";
import { verifyObject } from "./signing.js";
import type { NonceCache } from "./verify.js";

export const CONFIG_PROOF_PURPOSE = "config" as const;

/** Default config proof validity window (5 minutes). */
export const CONFIG_PROOF_TTL_MS = 5 * 60 * 1000;

export interface ConfigProofAssertion {
  subject: string;
  audience: string;
  purpose: typeof CONFIG_PROOF_PURPOSE;
  nonce: string;
  issued_at: string;
  expires_at: string;
}

export interface ConfigProof {
  assertion: ConfigProofAssertion;
  signature: string;
}

export interface VerifyConfigProofOptions {
  moduleId: string;
  directory: DirectoryClient;
  /** Replay cache for assertion nonce — one successful save per nonce. */
  nonceCache: NonceCache;
  /** Override current time (for tests). */
  now?: number;
  /** Clock skew tolerance in ms (default 0). */
  maxClockSkewMs?: number;
}

function configProofError(code: string, message: string): ModuleError {
  return new ModuleError({ code, message, retryable: false });
}

function parseConfigProof(raw: unknown): ConfigProof {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw configProofError("invalid_config_proof", "Config proof must be an object");
  }
  const record = raw as { assertion?: unknown; signature?: unknown };
  if (typeof record.signature !== "string" || record.signature.length === 0) {
    throw configProofError("invalid_config_proof", "Config proof missing signature");
  }
  const assertion = record.assertion;
  if (typeof assertion !== "object" || assertion === null || Array.isArray(assertion)) {
    throw configProofError("invalid_config_proof", "Config proof missing assertion");
  }
  const a = assertion as Record<string, unknown>;
  for (const key of ["subject", "audience", "purpose", "nonce", "issued_at", "expires_at"] as const) {
    if (typeof a[key] !== "string" || (a[key]).length === 0) {
      throw configProofError("invalid_config_proof", `Config proof assertion missing ${key}`);
    }
  }
  return {
    assertion: assertion as ConfigProofAssertion,
    signature: record.signature,
  };
}

/**
 * Verify a directory-signed config identity proof.
 * Returns the verified Huglo subject (directorySubject) on success.
 */
export async function verifyConfigProof(
  rawProof: unknown,
  options: VerifyConfigProofOptions,
): Promise<string> {
  const proof = parseConfigProof(rawProof);
  const { assertion } = proof;

  if (assertion.purpose !== CONFIG_PROOF_PURPOSE) {
    throw configProofError("config_proof_purpose_mismatch", "Invalid config proof purpose");
  }

  if (assertion.audience !== options.moduleId) {
    throw configProofError("config_proof_audience_mismatch", "Config proof audience does not match module");
  }

  const now = options.now ?? Date.now();
  const skew = options.maxClockSkewMs ?? 0;
  const expiresAt = Date.parse(assertion.expires_at);
  if (Number.isNaN(expiresAt) || now > expiresAt + skew) {
    throw configProofError("config_proof_expired", "Config proof has expired");
  }

  const issuedAt = Date.parse(assertion.issued_at);
  if (Number.isNaN(issuedAt) || issuedAt > now + skew) {
    throw configProofError("config_proof_invalid", "Config proof issued_at is in the future");
  }

  let publicKey;
  try {
    publicKey = await options.directory.getUserKey(assertion.subject);
  } catch {
    throw configProofError("config_proof_user_not_found", "Config proof subject not found in directory");
  }

  if (!verifyObject(assertion, proof.signature, publicKey)) {
    throw configProofError("config_proof_invalid_signature", "Config proof signature verification failed");
  }

  if (!options.nonceCache.checkAndMark(assertion.nonce)) {
    throw configProofError("config_proof_nonce_replayed", "Config proof nonce has already been used");
  }

  return assertion.subject;
}

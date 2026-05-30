import type { z } from "zod";
import { randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { DirectoryClient } from "./directory.js";
import type { SignedGrant, InvokeRequest } from "./envelope.js";
import {
  InvokeRequestSchema,
  sig1Payload,
  sig2Payload,
} from "./envelope.js";
import { authError, infraError, ModuleError } from "./errors.js";
import { verifyObject, parseSignature } from "./signing.js";

/** Default request timestamp acceptance window: ±5 minutes. */
export const TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;

/** Nonce cache TTL — slightly longer than timestamp window. */
export const NONCE_TTL_MS = 6 * 60 * 1000;

export interface VerifiedInvokeContext<I> {
  subject: string;
  input: I;
  grant: SignedGrant;
  caller: string;
  scope: string;
  requestId: string;
  dryRun: boolean;
}

export interface VerifyOptions {
  moduleId: string;
  urlScope: string;
  inputSchema: z.ZodType;
  directory: DirectoryClient;
  /** Constraint keys this holder recognizes. Unknown keys in grant.constraints → reject. */
  knownConstraints?: Set<string>;
  dryRun?: boolean;
  requestId?: string;
}

/** Simple in-process nonce replay cache. */
export class NonceCache {
  private readonly seen = new Map<string, number>();

  /** Returns true if nonce is fresh (not seen); marks it as seen. */
  checkAndMark(nonce: string): boolean {
    this.evict();
    if (this.seen.has(nonce)) {
      return false;
    }
    this.seen.set(nonce, Date.now() + NONCE_TTL_MS);
    return true;
  }

  /** Clear all seen nonces (for tests). */
  clear(): void {
    this.seen.clear();
  }

  private evict(): void {
    const now = Date.now();
    for (const [nonce, expiresAt] of this.seen) {
      if (now > expiresAt) {
        this.seen.delete(nonce);
      }
    }
  }
}

function rethrowDirectoryError(err: unknown, message: string): never {
  if (err instanceof ModuleError) throw err;
  throw infraError("directory_unreachable", message);
}

/** Step 1: Parse envelope. */
function parseEnvelope(rawBody: unknown): InvokeRequest {
  try {
    return InvokeRequestSchema.parse(rawBody);
  } catch {
    throw authError("malformed_request", "Request envelope is malformed");
  }
}

/** Step 2: Timestamp within ±5 min. */
function verifyTimestamp(timestamp: string, now = Date.now()): void {
  const reqTime = Date.parse(timestamp);
  if (Number.isNaN(reqTime)) {
    throw authError("invalid_timestamp", "Request timestamp is not valid ISO 8601");
  }
  if (Math.abs(now - reqTime) > TIMESTAMP_WINDOW_MS) {
    throw authError("timestamp_expired", "Request timestamp is outside acceptance window");
  }
}

/** Step 3: Nonce unseen (replay protection). */
function verifyNonce(nonceCache: NonceCache, nonce: string): void {
  if (!nonceCache.checkAndMark(nonce)) {
    throw authError("nonce_replayed", "Request nonce has already been used");
  }
}

/** Step 4: Verify Sig 2 (requester). */
async function verifyRequestSignature(
  req: InvokeRequest,
  directory: DirectoryClient,
): Promise<void> {
  let requesterKey: KeyObject;
  try {
    const parsed = parseSignature(req.requesterSignature);
    requesterKey = await directory.getModuleKey(
      req.grant.grant.requester,
      parsed.keyId,
    );
  } catch (err) {
    rethrowDirectoryError(err, "Unable to fetch requester public key");
  }

  if (!verifyObject(sig2Payload(req), req.requesterSignature, requesterKey)) {
    throw authError("invalid_request_signature", "Request signature verification failed");
  }
}

/** Step 5: Verify Sig 1 (author/subject). */
async function verifyGrantSignature(
  grant: SignedGrant,
  directory: DirectoryClient,
): Promise<void> {
  let authorKey: KeyObject;
  try {
    const parsed = parseSignature(grant.signature);
    const authorId = grant.grant.author;
    authorKey = authorId.startsWith("huglo:user:")
      ? await directory.getUserKey(authorId, parsed.keyId)
      : await directory.getModuleKey(authorId, parsed.keyId);
  } catch (err) {
    rethrowDirectoryError(err, "Unable to fetch author public key");
  }

  if (!verifyObject(sig1Payload(grant), grant.signature, authorKey)) {
    throw authError("invalid_grant_signature", "Grant signature verification failed");
  }
}

/** Step 6: Grant validity window. */
function verifyGrantValidityWindow(
  grant: SignedGrant["grant"],
  now = Date.now(),
): void {
  const issuedAt = Date.parse(grant.issued_at);
  const expiresAt = Date.parse(grant.expires_at);
  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt)) {
    throw authError("invalid_grant_dates", "Grant dates are not valid ISO 8601");
  }
  if (now < issuedAt || now > expiresAt) {
    throw authError("grant_expired", "Grant is outside its validity window");
  }
}

/** Step 7: Binding checks (holder, scope, requester). */
function verifyBindings(req: InvokeRequest, options: VerifyOptions): void {
  if (req.grant.grant.holder !== options.moduleId) {
    throw authError("grant_holder_mismatch", "Grant holder does not match this module");
  }
  if (req.grant.grant.scope !== options.urlScope) {
    throw authError("grant_scope_mismatch", "Grant scope does not match URL scope");
  }
  if (req.scope !== options.urlScope) {
    throw authError("scope_mismatch", "Body scope does not match URL scope");
  }
  // grant.requester is enforced by fetching key by grant.requester in step 4
}

/** Step 8: Constraints — fail closed on unknown keys. */
function verifyConstraints(
  constraints: Record<string, unknown>,
  knownConstraints?: Set<string>,
): void {
  const known = knownConstraints ?? new Set<string>();
  for (const key of Object.keys(constraints)) {
    if (!known.has(key)) {
      throw authError(
        "unknown_constraint",
        `Unrecognized grant constraint: ${key}`,
      );
    }
  }
}

/** Step 9: Revocation check. */
async function verifyNotRevoked(
  grantId: string,
  directory: DirectoryClient,
): Promise<void> {
  let revoked: boolean;
  try {
    revoked = await directory.isRevoked(grantId);
  } catch (err) {
    rethrowDirectoryError(err, "Unable to check revocation list");
  }
  if (revoked) {
    throw authError("grant_revoked", "Grant has been revoked");
  }
}

/** Step 10: Validate payload against input schema. */
function validatePayload<I>(payload: unknown, inputSchema: z.ZodType): I {
  try {
    return inputSchema.parse(payload) as I;
  } catch {
    throw authError("invalid_payload", "Payload does not match scope input schema");
  }
}

/**
 * Holder verification sequence (10 steps, in order):
 * 1. Parse envelope
 * 2. Timestamp within ±5 min
 * 3. Nonce unseen (replay protection)
 * 4. Verify Sig 2 (requester)
 * 5. Verify Sig 1 (author/subject)
 * 6. Grant validity window
 * 7. Binding checks (holder, scope, requester)
 * 8. Constraints (fail closed on unknown keys)
 * 9. Revocation check
 * 10. Validate payload against input schema
 */
export async function verifyInvokeRequest<I>(
  rawBody: unknown,
  nonceCache: NonceCache,
  options: VerifyOptions,
): Promise<VerifiedInvokeContext<I>> {
  const req = parseEnvelope(rawBody);
  const now = Date.now();

  verifyTimestamp(req.timestamp, now);
  verifyNonce(nonceCache, req.nonce);
  await verifyRequestSignature(req, options.directory);
  await verifyGrantSignature(req.grant, options.directory);
  verifyGrantValidityWindow(req.grant.grant, now);
  verifyBindings(req, options);
  verifyConstraints(req.grant.grant.constraints, options.knownConstraints);
  await verifyNotRevoked(req.grant.grant.grant_id, options.directory);

  const input = validatePayload<I>(req.payload, options.inputSchema);

  return {
    subject: req.grant.grant.subject,
    input,
    grant: req.grant,
    caller: req.grant.grant.requester,
    scope: options.urlScope,
    requestId: options.requestId ?? randomUUID(),
    dryRun: options.dryRun ?? false,
  };
}

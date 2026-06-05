import type { z } from "zod";
import { randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { DirectoryClient } from "./directory.js";
import type { SignedGrant, InvokeRequest, OpenInvokeRequest } from "./envelope.js";
import {
  InvokeRequestSchema,
  OpenInvokeRequestSchema,
  sig1Payload,
  sig2Payload,
  sig2OpenPayload,
} from "./envelope.js";
import { authError, infraError, ModuleError } from "./errors.js";
import { verifyObject, parseSignature } from "./signing.js";

/** Default request timestamp acceptance window: ±5 minutes. */
export const TIMESTAMP_WINDOW_MS = 5 * 60 * 1000;

/** Nonce cache TTL — slightly longer than timestamp window. */
export const NONCE_TTL_MS = 6 * 60 * 1000;

export interface VerifiedProtectedContext<I> {
  open: false;
  subject: string;
  input: I;
  grant: SignedGrant;
  caller: string;
  scope: string;
  requestId: string;
  dryRun: boolean;
}

export interface VerifiedOpenContext<I> {
  open: true;
  input: I;
  caller: string;
  scope: string;
  requestId: string;
  dryRun: boolean;
}

export type VerifiedInvokeContext<I> =
  | VerifiedProtectedContext<I>
  | VerifiedOpenContext<I>;

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

/** Step 4: Verify Sig 2 (requester) for protected invokes. */
async function verifyRequestSignature(
  req: InvokeRequest,
  directory: DirectoryClient,
): Promise<void> {
  await verifyModuleSignature(
    req.grant.grant.requester,
    sig2Payload(req),
    req.requesterSignature,
    directory,
  );
}

/** Verify Sig 2 for open-scope invokes. */
async function verifyOpenRequestSignature(
  req: OpenInvokeRequest,
  directory: DirectoryClient,
): Promise<void> {
  await verifyModuleSignature(
    req.requester,
    sig2OpenPayload(req),
    req.requesterSignature,
    directory,
  );
}

async function verifyModuleSignature(
  requesterId: string,
  payload: Record<string, unknown>,
  signature: string,
  directory: DirectoryClient,
): Promise<void> {
  let requesterKey: KeyObject;
  try {
    const parsed = parseSignature(signature);
    requesterKey = await directory.getModuleKey(requesterId, parsed.keyId);
  } catch (err) {
    rethrowDirectoryError(err, "Unable to fetch requester public key");
  }

  if (!verifyObject(payload, signature, requesterKey)) {
    throw authError("invalid_request_signature", "Request signature verification failed");
  }
}

/** Step 5: Grant author must be the subject (user self-authorization only). */
function verifyGrantAuthorIsSubject(grant: SignedGrant["grant"]): void {
  const { author, subject } = grant;
  if (!author.startsWith("huglo:user:") || !subject.startsWith("huglo:user:")) {
    throw authError(
      "invalid_grant_subject",
      "Grant author and subject must be user identifiers",
    );
  }
  if (author !== subject) {
    throw authError(
      "grant_author_mismatch",
      "Grant author must match subject",
    );
  }
}

/** Step 6: Verify Sig 1 (user author/subject). */
async function verifyGrantSignature(
  grant: SignedGrant,
  directory: DirectoryClient,
): Promise<void> {
  let authorKey: KeyObject;
  try {
    const parsed = parseSignature(grant.signature);
    const authorId = grant.grant.author;
    authorKey = await directory.getUserKey(authorId, parsed.keyId);
  } catch (err) {
    rethrowDirectoryError(err, "Unable to fetch author public key");
  }

  if (!verifyObject(sig1Payload(grant), grant.signature, authorKey)) {
    throw authError("invalid_grant_signature", "Grant signature verification failed");
  }
}

/** Step 7: Grant validity window. */
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

/** Step 8: Binding checks (holder, scope, requester). */
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

/** Step 9: Constraints — fail closed on unknown keys. */
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

/** Step 10: Revocation check. */
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

/** Step 11: Validate payload against input schema. */
function validatePayload<I>(payload: unknown, inputSchema: z.ZodType): I {
  try {
    return inputSchema.parse(payload) as I;
  } catch {
    throw authError("invalid_payload", "Payload does not match scope input schema");
  }
}

/**
 * Holder verification sequence (11 steps, in order):
 * 1. Parse envelope
 * 2. Timestamp within ±5 min
 * 3. Nonce unseen (replay protection)
 * 4. Verify Sig 2 (requester)
 * 5. Grant author/subject must be matching user identifiers
 * 6. Verify Sig 1 (user author)
 * 7. Grant validity window
 * 8. Binding checks (holder, scope, requester)
 * 9. Constraints (fail closed on unknown keys)
 * 10. Revocation check
 * 11. Validate payload against input schema
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
  verifyGrantAuthorIsSubject(req.grant.grant);
  await verifyGrantSignature(req.grant, options.directory);
  verifyGrantValidityWindow(req.grant.grant, now);
  verifyBindings(req, options);
  verifyConstraints(req.grant.grant.constraints, options.knownConstraints);
  await verifyNotRevoked(req.grant.grant.grant_id, options.directory);

  const input = validatePayload<I>(req.payload, options.inputSchema);

  return {
    open: false,
    subject: req.grant.grant.subject,
    input,
    grant: req.grant,
    caller: req.grant.grant.requester,
    scope: options.urlScope,
    requestId: options.requestId ?? randomUUID(),
    dryRun: options.dryRun ?? false,
  };
}

/** Step 1: Parse open invoke envelope. */
function parseOpenEnvelope(rawBody: unknown): OpenInvokeRequest {
  try {
    return OpenInvokeRequestSchema.parse(rawBody);
  } catch {
    throw authError("malformed_request", "Request envelope is malformed");
  }
}

/** Step 5 (open): Scope binding. */
function verifyOpenBindings(req: OpenInvokeRequest, urlScope: string): void {
  if (req.scope !== urlScope) {
    throw authError("scope_mismatch", "Body scope does not match URL scope");
  }
}

/**
 * Holder verification for open scopes (5 steps):
 * 1. Parse envelope
 * 2. Timestamp within ±5 min
 * 3. Nonce unseen
 * 4. Verify Sig 2 (requester)
 * 5. Scope binding + input schema
 */
export async function verifyOpenInvokeRequest<I>(
  rawBody: unknown,
  nonceCache: NonceCache,
  options: VerifyOptions,
): Promise<VerifiedOpenContext<I>> {
  const req = parseOpenEnvelope(rawBody);

  verifyTimestamp(req.timestamp);
  verifyNonce(nonceCache, req.nonce);
  await verifyOpenRequestSignature(req, options.directory);
  verifyOpenBindings(req, options.urlScope);

  const input = validatePayload<I>(req.payload, options.inputSchema);

  return {
    open: true,
    input,
    caller: req.requester,
    scope: options.urlScope,
    requestId: options.requestId ?? randomUUID(),
    dryRun: options.dryRun ?? false,
  };
}

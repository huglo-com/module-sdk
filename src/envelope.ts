import { z } from "zod";

export interface Grant {
  grant_id: string;
  holder: string;
  scope: string;
  subject: string;
  requester: string;
  author: string;
  constraints: Record<string, unknown>;
  issued_at: string;
  expires_at: string;
}

export interface SignedGrant {
  grant: Grant;
  /** Sig 1 — ed25519 over JCS(grant) */
  signature: string;
}

export interface InvokeRequest {
  payload: unknown;
  grant: SignedGrant;
  scope: string;
  timestamp: string;
  nonce: string;
  /** Sig 2 — ed25519 over JCS({payload, grant, scope, timestamp, nonce}) */
  requesterSignature: string;
}

export interface InvokeError {
  code: string;
  message: string;
  retryable: boolean;
}

export interface InvokeResponse {
  requestId: string;
  result?: unknown;
  error?: InvokeError;
  timestamp: string;
  /** Sig 3 — ed25519 over JCS({requestId, result|error, timestamp}) */
  holderSignature: string;
}

export const GrantSchema = z.object({
  grant_id: z.string(),
  holder: z.string(),
  scope: z.string(),
  subject: z.string(),
  requester: z.string(),
  author: z.string(),
  constraints: z.record(z.string(), z.unknown()),
  issued_at: z.string(),
  expires_at: z.string(),
});

export const SignedGrantSchema = z.object({
  grant: GrantSchema,
  signature: z.string(),
});

export const InvokeRequestSchema = z.object({
  payload: z.unknown(),
  grant: SignedGrantSchema,
  scope: z.string(),
  timestamp: z.string(),
  nonce: z.string(),
  requesterSignature: z.string(),
});

export const InvokeErrorSchema = z.object({
  code: z.string(),
  message: z.string(),
  retryable: z.boolean(),
});

export const InvokeResponseSchema = z.object({
  requestId: z.string(),
  result: z.unknown().optional(),
  error: InvokeErrorSchema.optional(),
  timestamp: z.string(),
  holderSignature: z.string(),
});

/** Object covered by Sig 1 (grant inner object, excluding signature sibling). */
export function sig1Payload(grant: SignedGrant): Grant {
  return grant.grant;
}

/** Object covered by Sig 2 (request body minus requesterSignature). */
export function sig2Payload(req: InvokeRequest): {
  payload: unknown;
  grant: SignedGrant;
  scope: string;
  timestamp: string;
  nonce: string;
} {
  return {
    payload: req.payload,
    grant: req.grant,
    scope: req.scope,
    timestamp: req.timestamp,
    nonce: req.nonce,
  };
}

/** Object covered by Sig 3 (response minus holderSignature). */
export function sig3Payload(res: InvokeResponse): {
  requestId: string;
  result?: unknown;
  error?: InvokeError;
  timestamp: string;
} {
  const base: {
    requestId: string;
    result?: unknown;
    error?: InvokeError;
    timestamp: string;
  } = {
    requestId: res.requestId,
    timestamp: res.timestamp,
  };
  if (res.error === undefined) {
    base.result = res.result;
  } else {
    base.error = res.error;
  }
  return base;
}

export interface ChallengePayload {
  challenge: string;
  moduleId: string;
  endpoint: string;
  publicKey: string;
}

export const ChallengePayloadSchema = z.object({
  challenge: z.string(),
  moduleId: z.string(),
  endpoint: z.string(),
  publicKey: z.string(),
});

export interface SignedChallenge {
  payload: ChallengePayload;
  signature: string;
}

export interface InviteScopeRequest {
  holder: string;
  scope: string;
}

export interface InvitePayload {
  moduleId: string;
  callbackUrl: string;
  scopes: InviteScopeRequest[];
  constraints: Record<string, unknown>;
  iat: string;
}

export interface SignedInvitePayload {
  payload: InvitePayload;
  /** ed25519 over JCS(payload) by the requester module */
  signature: string;
}

export interface InviteScope {
  id: string;
  inviteId: string;
  holder: string;
  scope: string;
}

export interface Invite {
  id: string;
  requesterModuleId: string;
  callbackUrl: string;
  constraints: Record<string, unknown>;
  expiresAt: string;
  createdByUserId: string;
  active: boolean;
  createdAt: string;
  updatedAt: string;
  scopes: InviteScope[];
}

export interface CreateInviteResponse {
  invite: Invite;
  inviteUrl: string;
}

export interface GrantExchangeResponse {
  grants: SignedGrant[];
}

export const InviteScopeRequestSchema = z.object({
  holder: z.string(),
  scope: z.string(),
});

export const InvitePayloadSchema = z.object({
  moduleId: z.string(),
  callbackUrl: z.string(),
  scopes: z.array(InviteScopeRequestSchema),
  constraints: z.record(z.string(), z.unknown()),
  iat: z.string(),
});

export const SignedInvitePayloadSchema = z.object({
  payload: InvitePayloadSchema,
  signature: z.string(),
});

export const InviteScopeSchema = z.object({
  id: z.string(),
  inviteId: z.string(),
  holder: z.string(),
  scope: z.string(),
});

export const InviteSchema = z.object({
  id: z.string(),
  requesterModuleId: z.string(),
  callbackUrl: z.string(),
  constraints: z.record(z.string(), z.unknown()),
  expiresAt: z.string(),
  createdByUserId: z.string(),
  active: z.boolean(),
  createdAt: z.string(),
  updatedAt: z.string(),
  scopes: z.array(InviteScopeSchema),
});

export const CreateInviteResponseSchema = z.object({
  invite: InviteSchema,
  inviteUrl: z.string(),
});

export const GrantExchangeResponseSchema = z.object({
  grants: z.array(SignedGrantSchema),
});

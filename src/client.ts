import { randomUUID } from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { DirectoryClient } from "./directory.js";
import type { SignedGrant, InvokeRequest, InvokeResponse } from "./envelope.js";
import {
  InvokeResponseSchema,
  sig2Payload,
  sig3Payload,
} from "./envelope.js";
import { ModuleError, authError, infraError } from "./errors.js";
import { signObject, verifyObject, parseSignature } from "./signing.js";

export interface CallOptions {
  target: string;
  scope: string;
  input: unknown;
  grant: SignedGrant;
  dryRun?: boolean;
}

export interface ModuleCallContext {
  moduleId: string;
  privateKey: KeyObject;
  directory: DirectoryClient;
}

function validateCallGrant(
  grant: SignedGrant,
  moduleId: string,
  target: string,
  scope: string,
): void {
  if (grant.grant.requester !== moduleId) {
    throw authError(
      "grant_requester_mismatch",
      "Grant requester does not match this module",
    );
  }
  if (grant.grant.holder !== target) {
    throw authError(
      "grant_holder_mismatch",
      "Grant holder does not match target module",
    );
  }
  if (grant.grant.scope !== scope) {
    throw authError(
      "grant_scope_mismatch",
      "Grant scope does not match requested scope",
    );
  }
}

async function resolveEndpoint(
  directory: DirectoryClient,
  target: string,
): Promise<string> {
  try {
    return await directory.getEndpoint(target);
  } catch (err) {
    if (err instanceof ModuleError) throw err;
    throw infraError("directory_unreachable", "Unable to resolve target endpoint");
  }
}

async function fetchHolderKey(
  directory: DirectoryClient,
  target: string,
  holderSignature: string,
): Promise<KeyObject> {
  try {
    const parsed = parseSignature(holderSignature);
    return await directory.getModuleKey(target, parsed.keyId);
  } catch (err) {
    if (err instanceof ModuleError) throw err;
    throw infraError("directory_unreachable", "Unable to fetch holder public key");
  }
}

function parseInvokeResponseBody(body: unknown): InvokeResponse {
  try {
    return InvokeResponseSchema.parse(body);
  } catch {
    throw infraError("invalid_response", "Target response envelope is malformed");
  }
}

/**
 * Outbound client: resolve target, build envelope, sign Sig 2,
 * POST to /invoke/:scope, verify Sig 3, return result or throw.
 */
export async function callScope(
  ctx: ModuleCallContext,
  options: CallOptions,
): Promise<unknown> {
  const { target, scope, input, grant, dryRun = false } = options;

  validateCallGrant(grant, ctx.moduleId, target, scope);

  const endpoint = await resolveEndpoint(ctx.directory, target);
  const timestamp = new Date().toISOString();
  const nonce = randomUUID();
  const requestId = randomUUID();

  const envelope: InvokeRequest = {
    payload: input,
    grant,
    scope,
    timestamp,
    nonce,
    requesterSignature: "", // filled below
  };

  envelope.requesterSignature = signObject(sig2Payload(envelope), ctx.privateKey);

  const url = `${endpoint}/invoke/${encodeURIComponent(scope)}`;
  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "X-Request-Id": requestId,
        ...(dryRun ? { "X-Dry-Run": "true" } : {}),
      },
      body: JSON.stringify(envelope),
    });
  } catch {
    throw infraError("network_error", "Failed to reach target module");
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw infraError("invalid_response", "Target returned non-JSON response");
  }

  const invokeResponse = parseInvokeResponseBody(body);

  if (invokeResponse.requestId !== requestId) {
    throw authError("request_id_mismatch", "Response requestId does not match");
  }

  const holderKey = await fetchHolderKey(
    ctx.directory,
    target,
    invokeResponse.holderSignature,
  );

  if (!verifyObject(sig3Payload(invokeResponse), invokeResponse.holderSignature, holderKey)) {
    throw authError("invalid_response_signature", "Response signature verification failed");
  }

  if (invokeResponse.error) {
    throw new ModuleError({
      code: invokeResponse.error.code,
      message: invokeResponse.error.message,
      retryable: invokeResponse.error.retryable,
    });
  }

  return invokeResponse.result;
}

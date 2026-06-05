import type { Context, MiddlewareHandler } from "hono";
import type { KeyObject } from "node:crypto";
import type { DirectoryClient } from "./directory.js";
import type {
  CreateInviteResponse,
  InviteScopeRequest,
  SignedGrant,
} from "./envelope.js";
import { signObject } from "./signing.js";
import type { GrantStore } from "./store.js";

export interface SignedCreateInviteOptions {
  callbackUrl: string;
  scopes: InviteScopeRequest[];
  constraints?: Record<string, unknown>;
}

export type GrantCallbackStage = "missing_code" | "exchange" | "save" | "render";

export interface GrantCallbackContext {
  c: Context;
  code: string;
  grants: SignedGrant[];
}

export interface GrantCallbackErrorContext {
  c: Context;
  code?: string;
  error: unknown;
  stage: GrantCallbackStage;
}

export type GrantCallbackResult = Response | string | void;

export type OnGrantCallback = (
  ctx: GrantCallbackContext,
) => GrantCallbackResult | Promise<GrantCallbackResult>;

export type OnGrantCallbackError = (
  ctx: GrantCallbackErrorContext,
) => GrantCallbackResult | Promise<GrantCallbackResult>;

export interface GrantCallbackOptions {
  onGrantCallback?: OnGrantCallback;
  onGrantCallbackError?: OnGrantCallbackError;
  callbackMiddleware?: MiddlewareHandler | MiddlewareHandler[];
}

/** Full grant callback URL (module endpoint + callback path). */
export function buildGrantCallbackUrl(
  endpoint: string,
  callbackPath: string,
): string {
  const base = endpoint.replaceAll(/\/$/g, "");
  const path = callbackPath.startsWith("/") ? callbackPath : `/${callbackPath}`;
  return `${base}${path}`;
}

/** Create a signed invite at Huglo (requester module signs the payload). */
export async function createSignedInvite(
  directory: DirectoryClient,
  moduleId: string,
  privateKey: KeyObject,
  options: SignedCreateInviteOptions,
): Promise<CreateInviteResponse> {
  const payload = {
    moduleId,
    callbackUrl: options.callbackUrl,
    scopes: options.scopes,
    constraints: options.constraints ?? {},
    iat: new Date().toISOString(),
  };
  const signature = signObject(payload, privateKey);
  return directory.createInvite(moduleId, { payload, signature });
}

/** Exchange an invite code for grants and persist each via `grantStore`. */
export async function exchangeAndSaveGrants(
  directory: DirectoryClient,
  grantStore: GrantStore,
  code: string,
): Promise<SignedGrant[]> {
  const grants = await directory.exchangeGrants(code);
  for (const grant of grants) {
    await grantStore.save(grant);
  }
  return grants;
}

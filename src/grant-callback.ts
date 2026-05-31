import type { Context, MiddlewareHandler } from "hono";
import type { DirectoryClient } from "./directory.js";
import type { SignedGrant } from "./envelope.js";
import type { GrantStore } from "./store.js";

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

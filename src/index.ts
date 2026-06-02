export { Module, ModuleError, DEFAULT_HUGLO_DIRECTORY_URL, exchangeAndSaveGrants } from "./module.js";
export type {
  ModuleConfig,
  ScopeOptions,
  ProtectedScopeOptions,
  OpenScopeOptions,
  EmitterOptions,
  CallOptions,
  CreateInviteOptions,
  GrantCallbackContext,
  GrantCallbackErrorContext,
  GrantCallbackResult,
  GrantCallbackStage,
  OnGrantCallback,
  OnGrantCallbackError,
  ConfigDefinition,
  ConfigOptions,
  FieldSource,
  ConfigStore,
  InstanceConfig,
  HugloOAuthClient,
  OAuthClientOptions,
  OnConfigSaved,
  OnConfigSavedContext,
  ConfigPageTheme,
} from "./module.js";
export {
  InMemoryConfigStore,
  assembleConfigValues,
  ConfigAssemblyError,
  HttpHugloOAuthClient,
  InMemoryHugloOAuthClient,
  resolveOAuthOptions,
  DEFAULT_CONFIG_PATH,
} from "./module.js";
export type {
  EmitterManifestEntry,
  EmitterDefinition,
  ConfigManifestEntry,
  ConfigManifestFieldEntry,
} from "./manifest.js";
export type { Ctx, ProtectedCtx, OpenCtx } from "./context.js";
export type {
  SignedGrant,
  InvokeRequest,
  OpenInvokeRequest,
  InvokeResponse,
  Grant,
  InvitePayload,
  InviteScopeRequest,
  Invite,
  CreateInviteResponse,
} from "./envelope.js";
export type { DirectoryClient } from "./directory.js";
export { HttpDirectoryClient, InMemoryDirectoryClient } from "./directory.js";
export type { GrantStore } from "./store.js";
export { InMemoryGrantStore } from "./store.js";
export { DEFAULT_CALLBACK_PATH } from "./server.js";
export { loadKeyPair, generateKeyPair } from "./keys.js";
export type { ModuleKeyPair } from "./keys.js";


// The following functions are exported only for testing purposes, they should not be used in the production code
export {
  createConfigSession,
  readConfigSession,
  CONFIG_SESSION_COOKIE,
  OAUTH_STATE_COOKIE,
} from "./oauth.js";
export { signObject, verifyObject } from "./signing.js";

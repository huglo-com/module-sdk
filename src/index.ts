export { Module, ModuleError, DEFAULT_HUGLO_DIRECTORY_URL, exchangeAndSaveGrants } from "./module.js";
export type { ModuleMetrics } from "./metrics.js";
export { createModuleMetrics } from "./metrics.js";
export { Counter, Gauge, Histogram, Registry } from "prom-client";
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
  RenderConfigPage,
  RenderConfigPageContext,
  RenderConfigPageResult,
  ConfigPageTheme,
  ConfigInstanceEntry,
} from "./module.js";
export { configPageHtml } from "./module.js";
export {
  InMemoryConfigStore,
  assembleConfigValues,
  ConfigAssemblyError,
  HttpHugloOAuthClient,
  InMemoryHugloOAuthClient,
  resolveOAuthOptions,
  DEFAULT_CONFIG_PATH,
  DEFAULT_HUGLO_OAUTH_ISSUER,
  DEFAULT_HUGLO_OAUTH_SCOPES,
  OAUTH_PKCE_COOKIE,
  generateCodeVerifier,
  generateCodeChallenge,
  createPkceCookie,
  readPkceCookie,
} from "./module.js";
export type { OAuthPkceParams } from "./module.js";
export type {
  EmitterManifestEntry,
  EmitterDefinition,
  ConfigManifestEntry,
  ConfigManifestFieldEntry,
} from "./manifest.js";
export type { TypeManifestEntry } from "./type-system.js";
export type {
  TypeDefinition,
  TypeDisplay,
  TypeOperator,
} from "./type-system.js";
export { computeSchemaHash, tagSchema } from "./type-system.js";
export { fileType, builtinTypes } from "./builtin-types/index.js";
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
export type { FileStore, StoredFile } from "./file-store.js";
export { InMemoryFileStore } from "./file-store.js";
export {
  type File,
  type CreateFileOptions,
  type CreateFileDataOptions,
  type CreateFileUrlOptions,
  DEFAULT_MAX_FILE_BYTES,
} from "./file.js";
export {
  DEFAULT_CALLBACK_PATH,
  DEFAULT_GRANT_INIT_PATH,
  grantInitPath,
  grantAuthorizedNotifyHtml,
} from "./module.js";
export { loadKeyPair, generateKeyPair } from "./keys.js";
export type { ModuleKeyPair } from "./keys.js";
export {
  openConfigPopup,
  buildConfigUrl,
  isConfigReadyMessage,
  parseConfigSavedMessage,
  CONFIG_READY_MESSAGE,
  CONFIG_SAVED_MESSAGE,
  DEFAULT_CONFIG_POPUP_FEATURES,
} from "./config-opener.js";
export type {
  OpenConfigPopupOptions,
  ConfigPopupWindow,
} from "./config-opener.js";
export {
  verifyConfigProof,
} from "./config-proof.js";


// The following functions are exported only for testing purposes, they should not be used in the production code
export {
  createConfigSession,
  readConfigSession,
  CONFIG_SESSION_COOKIE,
  OAUTH_STATE_COOKIE,
} from "./oauth.js";
export { signObject, verifyObject } from "./signing.js";

# Config Identity Proof

This document describes the cross-repo **config identity proof** feature. The module-sdk implementation is the reference; other repos follow the protocol defined here and in [HUGLO_SPECIFICATION.md](./HUGLO_SPECIFICATION.md) §7.6.

## Problem

A valid invoke grant proves *who may call a scope*, but not *which config instance* is allowed. Config instances must be bound to a **verifiable Huglo subject** at save time so invoke can enforce `instance.directorySubject === grant.subject`.

## Two sessions in the config popup

| Session | Purpose | Source |
|---------|---------|--------|
| **A — Module account** | Login to the module provider's UI; list/filter instances by module account | OAuth "Login with Huglo" (managed default) or developer custom login |
| **B — Configuration** | Stamp `directorySubject` on saved instances | Directory-signed `configProof` from host postMessage |

Session A and B are **independent**. Invoke enforcement uses only session B (`directorySubject`).

### Managed vs custom

| | Managed `module.config()` | Custom `customConfig()` |
|--|---------------------------|-------------------------|
| **Session A** | Required: Huglo OAuth on `/config/intake` (401 without cookie) | Developer-defined; optional; SDK does not provide session A |
| **Session B** | Required: `configProof` in intake body | Required: verified `configProof` on custom save route |
| **Invoke binding** | Auto: all protected invokes require `context.configInstanceId` | Manual: handler compares `directorySubject` to `ctx.subject` |

## Flow

1. User authorizes the scope node on the host (existing flow).
2. User clicks **Configure**.
3. Host fetches a config proof from the directory (`POST /directory/config-assertions`, body `{ "audience": "<moduleId>" }` only) using the user's directory session cookie. The directory generates `nonce` and signs the assertion.
4. Host opens module `/config` popup and, on `huglo:config:ready`, postMessages `{ configProof, ...hostValues }` (hostValues only for schema `hostProvided` fields).
5. User logs into module account (session A, managed only) and saves.
6. Module verifies proof, stores `directorySubject`, returns `instanceId`.
7. Host stores `configInstanceId` on the node.
8. At invoke, module/SDK rejects if `instance.directorySubject !== grant.subject`.

## Mint request (directory)

```
POST /directory/config-assertions
{ "audience": "holder-module-id" }
```

- **`audience` only** — no `nonce` on input.
- Directory always sets `assertion.nonce = randomUUID()` before signing.
- Host passes the returned proof to the config popup unchanged.
- Modules reject replayed proof nonces at save.

## Proof shape

See HUGLO_SPECIFICATION.md §7.6.1.

## SDK surface (module-sdk)

| Export | Role |
|--------|------|
| `verifyConfigProof(configProof, { moduleId, directory, nonceCache })` | Verify proof at custom save routes; `nonceCache` enforces single-use assertion nonces |
| `InstanceConfig.directorySubject` | Required stored verified subject |
| Managed `/config/intake` | Requires OAuth session A + `configProof` in body; stamps `directorySubject` |
| Invoke (`POST /invoke/:scope`) | Config-enabled modules: **requires** `context.configInstanceId` on every protected invoke (temporary auto-resolution — see [MODULE_SDK_FLOWBUILDER.md](./MODULE_SDK_FLOWBUILDER.md)) |
| `ctx.config` | Injected resolved config on successful invoke |
| `openConfigPopup({ configUrl, configProof, hostValues?, onSaved })` | Browser helper for host Configure handshake |

**Testing:** `test/helpers/create-signed-config-proof.ts` simulates directory mint output for unit tests only. It is not published in `@huglo/module-sdk`.

## onConfigSaved hook (managed only)

Fires after successful `POST /config/intake`. Not available for `customConfig()`.

| Field | Meaning | Use for |
|-------|---------|---------|
| `subject` | Session A (module OAuth) | Module UI tenancy only — **not** federation identity |
| `directorySubject` | Session B (verified proof) | Host sync, grants, audit, anything tied to invoke / `grant.subject` |

**Rule:** federation-side effects → `directorySubject`.

## Repo tasks

- **[MODULE_SDK_FLOWBUILDER.md](./MODULE_SDK_FLOWBUILDER.md)** — planned extension: `FlowNodeContext`, invoke config resolution (move out of core)
- **[foaf-auth/TASKS-config-proof.md](../foaf-auth/TASKS-config-proof.md)** — mint endpoint + CORS
- **[foaf-flowbuilder-api/TASKS-config-proof.md](../foaf-flowbuilder-api/TASKS-config-proof.md)** — invoke `configInstanceId` injection (API repo has no UI)
- **[foaf-platform/TASKS-config-proof.md](../foaf-platform/TASKS-config-proof.md)** — platform frontend: mint proof, Configure popup, persist `configInstanceId`
- **[email-sender](../email-sender/)** — remove manual subject check; use `ctx.config`; set `directorySubject` on instances

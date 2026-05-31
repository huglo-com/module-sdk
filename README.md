# @huglo/module-sdk

TypeScript SDK for building **Huglo federation modules** — HTTP servers that expose scoped capabilities to other modules via signed requests. The SDK handles the HTTP server, Ed25519 signatures, grant verification, manifest serving, canonicalization, registration challenges, and outbound calls.

**Target:** Node 20+, TypeScript, ESM.

## Install

```bash
npm install @huglo/module-sdk
```

## Quick start

```typescript
import { Module, ModuleError, loadKeyPair } from "@huglo/module-sdk";
import { z } from "zod";

const module = new Module({
  id: "trovi",
  name: "Trovi Invoicing",
  description: "Create and read invoices",
  version: "1.2.0",
  keyPair: loadKeyPair(),
});

module.scope("invoices:write", {
  description: "Create an invoice",
  input: z.object({ vendor: z.string(), amount: z.number().int() }),
  output: z.object({ id: z.string(), vendor: z.string(), amount: z.number().int() }),
  handler: async (ctx) => {
    if (ctx.dryRun) {
      return { id: "preview", vendor: ctx.input.vendor, amount: ctx.input.amount };
    }
    return { id: "inv-001", vendor: ctx.input.vendor, amount: ctx.input.amount };
  },
});

await module.listen(3000);
```

See [`examples/trovi/`](examples/trovi/) for a runnable example.

## Three roles

Every interaction involves up to three parties:

| Role | Description |
|------|-------------|
| **Subject** | The user whose data is concerned (`huglo:user:<id>`). Signs grants via Huglo. |
| **Holder** | The module that holds data / performs the action. Verifies and serves requests. |
| **Requester** | The module making the call. Signs the request. |

A module can be holder in one call and requester in another. The SDK supports both directions.

## HTTP routes (automatic)

| Route | Description |
|-------|-------------|
| `GET /health` | Health check |
| `GET /manifest` | Module metadata, scopes (JSON Schema), public key |
| `GET /.well-known/huglo-challenge` | Registration challenge response (signed) |
| `GET /grant/callback` | Invite callback — exchanges code, saves grants (when `grantStore` is set) |
| `POST /invoke/:scope` | Main entry — verified invoke |
| `GET /assets/*` | Optional static assets (when `assetsDir` is configured) |
| `ANY /api/*` | Optional custom routes (via `module.api(honoApp)`) |

## Wire protocol — `POST /invoke/:scope`

### Request envelope

```typescript
interface InvokeRequest {
  payload: unknown;           // scope input (validated against Zod schema)
  grant: SignedGrant;         // Sig 1 — signed by subject/author
  scope: string;              // must match URL :scope
  timestamp: string;          // ISO 8601 freshness
  nonce: string;              // unique per request (replay protection)
  requesterSignature: string; // Sig 2 — signed by requester
}
```

### Response envelope

```typescript
interface InvokeResponse {
  requestId: string;
  result?: unknown;           // scope output on success
  error?: { code: string; message: string; retryable: boolean };
  timestamp: string;
  holderSignature: string;    // Sig 3 — signed by holder
}
```

Exactly one of `result` or `error` is present — never both.

### Grant shape

```typescript
interface SignedGrant {
  grant: {
    grant_id: string;
    holder: string;           // module id that holds the data
    scope: string;
    subject: string;          // huglo:user:...
    requester: string;        // module id allowed to call
    author: string;           // who authorized (normally subject)
    constraints: Record<string, unknown>; // RESERVED — empty = no restrictions
    issued_at: string;
    expires_at: string;
  };
  signature: string;          // Sig 1 over JCS(grant)
}
```

**Constraints:** Reserved for future use. Holders MUST reject grants with constraint keys they do not recognize (fail closed). An empty `constraints` object imposes no restriction.

## Canonicalization (critical)

Every signature is computed over the **JCS (RFC 8785)** canonical serialization of the relevant parsed object — never raw wire bytes. Both signer and verifier canonicalize independently using the `canonicalize` package.

| Signature | Covers |
|-----------|--------|
| Sig 1 | `JCS(signedGrant.grant)` |
| Sig 2 | `JCS({ payload, grant, scope, timestamp, nonce })` |
| Sig 3 | `JCS({ requestId, result \| error, timestamp })` |

The signature is always a **sibling** of the object it covers and covers everything except itself.

**Rule:** Use integers or strings for numeric values in signed payloads — never floats — to avoid number-format divergence across implementations.

Signature wire format: `ed25519:<base64>` or `ed25519:<keyId>:<base64>` (key rotation stub).

## Holder verification sequence

Before running a handler, the SDK performs these checks **in order**:

1. Parse the envelope; reject if malformed
2. `timestamp` within ±5 minutes
3. `nonce` unseen in short-lived cache (replay protection)
4. Verify Sig 2 against requester's public key (from Huglo directory, cached)
5. Verify Sig 1 against author's public key (cached)
6. Grant validity: `issued_at ≤ now ≤ expires_at`
7. Binding: `grant.holder === this module`, `grant.scope === URL scope === body scope`, requester matches Sig 2
8. Constraints: reject unknown keys (fail closed)
9. Revocation: `grant_id` not on cached revocation list
10. Validate `payload` against scope's Zod input schema

Only if all pass: run handler → validate output → sign Sig 3 → respond.

Any check failure produces a **signed error response**. Auth/permanent failures set `retryable: false`; transient infrastructure failures set `retryable: true`.

**Fail-closed:** If a required key cannot be fetched (cache miss + Huglo unreachable), reject rather than serve.

## Open scopes

Some scopes do not require a subject grant. Register them with `open: true`:

```typescript
module.scope("status:read", {
  open: true,
  description: "Module status (no grant)",
  input: z.object({}),
  output: z.object({ status: z.string() }),
  handler: async (ctx) => {
    // ctx.open === true; no ctx.grant or ctx.subject
    return { status: "ok" };
  },
});
```

The manifest includes `"open": true` on those scope entries so callers know grants are not needed.

### Open invoke envelope

```typescript
interface OpenInvokeRequest {
  payload: unknown;
  requester: string;          // module id (Sig 2 key lookup)
  scope: string;
  timestamp: string;
  nonce: string;
  requesterSignature: string; // Sig 2 over JCS({ payload, requester, scope, timestamp, nonce })
}
```

Open scopes still verify **Sig 2** (registered requester module) and use timestamp/nonce replay protection. They skip Sig 1, grant validity, constraints, and revocation.

Sending a grant envelope to an open scope returns `grant_not_expected`. Sending an open envelope to a protected scope returns `grant_required`.

### Open scope verification (holder)

1. Parse open envelope
2. Timestamp within ±5 minutes
3. Nonce unseen
4. Verify Sig 2 against `requester`
5. Scope binding + input schema

| Signature | Protected | Open |
|-----------|-----------|------|
| Sig 2 | `JCS({ payload, grant, scope, timestamp, nonce })` | `JCS({ payload, requester, scope, timestamp, nonce })` |

## Outbound calls

```typescript
const result = await module.call({
  target: "trovi",
  scope: "invoices:write",
  input: { vendor: "Acme", amount: 500, currency: "USD" },
  grant: someSignedGrant,  // required for protected scopes
  dryRun: false,           // optional
});

// Open scope (no grant; check manifest for open: true)
const status = await module.call({
  target: "trovi",
  scope: "status:read",
  input: {},
});
```

`module.call` resolves the target endpoint and public key from the directory, builds the request envelope (grant or open), signs Sig 2, POSTs to `/invoke/:scope`, verifies Sig 3, matches `requestId`, and returns the result or throws a `ModuleError`.

## Obtaining grants (invite flow)

Before calling another module, the requester must obtain a `SignedGrant` from Huglo. Configure a `GrantStore` and the SDK serves `GET /grant/callback` automatically: it exchanges the code, saves grants via your store, and returns a page that closes the tab.

```typescript
import { Module, InMemoryGrantStore } from "@huglo/module-sdk";

const grantStore = new InMemoryGrantStore(); // replace with your DB-backed impl in production

const module = new Module({
  id: "trovi-test",
  // ...
  grantStore,
  // callbackPath: "/grant/callback", // optional; this is the default
});

// 1. Create an invite (signed by this module)
const { inviteUrl } = await module.createInvite({
  callbackUrl: module.getCallbackUrl(), // endpoint + /grant/callback
  scopes: [{ holder: "da", scope: "invoice:write" }],
  constraints: {}, // optional
});

// 2. Redirect the user to inviteUrl; they approve in Huglo
// 3. Huglo redirects to /grant/callback?code=... — SDK exchanges and saves grants

// 4. Load a grant from your store when calling another module
const grant = await grantStore.find({
  subject: "huglo:user:...",
  holder: "da",
  scope: "invoice:write",
  requester: module.id,
});

const result = await module.call({
  target: "da",
  scope: "invoice:write",
  input: { /* ... */ },
  grant: grant!,
});
```

### GrantStore (developer implements)

```typescript
interface GrantStore {
  save(grant: SignedGrant): Promise<void>;
  find(key: { subject: string; holder: string; scope: string; requester: string }): Promise<SignedGrant | null>;
  list?(filter: { subject?: string }): Promise<SignedGrant[]>;
  delete?(grantId: string): Promise<void>;
}
```

The SDK calls `save` from the callback route. `find` / `list` / `delete` are for your application logic. `InMemoryGrantStore` is exported for dev and tests.

The invite payload is signed with this module's Ed25519 private key (`JCS(payload)`). Huglo verifies the signature before issuing the `inviteUrl`.

You can still call `module.exchangeGrants(code)` manually if you use a custom callback path without `grantStore`.

## Handler context

Handler `ctx` is typed from the scope kind. Protected scopes (default) use `ProtectedCtx<I>`; open scopes use `OpenCtx<I>`.

Protected scopes:

```typescript
// ProtectedCtx<I> — default when open is omitted
{
  open: false;
  subject: string;    // huglo:user:... (from verified grant)
  grant: SignedGrant;
  caller: string;
  input: I;
  scope: string;
  requestId: string;
  dryRun: boolean;
}
```

Open scopes (`open: true`):

```typescript
// OpenCtx<I> — no subject or grant
{
  open: true;
  caller: string;
  input: I;
  scope: string;
  requestId: string;
  dryRun: boolean;
}
```

Throw `ModuleError` for structured errors:

```typescript
throw new ModuleError({
  code: "duplicate_invoice",
  message: "Invoice already exists",
  retryable: false,
});
```

Any other thrown error becomes `{ code: "internal_error", retryable: false }` without leaking internals.

### dryRun convention

When `dryRun` is true, the handler should compute the result but **must not** persist side effects. The SDK passes the flag via the `X-Dry-Run: true` header and exposes it as `ctx.dryRun`; honoring it is the handler's responsibility.

## Key management

### Generate a keypair

```bash
npx @huglo/module-sdk generate-keypair
npx @huglo/module-sdk generate-keypair --out ./private.pem
```

Public key is printed to stdout. Private key is written only when `--out` is provided; otherwise it is printed to stdout (never silently written to disk).

### Load a keypair

```typescript
import { loadKeyPair } from "@huglo/module-sdk";

const keyPair = loadKeyPair();
// Reads MODULE_PRIVATE_KEY (PEM) or MODULE_PRIVATE_KEY_PATH (file path)
```

Private keys are never logged or included in error messages.

## Registration flow

Registration is initiated in the **Huglo UI** (not via CLI). The SDK serves the ACME-style challenge response once env is configured.

1. Operator registers in Huglo UI: module id, endpoint URL, and public key
2. Huglo issues a random high-entropy challenge token (short expiry)
3. Operator sets environment variables and restarts the module:

```bash
MODULE_CHALLENGE=<token-from-huglo>
MODULE_ENDPOINT=https://your-module.example.com
MODULE_PRIVATE_KEY_PATH=./private.pem
```

Load `.env` in your app (e.g. with `dotenv`) or inject these via your deployment platform — the SDK reads `process.env` directly.

4. `GET /.well-known/huglo-challenge` serves a payload signed by the module's private key, binding `{ challenge, moduleId, endpoint, publicKey }`
5. Operator clicks **Verify** in Huglo UI; Huglo fetches the well-known route and verifies the challenge token and signature
6. On success, Huglo records the authoritative directory entry

The **directory public key** — not any self-served manifest key — is what verifiers use.

You can also pass `challenge` and `endpoint` in the `Module` constructor (overrides env), or call `module.setChallenge()` at runtime.

## Directory client (extension point)

The SDK uses a `DirectoryClient` interface internally. Inject your own implementation for testing or custom Huglo deployments:

```typescript
interface DirectoryClient {
  getModuleKey(moduleId: string, keyId?: string): Promise<KeyObject>;
  getUserKey(userId: string, keyId?: string): Promise<KeyObject>;
  getEndpoint(moduleId: string): Promise<string>;
  isRevoked(grantId: string): Promise<boolean>;
  createInvite(moduleId: string, signed: SignedInvitePayload): Promise<CreateInviteResponse>;
  exchangeGrants(code: string): Promise<SignedGrant[]>;
}
```

`InMemoryDirectoryClient` is exported for integration tests.

## CLI

```bash
npx @huglo/module-sdk generate-keypair [--out <path>]
```

## Development

```bash
npm install
npm run build
npm test
npm run test:coverage
```

Run the Trovi example (requires a keypair; see `.env.example` for registration vars):

```bash
npm run build
npx @huglo/module-sdk generate-keypair --out ./examples/trovi/private.pem
cp .env.example .env   # then fill MODULE_CHALLENGE/MODULE_ENDPOINT when registering
npx tsx examples/trovi/index.ts
```

## Key rotation (future)

Optional key-identifier slot in signature encoding (`ed25519:<keyId>:<base64>`) and directory key-version lookup are stubbed. Full overlap-window rotation protocol is future work.

## License

ISC

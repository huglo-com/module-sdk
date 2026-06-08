# @huglo/module-sdk

Build a Huglo module — define scopes, start an HTTP server, call other modules.

**Requirements:** Node 20+, TypeScript, ESM.

## Install

```bash
npm install @huglo/module-sdk
```

## Quick start

```typescript
import { Module, loadKeyPair } from "@huglo/module-sdk";
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
  input: z.object({
    vendor: z.string(),
    amount: z.number().int(),
    currency: z.string().length(3),
  }),
  output: z.object({
    id: z.string(),
    vendor: z.string(),
    amount: z.number().int(),
    currency: z.string(),
  }),
  handler: async (ctx) => {
    if (ctx.dryRun) {
      return {
        id: "preview",
        vendor: ctx.input.vendor,
        amount: ctx.input.amount,
        currency: ctx.input.currency,
      };
    }
    return {
      id: "inv-001",
      vendor: ctx.input.vendor,
      amount: ctx.input.amount,
      currency: ctx.input.currency,
    };
  },
});

await module.listen(3000);
```

Save as `index.ts`, then:

```bash
npx @huglo/module-sdk generate-keypair --out ./private.pem
export MODULE_PRIVATE_KEY_PATH=./private.pem   # or add to .env
npx tsx index.ts
```

`loadKeyPair()` reads `MODULE_PRIVATE_KEY` (PEM string) or `MODULE_PRIVATE_KEY_PATH` (file path).

## Register with Huglo

1. Register your module's endpoint URL in the Huglo UI.
2. Set `MODULE_CHALLENGE`, `MODULE_ENDPOINT`, and key env vars (see below).
3. Restart the module — the SDK serves `GET /.well-known/huglo-challenge`.
4. Click **Verify** in the Huglo UI.

## Common next steps

### Call another module

```typescript
const result = await module.call({
  target: "trovi",
  scope: "invoices:write",
  input: { vendor: "Acme", amount: 500, currency: "USD" },
  grant: someSignedGrant,
});
```

Protected scopes require a grant from the user. See [`docs/ai/HUGLO_SPECIFICATION.md`](docs/ai/HUGLO_SPECIFICATION.md) for the grant protocol.

### Open scope (no grant)

```typescript
module.scope("status:read", {
  open: true,
  description: "Module status",
  input: z.object({}),
  output: z.object({ status: z.string() }),
  handler: async () => ({ status: "ok" }),
});
```

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MODULE_PRIVATE_KEY` or `MODULE_PRIVATE_KEY_PATH` | Yes | Ed25519 private key (PEM or path to PEM file) |
| `MODULE_CHALLENGE` | For registration | Challenge token from Huglo UI |
| `MODULE_ENDPOINT` | For registration | Public base URL registered in Huglo |
| `HUGLO_DIRECTORY_URL` | No | Huglo directory URL (default: `https://account.huglo.com`) |
| `HUGLO_OAUTH_*` | No | OAuth settings when using `module.config()` |

## Learn more

- [`docs/ai/HUGLO_SPECIFICATION.md`](docs/ai/HUGLO_SPECIFICATION.md) — federation protocol and directory API
- [`docs/ai/CONFIG_IDENTITY_PROOF.md`](docs/ai/CONFIG_IDENTITY_PROOF.md) — config proof and two-session model
- [`examples/trovi/`](examples/trovi/) — full runnable example (GitHub repo)

## License

MIT

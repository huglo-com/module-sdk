import "dotenv/config";
import { z } from "zod";
import { Module, ModuleError, InMemoryGrantStore, loadKeyPair } from "../../dist/index.js";

// Registration challenge: set MODULE_CHALLENGE and MODULE_ENDPOINT in .env (see .env.example)

const InvoiceInputSchema = z.object({
  vendor: z.string(),
  amount: z.number().int(),
  currency: z.string().length(3),
});

const InvoiceOutputSchema = z.object({
  id: z.string(),
  vendor: z.string(),
  amount: z.number().int(),
  currency: z.string(),
  status: z.enum(["draft", "sent"]),
});

/** In-memory invoice store for the example. */
const invoices = new Map<string, z.infer<typeof InvoiceOutputSchema>>();

function computeWouldBeInvoice(
  input: z.infer<typeof InvoiceInputSchema>,
): z.infer<typeof InvoiceOutputSchema> {
  return {
    id: "dry-run-preview",
    vendor: input.vendor,
    amount: input.amount,
    currency: input.currency,
    status: "draft",
  };
}

const grantStore = new InMemoryGrantStore();

const module = new Module({
  id: "trovi-test",
  name: "Trovi Invoicing",
  description: "Create and read invoices",
  version: "1.2.0",
  keyPair: loadKeyPair(),
  grantStore,
});

module.scope("invoices:write", {
  description: "Create an invoice",
  input: InvoiceInputSchema,
  output: InvoiceOutputSchema,
  handler: async (ctx) => {
    if (ctx.dryRun) {
      return computeWouldBeInvoice(ctx.input);
    }

    const existing = [...invoices.values()].find(
      (inv) => inv.vendor === ctx.input.vendor && inv.amount === ctx.input.amount,
    );
    if (existing) {
      throw new ModuleError({
        code: "duplicate_invoice",
        message: `Invoice for ${ctx.input.vendor} already exists`,
        retryable: false,
      });
    }

    const invoice: z.infer<typeof InvoiceOutputSchema> = {
      id: `inv-${crypto.randomUUID().slice(0, 8)}`,
      vendor: ctx.input.vendor,
      amount: ctx.input.amount,
      currency: ctx.input.currency,
      status: "draft",
    };
    invoices.set(invoice.id, invoice);
    return invoice;
  },
});

const port = Number(process.env["PORT"] ?? 3200);
await module.listen(port);
console.log(`Trovi module listening on http://localhost:${port}`);
console.log(`  GET  /health`);
console.log(`  GET  /manifest`);
console.log(`  GET  /grant/callback`);
console.log(`  POST /invoke/invoices:write`);

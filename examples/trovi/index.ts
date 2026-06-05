import "dotenv/config";
import { z } from "zod";
import { Module, ModuleError, InMemoryGrantStore, loadKeyPair } from "../../dist/index.js";

// Invoice input schema
const InvoiceInputSchema = z.object({
  vendor: z.string(),
  amount: z.number().int(),
  currency: z.string().length(3),
});

// Invoice output schema
const InvoiceOutputSchema = z.object({
  id: z.string(),
  vendor: z.string(),
  amount: z.number().int(),
  currency: z.string(),
  status: z.enum(["draft", "sent"]),
});

// In-memory invoice store for the example.
const invoices = new Map<string, z.infer<typeof InvoiceOutputSchema>>();

// Dry-run example invoice
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

// In-memory grant store for the example.
// For production, use a database or a file system and implement the GrantStore interface.
const grantStore = new InMemoryGrantStore();

// Module instance
const module = new Module({
  id: "trovi-test",
  name: "Trovi Invoicing",
  description: "Create and read invoices",
  version: "1.2.0",
  keyPair: loadKeyPair(),
  grantStore,
});

// Register a invoices:write scope
module.scope("invoices:write", {
  description: "Create an invoice",
  input: InvoiceInputSchema,
  output: InvoiceOutputSchema,
  // handler can be any function that returns a promise of the output schema
  handler: async (ctx) => {

    // ctx is the context object for the scope
    // ctx.input
    // ctx.dryRun
    // ctx.grant
    // ctx.caller
    // ctx.subject

    // If the request is a dry run, return the computed invoice
    if (ctx.dryRun) {
      return computeWouldBeInvoice(ctx.input);
    }

    // The actual business logic for creating an invoice
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

    // Return InvoiceOutputSchema
    return invoice;
  },
});

// Start the module on port 3200
const port = Number(process.env["PORT"] ?? 3200);
await module.listen(port);
console.log(`Trovi module listening on http://localhost:${port}`);

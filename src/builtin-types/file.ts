import { z } from "zod";
import type { TypeDefinition } from "../type-system.js";

export const fileObjectSchema = z.object({
  url: z.string().min(1),
  content_type: z.string().min(1),
  filename: z.string().min(1),
  size: z.number().int().nonnegative(),
  expires_at: z.iso.datetime(),
});

export const fileType: TypeDefinition = {
  id: "huglo:file",
  schema: fileObjectSchema,
  display: {
    label: "file",
    background: "#fee2e2",
    border: "#dc2626",
    color: "#991b1b",
  },
  operators: [
    {
      id: "contentTypeIs",
      label: "content type is",
      field: "content_type",
      compare: "string",
      op: "eq",
    },
    {
      id: "sizeGreaterThan",
      label: "size greater than",
      field: "size",
      compare: "integer",
      op: "gt",
    },
    {
      id: "isEmpty",
      label: "is empty",
      field: "size",
      compare: "integer",
      op: "eq",
    },
  ],
};

/**
 * TODO(module-sdk-flowbuilder): Move to @huglo/module-sdk-flowbuilder.
 * Temporary core export so modules can share FlowNodeContextSchema until the
 * extension package exists.
 */
import { z } from "zod";

export const FlowNodeContextSchema = z.object({
  flowId: z.string().min(1),
  nodeId: z.string().min(1),
  configInstanceId: z.string().min(1).optional(),
});

export type FlowNodeContext = z.infer<typeof FlowNodeContextSchema>;

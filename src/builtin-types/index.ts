import type { TypeDefinition } from "../type-system.js";
import { fileType } from "./file.js";

export { fileType, fileObjectSchema } from "./file.js";

export const builtinTypes: TypeDefinition[] = [fileType];

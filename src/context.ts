import type { SignedGrant } from "./envelope.js";

export interface Ctx<I> {
  /** The subject whose data this request concerns (`huglo:user:...`). */
  subject: string;
  /** Validated payload, typed from the scope's Zod input schema. */
  input: I;
  /** The full verified signed grant. */
  grant: SignedGrant;
  /** The requester module id (verified from Sig 2). */
  caller: string;
  /** The scope being invoked. */
  scope: string;
  /** Correlation id for this request. */
  requestId: string;
  /**
   * When true, the handler should compute the result but MUST NOT commit side effects.
   * The SDK passes this flag; honoring it is the handler's responsibility.
   */
  dryRun: boolean;
}

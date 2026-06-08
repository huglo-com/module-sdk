import type { KeyObject } from "node:crypto";
import { randomUUID } from "node:crypto";
import {
  CONFIG_PROOF_PURPOSE,
  CONFIG_PROOF_TTL_MS,
  type ConfigProof,
  type ConfigProofAssertion,
} from "../../src/config-proof.js";
import { signObject } from "../../src/signing.js";

/** Simulates directory mint output for unit tests. Not part of the published SDK. */
export function createSignedConfigProof(options: {
  subject: string;
  audience: string;
  privateKey: KeyObject;
  ttlMs?: number;
  now?: number;
}): ConfigProof {
  const now = options.now ?? Date.now();
  const ttlMs = options.ttlMs ?? CONFIG_PROOF_TTL_MS;
  const assertion: ConfigProofAssertion = {
    subject: options.subject,
    audience: options.audience,
    purpose: CONFIG_PROOF_PURPOSE,
    nonce: randomUUID(),
    issued_at: new Date(now).toISOString(),
    expires_at: new Date(now + ttlMs).toISOString(),
  };
  return {
    assertion,
    signature: signObject(assertion, options.privateKey),
  };
}

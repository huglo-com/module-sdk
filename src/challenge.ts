import type { KeyObject } from "node:crypto";
import type { ChallengePayload, SignedChallenge } from "./envelope.js";
import { signObject } from "./signing.js";

export interface ChallengeConfig {
  challenge: string;
  moduleId: string;
  endpoint: string;
  publicKey: string;
  privateKey: KeyObject;
}

/**
 * Build the signed challenge response for GET /.well-known/huglo-challenge.
 * Binds {challenge, moduleId, endpoint, publicKey} so it cannot be replayed
 * for another module or endpoint.
 */
export function buildSignedChallenge(config: ChallengeConfig): SignedChallenge {
  const payload: ChallengePayload = {
    challenge: config.challenge,
    moduleId: config.moduleId,
    endpoint: config.endpoint,
    publicKey: config.publicKey,
  };
  const signature = signObject(payload, config.privateKey);
  return { payload, signature };
}

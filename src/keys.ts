import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { readFileSync } from "node:fs";

export interface ModuleKeyPair {
  publicKey: KeyObject;
  privateKey: KeyObject;
  /** Base64-encoded raw 32-byte public key for wire/manifest use. */
  publicKeyBase64: string;
}

/** Generate a new Ed25519 keypair. */
export function generateKeyPair(): ModuleKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyBase64 = exportPublicKeyBase64(publicKey);
  return { publicKey, privateKey, publicKeyBase64 };
}

/** Export a public KeyObject as base64 raw bytes. */
export function exportPublicKeyBase64(publicKey: KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  // Ed25519 SPKI DER is 12-byte prefix + 32-byte key
  return der.subarray(-32).toString("base64");
}

/** Import a base64 raw Ed25519 public key. */
export function importPublicKeyBase64(b64: string): KeyObject {
  const raw = Buffer.from(b64, "base64");
  // Wrap raw 32-byte key in SPKI DER for Node crypto
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  const der = Buffer.concat([prefix, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/** Import a PEM-encoded Ed25519 private key. */
export function importPrivateKeyPem(pem: string): KeyObject {
  return createPrivateKey(pem);
}

/** Export a private KeyObject as PEM (PKCS8). */
export function exportPrivateKeyPem(privateKey: KeyObject): string {
  return privateKey.export({ type: "pkcs8", format: "pem" }) as string;
}

export interface LoadKeyPairOptions {
  /** Path to a PEM private key file. Falls back to MODULE_PRIVATE_KEY_PATH env var. */
  path?: string;
  /** PEM string directly. Falls back to MODULE_PRIVATE_KEY env var. */
  pem?: string;
}

/**
 * Load an Ed25519 keypair from env var or file path.
 * Reads MODULE_PRIVATE_KEY (PEM) or MODULE_PRIVATE_KEY_PATH (file path).
 * Never logs key material.
 */
export function loadKeyPair(options: LoadKeyPairOptions = {}): ModuleKeyPair {
  const pem =
    options.pem ??
    process.env["MODULE_PRIVATE_KEY"] ??
    (() => {
      const filePath =
        options.path ?? process.env["MODULE_PRIVATE_KEY_PATH"];
      if (!filePath) {
        throw new Error(
          "No private key found. Set MODULE_PRIVATE_KEY or MODULE_PRIVATE_KEY_PATH.",
        );
      }
      return readFileSync(filePath, "utf8");
    })();

  const privateKey = importPrivateKeyPem(pem);
  const publicKey = createPublicKey(privateKey);
  const publicKeyBase64 = exportPublicKeyBase64(publicKey);
  return { publicKey, privateKey, publicKeyBase64 };
}

#!/usr/bin/env node
import { writeFileSync } from "node:fs";
import { generateKeyPair, exportPrivateKeyPem } from "./keys.js";

const args = process.argv.slice(2);
const command = args[0];

async function main(): Promise<void> {
  try {
    switch (command) {
      case "generate-keypair":
        await cmdGenerateKeypair(args.slice(1));
        break;
      default:
        printUsage();
        process.exit(command ? 1 : 0);
    }
  } catch (err) {
    console.error("Fatal error:", (err as Error).message);
    process.exit(1);
  }
}

function printUsage(): void {
  console.log(`@huglo/module-sdk — Huglo federation module SDK

Usage:
  npx @huglo/module-sdk generate-keypair [--out <path>]

Commands:
  generate-keypair   Generate an Ed25519 keypair. Prints public key.
                     Private key written only when --out is provided.
`);
}

async function cmdGenerateKeypair(args: string[]): Promise<void> {
  let outPath: string | undefined;
  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--out" && args[i + 1]) {
      outPath = args[++i];
    }
  }

  const keyPair = generateKeyPair();
  const pem = exportPrivateKeyPem(keyPair.privateKey);

  console.log("Public key (base64):", keyPair.publicKeyBase64);

  if (outPath) {
    writeFileSync(outPath, pem, { mode: 0o600 });
    console.log(`Private key written to ${outPath}`);
  } else {
    console.log("\nPrivate key (PEM) — save securely:\n");
    console.log(pem);
  }
}

await main();

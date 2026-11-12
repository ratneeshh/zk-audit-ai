import { generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const priv = privateKey.export({ type: "pkcs8", format: "der" }).toString("base64");
const pub = publicKey.export({ type: "spki", format: "pem" }).toString();

let env = existsSync(".env") ? readFileSync(".env", "utf8") : "";
if (/^RECEIPT_PRIVATE_KEY=/m.test(env)) {
  if (!process.argv.includes("--force")) {
    console.error("RECEIPT_PRIVATE_KEY already in .env. Use --force to replace it (old receipts stop verifying).");
    process.exit(1);
  }
  env = env.replace(/^RECEIPT_PRIVATE_KEY=.*$/m, () => `RECEIPT_PRIVATE_KEY=${priv}`);
} else {
  env = env.replace(/\n*$/, "\n") + `RECEIPT_PRIVATE_KEY=${priv}\n`;
}
writeFileSync(".env", env, { mode: 0o600 });
writeFileSync("receipt-public-key.pem", pub);
console.log("Private key written to .env (not shown). Public key saved to receipt-public-key.pem:\n\n" + pub);

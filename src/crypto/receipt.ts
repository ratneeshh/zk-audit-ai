import {
  createHash, createPrivateKey, createPublicKey,
  sign as edSign, verify as edVerify,
} from "node:crypto";
import { env } from "../config/env.js";

export const GENESIS = "0".repeat(64);

export interface ReceiptPayload {
  seq: number;
  auditId: string;
  repositoryHash: string;
  astRootHash: string;
  findingsHash: string;
  prevReceiptHash: string;
  ts: string;
}

const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

const privateKey = createPrivateKey({
  key: Buffer.from(env.RECEIPT_PRIVATE_KEY, "base64"),
  format: "der",
  type: "pkcs8",
});
const publicKey = createPublicKey(privateKey);

export const publicKeyPem = () =>
  publicKey.export({ type: "spki", format: "pem" }).toString();

export function hashFindings(
  fs: { vulnerability: string; severity: string; nodeId: number }[]
): string {
  const rows = fs
    .map((f) => [f.nodeId, f.vulnerability, f.severity] as const)
    .sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
  return sha256(JSON.stringify(rows));
}

export function receiptHash(p: ReceiptPayload): string {
  return sha256(
    JSON.stringify([
      p.seq, p.auditId, p.repositoryHash, p.astRootHash,
      p.findingsHash, p.prevReceiptHash, p.ts,
    ])
  );
}

export const sign = (hash: string) =>
  edSign(null, Buffer.from(hash, "hex"), privateKey).toString("hex");

export function checkSignature(hash: string, sig: string): boolean {
  if (!/^[0-9a-f]{128}$/.test(sig)) return false;
  try {
    return edVerify(null, Buffer.from(hash, "hex"), publicKey, Buffer.from(sig, "hex"));
  } catch {
    return false;
  }
}

export const rootToHex = (root: bigint) => root.toString(16).padStart(64, "0");

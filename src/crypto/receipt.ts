import { createHash, createHmac, timingSafeEqual } from "node:crypto";
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

export function hashFindings(
  fs: { vulnerability: string; severity: string; nodeId: number }[]
): string {
  const rows = fs
    .map((f) => [f.nodeId, f.vulnerability, f.severity] as const)
    .sort((a, b) => a[0] - b[0] || a[1].localeCompare(b[1]));
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
  createHmac("sha256", env.RECEIPT_SIGNING_SECRET).update(hash).digest("hex");

export function checkSignature(hash: string, sig: string): boolean {
  const a = Buffer.from(sign(hash), "hex");
  const b = Buffer.from(sig, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

export const rootToHex = (root: bigint) => root.toString(16).padStart(64, "0");

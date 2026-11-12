import { beforeAll, describe, expect, it } from "vitest";

let r: typeof import("../src/crypto/receipt.js");

beforeAll(async () => {
  process.env.DATABASE_URL ??= "postgres://x";
  process.env.GROQ_API_KEY ??= "x".repeat(12);
  r = await import("../src/crypto/receipt.js");
});

const payload = () => ({
  seq: 1, auditId: "a", repositoryHash: "b", astRootHash: "c",
  findingsHash: "d", prevReceiptHash: r.GENESIS, ts: "2026-01-01T00:00:00Z",
});

describe("ed25519 receipts", () => {
  it("signs and verifies, and rejects other hashes", () => {
    const h = r.receiptHash(payload());
    const sig = r.sign(h);
    expect(sig).toMatch(/^[0-9a-f]{128}$/);
    expect(r.checkSignature(h, sig)).toBe(true);
    expect(r.checkSignature(r.receiptHash({ ...payload(), seq: 2 }), sig)).toBe(false);
    expect(r.checkSignature(h, "00".repeat(64))).toBe(false);
  });

  it("findings hash ignores order but not content", () => {
    const a = { vulnerability: "x", severity: "high", nodeId: 1 };
    const b = { vulnerability: "y", severity: "low", nodeId: 2 };
    expect(r.hashFindings([a, b])).toBe(r.hashFindings([b, a]));
    expect(r.hashFindings([a, b])).not.toBe(r.hashFindings([{ ...a, severity: "low" }, b]));
  });
});

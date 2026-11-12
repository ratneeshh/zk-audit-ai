import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";

const [file, pemFile] = process.argv.slice(2);
if (!file) {
  console.error("usage: node scripts/verify-receipt.mjs receipt.json [public-key.pem]");
  process.exit(2);
}
const sha256 = (s) => createHash("sha256").update(s).digest("hex");
const r = JSON.parse(readFileSync(file, "utf8"));
const pem = pemFile ? readFileSync(pemFile, "utf8") : r.publicKey;

const rows = r.findings
  .map((f) => [f.nodeId, f.vulnerability, f.severity])
  .sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0));
const findingsHash = sha256(JSON.stringify(rows));
const p = r.payload;
const hash = sha256(
  JSON.stringify([p.seq, p.auditId, p.repositoryHash, p.astRootHash, findingsHash, p.prevReceiptHash, p.ts])
);

const hashOk = findingsHash === p.findingsHash && hash === r.receiptHash;
let sigOk = false;
try {
  sigOk = verify(null, Buffer.from(r.receiptHash, "hex"), createPublicKey(pem), Buffer.from(r.signature, "hex"));
} catch {}

console.log({ hashOk, sigOk, publicKeySource: pemFile ? "pinned file" : "embedded in receipt (not trustworthy)" });
process.exit(hashOk && sigOk ? 0 : 1);

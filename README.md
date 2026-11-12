# ZK-Audit-AI

Audit smart contracts with an LLM without sending source code to it, and get a
tamper-evident, signed, hash-chained receipt for every audit.

## Pipeline

1. Parse Solidity to an AST locally (@solidity-parser/parser).
2. Mask identifiers and string literals with a per-audit random salt (HMAC-SHA256).
   Security-relevant names (msg, sender, call, require, ...) stay readable.
3. Commit to the masked AST with a Poseidon Merkle tree (depth 14, max 16384 nodes).
4. Send only the masked skeleton to Groq (openai/gpt-oss-120b). JSON-schema output,
   token-bucket rate limit, exponential backoff, rule-engine fallback.
5. Drop any finding whose node reference does not exist in the AST.
6. For each finding, generate a Groth16 proof (Circom + snarkjs) that the referenced
   node is a leaf of the committed tree. Type, parent and label stay private.
7. Store findings and a receipt: HMAC-signed, chained to the previous receipt hash.

## What the receipt proves

- The report was not modified after signing (hash, signature, chain checks).
- Each finding points at a node that is committed in the AST root (ZK proofs).
- The audit record sits in order after the previous record.

## What it does NOT prove

- It does not prove the LLM actually produced these findings. Groq is an external
  server and a circuit cannot attest to it. Closing this gap needs zkTLS (TLSNotary).
- It does not prove findings are correct or complete.
- The signature is an HMAC, so only holders of the secret can verify it. Use Ed25519
  if third parties must verify receipts.
- The chain check only compares each record with its direct predecessor.
- The dev trusted setup (single local contributor) is not suitable for production.

## Threat model: masking leakage

Masking removes names, but the structural skeleton still leaks logic. In testing the
model inferred plausible original names (for example "withdraw", "amount") from
control flow alone. Hashing names does not hide program semantics from a capable
model, so treat this as reducing exposure, not eliminating it. Do not use it on code
whose structure is itself secret.

## Run

    docker compose up -d
    npm install
    npm run circuit:build
    npm run db:push
    npm run dev
    cd web && npm install && npm run dev

API: POST /audits, GET /audits, GET /audits/:id, GET /audits/:id/verify

## Known gaps

- Chunking groups whole functions per contract; free functions outside contracts are skipped, and one oversized function is sent whole.
- Proving runs in-process; a job queue or worker is better under load.
- Solidity only.

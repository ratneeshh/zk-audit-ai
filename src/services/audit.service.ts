import { createHash, randomUUID } from "node:crypto";
import { desc, eq, sql } from "drizzle-orm";
import { db } from "../db/client.js";
import { auditFindings, codeAudits } from "../db/schema.js";
import { parseSolidity } from "../ast/parser.js";
import { flattenAst } from "../ast/flatten.js";
import { maskNodes, type MaskedNode } from "../crypto/masking.js";
import { buildTree } from "../crypto/merkle.js";
import {
  GENESIS, checkSignature, hashFindings, receiptHash, rootToHex, sign,
  type ReceiptPayload,
} from "../crypto/receipt.js";
import { auditNodes } from "../llm/audit.js";
import { proveNode, verifyNodeProof, type NodeProof } from "../zk/prover.js";

const badRequest = (msg: string) =>
  Object.assign(new Error(msg), { statusCode: 400 });

function snippet(masked: MaskedNode[], id: number): string {
  const start = masked[id];
  const out: string[] = [];
  for (let j = id; j < masked.length && out.length < 12; j++) {
    if (j > id && masked[j].depth <= start.depth) break;
    const n = masked[j];
    out.push(
      `${"  ".repeat(n.depth - start.depth)}#${n.id} ${n.type}${n.label ? " " + n.label : ""}`
    );
  }
  return out.join("\n");
}

export async function runAudit(source: string) {
  let masked: MaskedNode[];
  let tree: ReturnType<typeof buildTree>;
  try {
    masked = maskNodes(flattenAst(parseSolidity(source))).masked;
    tree = buildTree(masked);
  } catch (e) {
    throw badRequest(`Cannot process source: ${(e as Error).message}`);
  }

  const result = await auditNodes(masked);

  // one ZK membership proof per finding (slow, so done before taking the DB lock)
  const proofs: { proof: NodeProof; verified: boolean }[] = [];
  for (const f of result.findings) {
    const { verified, ...p } = await proveNode(tree, masked, f.nodeId);
    proofs.push({ proof: p, verified });
  }

  const auditId = randomUUID();
  const repositoryHash = createHash("sha256").update(source).digest("hex");
  const astRootHash = rootToHex(tree.root);
  const findingsHash = hashFindings(
    result.findings.map((f) => ({
      vulnerability: f.vulnerability, severity: f.severity, nodeId: f.nodeId,
    }))
  );

  return db.transaction(async (tx) => {
    await tx.execute(sql`select pg_advisory_xact_lock(42)`);
    const [last] = await tx
      .select()
      .from(codeAudits)
      .orderBy(desc(codeAudits.seq))
      .limit(1);

    const payload: ReceiptPayload = {
      seq: last ? last.seq + 1 : 1,
      auditId,
      repositoryHash,
      astRootHash,
      findingsHash,
      prevReceiptHash: last ? last.receiptHash : GENESIS,
      ts: new Date().toISOString(),
    };
    const hash = receiptHash(payload);
    const signature = sign(hash);

    await tx.insert(codeAudits).values({
      auditId,
      repositoryHash,
      astRootHash,
      status: "completed",
      usedFallback: result.usedFallback,
      seq: payload.seq,
      prevReceiptHash: payload.prevReceiptHash,
      receiptHash: hash,
      signature,
      receiptTs: payload.ts,
    });

    if (result.findings.length) {
      await tx.insert(auditFindings).values(
        result.findings.map((f, i) => ({
          auditId,
          vulnerabilityType: f.vulnerability.slice(0, 128),
          severity: f.severity,
          confidenceScore: f.confidence.toFixed(2),
          nodeId: f.nodeId,
          line: f.line,
          maskedCodeSnippet: snippet(masked, f.nodeId),
          aiExplanation: f.explanation,
          source: f.source,
          zkProofVerified: proofs[i].verified,
          proof: proofs[i].proof as object,
        }))
      );
    }

    return {
      auditId,
      seq: payload.seq,
      astRootHash,
      repositoryHash,
      receiptHash: hash,
      prevReceiptHash: payload.prevReceiptHash,
      signature,
      usedFallback: result.usedFallback,
      discarded: result.discarded,
      findings: result.findings.map((f, i) => ({
        ...f, zkProofVerified: proofs[i].verified,
      })),
    };
  });
}

export const listAudits = () =>
  db.select().from(codeAudits).orderBy(desc(codeAudits.seq)).limit(50);

export async function getAudit(id: string) {
  const [audit] = await db.select().from(codeAudits).where(eq(codeAudits.auditId, id));
  if (!audit) return null;
  const findings = await db
    .select()
    .from(auditFindings)
    .where(eq(auditFindings.auditId, id));
  return { audit, findings };
}

export async function verifyAudit(id: string) {
  const data = await getAudit(id);
  if (!data) return null;
  const { audit, findings } = data;

  const payload: ReceiptPayload = {
    seq: audit.seq,
    auditId: audit.auditId,
    repositoryHash: audit.repositoryHash,
    astRootHash: audit.astRootHash,
    findingsHash: hashFindings(
      findings.map((f) => ({
        vulnerability: f.vulnerabilityType, severity: f.severity, nodeId: f.nodeId,
      }))
    ),
    prevReceiptHash: audit.prevReceiptHash,
    ts: audit.receiptTs,
  };
  const recomputed = receiptHash(payload);
  const hashOk = recomputed === audit.receiptHash;
  const signatureOk = checkSignature(audit.receiptHash, audit.signature);

  let chainOk = true;
  if (audit.seq === 1) {
    chainOk = audit.prevReceiptHash === GENESIS;
  } else {
    const [prev] = await db
      .select()
      .from(codeAudits)
      .where(eq(codeAudits.seq, audit.seq - 1));
    chainOk = !!prev && prev.receiptHash === audit.prevReceiptHash;
  }

  const rootDec = BigInt("0x" + audit.astRootHash).toString();
  const proofResults = await Promise.all(
    findings.map(async (f) => {
      const p = f.proof as NodeProof | null;
      if (!p) return false;
      const bound =
        p.publicSignals[0] === rootDec && p.publicSignals[1] === String(f.nodeId);
      return bound && (await verifyNodeProof(p));
    })
  );
  const proofsOk = proofResults.every(Boolean);

  return {
    auditId: id,
    valid: hashOk && signatureOk && chainOk && proofsOk,
    checks: { hashOk, signatureOk, chainOk, proofsOk, proofCount: findings.length },
  };
}

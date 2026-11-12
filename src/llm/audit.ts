import type { MaskedNode } from "../crypto/masking.js";
import { callGroq } from "./groq.client.js";
import { ResponseSchema, type AuditFinding } from "./schema.js";
import { ruleBasedAudit } from "./fallback.rules.js";
import { chunkNodes } from "./chunk.js";

export interface AuditResult {
  findings: AuditFinding[];
  discarded: number;
  usedFallback: boolean;
  chunks: number;
}

export async function auditNodes(masked: MaskedNode[]): Promise<AuditResult> {
  const byId = new Map(masked.map((n) => [n.id, n]));
  const chunks = chunkNodes(masked);
  const compiler = masked.find((n) => n.type === "PragmaDirective")?.label ?? "unknown";

  const findings: AuditFinding[] = [];
  const seen = new Set<string>();
  let discarded = 0;
  let usedFallback = false;
  let rules: AuditFinding[] | null = null;

  const add = (f: AuditFinding) => {
    const key = `${f.vulnerability}:${f.nodeId}`;
    if (seen.has(key)) {
      discarded++;
      return;
    }
    seen.add(key);
    findings.push(f);
  };

  for (const [i, chunk] of chunks.entries()) {
    try {
      const raw = await callGroq(`Compiler: ${compiler}\nPart ${i + 1} of ${chunks.length}\n\n${chunk.text}`);
      const parsed = ResponseSchema.parse(JSON.parse(raw));
      for (const f of parsed.findings) {
        const node = chunk.nodeIds.has(f.ast_node_reference)
          ? byId.get(f.ast_node_reference)
          : undefined;
        if (!node) {
          discarded++; // hallucinated, or points outside the code the model was shown
          continue;
        }
        add({
          vulnerability: f.vulnerability,
          severity: f.severity,
          confidence: f.confidence_score,
          nodeId: node.id,
          line: node.line,
          explanation: f.explanation,
          source: "llm",
        });
      }
    } catch (err) {
      console.warn(
        `chunk ${i + 1}/${chunks.length}: LLM unavailable, using rule engine:`,
        (err as Error).message
      );
      usedFallback = true;
      rules ??= ruleBasedAudit(masked);
      for (const f of rules) if (chunk.nodeIds.has(f.nodeId)) add(f);
    }
  }

  return { findings, discarded, usedFallback, chunks: chunks.length };
}

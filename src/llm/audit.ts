import type { MaskedNode } from "../crypto/masking.js";
import { renderSkeleton } from "../crypto/masking.js";
import { callGroq } from "./groq.client.js";
import { ResponseSchema, type AuditFinding } from "./schema.js";
import { ruleBasedAudit } from "./fallback.rules.js";

export interface AuditResult {
  findings: AuditFinding[];
  discarded: number;
  usedFallback: boolean;
}

export async function auditNodes(masked: MaskedNode[]): Promise<AuditResult> {
  const byId = new Map(masked.map((n) => [n.id, n]));

  try {
    const raw = await callGroq(renderSkeleton(masked));
    const parsed = ResponseSchema.parse(JSON.parse(raw));

    const seen = new Set<string>();
    const findings: AuditFinding[] = [];
    let discarded = 0;

    for (const f of parsed.findings) {
      const node = byId.get(f.ast_node_reference);
      const key = `${f.vulnerability}:${f.ast_node_reference}`;
      // hallucination filter: reference must be a real node, no duplicates
      if (!node || seen.has(key)) {
        discarded++;
        continue;
      }
      seen.add(key);
      findings.push({
        vulnerability: f.vulnerability,
        severity: f.severity,
        confidence: f.confidence_score,
        nodeId: node.id,
        line: node.line,
        explanation: f.explanation,
        source: "llm",
      });
    }
    return { findings, discarded, usedFallback: false };
  } catch (err) {
    console.warn("LLM unavailable, using rule engine:", (err as Error).message);
    return { findings: ruleBasedAudit(masked), discarded: 0, usedFallback: true };
  }
}

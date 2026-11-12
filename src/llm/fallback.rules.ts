import type { MaskedNode } from "../crypto/masking.js";
import type { AuditFinding } from "./schema.js";

const EXTERNAL_CALLS = new Set(["call", "send", "transfer", "delegatecall"]);
const STATE_WRITE_OPS = new Set(["=", "+=", "-=", "*=", "/="]);

// Deterministic check: external call followed by a state write in the same function
export function ruleBasedAudit(nodes: MaskedNode[]): AuditFinding[] {
  const findings: AuditFinding[] = [];

  nodes.forEach((fn, i) => {
    if (fn.type !== "FunctionDefinition") return;

    // DFS order: descendants are the following nodes that are deeper than fn
    const body: MaskedNode[] = [];
    for (let j = i + 1; j < nodes.length && nodes[j].depth > fn.depth; j++) {
      body.push(nodes[j]);
    }

    const call = body.find(
      (n) => n.type === "MemberAccess" && EXTERNAL_CALLS.has(n.label)
    );
    if (!call) return;

    const writeAfter = body.find(
      (n) =>
        n.id > call.id &&
        n.type === "BinaryOperation" &&
        STATE_WRITE_OPS.has(n.label)
    );
    if (!writeAfter) return;

    findings.push({
      vulnerability: "Possible reentrancy (state update after external call)",
      severity: "high",
      confidence: 0.6,
      nodeId: call.id,
      line: call.line,
      explanation:
        "An external call is made before a later state write in the same function. Apply checks-effects-interactions or a reentrancy guard.",
      source: "rules",
    });
  });

  return findings;
}

import { describe, expect, it } from "vitest";
import { categoryOf, mergeFindings } from "../src/llm/merge.js";
import type { AuditFinding } from "../src/llm/schema.js";

const f = (over: Partial<AuditFinding>): AuditFinding => ({
  vulnerability: "x",
  severity: "low",
  confidence: 0.5,
  nodeId: 1,
  line: 1,
  explanation: "",
  source: "llm",
  ...over,
});

describe("finding merge", () => {
  it("collapses differently worded access-control findings", () => {
    const merged = mergeFindings([
      f({ vulnerability: "Missing access control on external functions", severity: "high", nodeId: 10, line: 41 }),
      f({ vulnerability: "Unrestricted state modification (potential unlimited minting)", severity: "medium", nodeId: 20, line: 101 }),
      f({ vulnerability: "Functions are callable by any address", severity: "high", confidence: 0.9, nodeId: 30, line: 161 }),
    ]);
    expect(merged.length).toBe(1);
    expect(merged[0].nodeId).toBe(30); // highest severity, then highest confidence
    expect(merged[0].explanation).toContain("line 41");
    expect(merged[0].explanation).toContain("line 101");
  });

  it("keeps different categories separate and sorts by severity", () => {
    const merged = mergeFindings([
      f({ vulnerability: "Integer overflow in sum", severity: "medium", nodeId: 5 }),
      f({ vulnerability: "Reentrancy due to external call", severity: "high", nodeId: 9 }),
    ]);
    expect(merged.map((m) => categoryOf(m.vulnerability))).toEqual(["reentrancy", "overflow"]);
  });

  it("does not touch a single finding", () => {
    const one = f({ vulnerability: "Reentrancy", explanation: "text" });
    expect(mergeFindings([one])).toEqual([one]);
  });
});

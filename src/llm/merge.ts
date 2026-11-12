import type { AuditFinding } from "./schema.js";

const RANK = { low: 0, medium: 1, high: 2, critical: 3 } as const;

// Order matters: the first matching category wins.
const CATEGORIES: [string, RegExp][] = [
  ["reentrancy", /re-?entran/i],
  ["tx-origin", /tx\.origin/i],
  ["delegatecall", /delegatecall/i],
  ["overflow", /overflow|underflow/i],
  ["unchecked-call", /unchecked.*(call|send|return)|return value/i],
  [
    "access-control",
    /access control|unrestricted|unauthori[sz]ed|any (caller|address|user)|anyone|permission|missing (owner|auth)/i,
  ],
  ["timestamp", /timestamp|block\.number/i],
  ["front-running", /front-?run|race condition/i],
];

export function categoryOf(vulnerability: string): string {
  for (const [name, re] of CATEGORIES) if (re.test(vulnerability)) return name;
  const words = vulnerability
    .toLowerCase()
    .replace(/[^a-z ]/g, " ")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 6)
    .join(" ");
  return "other:" + words;
}

export function mergeFindings(findings: AuditFinding[]): AuditFinding[] {
  const groups = new Map<string, AuditFinding[]>();
  for (const f of findings) {
    const key = categoryOf(f.vulnerability);
    const list = groups.get(key) ?? [];
    list.push(f);
    groups.set(key, list);
  }

  const out: AuditFinding[] = [];
  for (const group of groups.values()) {
    const sorted = [...group].sort(
      (a, b) =>
        RANK[b.severity] - RANK[a.severity] ||
        b.confidence - a.confidence ||
        a.nodeId - b.nodeId
    );
    const [rep, ...rest] = sorted;
    if (rest.length === 0) {
      out.push(rep);
      continue;
    }
    const where = rest
      .sort((a, b) => a.nodeId - b.nodeId)
      .map((f) => (f.line ? `line ${f.line}` : `node #${f.nodeId}`))
      .join(", ");
    out.push({
      ...rep,
      explanation: `${rep.explanation}${rep.explanation ? "\n\n" : ""}Also reported at: ${where}.`,
    });
  }
  return out.sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.nodeId - b.nodeId);
}

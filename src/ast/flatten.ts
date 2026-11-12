import type { AstNode } from "./parser.js";

export interface FlatNode {
  id: number;
  type: string;
  parentId: number | null;
  depth: number;
  name: string | null;
  member: string | null;   // e.g. "call", "sender"
  op: string | null;       // e.g. "+=", "-="
  flags: string | null;    // visibility / mutability
  literal: string | null;
  line: number | null;
}

const SKIP_KEYS = new Set(["loc", "range"]);

const isNode = (v: unknown): v is AstNode =>
  typeof v === "object" && v !== null && typeof (v as any).type === "string";

const str = (v: unknown) => (typeof v === "string" ? v : null);

export function flattenAst(root: AstNode): FlatNode[] {
  const out: FlatNode[] = [];

  const visit = (node: AstNode, parentId: number | null, depth: number) => {
    const id = out.length;
    const flags = [str(node.visibility), str(node.stateMutability)]
      .filter(Boolean)
      .join("|");
    out.push({
      id,
      type: node.type,
      parentId,
      depth,
      name: str(node.name),
      member: str(node.memberName),
      op: str(node.operator),
      flags: flags || null,
      literal: str(node.value) ?? str(node.number),
      line: node.loc?.start?.line ?? null,
    });

    for (const key of Object.keys(node).sort()) {
      if (SKIP_KEYS.has(key)) continue;
      const val = node[key];
      if (Array.isArray(val)) {
        for (const item of val) if (isNode(item)) visit(item, id, depth + 1);
      } else if (isNode(val)) {
        visit(val, id, depth + 1);
      }
    }
  };

  visit(root, null, 0);
  return out;
}
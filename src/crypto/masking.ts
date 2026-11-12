import { createHmac, randomBytes } from "node:crypto";
import type { FlatNode } from "../ast/flatten.js";

// Names the LLM needs in order to reason about vulnerabilities. Never masked.
const KEEP = new Set([
  "msg", "sender", "value", "call", "delegatecall", "staticcall", "transfer",
  "send", "balance", "origin", "timestamp", "number", "push", "pop", "length",
  "require", "assert", "revert", "selfdestruct", "this", "super", "block", "tx",
  "keccak256", "abi", "encode", "encodePacked", "ecrecover",
]);

// Nodes whose `name` is a language construct, not a business identifier.
const RAW_NAME_TYPES = new Set(["ElementaryTypeName", "PragmaDirective"]);

export interface MaskedNode {
  id: number;
  type: string;
  parentId: number | null;
  depth: number;
  line: number | null; // local use only, never sent to the LLM
  label: string;       // masked text: no raw identifiers or strings
}

export function maskNodes(
  nodes: FlatNode[],
  salt: Buffer = randomBytes(32)
): { masked: MaskedNode[]; salt: Buffer } {
  const h = (prefix: string, v: string) =>
    prefix + createHmac("sha256", salt).update(v).digest("hex").slice(0, 8);

  const maskId = (v: string) => (KEEP.has(v) ? v : h("n_", v));

  const masked = nodes.map((n): MaskedNode => {
    const parts: string[] = [];
    if (n.name) parts.push(RAW_NAME_TYPES.has(n.type) ? n.name : maskId(n.name));
    if (n.member) parts.push(maskId(n.member));
    if (n.op) parts.push(n.op);
    if (n.flags) parts.push(n.flags);
    if (n.literal) {
      if (n.type === "StringLiteral") parts.push(h("s_", n.literal));
      else parts.push(n.literal); // numbers, pragma versions
    }
    return {
      id: n.id,
      type: n.type,
      parentId: n.parentId,
      depth: n.depth,
      line: n.line,
      label: parts.join("|"),
    };
  });

  return { masked, salt };
}

export function renderSkeleton(nodes: MaskedNode[]): string {
  return nodes
    .map((n) => `${"  ".repeat(n.depth)}#${n.id} ${n.type}${n.label ? " " + n.label : ""}`)
    .join("\n");
}
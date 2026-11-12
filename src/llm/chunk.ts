import type { MaskedNode } from "../crypto/masking.js";

export interface Chunk {
  nodeIds: Set<number>;
  text: string;
}

const subtreeEnd = (nodes: MaskedNode[], i: number) => {
  let j = i + 1;
  while (j < nodes.length && nodes[j].depth > nodes[i].depth) j++;
  return j;
};

const range = (a: number, b: number) => Array.from({ length: b - a }, (_, k) => a + k);

export function chunkNodes(nodes: MaskedNode[], maxChars = 6000): Chunk[] {
  const chunks: Chunk[] = [];

  for (let i = 0; i < nodes.length; i++) {
    if (nodes[i].type !== "ContractDefinition") continue;
    const base = nodes[i].depth;
    const end = subtreeEnd(nodes, i);

    const render = (ids: number[]) =>
      ids
        .map((id) => {
          const n = nodes[id];
          return `${"  ".repeat(n.depth - base)}#${n.id} ${n.type}${n.label ? " " + n.label : ""}`;
        })
        .join("\n");

    // header = contract node + everything that is not a function (state vars, events, ...)
    const header: number[] = [i];
    const funcs: number[][] = [];
    for (let j = i + 1; j < end; ) {
      const cEnd = subtreeEnd(nodes, j);
      if (nodes[j].depth === base + 1) {
        if (nodes[j].type === "FunctionDefinition") funcs.push(range(j, cEnd));
        else header.push(...range(j, cEnd));
      }
      j = cEnd;
    }
    if (funcs.length === 0) continue;

    const flush = (ids: number[]) => {
      ids.sort((a, b) => a - b);
      chunks.push({ nodeIds: new Set(ids), text: render(ids) });
    };

    let current = [...header];
    let size = render(header).length;
    let hasFunc = false;
    for (const fn of funcs) {
      const len = render(fn).length;
      if (hasFunc && size + len > maxChars) {
        flush(current);
        current = [...header];
        size = render(header).length;
        hasFunc = false;
      }
      current.push(...fn);
      size += len;
      hasFunc = true;
    }
    if (hasFunc) flush(current);
  }
  return chunks;
}

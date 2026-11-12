import { createHash } from "node:crypto";
import { poseidonHash } from "./poseidon.js";
import type { MaskedNode } from "./masking.js";

export const TREE_DEPTH = 14;
export const MAX_LEAVES = 1 << TREE_DEPTH;

const hexField = (s: string, hexChars: number) =>
  BigInt("0x" + createHash("sha256").update(s).digest("hex").slice(0, hexChars));

export function leafFields(n: MaskedNode): bigint[] {
  return [
    BigInt(n.id),
    hexField(n.type, 14),
    n.parentId === null ? 0n : BigInt(n.parentId + 1),
    n.label ? hexField(n.label, 30) : 0n,
  ];
}

export function leafHash(n: MaskedNode): bigint {
  return poseidonHash(leafFields(n));
}

export interface MerkleTree {
  root: bigint;
  levels: bigint[][]; // only real nodes; empty positions are implied zeros
  zeros: bigint[];    // zeros[d] = hash of an empty subtree of height d
}

export function buildTree(nodes: MaskedNode[]): MerkleTree {
  if (nodes.length > MAX_LEAVES) {
    throw new Error(`AST has ${nodes.length} nodes, max is ${MAX_LEAVES}`);
  }
  const zeros: bigint[] = [0n];
  for (let d = 0; d < TREE_DEPTH; d++) {
    zeros.push(poseidonHash([zeros[d], zeros[d]]));
  }

  let level = nodes.map(leafHash);
  const levels = [level];
  for (let d = 0; d < TREE_DEPTH; d++) {
    const next: bigint[] = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(poseidonHash([level[i], i + 1 < level.length ? level[i + 1] : zeros[d]]));
    }
    levels.push(next);
    level = next;
  }
  return { root: level[0], levels, zeros };
}

export interface MerkleProof {
  pathElements: bigint[];
  pathIndices: number[];
}

export function getProof(tree: MerkleTree, index: number): MerkleProof {
  const pathElements: bigint[] = [];
  const pathIndices: number[] = [];
  let idx = index;
  for (let d = 0; d < TREE_DEPTH; d++) {
    pathElements.push(tree.levels[d][idx ^ 1] ?? tree.zeros[d]);
    pathIndices.push(idx & 1);
    idx >>= 1;
  }
  return { pathElements, pathIndices };
}

export function verifyProof(leaf: bigint, proof: MerkleProof, root: bigint): boolean {
  let cur = leaf;
  for (let i = 0; i < TREE_DEPTH; i++) {
    cur =
      proof.pathIndices[i] === 0
        ? poseidonHash([cur, proof.pathElements[i]])
        : poseidonHash([proof.pathElements[i], cur]);
  }
  return cur === root;
}

import type { MaskedNode } from "../crypto/masking.js";
import { getProof, leafFields, type MerkleTree } from "../crypto/merkle.js";

export function buildWitnessInput(tree: MerkleTree, masked: MaskedNode[], index: number) {
  const [nodeId, leafType, leafParent, leafLabel] = leafFields(masked[index]);
  const proof = getProof(tree, index);
  return {
    root: tree.root.toString(),
    nodeId: nodeId.toString(),
    leafType: leafType.toString(),
    leafParent: leafParent.toString(),
    leafLabel: leafLabel.toString(),
    pathElements: proof.pathElements.map((x) => x.toString()),
    pathIndices: proof.pathIndices.map(String),
  };
}

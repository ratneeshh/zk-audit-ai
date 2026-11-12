import { readFileSync } from "node:fs";
import path from "node:path";
import * as snarkjs from "snarkjs";
import type { MaskedNode } from "../crypto/masking.js";
import type { MerkleTree } from "../crypto/merkle.js";
import { buildWitnessInput } from "./witness.js";

const B = path.resolve("circuits/build");
const WASM = `${B}/merkle_membership_js/merkle_membership.wasm`;
const ZKEY = `${B}/mm_final.zkey`;
const vkey = JSON.parse(readFileSync(`${B}/verification_key.json`, "utf8"));

export interface NodeProof {
  proof: unknown;
  publicSignals: string[];
}

export async function proveNode(
  tree: MerkleTree,
  masked: MaskedNode[],
  index: number
): Promise<NodeProof & { verified: boolean }> {
  const input = buildWitnessInput(tree, masked, index);
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, WASM, ZKEY);
  const verified = await snarkjs.groth16.verify(vkey, publicSignals, proof);
  return { proof, publicSignals, verified };
}

export const verifyNodeProof = (p: NodeProof): Promise<boolean> =>
  snarkjs.groth16.verify(vkey, p.publicSignals, p.proof);

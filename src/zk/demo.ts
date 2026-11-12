import { readFileSync } from "node:fs";
import * as snarkjs from "snarkjs";
import { parseSolidity } from "../ast/parser.js";
import { flattenAst } from "../ast/flatten.js";
import { initPoseidon } from "../crypto/poseidon.js";
import { maskNodes } from "../crypto/masking.js";
import { buildTree } from "../crypto/merkle.js";
import { buildWitnessInput } from "./witness.js";

await initPoseidon();

const src = readFileSync("contracts-sample/Vulnerable.sol", "utf8");
const { masked } = maskNodes(flattenAst(parseSolidity(src)));
const tree = buildTree(masked);

const index = masked.map((n) => n.type).lastIndexOf("FunctionDefinition");
const input = buildWitnessInput(tree, masked, index);

const B = "circuits/build";
console.time("prove");
const { proof, publicSignals } = await snarkjs.groth16.fullProve(
  input,
  `${B}/merkle_membership_js/merkle_membership.wasm`,
  `${B}/mm_final.zkey`
);
console.timeEnd("prove");

const vkey = JSON.parse(readFileSync(`${B}/verification_key.json`, "utf8"));
console.log("public signals (root, nodeId):", publicSignals);
console.log("valid proof:", await snarkjs.groth16.verify(vkey, publicSignals, proof));

const forged = [publicSignals[0], String(Number(publicSignals[1]) + 1)];
console.log("forged nodeId:", await snarkjs.groth16.verify(vkey, forged, proof));

process.exit(0);

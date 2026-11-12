import { readFileSync } from "node:fs";
import { parseSolidity } from "../ast/parser.js";
import { flattenAst } from "../ast/flatten.js";
import { initPoseidon } from "./poseidon.js";
import { maskNodes, renderSkeleton } from "./masking.js";
import { buildTree, getProof, verifyProof, leafHash } from "./merkle.js";

await initPoseidon();

const src = readFileSync("contracts-sample/Vulnerable.sol", "utf8");
const { masked } = maskNodes(flattenAst(parseSolidity(src)));

console.log(renderSkeleton(masked).split("\n").slice(0, 40).join("\n"));

const tree = buildTree(masked);
console.log("\nroot:", tree.root.toString());

const idx = masked.map((n) => n.type).lastIndexOf("FunctionDefinition");
const leaf = leafHash(masked[idx]);
const proof = getProof(tree, idx);
console.log(`node #${idx} membership:`, verifyProof(leaf, proof, tree.root));
console.log("tampered leaf:", verifyProof(leaf + 1n, proof, tree.root));
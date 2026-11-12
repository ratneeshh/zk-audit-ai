import { beforeAll, describe, expect, it } from "vitest";
import { parseSolidity } from "../src/ast/parser.js";
import { flattenAst } from "../src/ast/flatten.js";
import { initPoseidon } from "../src/crypto/poseidon.js";
import { maskNodes, type MaskedNode } from "../src/crypto/masking.js";
import { buildTree, getProof, leafHash, verifyProof } from "../src/crypto/merkle.js";
import { chunkNodes } from "../src/llm/chunk.js";

beforeAll(async () => {
  await initPoseidon();
});

const bigSource = (n: number) => {
  let s = "pragma solidity ^0.8.20;\ncontract Big {\n  uint256 public total;\n";
  for (let i = 0; i < n; i++) {
    s += `  function f${i}(uint256 a) external { require(a > ${i}); total += a * ${i + 1}; }\n`;
  }
  return s + "}\n";
};

describe("chunking", () => {
  const masked = maskNodes(flattenAst(parseSolidity(bigSource(60)))).masked;
  const chunks = chunkNodes(masked, 3000);

  it("splits a large contract into several chunks", () => {
    expect(chunks.length).toBeGreaterThan(1);
  });

  it("puts every function in exactly one chunk", () => {
    const fnIds = masked.filter((n) => n.type === "FunctionDefinition").map((n) => n.id);
    for (const id of fnIds) {
      expect(chunks.filter((c) => c.nodeIds.has(id)).length).toBe(1);
    }
  });

  it("repeats the state variable context in every chunk", () => {
    const stateVar = masked.find((n) => n.type === "StateVariableDeclaration")!.id;
    for (const c of chunks) expect(c.nodeIds.has(stateVar)).toBe(true);
  });
});

describe("sparse merkle tree at depth 14", () => {
  it("proves membership for a node deep in a large tree", () => {
    const nodes: MaskedNode[] = Array.from({ length: 1500 }, (_, i) => ({
      id: i, type: "Identifier", parentId: i ? 0 : null, depth: 1, line: null, label: `n_${i}`,
    }));
    const tree = buildTree(nodes);
    const proof = getProof(tree, 1499);
    expect(verifyProof(leafHash(nodes[1499]), proof, tree.root)).toBe(true);
    expect(verifyProof(leafHash(nodes[1499]) + 1n, proof, tree.root)).toBe(false);
  }, 30_000);
});

describe("unchecked blocks", () => {
  it("stay visible to the model as UncheckedStatement nodes", () => {
    const src = "pragma solidity ^0.8.20;\ncontract C { uint256 x; function f(uint256 a) external { unchecked { x += a; } } }";
    const masked = maskNodes(flattenAst(parseSolidity(src))).masked;
    const chunks = chunkNodes(masked);
    expect(chunks[0].text).toContain("UncheckedStatement");
  });
});

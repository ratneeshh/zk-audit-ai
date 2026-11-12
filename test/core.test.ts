import { readFileSync } from "node:fs";
import { beforeAll, describe, expect, it } from "vitest";
import { parseSolidity } from "../src/ast/parser.js";
import { flattenAst } from "../src/ast/flatten.js";
import { initPoseidon } from "../src/crypto/poseidon.js";
import { maskNodes, renderSkeleton } from "../src/crypto/masking.js";
import { buildTree, getProof, leafHash, verifyProof } from "../src/crypto/merkle.js";
import { ruleBasedAudit } from "../src/llm/fallback.rules.js";

const VULN = readFileSync("contracts-sample/Vulnerable.sol", "utf8");

const SAFE = `pragma solidity ^0.8.20;
contract Safe {
  mapping(address => uint256) public balances;
  function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
  }
}`;

const mask = (src: string, salt = Buffer.alloc(32, 1)) =>
  maskNodes(flattenAst(parseSolidity(src)), salt).masked;

beforeAll(async () => {
  await initPoseidon();
});

describe("masking", () => {
  it("does not leak raw identifiers or strings", () => {
    const skeleton = renderSkeleton(mask(VULN));
    expect(skeleton).not.toMatch(/VulnerableBank|withdraw|deposit|balances|insufficient/);
  });

  it("keeps security-relevant names readable", () => {
    const skeleton = renderSkeleton(mask(VULN));
    expect(skeleton).toMatch(/msg/);
    expect(skeleton).toMatch(/call/);
    expect(skeleton).toMatch(/require/);
  });

  it("is deterministic per salt and different across salts", () => {
    const a = renderSkeleton(mask(VULN, Buffer.alloc(32, 1)));
    const b = renderSkeleton(mask(VULN, Buffer.alloc(32, 1)));
    const c = renderSkeleton(mask(VULN, Buffer.alloc(32, 2)));
    expect(a).toBe(b);
    expect(a).not.toBe(c);
  });
});

describe("merkle commitment", () => {
  it("accepts a real leaf and rejects a tampered one", () => {
    const masked = mask(VULN);
    const tree = buildTree(masked);
    const i = 19;
    const proof = getProof(tree, i);
    expect(verifyProof(leafHash(masked[i]), proof, tree.root)).toBe(true);
    expect(verifyProof(leafHash(masked[i]) + 1n, proof, tree.root)).toBe(false);
  });

  it("changes the root when any node changes", () => {
    const masked = mask(VULN);
    const root1 = buildTree(masked).root;
    masked[5] = { ...masked[5], label: masked[5].label + "x" };
    expect(buildTree(masked).root).not.toBe(root1);
  });
});

describe("rule engine", () => {
  it("flags state update after external call", () => {
    expect(ruleBasedAudit(mask(VULN)).length).toBe(1);
  });

  it("does not flag checks-effects-interactions code", () => {
    expect(ruleBasedAudit(mask(SAFE)).length).toBe(0);
  });
});

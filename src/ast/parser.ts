import { parse } from "@solidity-parser/parser";

export type AstNode = { type: string; [key: string]: any };

export function parseSolidity(source: string): AstNode {
  return parse(source, { loc: true, range: true, tolerant: false }) as AstNode;
}
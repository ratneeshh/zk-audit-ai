import { readFileSync } from "node:fs";
import { parseSolidity } from "./parser.js";
import { flattenAst } from "./flatten.js";

const src = readFileSync("contracts-sample/Vulnerable.sol", "utf8");
const nodes = flattenAst(parseSolidity(src));
console.log(`${nodes.length} nodes`);
console.table(nodes.slice(0, 15));
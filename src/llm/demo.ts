import { readFileSync } from "node:fs";
import { parseSolidity } from "../ast/parser.js";
import { flattenAst } from "../ast/flatten.js";
import { initPoseidon } from "../crypto/poseidon.js";
import { maskNodes } from "../crypto/masking.js";
import { ruleBasedAudit } from "./fallback.rules.js";
import { auditNodes } from "./audit.js";

await initPoseidon();
const src = readFileSync("contracts-sample/Vulnerable.sol", "utf8");
const { masked } = maskNodes(flattenAst(parseSolidity(src)));

console.log("--- rule engine ---");
console.table(ruleBasedAudit(masked));

console.log("--- groq audit ---");
const result = await auditNodes(masked);
console.log({ usedFallback: result.usedFallback, discarded: result.discarded });
console.table(result.findings);
process.exit(0);

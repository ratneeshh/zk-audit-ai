import { z } from "zod";

export const FindingSchema = z.object({
  vulnerability: z.string().min(1),
  severity: z.preprocess(
    (v) => (typeof v === "string" ? v.toLowerCase() : v),
    z.enum(["low", "medium", "high", "critical"])
  ),
  confidence_score: z.coerce.number().min(0).max(1),
  ast_node_reference: z.coerce.number().int().nonnegative(),
  explanation: z.string().default(""),
});

export const ResponseSchema = z.object({ findings: z.array(FindingSchema) });

export type LlmFinding = z.infer<typeof FindingSchema>;

export interface AuditFinding {
  vulnerability: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: number;
  nodeId: number;
  line: number | null; // looked up locally, never sent to the LLM
  explanation: string;
  source: "llm" | "rules";
}

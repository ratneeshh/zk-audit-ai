import {
  pgTable, uuid, varchar, text, timestamp, integer, numeric, boolean, jsonb,
} from "drizzle-orm/pg-core";

export const codeAudits = pgTable("code_audits", {
  auditId: uuid("audit_id").primaryKey(),
  repositoryHash: varchar("repository_hash", { length: 64 }).notNull(),
  astRootHash: varchar("ast_root_hash", { length: 64 }).notNull(),
  status: varchar("status", { length: 32 }).notNull(),
  usedFallback: boolean("used_fallback").notNull().default(false),
  seq: integer("seq").notNull().unique(),
  prevReceiptHash: varchar("prev_receipt_hash", { length: 64 }).notNull(),
  receiptHash: varchar("receipt_hash", { length: 64 }).notNull(),
  signature: varchar("signature", { length: 128 }).notNull(),
  receiptTs: text("receipt_ts").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true }).defaultNow().notNull(),
});

export const auditFindings = pgTable("audit_findings", {
  findingId: uuid("finding_id").primaryKey().defaultRandom(),
  auditId: uuid("audit_id")
    .notNull()
    .references(() => codeAudits.auditId, { onDelete: "cascade" }),
  vulnerabilityType: varchar("vulnerability_type", { length: 128 }).notNull(),
  severity: varchar("severity", { length: 16 }).notNull(),
  confidenceScore: numeric("confidence_score", { precision: 3, scale: 2 }),
  nodeId: integer("node_id").notNull(),
  line: integer("line"),
  maskedCodeSnippet: text("masked_code_snippet"),
  aiExplanation: text("ai_explanation"),
  source: varchar("source", { length: 16 }).notNull(),
  zkProofVerified: boolean("zk_proof_verified").notNull().default(false),
  proof: jsonb("proof"),
});

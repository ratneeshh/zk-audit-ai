import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { publicKeyPem } from "../crypto/receipt.js";
import {
  getAudit, getReceipt, listAudits, runAudit, verifyAudit, verifyChain,
} from "../services/audit.service.js";

const Body = z.object({ source: z.string().min(1).max(200_000) });
const Params = z.object({ id: z.string().uuid() });

export async function auditRoutes(app: FastifyInstance) {
  app.post("/audits", async (req, reply) => {
    const parsed = Body.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "body must be { source: string }" });
    return runAudit(parsed.data.source);
  });

  app.get("/audits", async () => listAudits());

  app.get("/public-key", async () => ({ alg: "ed25519", publicKey: publicKeyPem() }));

  app.get("/audits/verify-chain", async (req) =>
    verifyChain((req.query as { proofs?: string }).proofs === "true")
  );

  app.get("/audits/:id", async (req, reply) => {
    const p = Params.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ error: "invalid id" });
    return (await getAudit(p.data.id)) ?? reply.code(404).send({ error: "not found" });
  });

  app.get("/audits/:id/verify", async (req, reply) => {
    const p = Params.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ error: "invalid id" });
    return (await verifyAudit(p.data.id)) ?? reply.code(404).send({ error: "not found" });
  });

  app.get("/audits/:id/receipt", async (req, reply) => {
    const p = Params.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ error: "invalid id" });
    return (await getReceipt(p.data.id)) ?? reply.code(404).send({ error: "not found" });
  });
}

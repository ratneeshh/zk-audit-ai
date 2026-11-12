import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { getAudit, listAudits, runAudit, verifyAudit } from "../services/audit.service.js";

const Body = z.object({ source: z.string().min(1).max(200_000) });
const Params = z.object({ id: z.string().uuid() });

export async function auditRoutes(app: FastifyInstance) {
  app.post("/audits", async (req, reply) => {
    const parsed = Body.safeParse(req.body);
    if (!parsed.success) return reply.code(400).send({ error: "body must be { source: string }" });
    return runAudit(parsed.data.source);
  });

  app.get("/audits", async () => listAudits());

  app.get("/audits/:id", async (req, reply) => {
    const p = Params.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ error: "invalid id" });
    const data = await getAudit(p.data.id);
    return data ?? reply.code(404).send({ error: "not found" });
  });

  app.get("/audits/:id/verify", async (req, reply) => {
    const p = Params.safeParse(req.params);
    if (!p.success) return reply.code(400).send({ error: "invalid id" });
    const data = await verifyAudit(p.data.id);
    return data ?? reply.code(404).send({ error: "not found" });
  });
}

import Fastify from "fastify";
import cors from "@fastify/cors";
import { env } from "./config/env.js";
import { initPoseidon } from "./crypto/poseidon.js";
import { auditRoutes } from "./routes/audit.routes.js";

await initPoseidon();

const app = Fastify({ logger: true, bodyLimit: 1_000_000 });
await app.register(cors, { origin: true });
app.get("/health", async () => ({ ok: true }));
await app.register(auditRoutes);

await app.listen({ port: env.PORT, host: "0.0.0.0" });

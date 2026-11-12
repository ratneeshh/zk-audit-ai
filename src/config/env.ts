import dotenv from "dotenv";
dotenv.config({ override: true });
import { z } from "zod";

const schema = z.object({
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().min(1),
  GROQ_API_KEY: z.string().min(10),
  GROQ_MODEL: z.string().default("llama-3.3-70b-versatile"),
  RECEIPT_SIGNING_SECRET: z.string().min(32),
});

export const env = schema.parse(process.env);
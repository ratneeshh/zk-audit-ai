import dotenv from "dotenv";
import { z } from "zod";

dotenv.config({ override: true });

const schema = z.object({
  PORT: z.coerce.number().default(3000),
  DATABASE_URL: z.string().min(1),
  GROQ_API_KEY: z.string().min(10),
  GROQ_MODEL: z.string().default("openai/gpt-oss-120b"),
  RECEIPT_PRIVATE_KEY: z.string().min(40),
});

export const env = schema.parse(process.env);

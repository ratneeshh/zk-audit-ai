import dotenv from "dotenv";
import { defineConfig } from "drizzle-kit";
dotenv.config({ override: true });

export default defineConfig({
  dialect: "postgresql",
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  dbCredentials: { url: process.env.DATABASE_URL! },
});

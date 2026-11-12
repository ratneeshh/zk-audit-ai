import Groq from "groq-sdk";
import Bottleneck from "bottleneck";
import pRetry, { AbortError } from "p-retry";
import { env } from "../config/env.js";
import { SYSTEM_PROMPT, buildUserPrompt } from "./prompts.js";

const groq = new Groq({ apiKey: env.GROQ_API_KEY });

// Token-bucket style limiter: ~25 requests/min, one at a time
const limiter = new Bottleneck({
  maxConcurrent: 1,
  minTime: 2400,
  reservoir: 25,
  reservoirRefreshAmount: 25,
  reservoirRefreshInterval: 60_000,
});

export async function callGroq(skeleton: string): Promise<string> {
  return limiter.schedule(() =>
    pRetry(
      async () => {
        try {
          const res = await groq.chat.completions.create({
            model: env.GROQ_MODEL,
            temperature: 0,
            response_format: { type: "json_object" },
            messages: [
              { role: "system", content: SYSTEM_PROMPT },
              { role: "user", content: buildUserPrompt(skeleton) },
            ],
          });
          return res.choices[0]?.message?.content ?? "";
        } catch (err: any) {
          const status = err?.status as number | undefined;
          // retry on rate limit and server errors, abort on everything else
          if (status === 429 || (status && status >= 500) || !status) throw err;
          throw new AbortError(err);
        }
      },
      { retries: 4, factor: 2, minTimeout: 2000, maxTimeout: 20_000 }
    )
  );
}

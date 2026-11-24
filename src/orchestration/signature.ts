// src/orchestration/signature.ts
import { Env } from "../types";

/**
 * Computes deterministic SHA-256 hash:
 * Hash = SHA256(Role + ModelID + InputSourceDigest + InjectedPrompt)
 */
export async function computeDeterministicSignature(
  roleId: string,
  modelId: string,
  inputSourceDigest: string,
  injectedPrompt: string
): Promise<string> {
  const raw = `${roleId}::${modelId}::${inputSourceDigest}::${injectedPrompt}`;
  const msgUint8 = new TextEncoder().encode(raw);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function lookupDeterministicCache(env: Env, cacheKey: string): Promise<string | null> {
  try {
    const row = await env.DB.prepare(
      "SELECT output_text FROM dag_execution_cache WHERE cache_key = ? AND created_at >= datetime('now', '-7 days')"
    )
      .bind(cacheKey)
      .first<{ output_text: string }>();
    return row?.output_text || null;
  } catch (e) {
    console.warn("Cache lookup error:", e);
    return null;
  }
}

export async function storeDeterministicCache(
  env: Env,
  cacheKey: string,
  roleId: string,
  modelId: string,
  inputDigest: string,
  injectedPrompt: string,
  outputText: string,
  ctx?: ExecutionContext
): Promise<void> {
  try {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO dag_execution_cache 
       (cache_key, role_id, model_id, input_digest, injected_prompt, output_text, created_at)
       VALUES (?, ?, ?, ?, ?, ?, datetime('now'))`
    )
      .bind(cacheKey, roleId, modelId, inputDigest, injectedPrompt, outputText)
      .run();

    // Probabilistic lazy pruning: 1% chance on write to sweep cold entries older than 14 days
    if (Math.random() < 0.01) {
      const prunePromise = env.DB.prepare(
        "DELETE FROM dag_execution_cache WHERE created_at < datetime('now', '-14 days')"
      )
        .run()
        .catch((err) => {
          console.warn("[CachePrune] Prune failed:", err);
        });

      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(prunePromise);
      } else {
        await prunePromise;
      }
    }
  } catch (e) {
    console.warn("Cache store error:", e);
  }
}

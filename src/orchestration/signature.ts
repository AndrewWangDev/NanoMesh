// src/orchestration/signature.ts
import { Env } from "../types";

/**
 * Computes tenant & session-scoped deterministic SHA-256 hash:
 * Hash = SHA256(UserID + SessionID + Role + ModelID + InputSourceDigest + InjectedPrompt)
 */
export async function computeDeterministicSignature(
  roleId: string,
  modelId: string,
  inputSourceDigest: string,
  injectedPrompt: string,
  userId: string = "anonymous",
  sessionId: string = "default-session"
): Promise<string> {
  const safeUser = userId || "anonymous";
  const safeSession = sessionId || "default-session";
  const modelSignature = modelId === "cf-moondream-9b" ? modelId + ":query-v2" : modelId;
  const raw = `${safeUser}::${safeSession}::${roleId}::${modelSignature}::${inputSourceDigest}::${injectedPrompt}`;
  const msgUint8 = new TextEncoder().encode(raw);
  const hashBuffer = await crypto.subtle.digest("SHA-256", msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function lookupDeterministicCache(
  env: Env,
  cacheKey: string,
  userId: string,
  sessionId: string
): Promise<string | null> {
  if (!userId || !sessionId) return null;
  try {
    const row = await env.DB.prepare(
      "SELECT output_text FROM dag_execution_cache WHERE cache_key = ? AND user_id = ? AND session_id = ? AND created_at >= datetime('now', '-7 days')"
    )
      .bind(cacheKey, userId, sessionId)
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
  userId: string,
  sessionId: string,
  ctx?: ExecutionContext
): Promise<void> {
  if (!userId || !sessionId) return;
  try {
    await env.DB.prepare(
      `INSERT INTO dag_execution_cache
       (cache_key, user_id, session_id, role_id, model_id, input_digest, injected_prompt, output_text, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(user_id, session_id, cache_key) DO UPDATE SET
         output_text = excluded.output_text,
         created_at = datetime('now')`
    )
      .bind(cacheKey, userId, sessionId, roleId, modelId, inputDigest, injectedPrompt, outputText)
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

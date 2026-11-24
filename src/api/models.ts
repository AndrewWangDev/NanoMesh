import type { Env } from "../types";

/**
 * Public Active Model Catalog inquiry
 * Returns sanitized public metadata of all online compute models.
 * Internal sensitive fields like auth_secret are strictly excluded.
 */
export async function handleGetPublicModels(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET") {
    return new Response("Method not allowed", { status: 405 });
  }

  try {
    const { results } = await env.DB.prepare(
      `SELECT model_id, display_name, provider, modalities, tags, context_window,
              precision, user_rating, usage_count, cost_per_1k_tokens, status,
              inference_target, browser_runtime, download_size_bytes, api_format
       FROM models
       WHERE status = 'active'
       ORDER BY cost_per_1k_tokens ASC`
    ).all();

    return Response.json({ models: results || [] });
  } catch (err: any) {
    console.error("Failed to load models:", err);
    const isDev = env.ENVIRONMENT === "development";
    const errorMessage = isDev ? err?.message || "Failed to load models" : "Failed to load models";
    return new Response(JSON.stringify({ error: errorMessage }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

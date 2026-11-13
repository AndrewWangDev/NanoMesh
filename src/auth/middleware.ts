import { Env, SessionPayload } from "../types";
import { verifyJWT } from "./jwt";

export async function getSession(request: Request, env: Env): Promise<SessionPayload | null> {
  let token: string | null = null;

  // 1. Check Authorization header (Bearer token)
  const authHeader = request.headers.get("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.slice(7).trim();
  }

  // 2. Fall back to Cookie
  if (!token) {
    const cookieHeader = request.headers.get("Cookie");
    if (cookieHeader) {
      const match = cookieHeader.match(/session=([^;]+)/);
      if (match) token = match[1];
    }
  }

  if (!token) return null;

  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload || !payload.userId) return null;

  // Verify token_version and active status against database (supports immediate session revocation and blocks deleted accounts)
  let user: { token_version: number | null; email: string } | null = null;
  try {
    user = await env.DB.prepare(
      "SELECT token_version, email FROM users WHERE user_id = ?"
    ).bind(payload.userId).first<{token_version: number | null; email: string}>();
  } catch (dbErr) {
    // Graceful fallback during migration deployment window if token_version is not yet applied
    user = await env.DB.prepare(
      "SELECT email FROM users WHERE user_id = ?"
    ).bind(payload.userId).first<{email: string}>().then(r => r ? { token_version: 1, email: r.email } : null);
  }

  if (!user || (user.email && user.email.startsWith("deleted_"))) return null;

  const currentVersion = user.token_version ?? 1;
  const tokenVersion = payload.tokenVersion ?? 1;
  if (tokenVersion < currentVersion) {
    return null;
  }

  return payload as SessionPayload;
}

export async function requireAuth(request: Request, env: Env): Promise<SessionPayload | Response> {
  const session = await getSession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), { 
      status: 401, 
      headers: { "Content-Type": "application/json" } 
    });
  }
  return session;
}

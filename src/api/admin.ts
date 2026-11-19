import type { Env } from "../types";
import { signJWT, verifyJWT } from "../auth/jwt";
import { AwsClient } from "aws4fetch";
import { hashGiftCode, normalizeGiftCode, getPersistentSalt } from "./billing";
import { resolveRoleCompetence } from "../orchestration/competence";
import { isSafeExternalUrl } from "../orchestration/dispatcher";
import type { DAGRole, ModelMetadata } from "../orchestration/types";

function safeJsonParse<T>(val: any, fallback: T): T {
  if (val === null || val === undefined) return fallback;
  if (typeof val !== "string") return (val as T) ?? fallback;
  try {
    return JSON.parse(val);
  } catch {
    return fallback;
  }
}

// Crockford Base32 alphabet (32 characters, no I, L, O, U)
const CROCKFORD_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function generateCrockfordCode(): { raw: string; formatted: string } {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let chars = "";
  for (let i = 0; i < 16; i++) {
    chars += CROCKFORD_ALPHABET[bytes[i] & 31];
  }
  const formatted = `${chars.slice(0, 4)}-${chars.slice(4, 8)}-${chars.slice(8, 12)}-${chars.slice(12, 16)}`;
  return { raw: chars, formatted };
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export async function getAdminSigningSecret(env: Env): Promise<string> {
  const enc = new TextEncoder();
  const salt = `nanomesh_admin_sign_v1:${env.ADMIN_PASSWORD || ''}:${env.JWT_SECRET}`;
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(salt));
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function getAdminSession(request: Request, env: Env) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(/admin_session=([^;]+)/);
  if (!match) return null;
  const token = match[1];
  try {
    const adminSecret = await getAdminSigningSecret(env);
    const payload = await verifyJWT(token, adminSecret);
    if (payload && payload.role === "admin") return payload;
  } catch (e) {}
  return null;
}

export async function handleAdminLogin(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
  // Opportunistic cleanup of stale admin login attempts (> 1 day old)
  const cleanupPromise = env.DB.prepare("DELETE FROM admin_login_attempts WHERE created_at < datetime('now', '-1 day')").run().catch(() => {});
  if (ctx && typeof ctx.waitUntil === 'function') {
    ctx.waitUntil(cleanupPromise);
  }

  const adminPass = env.ADMIN_PASSWORD;
  // Security hardening: reject login if ADMIN_PASSWORD secret is not configured
  if (!adminPass) {
    return new Response(JSON.stringify({ error: "Admin access not configured on server" }), {
      status: 503,
      headers: { "Content-Type": "application/json" }
    });
  }

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";

  // Rate limit: 5 failed attempts per IP in last 15 minutes
  const failRecord = await env.DB.prepare(
    "SELECT COUNT(*) as count FROM admin_login_attempts WHERE ip = ? AND created_at > datetime('now', '-15 minutes')"
  ).bind(ip).first<{ count: number }>();

  if (failRecord && failRecord.count >= 5) {
    return new Response(JSON.stringify({ error: "Too many failed login attempts. Please wait 15 minutes." }), {
      status: 429,
      headers: { "Content-Type": "application/json" }
    });
  }

  const body = await request.json().catch(() => ({})) as { password?: string };
  const enc = new TextEncoder();
  const inputBuffer = enc.encode(body.password || "");
  const passBuffer = enc.encode(adminPass);
  const isMatch = timingSafeEqual(inputBuffer, passBuffer);

  if (!isMatch) {
    await env.DB.prepare("INSERT INTO admin_login_attempts (ip) VALUES (?)").bind(ip).run();
    return new Response(JSON.stringify({ error: "Invalid admin password" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  // Clear failed attempts on successful authentication
  await env.DB.prepare("DELETE FROM admin_login_attempts WHERE ip = ?").bind(ip).run();

  const adminSecret = await getAdminSigningSecret(env);
  const token = await signJWT({ role: "admin" }, adminSecret, 2 * 3600);
  const headers = new Headers();
  headers.set("Set-Cookie", `admin_session=${token}; HttpOnly; Path=/; Max-Age=${2 * 3600}; SameSite=Lax; Secure`);
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify({ success: true }), { headers });
}

export async function handleAdminLogout(request: Request, env: Env): Promise<Response> {
  const headers = new Headers();
  headers.set("Set-Cookie", "admin_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure");
  headers.set("Content-Type", "application/json");
  return new Response(JSON.stringify({ success: true }), { headers });
}

// =========================================================================
// Compute Topology & Node Registry (Light / Medium / Heavy)
// =========================================================================

export async function handleAdminListNodes(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const url = new URL(request.url);
  const filter = url.searchParams.get("filter") || "all";

  let whereClause = "";
  const params: any[] = [];
  if (filter === "active") {
    whereClause = "WHERE status = 'active'";
  } else if (filter === "disabled") {
    whereClause = "WHERE status = 'disabled'";
  } else if (filter === "browser") {
    whereClause = "WHERE inference_target = 'browser'";
  } else if (filter === "edge") {
    whereClause = "WHERE inference_target = 'edge'";
  } else if (filter === "heavy") {
    whereClause = "WHERE inference_target = 'heavy'";
  }

  const query = `SELECT * FROM models ${whereClause} ORDER BY created_at DESC`;
  const rows = await env.DB.prepare(query).bind(...params).all<any>();

  const nodes = (rows.results || []).map(r => ({
    model_id: r.model_id,
    display_name: r.display_name,
    provider: r.provider,
    endpoint: r.endpoint,
    modalities: safeJsonParse<string[]>(r.modalities, ["text"]),
    in_modalities: safeJsonParse<string[]>(r.in_modalities || r.modalities, ["text"]),
    out_modalities: safeJsonParse<string[]>(r.out_modalities, ["text"]),
    tags: safeJsonParse<string[]>(r.tags, []),
    context_window: r.context_window ?? 4096,
    max_concurrency: r.max_concurrency ?? 10,
    active_connections: r.active_connections ?? 0,
    precision: r.precision ?? 0.8,
    user_rating: r.user_rating ?? 5.0,
    usage_count: r.usage_count ?? 0,
    cost_per_1k_tokens: r.cost_per_1k_tokens ?? 1.0,
    cost_per_invocation: r.cost_per_invocation ?? 0.0,
    status: r.status,
    inference_target: r.inference_target || "edge",
    auth_mode: r.auth_mode || "none",
    // Strictly sanitize and mask secret credentials!
    auth_secret: r.auth_secret ? "••••••••" : "",
    has_secret: !!r.auth_secret,
    api_format: r.api_format || "workers_ai",
    created_at: r.created_at,
    updated_at: r.updated_at
  }));

  return Response.json({ success: true, nodes });
}

export async function handleAdminCreateNode(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const body = await request.json().catch(() => ({})) as any;
  const modelId = (body.model_id || "").trim();
  const displayName = (body.display_name || "").trim();
  const provider = (body.provider || "").trim();
  const endpoint = (body.endpoint || "").trim();

  if (!modelId || !displayName || !provider || !endpoint) {
    return Response.json({ error: "Missing required fields: model_id, display_name, provider, endpoint" }, { status: 400 });
  }

  if (!/^[a-zA-Z0-9_\-\.]+$/.test(modelId)) {
    return Response.json({ error: "Invalid model_id format: only letters, numbers, dash, underscore, and dot allowed" }, { status: 400 });
  }

  if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
    if (!isSafeExternalUrl(endpoint)) {
      return Response.json({
        error: "非法算力终端地址：禁止绑定本地回环、内网私有地址（RFC1918）或受保护的网络接口"
      }, { status: 400 });
    }
  } else if (!endpoint.startsWith("@cf/") && body.inference_target !== "browser") {
    return Response.json({
      error: "未知节点协议：必须为合法 HTTP(S) 地址或 Workers AI 标识符（如 @cf/...）"
    }, { status: 400 });
  }

  const modalities = Array.isArray(body.modalities) ? body.modalities : (typeof body.modalities === "string" ? body.modalities.split(",").map((s: string) => s.trim()).filter(Boolean) : ["text"]);
  const tags = Array.isArray(body.tags) ? body.tags : (typeof body.tags === "string" ? body.tags.split(",").map((s: string) => s.trim()).filter(Boolean) : ["#chat"]);
  const contextWindow = Number(body.context_window) || 4096;
  const maxConcurrency = Number(body.max_concurrency) || 10;
  const precision = Number(body.precision) || 0.8;
  const cost = Number(body.cost_per_1k_tokens) || 0.0;
  const status = body.status === "disabled" ? "disabled" : "active";
  const authMode = ["none", "bearer_static", "jwt_ephemeral"].includes(body.auth_mode) ? body.auth_mode : "none";
  const apiFormat = ["workers_ai", "openai_compat", "google_ai"].includes(body.api_format) ? body.api_format : "workers_ai";
  const inferenceTarget = ["browser", "edge", "cloud", "heavy"].includes(body.inference_target) ? body.inference_target : "edge";
  const authSecret = body.auth_secret && body.auth_secret !== "••••••••" && body.auth_secret !== "******" ? body.auth_secret.trim() : null;

  await env.DB.prepare(`
    INSERT INTO models (
      model_id, display_name, provider, endpoint, modalities, tags,
      context_window, max_concurrency, precision, cost_per_1k_tokens,
      status, auth_mode, auth_secret, api_format, inference_target,
      created_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
    ON CONFLICT(model_id) DO UPDATE SET
      display_name = excluded.display_name,
      provider = excluded.provider,
      endpoint = excluded.endpoint,
      modalities = excluded.modalities,
      tags = excluded.tags,
      context_window = excluded.context_window,
      max_concurrency = excluded.max_concurrency,
      precision = excluded.precision,
      cost_per_1k_tokens = excluded.cost_per_1k_tokens,
      status = excluded.status,
      auth_mode = excluded.auth_mode,
      auth_secret = COALESCE(excluded.auth_secret, models.auth_secret),
      api_format = excluded.api_format,
      inference_target = excluded.inference_target,
      updated_at = datetime('now')
  `).bind(
    modelId,
    displayName,
    provider,
    endpoint,
    JSON.stringify(modalities),
    JSON.stringify(tags),
    contextWindow,
    maxConcurrency,
    precision,
    cost,
    status,
    authMode,
    authSecret,
    apiFormat,
    inferenceTarget
  ).run();

  return Response.json({ success: true, model_id: modelId });
}

export async function handleAdminUpdateNode(request: Request, env: Env, nodeId: string): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  if (!nodeId) return Response.json({ error: "Missing node_id" }, { status: 400 });

  const existing = await env.DB.prepare("SELECT * FROM models WHERE model_id = ?").bind(nodeId).first<any>();
  if (!existing) return Response.json({ error: "Node not found" }, { status: 404 });

  const body = await request.json().catch(() => ({})) as any;

  const displayName = body.display_name !== undefined ? body.display_name.trim() : existing.display_name;
  const provider = body.provider !== undefined ? body.provider.trim() : existing.provider;
  const endpoint = body.endpoint !== undefined ? body.endpoint.trim() : existing.endpoint;

  if (body.endpoint !== undefined) {
    if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
      if (!isSafeExternalUrl(endpoint)) {
        return Response.json({
          error: "非法算力终端地址：禁止绑定本地回环、内网私有地址（RFC1918）或受保护的网络接口"
        }, { status: 400 });
      }
    } else if (!endpoint.startsWith("@cf/") && existing.inference_target !== "browser") {
      return Response.json({
        error: "未知节点协议：必须为合法 HTTP(S) 地址或 Workers AI 标识符（如 @cf/...）"
      }, { status: 400 });
    }
  }
  const modalities = body.modalities !== undefined ? (Array.isArray(body.modalities) ? JSON.stringify(body.modalities) : body.modalities) : existing.modalities;
  const tags = body.tags !== undefined ? (Array.isArray(body.tags) ? JSON.stringify(body.tags) : body.tags) : existing.tags;
  const contextWindow = body.context_window !== undefined ? Number(body.context_window) : existing.context_window;
  const maxConcurrency = body.max_concurrency !== undefined ? Number(body.max_concurrency) : existing.max_concurrency;
  const precision = body.precision !== undefined ? Number(body.precision) : existing.precision;
  const cost = body.cost_per_1k_tokens !== undefined ? Number(body.cost_per_1k_tokens) : existing.cost_per_1k_tokens;
  const status = body.status !== undefined ? (body.status === "disabled" || body.status === "offline" ? "disabled" : "active") : existing.status;
  const authMode = body.auth_mode !== undefined ? body.auth_mode : existing.auth_mode;
  const apiFormat = body.api_format !== undefined ? body.api_format : existing.api_format;
  const inferenceTarget = body.inference_target !== undefined ? body.inference_target : existing.inference_target;

  // Security gate: When activating node, strictly verify endpoint validity!
  if (status === "active") {
    if (!endpoint || endpoint === "/api/infer") {
      return Response.json({
        error: "无法启用节点：端点无效或为已废弃的占位符 (/api/infer)"
      }, { status: 400 });
    }
    if (
      !endpoint.startsWith("https://") &&
      !endpoint.startsWith("http://") &&
      !endpoint.startsWith("@cf/") &&
      inferenceTarget !== "browser"
    ) {
      return Response.json({
        error: "无法启用节点：必须具备合法的 HTTP(S) 地址或 Workers AI 标识符（如 @cf/...）"
      }, { status: 400 });
    }
  }

  let authSecret = existing.auth_secret;
  if (body.auth_secret !== undefined && body.auth_secret !== "••••••••" && body.auth_secret !== "******") {
    authSecret = body.auth_secret ? body.auth_secret.trim() : null;
  }

  await env.DB.prepare(`
    UPDATE models SET
      display_name = ?,
      provider = ?,
      endpoint = ?,
      modalities = ?,
      tags = ?,
      context_window = ?,
      max_concurrency = ?,
      precision = ?,
      cost_per_1k_tokens = ?,
      status = ?,
      auth_mode = ?,
      auth_secret = ?,
      api_format = ?,
      inference_target = ?,
      updated_at = datetime('now')
    WHERE model_id = ?
  `).bind(
    displayName,
    provider,
    endpoint,
    modalities,
    tags,
    contextWindow,
    maxConcurrency,
    precision,
    cost,
    status,
    authMode,
    authSecret,
    apiFormat,
    inferenceTarget,
    nodeId
  ).run();

  return Response.json({ success: true, model_id: nodeId });
}

export async function handleAdminDeleteNode(request: Request, env: Env, nodeId: string): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  if (!nodeId) return Response.json({ error: "Missing node_id" }, { status: 400 });

  const url = new URL(request.url);
  const permanent = url.searchParams.get("permanent") === "true";

  if (permanent) {
    await env.DB.prepare("DELETE FROM models WHERE model_id = ?").bind(nodeId).run();
  } else {
    await env.DB.prepare("UPDATE models SET status = 'disabled', updated_at = datetime('now') WHERE model_id = ?").bind(nodeId).run();
  }

  return Response.json({ success: true, model_id: nodeId, permanent });
}

export async function handleAdminUploadLightNode(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const body = await request.json().catch(() => ({})) as { filename?: string };
  const filename = (body.filename || "").replace(/[^a-zA-Z0-9_\-\.]/g, "_");
  if (!filename) return Response.json({ error: "Missing filename" }, { status: 400 });

  const objectKey = `models/light/${Date.now()}_${filename}`;
  const aws = new AwsClient({
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    service: "s3",
    region: "auto"
  });
  const bucket = (env as any).R2_BUCKET_NAME || "nanomesh-assets";
  const objectUrl = new URL(`https://${env.Cloudflare_Account_ID}.r2.cloudflarestorage.com/${bucket}/${objectKey}`);
  objectUrl.searchParams.set("X-Amz-Expires", "3600");

  const presigned = await aws.sign(objectUrl, {
    method: "PUT",
    aws: { signQuery: true }
  });

  return Response.json({
    success: true,
    upload_url: presigned.url,
    r2_key: objectKey,
    public_url: `/api/assets/${objectKey}`
  });
}

// =========================================================================
// Role Dictionary & Competence Health Matrix
// =========================================================================

export async function handleAdminListRoles(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const rows = await env.DB.prepare("SELECT * FROM dag_roles ORDER BY role_id ASC").all<any>();
  const roles = (rows.results || []).map(r => ({
    role_id: r.role_id,
    name_zh: r.name_zh,
    name_en: r.name_en,
    in_modalities: safeJsonParse<string[]>(r.in_modalities, ["text"]),
    out_modalities: safeJsonParse<string[]>(r.out_modalities, ["text"]),
    requisition_tags: safeJsonParse<string[]>(r.requisition_tags, []),
    compensation_prompts: safeJsonParse<Record<string, string>>(r.compensation_prompts, {}),
    created_at: r.created_at
  }));

  return Response.json({ success: true, roles });
}

export async function handleAdminCreateOrUpdateRole(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const body = await request.json().catch(() => ({})) as any;
  const roleId = (body.role_id || "").trim();
  const nameZh = (body.name_zh || "").trim();
  const nameEn = (body.name_en || roleId).trim();

  if (!roleId || !nameZh) {
    return Response.json({ error: "Missing required fields: role_id, name_zh" }, { status: 400 });
  }

  const inModalities = Array.isArray(body.in_modalities) ? body.in_modalities : ["text"];
  const outModalities = Array.isArray(body.out_modalities) ? body.out_modalities : ["text"];
  const tags = Array.isArray(body.requisition_tags) ? body.requisition_tags : ["#general"];
  const compensationPrompts = typeof body.compensation_prompts === "object" && body.compensation_prompts !== null ? body.compensation_prompts : {};

  await env.DB.prepare(`
    INSERT INTO dag_roles (role_id, name_zh, name_en, in_modalities, out_modalities, requisition_tags, compensation_prompts)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(role_id) DO UPDATE SET
      name_zh = excluded.name_zh,
      name_en = excluded.name_en,
      in_modalities = excluded.in_modalities,
      out_modalities = excluded.out_modalities,
      requisition_tags = excluded.requisition_tags,
      compensation_prompts = excluded.compensation_prompts
  `).bind(
    roleId,
    nameZh,
    nameEn,
    JSON.stringify(inModalities),
    JSON.stringify(outModalities),
    JSON.stringify(tags),
    JSON.stringify(compensationPrompts)
  ).run();

  return Response.json({ success: true, role_id: roleId });
}

export async function handleAdminCompetenceMatrix(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const rolesRes = await env.DB.prepare("SELECT * FROM dag_roles ORDER BY role_id ASC").all<any>();
  const modelsRes = await env.DB.prepare("SELECT * FROM models WHERE status = 'active'").all<any>();

  const activeModels: ModelMetadata[] = (modelsRes.results || []).map(r => ({
    model_id: r.model_id,
    display_name: r.display_name,
    provider: r.provider,
    endpoint: r.endpoint,
    modalities: safeJsonParse<string[]>(r.modalities, ["text"]),
    in_modalities: r.in_modalities ? safeJsonParse<string[]>(r.in_modalities, ["text"]) : undefined,
    out_modalities: r.out_modalities ? safeJsonParse<string[]>(r.out_modalities, ["text"]) : undefined,
    tags: safeJsonParse<string[]>(r.tags, []),
    context_window: r.context_window || 4096,
    max_concurrency: r.max_concurrency || 10,
    active_connections: r.active_connections || 0,
    precision: r.precision || 0.8,
    user_rating: r.user_rating || 5.0,
    usage_count: r.usage_count || 0,
    cost_per_1k_tokens: (r.cost_per_1k_tokens !== undefined && r.cost_per_1k_tokens !== null) ? Number(r.cost_per_1k_tokens) : 1.0,
    cost_per_invocation: (r.cost_per_invocation !== undefined && r.cost_per_invocation !== null) ? Number(r.cost_per_invocation) : 0.0,
    status: r.status,
    is_generalist: r.is_generalist || 0,
    prior_score: r.prior_score || 0.0,
    scenario_anchors: safeJsonParse<string[]>(r.scenario_anchors, []),
    inference_target: r.inference_target || 'edge',
    auth_mode: r.auth_mode || 'none',
    api_format: r.api_format || 'workers_ai'
  }));

  const matrix = (rolesRes.results || []).map(r => {
    const role: DAGRole = {
      role_id: r.role_id,
      name_zh: r.name_zh,
      name_en: r.name_en,
      in_modalities: safeJsonParse<string[]>(r.in_modalities, ["text"]),
      out_modalities: safeJsonParse<string[]>(r.out_modalities, ["text"]),
      in_degree: 0,
      out_degree: 0,
      requisition_tags: safeJsonParse<string[]>(r.requisition_tags, ["#general"]),
      compensation_prompts: safeJsonParse<Record<string, string>>(r.compensation_prompts, {})
    };

    let matching: any[] = [];
    let downgraded = false;
    try {
      const resolution = resolveRoleCompetence(role, activeModels);
      matching = resolution.selectedModels.map(m => ({
        model_id: m.model_id,
        display_name: m.display_name,
        provider: m.provider,
        inference_target: m.inference_target,
        cost_per_1k_tokens: m.cost_per_1k_tokens
      }));
      downgraded = resolution.downgraded;
    } catch (e) {
      // 0 matching models in pool -> orphaned role
      matching = [];
      downgraded = false;
    }

    let healthStatus: "healthy" | "warning_single_point" | "critical_orphaned" = "healthy";
    if (matching.length === 0) {
      healthStatus = "critical_orphaned";
    } else if (matching.length === 1) {
      healthStatus = "warning_single_point";
    }

    return {
      role_id: role.role_id,
      name_zh: role.name_zh,
      name_en: role.name_en,
      in_modalities: role.in_modalities,
      out_modalities: role.out_modalities,
      requisition_tags: role.requisition_tags,
      matching_models: matching,
      count: matching.length,
      health_status: healthStatus,
      downgraded
    };
  });

  return Response.json({ success: true, matrix });
}

// =========================================================================
// Linear Workflow Templates & Validation Gate
// =========================================================================

export async function handleAdminListTemplates(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const rows = await env.DB.prepare("SELECT * FROM dag_templates ORDER BY created_at DESC").all<any>();
  const templates = (rows.results || []).map(r => ({
    template_id: r.template_id,
    name: r.name_zh || r.name || "",
    name_zh: r.name_zh || r.name || "",
    name_en: r.name_en || r.name || "",
    description: r.desc_zh || r.description || "",
    desc_zh: r.desc_zh || r.description || "",
    desc_en: r.desc_en || r.description || "",
    role_sequence: safeJsonParse<string[]>(r.role_sequence, []),
    in_modalities: safeJsonParse<string[]>(r.head_modalities || r.in_modalities, []),
    out_modalities: safeJsonParse<string[]>(r.tail_modalities || r.out_modalities, []),
    status: r.status || (r.is_active !== 0 ? 'active' : 'disabled'),
    is_active: r.status === 'active' || r.is_active !== 0,
    created_at: r.created_at
  }));

  return Response.json({ success: true, templates });
}

export async function handleAdminCreateOrUpdateTemplate(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const body = await request.json().catch(() => ({})) as any;
  const nameZh = (body.name_zh || body.name || "").trim();
  const nameEn = (body.name_en || body.name || nameZh).trim();
  const descZh = (body.desc_zh || body.description || "").trim();
  const descEn = (body.desc_en || body.description || descZh).trim();
  const roleSequence: string[] = Array.isArray(body.role_sequence) ? (body.role_sequence as string[]) : [];
  let templateId = (body.template_id || "").trim();

  if (!nameZh || roleSequence.length === 0) {
    return Response.json({ error: "Missing required fields: name and non-empty role_sequence" }, { status: 400 });
  }

  // 1. Fetch all roles from dag_roles
  const rolesRows = await env.DB.prepare("SELECT * FROM dag_roles").all<any>();
  const rolesMap = new Map<string, DAGRole>();
  for (const r of rolesRows.results || []) {
    rolesMap.set(r.role_id, {
      role_id: r.role_id,
      name_zh: r.name_zh,
      name_en: r.name_en,
      in_modalities: safeJsonParse<string[]>(r.in_modalities, ["text"]),
      out_modalities: safeJsonParse<string[]>(r.out_modalities, ["text"]),
      in_degree: 0,
      out_degree: 0,
      requisition_tags: safeJsonParse<string[]>(r.requisition_tags, ["#general"]),
      compensation_prompts: safeJsonParse<Record<string, string>>(r.compensation_prompts, {})
    });
  }

  // 2. Verify all roles exist
  for (let i = 0; i < roleSequence.length; i++) {
    const rid = roleSequence[i];
    if (!rolesMap.has(rid)) {
      return Response.json({ error: `Step ${i + 1}: Role '${rid}' does not exist in dag_roles` }, { status: 400 });
    }
  }

  // 3. VALIDATION GATE: Linear Modality Continuity Check (R_i.out ∩ R_{i+1}.in ≠ ∅)
  for (let i = 0; i < roleSequence.length - 1; i++) {
    const currentRole = rolesMap.get(roleSequence[i])!;
    const nextRole = rolesMap.get(roleSequence[i + 1])!;
    const outSet = new Set(currentRole.out_modalities);
    const hasIntersection = nextRole.in_modalities.some(m => outSet.has(m));
    if (!hasIntersection) {
      return Response.json({
        error: `Modality Discontinuity: Step ${i + 1} (${currentRole.name_zh || currentRole.role_id}) outputs [${currentRole.out_modalities.join(", ")}], but Step ${i + 2} (${nextRole.name_zh || nextRole.role_id}) requires inputs [${nextRole.in_modalities.join(", ")}]. Pipeline connection rejected.`
      }, { status: 400 });
    }
  }

  // 4. VALIDATION GATE: Role Subsistence Check (Active compute node availability)
  const modelsRes = await env.DB.prepare("SELECT * FROM models WHERE status = 'active'").all<any>();
  const activeModels: ModelMetadata[] = (modelsRes.results || []).map(r => ({
    model_id: r.model_id,
    display_name: r.display_name,
    provider: r.provider,
    endpoint: r.endpoint,
    modalities: safeJsonParse<string[]>(r.modalities, ["text"]),
    in_modalities: r.in_modalities ? safeJsonParse<string[]>(r.in_modalities, ["text"]) : undefined,
    out_modalities: r.out_modalities ? safeJsonParse<string[]>(r.out_modalities, ["text"]) : undefined,
    tags: safeJsonParse<string[]>(r.tags, []),
    context_window: r.context_window || 4096,
    max_concurrency: r.max_concurrency || 10,
    active_connections: r.active_connections || 0,
    precision: r.precision || 0.8,
    user_rating: r.user_rating || 5.0,
    usage_count: r.usage_count || 0,
    cost_per_1k_tokens: (r.cost_per_1k_tokens !== undefined && r.cost_per_1k_tokens !== null) ? Number(r.cost_per_1k_tokens) : 1.0,
    cost_per_invocation: (r.cost_per_invocation !== undefined && r.cost_per_invocation !== null) ? Number(r.cost_per_invocation) : 0.0,
    status: r.status,
    is_generalist: r.is_generalist || 0,
    prior_score: r.prior_score || 0.0,
    scenario_anchors: safeJsonParse<string[]>(r.scenario_anchors, []),
    inference_target: r.inference_target || 'edge',
    auth_mode: r.auth_mode || 'none',
    api_format: r.api_format || 'workers_ai'
  }));

  for (let i = 0; i < roleSequence.length; i++) {
    const role = rolesMap.get(roleSequence[i])!;
    let hasModels = false;
    let res: any = null;
    try {
      res = resolveRoleCompetence(role, activeModels);
      hasModels = res.selectedModels.length > 0;
    } catch {
      hasModels = false;
    }
    if (!hasModels) {
      return Response.json({
        error: `Subsistence Check Failed: Step ${i + 1} Role '${role.name_zh || role.role_id}' currently has 0 active models in the compute pool. An un-executable pipeline cannot be saved.`
      }, { status: 400 });
    }
  }

  // 5. Determine in_modalities & out_modalities
  const firstRole = rolesMap.get(roleSequence[0])!;
  const lastRole = rolesMap.get(roleSequence[roleSequence.length - 1])!;
  const inModalities = firstRole.in_modalities;
  const outModalities = lastRole.out_modalities;

  if (!templateId) {
    templateId = `tpl-custom-${Date.now().toString(36)}`;
  }

  // 6. Build linear roles snapshot for backward compatibility
  const fullRoles = roleSequence.map((rid: string, idx: number) => {
    const roleDef = rolesMap.get(rid);
    return {
      ...(roleDef || { role_id: rid, name_zh: rid, name_en: rid, in_modalities: ["text"], out_modalities: ["text"], requisition_tags: ["#general"] }),
      in_degree: idx === 0 ? 0 : 1,
      out_degree: idx === roleSequence.length - 1 ? 0 : 1
    };
  });

  const status = body.status ? (body.status === 'active' ? 'active' : 'disabled') : (body.is_active === false || body.is_active === 0 ? 'disabled' : 'active');

  await env.DB.prepare(`
    INSERT INTO dag_templates (
      template_id, name_zh, name_en, desc_zh, desc_en,
      head_modalities, tail_modalities, roles, role_sequence, priority, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(template_id) DO UPDATE SET
      name_zh = excluded.name_zh,
      name_en = excluded.name_en,
      desc_zh = excluded.desc_zh,
      desc_en = excluded.desc_en,
      head_modalities = excluded.head_modalities,
      tail_modalities = excluded.tail_modalities,
      roles = excluded.roles,
      role_sequence = excluded.role_sequence,
      priority = excluded.priority,
      status = excluded.status
  `).bind(
    templateId,
    nameZh,
    nameEn,
    descZh,
    descEn,
    JSON.stringify(inModalities),
    JSON.stringify(outModalities),
    JSON.stringify(fullRoles),
    JSON.stringify(roleSequence),
    body.priority || 1,
    status
  ).run();

  return Response.json({ success: true, template_id: templateId, status });
}

export async function handleAdminToggleTemplate(request: Request, env: Env, templateId: string): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  if (!templateId) return Response.json({ error: "Missing template_id" }, { status: 400 });

  const body = await request.json().catch(() => ({})) as any;
  const newStatus = body.status ? (body.status === 'active' ? 'active' : 'disabled') : (body.is_active === false || body.is_active === 0 ? 'disabled' : 'active');

  await env.DB.prepare("UPDATE dag_templates SET status = ? WHERE template_id = ?").bind(newStatus, templateId).run();

  return Response.json({ success: true, template_id: templateId, status: newStatus, is_active: newStatus === 'active' });
}

export async function handleAdminDeleteTemplate(request: Request, env: Env, templateId: string): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  if (!templateId) return Response.json({ error: "Missing templateId" }, { status: 400 });

  await env.DB.prepare("DELETE FROM dag_templates WHERE template_id = ?").bind(templateId).run();
  return Response.json({ success: true, template_id: templateId });
}

// ----------------- Model Management -----------------

export async function handleAdminListModels(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const url = new URL(request.url);
  const statusFilter = url.searchParams.get("status") || "all";

  const allowedStatuses = ['pending', 'approved', 'published', 'rejected'];
  let whereClause = "WHERE uum.status != 'uploading'";
  const queryParams: any[] = [];
  if (statusFilter !== "all" && allowedStatuses.includes(statusFilter)) {
    whereClause += " AND uum.status = ?";
    queryParams.push(statusFilter);
  }

  let stmt = env.DB.prepare(
    `SELECT uum.*, u.username, u.email 
     FROM user_uploaded_models uum
     LEFT JOIN users u ON uum.user_id = u.user_id 
     ${whereClause}
     ORDER BY uum.created_at DESC`
  );
  if (queryParams.length > 0) {
    stmt = stmt.bind(...queryParams);
  }
  const { results } = await stmt.all();

  // Pending counts for sidebar badge
  const pendingCount = await env.DB.prepare(
    "SELECT COUNT(*) as count FROM user_uploaded_models WHERE status = 'pending'"
  ).first<{ count: number }>();

  return Response.json({
    models: results,
    pendingCount: pendingCount?.count || 0
  });
}

export async function handleAdminDownload(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const url = new URL(request.url);
  const pathParts = url.pathname.split("/");
  const id = pathParts[pathParts.length - 2];

  const model = await env.DB.prepare("SELECT r2_object_key FROM user_uploaded_models WHERE upload_id = ?").bind(id).first<{ r2_object_key: string }>();
  if (!model) return new Response("Not found", { status: 404 });

  const aws = new AwsClient({
    accessKeyId: env.R2_ACCESS_KEY_ID,
    secretAccessKey: env.R2_SECRET_ACCESS_KEY,
    service: "s3",
    region: "auto"
  });
  const bucket = (env as any).R2_BUCKET_NAME || "nanomesh-assets";
  const objectUrl = new URL(`https://${env.Cloudflare_Account_ID}.r2.cloudflarestorage.com/${bucket}/${model.r2_object_key}`);
  objectUrl.searchParams.set("X-Amz-Expires", "3600");
  const req = await aws.sign(objectUrl, {
    method: "GET",
    aws: { signQuery: true }
  });

  return Response.json({ url: req.url });
}

export async function handleAdminUpdateModel(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  try {
    const url = new URL(request.url);
    const id = url.pathname.split("/").pop();
    if (!id) return Response.json({ error: "Missing model id" }, { status: 400 });

    const body = (await request.json().catch(() => ({}))) as {
      status: string;
      reason?: string;
      endpoint?: string;
      inference_target?: string;
      auth_mode?: string;
      api_format?: string;
      auth_secret?: string;
    };
    if (!body.status) return Response.json({ error: "Missing status" }, { status: 400 });

    const model = await env.DB.prepare("SELECT * FROM user_uploaded_models WHERE upload_id = ?").bind(id).first<any>();
    if (!model) return new Response("Not found", { status: 404 });

    const { dispatchNotification } = await import("./notifications");

    if (body.status === "published" && (model.status === "approved" || model.status === "pending")) {
      const liveModelId = model.live_model_id || ("um-" + id);
      const existingModel = model.live_model_id
        ? await env.DB.prepare("SELECT * FROM models WHERE model_id = ?").bind(model.live_model_id).first<any>()
        : null;

      const targetEndpoint = (body.endpoint || existingModel?.endpoint || "").trim();
      if (!targetEndpoint || targetEndpoint === "/api/infer") {
        return Response.json({
          error: "error.validEndpointRequired",
          message: "A valid endpoint and inference_target are required to publish this model into the network topology."
        }, { status: 400 });
      }

      if (targetEndpoint.startsWith("http://") || targetEndpoint.startsWith("https://")) {
        if (!isSafeExternalUrl(targetEndpoint)) {
          return Response.json({
            error: "非法算力终端地址：禁止绑定本地回环、内网私有地址（RFC1918）或受保护的网络接口"
          }, { status: 400 });
        }
      } else if (!targetEndpoint.startsWith("@cf/") && body.inference_target !== "browser" && existingModel?.inference_target !== "browser") {
        return Response.json({
          error: "未知节点协议：必须为合法 HTTP(S) 地址或 Workers AI 标识符（如 @cf/...）"
        }, { status: 400 });
      }

      const inferenceTarget = ["browser", "edge", "cloud", "heavy"].includes(body.inference_target || "")
        ? body.inference_target
        : (existingModel?.inference_target || (targetEndpoint.startsWith("@cf/") ? "edge" : "heavy"));
      const authMode = ["none", "bearer_static", "jwt_ephemeral"].includes(body.auth_mode || "")
        ? body.auth_mode
        : (existingModel?.auth_mode || "none");
      const apiFormat = ["workers_ai", "openai_compat", "google_ai"].includes(body.api_format || "")
        ? body.api_format
        : (existingModel?.api_format || "workers_ai");
      const authSecret = body.auth_secret && body.auth_secret !== "••••••••" && body.auth_secret !== "******"
        ? body.auth_secret.trim()
        : (existingModel?.auth_secret || null);

      // Use ON CONFLICT to gracefully handle re-publishing previously published/taken-down models
      await env.DB.prepare(
        `INSERT INTO models 
         (model_id, display_name, provider, endpoint, modalities, tags, context_window, max_concurrency, precision, user_rating, usage_count, cost_per_1k_tokens, status, auth_mode, auth_secret, api_format, inference_target)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(model_id) DO UPDATE SET 
           display_name = excluded.display_name,
           endpoint = excluded.endpoint,
           modalities = excluded.modalities,
           tags = excluded.tags,
           context_window = excluded.context_window,
           status = 'active',
           auth_mode = excluded.auth_mode,
           auth_secret = COALESCE(excluded.auth_secret, models.auth_secret),
           api_format = excluded.api_format,
           inference_target = excluded.inference_target,
           updated_at = datetime('now')`
      ).bind(
        liveModelId,
        model.display_name || "User Model",
        "user-upload",
        targetEndpoint,
        model.in_modalities || "[]",
        model.capability_tags || "[]",
        model.context_window || 4096,
        10,
        0.8,
        5.0,
        0,
        1.0,
        "active",
        authMode,
        authSecret,
        apiFormat,
        inferenceTarget
      ).run();

      await env.DB.prepare(
        "UPDATE user_uploaded_models SET status = ?, live_model_id = ?, published_at = datetime('now') WHERE upload_id = ?"
      ).bind("published", liveModelId, id).run();

      if (model.user_id) {
        await dispatchNotification(env, {
          userId: model.user_id,
          category: 'model',
          eventType: 'model_published',
          priority: 'normal',
          titleZh: '模型已成功发布上线',
          titleEn: 'Model Published Successfully',
          contentZh: `您的模型「${model.display_name || '自定义模型'}」已通过审核并正式加入 NanoMesh 全网调度池。`,
          contentEn: `Your model "${model.display_name || 'Custom Model'}" has passed review and is now live on the NanoMesh network.`,
          actionType: 'route',
          actionPayload: JSON.stringify({ modal: 'settings', tab: 'models' }),
          relatedId: id
        });
      }
    } else if (body.status === "approved" && model.status === "published") {
      // Take down / unpublish
      if (model.live_model_id) {
        await env.DB.prepare("UPDATE models SET status = 'disabled', updated_at = datetime('now') WHERE model_id = ?").bind(model.live_model_id).run();
      }
      await env.DB.prepare("UPDATE user_uploaded_models SET status = ? WHERE upload_id = ?").bind("approved", id).run();

      if (model.user_id) {
        const reasonZh = body.reason?.trim() ? `原因：${body.reason.trim()}` : '如需重新上线，请联系平台支持或更新模型。';
        const reasonEn = body.reason?.trim() ? `Reason: ${body.reason.trim()}` : 'To republish, please contact support or update the model.';
        await dispatchNotification(env, {
          userId: model.user_id,
          category: 'model',
          eventType: 'model_delisted',
          priority: 'urgent',
          titleZh: '模型已下架',
          titleEn: 'Model Delisted',
          contentZh: `您的模型「${model.display_name || '自定义模型'}」已被下架。${reasonZh}`,
          contentEn: `Your model "${model.display_name || 'Custom Model'}" has been delisted from the network. ${reasonEn}`,
          actionType: 'route',
          actionPayload: JSON.stringify({ modal: 'settings', tab: 'models' }),
          relatedId: id,
          extraData: body.reason ? JSON.stringify({ reason: body.reason }) : undefined
        });
      }
    } else {
      // If taking down to rejected, disable live model if it was active
      if (model.status === "published" && model.live_model_id) {
        await env.DB.prepare("UPDATE models SET status = 'disabled', updated_at = datetime('now') WHERE model_id = ?").bind(model.live_model_id).run();
      }
      await env.DB.prepare("UPDATE user_uploaded_models SET status = ?, reviewed_at = datetime('now') WHERE upload_id = ?").bind(body.status, id).run();

      if (model.user_id) {
        if (body.status === 'rejected') {
          const reasonZh = body.reason?.trim() ? `原因：${body.reason.trim()}` : '未符合平台合规条款或格式规范。';
          const reasonEn = body.reason?.trim() ? `Reason: ${body.reason.trim()}` : 'Did not meet compliance guidelines or format specifications.';
          await dispatchNotification(env, {
            userId: model.user_id,
            category: 'model',
            eventType: 'model_rejected',
            priority: 'urgent',
            titleZh: '模型审核未通过',
            titleEn: 'Model Review Rejected',
            contentZh: `您的模型「${model.display_name || '自定义模型'}」未能通过审核。${reasonZh}`,
            contentEn: `Your model "${model.display_name || 'Custom Model'}" was rejected. ${reasonEn}`,
            actionType: 'route',
            actionPayload: JSON.stringify({ modal: 'settings', tab: 'models' }),
            relatedId: id,
            extraData: body.reason ? JSON.stringify({ reason: body.reason }) : undefined
          });
        } else if (body.status === 'approved') {
          await dispatchNotification(env, {
            userId: model.user_id,
            category: 'model',
            eventType: 'model_approved',
            priority: 'normal',
            titleZh: '模型审核通过',
            titleEn: 'Model Approved',
            contentZh: `您的模型「${model.display_name || '自定义模型'}」已通过安全合规与模型结构审核，等待上线调度。`,
            contentEn: `Your model "${model.display_name || 'Custom Model'}" has passed review and is awaiting scheduling activation.`,
            actionType: 'route',
            actionPayload: JSON.stringify({ modal: 'settings', tab: 'models' }),
            relatedId: id
          });
        }
      }
    }

    return Response.json({ success: true, upload_id: id, status: body.status });
  } catch (err: any) {
    console.error("handleAdminUpdateModel error:", err);
    return Response.json({ error: err.message || "Failed to update model status" }, { status: 500 });
  }
}

// ----------------- Gift Code Management -----------------

export async function handleAdminCreateGiftCodes(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const body = (await request.json().catch(() => ({}))) as {
    amount?: number;
    count?: number;
    expires_at?: string | null; // ISO string from client e.g. "2026-12-31T15:00:00.000Z"
    note?: string;
  };

  const amount = Number(body.amount);
  if (isNaN(amount) || amount <= 0 || amount > 10000000) {
    return Response.json({ error: "Invalid credit amount (1 - 10,000,000)" }, { status: 400 });
  }

  const count = Math.min(500, Math.max(1, Math.floor(Number(body.count) || 1)));
  const note = (body.note || "").trim().slice(0, 100);

  let expiresAtDb: string | null = null;
  if (body.expires_at) {
    const expDate = new Date(body.expires_at);
    if (isNaN(expDate.getTime()) || expDate.getTime() <= Date.now()) {
      return Response.json({ error: "Expiration date must be in the future" }, { status: 400 });
    }
    // SQLite UTC format 'YYYY-MM-DD HH:MM:SS'
    expiresAtDb = expDate.toISOString().replace("T", " ").replace(/\.\d+Z$/, "");
  }

  const batchId = crypto.randomUUID();
  const generatedCodes: Array<{ id: string; hash: string; hint: string; displayCode: string }> = [];

  for (let i = 0; i < count; i++) {
    const { raw, formatted } = generateCrockfordCode();
    const hash = await hashGiftCode(raw, getPersistentSalt(env));
    generatedCodes.push({
      id: crypto.randomUUID(),
      hash,
      hint: raw.slice(-4),
      displayCode: formatted
    });
  }

  // Insert in chunks of 50 to stay well within D1 batch boundaries
  const CHUNK_SIZE = 50;
  for (let i = 0; i < generatedCodes.length; i += CHUNK_SIZE) {
    const chunk = generatedCodes.slice(i, i + CHUNK_SIZE);
    const statements = chunk.map(c =>
      env.DB.prepare(`
        INSERT INTO gift_codes (code_id, code_hash, code_hint, amount, status, expires_at, batch_id, note)
        VALUES (?, ?, ?, ?, 'active', ?, ?, ?)
      `).bind(c.id, c.hash, c.hint, amount, expiresAtDb, batchId, note || null)
    );
    await env.DB.batch(statements);
  }

  return Response.json({
    success: true,
    batch_id: batchId,
    count: generatedCodes.length,
    amount,
    expires_at: expiresAtDb,
    note,
    codes: generatedCodes.map(c => c.displayCode)
  });
}

export async function handleAdminListGiftCodes(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const url = new URL(request.url);
  const status = url.searchParams.get("status") || "all";
  const batch = url.searchParams.get("batch") || "all";
  const q = (url.searchParams.get("q") || "").trim();
  const page = Math.max(1, parseInt(url.searchParams.get("page") || "1"));
  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") || "50")));
  const offset = (page - 1) * limit;

  // 1. Stats calculation
  const activeStats = await env.DB.prepare(`
    SELECT COUNT(*) as count, COALESCE(SUM(amount), 0) as total_credits 
    FROM gift_codes 
    WHERE status = 'active' AND (expires_at IS NULL OR expires_at > datetime('now'))
  `).first<{ count: number; total_credits: number }>();

  const redeemedStats = await env.DB.prepare(`
    SELECT COUNT(*) as count 
    FROM gift_codes 
    WHERE status = 'redeemed'
  `).first<{ count: number }>();

  const revokedStats = await env.DB.prepare(`
    SELECT COUNT(*) as count 
    FROM gift_codes 
    WHERE status = 'revoked'
  `).first<{ count: number }>();

  const expiredStats = await env.DB.prepare(`
    SELECT COUNT(*) as count 
    FROM gift_codes 
    WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= datetime('now')
  `).first<{ count: number }>();

  // 2. Query filter assembly
  const conditions: string[] = [];
  const params: any[] = [];

  if (status === "active") {
    conditions.push("g.status = 'active' AND (g.expires_at IS NULL OR g.expires_at > datetime('now'))");
  } else if (status === "expired") {
    conditions.push("g.status = 'active' AND g.expires_at IS NOT NULL AND g.expires_at <= datetime('now')");
  } else if (status === "redeemed") {
    conditions.push("g.status = 'redeemed'");
  } else if (status === "revoked") {
    conditions.push("g.status = 'revoked'");
  }

  if (batch && batch !== "all") {
    conditions.push("g.batch_id = ?");
    params.push(batch);
  }

  if (q) {
    conditions.push("(g.code_hint LIKE ? OR g.note LIKE ?)");
    params.push(`%${q}%`, `%${q}%`);
  }

  const whereStr = conditions.length > 0 ? "WHERE " + conditions.join(" AND ") : "";

  const countQuery = `SELECT COUNT(*) as total FROM gift_codes g ${whereStr}`;
  const totalRes = await env.DB.prepare(countQuery).bind(...params).first<{ total: number }>();

  const listQuery = `
    SELECT g.code_id, g.code_hint, g.amount, g.status, g.expires_at, g.redeemed_at, g.revoked_at, 
           g.batch_id, g.note, g.created_at,
           CASE 
             WHEN g.status = 'active' AND g.expires_at IS NOT NULL AND g.expires_at <= datetime('now') THEN 'expired'
             ELSE g.status 
           END as computed_status,
           u.username as redeemed_username, u.email as redeemed_email
    FROM gift_codes g
    LEFT JOIN users u ON g.redeemed_by = u.user_id
    ${whereStr}
    ORDER BY g.created_at DESC
    LIMIT ? OFFSET ?
  `;
  const listParams = [...params, limit, offset];
  const items = await env.DB.prepare(listQuery).bind(...listParams).all();

  // 3. Batches dropdown list
  const batches = await env.DB.prepare(`
    SELECT batch_id, note, amount, created_at, COUNT(*) as code_count
    FROM gift_codes
    GROUP BY batch_id
    ORDER BY created_at DESC
    LIMIT 50
  `).all();

  return Response.json({
    items: items.results,
    total: totalRes?.total || 0,
    page,
    limit,
    stats: {
      active: activeStats?.count || 0,
      activeCredits: activeStats?.total_credits || 0,
      redeemed: redeemedStats?.count || 0,
      revoked: revokedStats?.count || 0,
      expired: expiredStats?.count || 0
    },
    batches: batches.results
  });
}

export async function handleAdminRevokeGiftCode(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const url = new URL(request.url);
  // Match /api/admin/gift-codes/:id/revoke
  const parts = url.pathname.split("/");
  const codeId = parts[parts.length - 2];

  if (!codeId) return Response.json({ error: "Missing code id" }, { status: 400 });

  const res = await env.DB.prepare(`
    UPDATE gift_codes 
    SET status = 'revoked', revoked_at = datetime('now') 
    WHERE code_id = ? AND status = 'active'
  `).bind(codeId).run();

  if (res.meta.changes === 0) {
    return Response.json({ error: "Code not found, already redeemed, or already revoked" }, { status: 400 });
  }

  return Response.json({ success: true, code_id: codeId });
}

export async function handleAdminRevokeBatch(request: Request, env: Env): Promise<Response> {
  const session = await getAdminSession(request, env);
  if (!session) return new Response("Unauthorized", { status: 401 });

  const body = (await request.json().catch(() => ({}))) as { batch_id?: string };
  if (!body.batch_id) {
    return Response.json({ error: "Missing batch_id" }, { status: 400 });
  }

  const res = await env.DB.prepare(`
    UPDATE gift_codes 
    SET status = 'revoked', revoked_at = datetime('now') 
    WHERE batch_id = ? AND status = 'active'
  `).bind(body.batch_id).run();

  return Response.json({
    success: true,
    batch_id: body.batch_id,
    revokedCount: res.meta.changes || 0
  });
}

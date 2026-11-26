import { Env } from "../types";
import { getSession } from "../auth/middleware";
import { getSinglePresignedPutUrl } from "../lib/r2s3";
import { registerPresignedAssetTicket } from "./session";

const MAX_CHAT_FILE_SIZE = 25 * 1024 * 1024; // 25MB hard limit
const DAILY_UPLOAD_QUOTA = 50;

async function checkDailyUploadQuota(
  env: Env,
  userId: string,
  ctx?: ExecutionContext
): Promise<{ allowed: boolean; counterKey: string }> {
  const todayStr = new Date().toISOString().slice(0, 10);
  const counterKey = `presign_daily_${todayStr}_${userId}`;

  // Opportunistically prune expired daily upload counters (> 2 days old)
  const prunePromise = env.DB.prepare(
    "DELETE FROM system_counters WHERE key LIKE 'presign_daily_%' AND key < 'presign_daily_' || date('now', '-2 days')"
  )
    .run()
    .catch(() => {});
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(prunePromise);
  }

  const counter = await env.DB.prepare("SELECT value FROM system_counters WHERE key = ?")
    .bind(counterKey)
    .first<{ value: number }>();

  return {
    allowed: !counter || counter.value < DAILY_UPLOAD_QUOTA,
    counterKey
  };
}

export async function handleChatPresign(
  request: Request,
  env: Env,
  ctx?: ExecutionContext
): Promise<Response> {
  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  const session = await getSession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  // 1. Quota check: Query DB for user credits
  const userRow = await env.DB.prepare("SELECT credits FROM users WHERE user_id = ?")
    .bind(session.userId)
    .first<{ credits: number }>();

  const credits = userRow?.credits ?? 0;
  if (credits <= 0) {
    return new Response(
      JSON.stringify({
        error: "insufficient_quota",
        message: "当前可用积分余额为 0 ⚡，无法上传附件或提交任务，请先充值额度。"
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // 1b. Per-user daily upload quota check to prevent unmetered tmp/ R2 exhaustion (NM-AUD-02)
  const quota = await checkDailyUploadQuota(env, session.userId, ctx);
  if (!quota.allowed) {
    return new Response(
      JSON.stringify({
        error: "presign_daily_limit",
        message: "今日临时文件上传次数已达上限（50 次/日），请明日再试。"
      }),
      {
        status: 429,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
  const presignCounterKey = quota.counterKey;

  // 2. Parse request
  let body: { file_name?: string; file_size?: number; mime_type?: string; modality?: string };
  try {
    body = await request.json();
    if (!body || typeof body !== "object") throw new Error("Not an object");
  } catch (e) {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const fileName = (body.file_name || (body as any).fileName || "upload.bin").replace(
    /[^a-zA-Z0-9._-]/g,
    "_"
  );
  const rawFileSize = Number(
    body.file_size !== undefined ? body.file_size : (body as any).fileSize
  );
  if (!Number.isFinite(rawFileSize) || rawFileSize < 1 || rawFileSize > MAX_CHAT_FILE_SIZE) {
    return new Response(
      JSON.stringify({
        error: "invalid_file_size",
        message: "文件大小无效或超出 25MB 大小限制，请精简后重试。"
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
  const fileSize = Math.floor(rawFileSize);
  if (fileSize < 1) {
    return new Response(
      JSON.stringify({
        error: "invalid_file_size",
        message: "文件大小无效，必须大于等于 1 字节。"
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
  const mimeType = body.mime_type || (body as any).fileType || "application/octet-stream";

  // 3. Generate presigned URL targeting tmp/ directory
  const assetId = crypto.randomUUID();
  const r2Key = `tmp/${session.userId}/${assetId}/${fileName}`;

  try {
    const uploadUrl = await getSinglePresignedPutUrl(env, r2Key, mimeType, fileSize, 300);
    await env.DB.prepare(
      "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
    )
      .bind(presignCounterKey)
      .run()
      .catch(() => {});
    await registerPresignedAssetTicket(env, {
      assetId,
      userId: session.userId,
      filename: fileName,
      modality: body.modality || "image",
      mimeType,
      fileSize,
      r2Key,
      origin: "upload"
    });
    return new Response(
      JSON.stringify({
        assetId,
        r2Key,
        uploadUrl,
        modality: body.modality || "image"
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" }
      }
    );
  } catch (err: any) {
    return new Response(
      JSON.stringify({
        error: "presign_failed",
        message:
          env.ENVIRONMENT === "production"
            ? "Failed to generate presigned upload URL"
            : err.message || "Failed to generate presigned upload URL"
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}

export async function handleChatUpload(
  request: Request,
  env: Env,
  ctx?: ExecutionContext
): Promise<Response> {
  const session = await getSession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  if (request.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }

  // 1. Quota check
  const userRow = await env.DB.prepare("SELECT credits FROM users WHERE user_id = ?")
    .bind(session.userId)
    .first<{ credits: number }>();

  const credits = userRow?.credits ?? 0;
  if (credits <= 0) {
    return new Response(
      JSON.stringify({
        error: "insufficient_quota",
        message: "当前可用积分余额为 0 ⚡，无法上传附件，请先充值额度。"
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // 1b. Unified per-user daily upload quota check (closes /api/upload/file bypass for NM-AUD-02)
  const uploadQuota = await checkDailyUploadQuota(env, session.userId, ctx);
  if (!uploadQuota.allowed) {
    return new Response(
      JSON.stringify({
        error: "presign_daily_limit",
        message: "今日临时文件上传次数已达上限（50 次/日），请明日再试。"
      }),
      {
        status: 429,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // 2. Check Content-Length BEFORE buffering multipart FormData into 128MB Worker memory (NM-AUD-02)
  const rawContentLength = request.headers.get("Content-Length");
  if (rawContentLength) {
    const contentLen = Number(rawContentLength);
    if (Number.isFinite(contentLen) && contentLen > MAX_CHAT_FILE_SIZE + 65536) {
      return new Response(
        JSON.stringify({
          error: "file_too_large",
          message: "请求体积超出 25MB 上传限制，已拒绝解析。"
        }),
        {
          status: 413,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  }

  // 3. Parse FormData
  let formData: FormData;
  try {
    formData = await request.formData();
  } catch (err) {
    return new Response(JSON.stringify({ error: "Invalid multipart form data" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const file = formData.get("file") as File | null;
  const modality = (formData.get("modality") as string) || "image";

  if (!file) {
    return new Response(JSON.stringify({ error: "Missing file payload" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  if (file.size > MAX_CHAT_FILE_SIZE) {
    return new Response(
      JSON.stringify({
        error: "file_too_large",
        message: "单文件超出 25MB 大小限制，请精简后重试。"
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  const fileName = (file.name || "upload.bin").replace(/[^a-zA-Z0-9._-]/g, "_");
  const assetId = crypto.randomUUID();
  const r2Key = `tmp/${session.userId}/${assetId}/${fileName}`;
  const contentType = file.type || "application/octet-stream";

  try {
    await env.R2.put(r2Key, file.stream(), {
      httpMetadata: {
        contentType: contentType
      },
      customMetadata: {
        userId: session.userId,
        originalName: fileName,
        assetId: assetId
      }
    });

    await env.DB.prepare(
      "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
    )
      .bind(uploadQuota.counterKey)
      .run()
      .catch(() => {});

    await registerPresignedAssetTicket(env, {
      assetId,
      userId: session.userId,
      filename: fileName,
      modality,
      mimeType: contentType,
      fileSize: file.size,
      r2Key,
      origin: "upload"
    });

    return new Response(
      JSON.stringify({
        assetId,
        r2Key,
        file_name: fileName,
        file_size: file.size,
        mime_type: contentType,
        modality
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" }
      }
    );
  } catch (putErr: any) {
    console.error("Direct R2 upload error:", putErr);
    return new Response(
      JSON.stringify({
        error: "upload_failed",
        message:
          env.ENVIRONMENT === "production"
            ? "Failed to store file to R2"
            : putErr.message || "Failed to store file to R2"
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}

export async function handleGetAsset(request: Request, env: Env): Promise<Response> {
  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405 });
  }
  const url = new URL(request.url);
  let key = url.searchParams.get("key");
  if (!key) {
    if (url.pathname.startsWith("/api/assets/")) {
      key = decodeURIComponent(url.pathname.slice("/api/assets/".length));
    } else if (url.pathname.startsWith("/api/asset/")) {
      key = decodeURIComponent(url.pathname.slice("/api/asset/".length));
    }
  }

  if (!key) {
    return new Response("Missing asset key", { status: 400 });
  }

  // Defend against path traversal, backslashes, and directory confusion in CDN and cache layers
  if (key.includes("..") || key.includes("\\") || key.includes("//")) {
    return new Response("Invalid asset key: path traversal sequences prohibited", { status: 400 });
  }

  // 1. Public Light Node Models: accessible without user session for WebGPU/browser runtimes
  if (key.startsWith("models/light/")) {
    const object = await env.R2.get(key);
    if (!object) {
      return new Response("Not Found", { status: 404 });
    }
    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("etag", object.httpEtag);
    headers.set("cache-control", "public, max-age=31536000, immutable");
    headers.set("access-control-allow-origin", "*");
    headers.set("X-Content-Type-Options", "nosniff");
    headers.set("Content-Security-Policy", "default-src 'none'; sandbox");
    headers.set("Content-Disposition", "attachment");
    return new Response(object.body, { headers });
  }

  // 2. Private Temporary User Assets: strictly require user session and isolation
  const session = await getSession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  // Security check: Only allow user to access their own assets
  if (!key.startsWith(`tmp/${session.userId}/`)) {
    return new Response("Forbidden", { status: 403 });
  }

  const object = await env.R2.get(key);
  if (!object) {
    return new Response("Not Found", { status: 404 });
  }

  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("cache-control", "private, max-age=86400");
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Content-Security-Policy", "default-src 'none'; sandbox");
  return new Response(object.body, { headers });
}

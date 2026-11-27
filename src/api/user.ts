import { Env } from "../types";
import { getSession } from "../auth/middleware";
import { signJWT } from "../auth/jwt";
import { getPersistentSalt } from "./billing";
import { hashPasswordPBKDF2, verifyPassword } from "../lib/password";
import { safeJsonBody } from "../lib/utils";
import { sweepPendingR2Cleanups } from "./session";

export async function handleUpdateProfile(req: Request, env: Env) {
  if (req.method !== "PUT") return new Response("Method not allowed", { status: 405 });
  const session = await getSession(req, env);
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const body: any = await safeJsonBody(req);
  const { username } = body;

  if (!username || !/^[a-zA-Z0-9_-]{3,20}$/.test(username)) {
    return Response.json({ error: "error.invalidUsernameFormat" }, { status: 400 });
  }

  // Check uniqueness (case-insensitive)
  const existing = await env.DB.prepare(
    "SELECT user_id FROM users WHERE LOWER(username) = LOWER(?) AND user_id != ?"
  )
    .bind(username, session.userId)
    .first();
  if (existing) {
    return Response.json({ error: "error.usernameExists" }, { status: 400 });
  }

  await env.DB.prepare("UPDATE users SET username = ? WHERE user_id = ?")
    .bind(username, session.userId)
    .run();

  return Response.json({ success: true });
}

export async function handleUpdatePassword(req: Request, env: Env) {
  if (req.method !== "PUT") return new Response("Method not allowed", { status: 405 });
  const session = await getSession(req, env);
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const body: any = await safeJsonBody(req);
  const { oldPassword, newPassword } = body;

  if (
    !newPassword ||
    newPassword.length < 8 ||
    newPassword.length > 64 ||
    !/[a-zA-Z]/.test(newPassword) ||
    !/[0-9]/.test(newPassword)
  ) {
    return Response.json({ error: "error.invalidPasswordFormat" }, { status: 400 });
  }

  // Get user
  const user = await env.DB.prepare(
    "SELECT password_hash, token_version FROM users WHERE user_id = ?"
  )
    .bind(session.userId)
    .first<{ password_hash: string | null; token_version: number | null }>();
  if (!user) return Response.json({ error: "error.userNotFound" }, { status: 404 });

  if (user.password_hash) {
    if (!oldPassword) {
      return Response.json({ error: "error.oldPasswordRequired" }, { status: 400 });
    }
    const { valid } = await verifyPassword(oldPassword, user.password_hash);
    if (!valid) return Response.json({ error: "error.incorrectOldPassword" }, { status: 400 });
  }

  const newHash = await hashPasswordPBKDF2(newPassword);
  const nextTokenVersion = (user.token_version ?? 1) + 1;
  await env.DB.prepare("UPDATE users SET password_hash = ?, token_version = ? WHERE user_id = ?")
    .bind(newHash, nextTokenVersion, session.userId)
    .run();

  const newToken = await signJWT(
    { userId: session.userId, tokenVersion: nextTokenVersion, typ: "session" },
    env.JWT_SECRET,
    30 * 24 * 3600
  );
  const response = Response.json({ success: true, token: newToken });
  response.headers.set(
    "Set-Cookie",
    `session=${newToken}; HttpOnly; Path=/; Max-Age=${30 * 24 * 3600}; SameSite=Lax; Secure`
  );
  return response;
}

export async function handleUpdateAvatar(req: Request, env: Env, ctx?: ExecutionContext) {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const session = await getSession(req, env);
  if (!session) return Response.json({ error: "error.unauthorized" }, { status: 401 });

  const userRow = await env.DB.prepare(
    "SELECT avatar_url, avatar_updated_at FROM users WHERE user_id = ?"
  )
    .bind(session.userId)
    .first<{ avatar_url: string | null; avatar_updated_at: string | null }>();
  if (!userRow) return Response.json({ error: "error.userNotFound" }, { status: 404 });

  const previousAvatarUrl = userRow.avatar_url;

  if (userRow.avatar_updated_at) {
    const lastUpdate = new Date(userRow.avatar_updated_at.replace(" ", "T") + "Z").getTime();
    if (Date.now() - lastUpdate < 24 * 60 * 60 * 1000) {
      return Response.json({ error: "error.avatarCooldown" }, { status: 429 });
    }
  }

  // Check Content-Length BEFORE buffering multipart FormData into Worker memory (NM-AUD-02)
  const rawContentLength = req.headers.get("Content-Length");
  if (rawContentLength) {
    const contentLen = Number(rawContentLength);
    if (Number.isFinite(contentLen) && contentLen > 5 * 1024 * 1024 + 65536) {
      return Response.json({ error: "error.fileTooLarge" }, { status: 413 });
    }
  }

  const formData = await req.formData().catch(() => null);
  if (!formData) return Response.json({ error: "error.invalidRequest" }, { status: 400 });

  const file = formData.get("file") as File;
  if (!file || !file.size) return Response.json({ error: "error.noFile" }, { status: 400 });

  if (file.size > 5 * 1024 * 1024) {
    return Response.json({ error: "error.fileTooLarge" }, { status: 400 });
  }

  const extension = file.name.split(".").pop()?.toLowerCase() || "png";
  const EXT_TO_MIME: Record<string, string> = {
    png: "image/png",
    jpg: "image/jpeg",
    jpeg: "image/jpeg",
    webp: "image/webp",
    gif: "image/gif"
  };
  const safeContentType = EXT_TO_MIME[extension];
  if (!safeContentType) {
    return Response.json({ error: "error.unsupportedFile" }, { status: 400 });
  }

  // Magic bytes verification to prevent disguised HTML/SVG/binary uploads (NM-AUD-12)
  const headerBytes = new Uint8Array(await file.slice(0, 16).arrayBuffer());
  const isPng =
    headerBytes.length >= 4 &&
    headerBytes[0] === 0x89 &&
    headerBytes[1] === 0x50 &&
    headerBytes[2] === 0x4e &&
    headerBytes[3] === 0x47;
  const isJpeg =
    headerBytes.length >= 3 &&
    headerBytes[0] === 0xff &&
    headerBytes[1] === 0xd8 &&
    headerBytes[2] === 0xff;
  const isGif =
    headerBytes.length >= 4 &&
    headerBytes[0] === 0x47 &&
    headerBytes[1] === 0x49 &&
    headerBytes[2] === 0x46 &&
    headerBytes[3] === 0x38;
  const isWebp =
    headerBytes.length >= 12 &&
    headerBytes[0] === 0x52 &&
    headerBytes[1] === 0x49 &&
    headerBytes[2] === 0x46 &&
    headerBytes[3] === 0x46 &&
    headerBytes[8] === 0x57 &&
    headerBytes[9] === 0x45 &&
    headerBytes[10] === 0x42 &&
    headerBytes[11] === 0x50;

  const magicMatches =
    (safeContentType === "image/png" && isPng) ||
    (safeContentType === "image/jpeg" && isJpeg) ||
    (safeContentType === "image/gif" && isGif) ||
    (safeContentType === "image/webp" && isWebp);
  if (!magicMatches) {
    return Response.json({ error: "error.unsupportedFile" }, { status: 400 });
  }

  const objectKey = `avatars/${session.userId}_${Date.now()}.${extension}`;

  await env.R2.put(objectKey, file.stream(), {
    httpMetadata: {
      contentType: safeContentType
    }
  });

  const avatarUrl = `/storage/${objectKey}`;

  // Atomic CAS cooldown guard to eliminate concurrent 24h TOCTOU orphan uploads (NM-AUD-12)
  const casUpdate = await env.DB.prepare(
    "UPDATE users SET avatar_url = ?, avatar_updated_at = datetime('now') WHERE user_id = ? AND (avatar_updated_at IS NULL OR avatar_updated_at <= datetime('now', '-24 hours'))"
  )
    .bind(avatarUrl, session.userId)
    .run();

  if (!casUpdate.meta.changes || casUpdate.meta.changes === 0) {
    if (env.R2 && typeof env.R2.delete === "function") {
      await env.R2.delete(objectKey).catch(() => {});
    }
    return Response.json({ error: "error.avatarCooldown" }, { status: 429 });
  }

  // Asynchronously clean up previous avatar from R2 to eliminate orphaned storage accumulation
  if (previousAvatarUrl && previousAvatarUrl.startsWith("/storage/avatars/")) {
    const oldKey = previousAvatarUrl.replace("/storage/", "");
    if (oldKey && oldKey !== objectKey && env.R2 && typeof env.R2.delete === "function") {
      const deletePromise = env.R2.delete(oldKey).catch((err) => {
        console.warn("[R2_CLEANUP_WARN] Failed to delete old avatar:", oldKey, err);
      });
      if (ctx && typeof ctx.waitUntil === "function") {
        ctx.waitUntil(deletePromise);
      } else {
        await deletePromise;
      }
    }
  }

  return Response.json({ success: true, avatar_url: avatarUrl });
}

export async function handleDeleteAccount(req: Request, env: Env) {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const session = await getSession(req, env);
  if (!session) return Response.json({ error: "error.unauthorized" }, { status: 401 });

  // 1. Check frozen_credits
  const user = await env.DB.prepare(
    "SELECT email, oauth_id, oauth_provider, frozen_credits FROM users WHERE user_id = ?"
  )
    .bind(session.userId)
    .first<{
      email: string;
      oauth_id: string | null;
      oauth_provider: string | null;
      frozen_credits: number;
    }>();
  if (!user) return Response.json({ error: "error.userNotFound" }, { status: 404 });

  if (user.frozen_credits > 0) {
    return Response.json({ error: "error.hasFrozenCredits" }, { status: 400 });
  }

  // 2. Hash fingerprints (email and oauth_id)
  const encoder = new TextEncoder();
  const persistentSalt = getPersistentSalt(env);
  const emailData = encoder.encode(user.email + persistentSalt);
  const emailHashBuffer = await crypto.subtle.digest("SHA-256", emailData);
  const emailHash = Array.from(new Uint8Array(emailHashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  // 3. Insert tombstone (with in-memory Set deduplication & INSERT OR IGNORE idempotency)
  const tombstoneHashes = new Set<string>();
  tombstoneHashes.add(emailHash);
  await env.DB.prepare(
    "INSERT OR IGNORE INTO account_tombstones (hash_id, type, expires_at) VALUES (?, 'email', datetime('now', '+90 days'))"
  )
    .bind(emailHash)
    .run();

  const bindings = await env.DB.prepare(
    "SELECT provider, provider_id FROM user_oauth_bindings WHERE user_id = ?"
  )
    .bind(session.userId)
    .all<{ provider: string; provider_id: string }>();
  if (bindings.results && bindings.results.length > 0) {
    for (const b of bindings.results) {
      const oauthData = encoder.encode(`${b.provider}:${b.provider_id}` + persistentSalt);
      const oauthHashBuffer = await crypto.subtle.digest("SHA-256", oauthData);
      const oauthHash = Array.from(new Uint8Array(oauthHashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      if (!tombstoneHashes.has(oauthHash)) {
        tombstoneHashes.add(oauthHash);
        await env.DB.prepare(
          "INSERT OR IGNORE INTO account_tombstones (hash_id, type, expires_at) VALUES (?, 'oauth', datetime('now', '+90 days'))"
        )
          .bind(oauthHash)
          .run();
      }
    }
  }

  if (user.oauth_provider && user.oauth_id) {
    const oauthData = encoder.encode(`${user.oauth_provider}:${user.oauth_id}` + persistentSalt);
    const oauthHashBuffer = await crypto.subtle.digest("SHA-256", oauthData);
    const oauthHash = Array.from(new Uint8Array(oauthHashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    if (!tombstoneHashes.has(oauthHash)) {
      tombstoneHashes.add(oauthHash);
      await env.DB.prepare(
        "INSERT OR IGNORE INTO account_tombstones (hash_id, type, expires_at) VALUES (?, 'oauth', datetime('now', '+90 days'))"
      )
        .bind(oauthHash)
        .run();
    }
  }

  // 4. In-place anonymization & full multi-tenant session/cache erasure (GDPR & PLAN-07/REV-06)
  const r2Prefixes = [`tmp/${session.userId}/`, `avatars/${session.userId}_`];
  await env.DB.batch([
    env.DB.prepare(
      `
      UPDATE users 
      SET email = 'deleted_' || user_id, 
          oauth_id = NULL, 
          oauth_provider = NULL, 
          username = 'del_' || substr(user_id, 1, 12), 
          password_hash = NULL, 
          avatar_url = NULL, 
          referral_code = NULL, 
          credits = 0,
          token_version = token_version + 1
      WHERE user_id = ?
    `
    ).bind(session.userId),
    env.DB.prepare(
      `INSERT INTO pending_r2_deletions (delete_id, user_id, session_id, r2_key)
       SELECT lower(hex(randomblob(16))), user_id, session_id, r2_key
       FROM session_assets
       WHERE user_id = ? AND r2_key IS NOT NULL AND r2_key != ''
       ON CONFLICT(user_id, r2_key) DO NOTHING`
    ).bind(session.userId),
    env.DB.prepare(
      `INSERT INTO pending_r2_deletions (delete_id, user_id, session_id, r2_key)
       SELECT lower(hex(randomblob(16))), user_id, session_id, text_r2_key
       FROM session_assets
       WHERE user_id = ? AND text_r2_key IS NOT NULL AND text_r2_key != ''
       ON CONFLICT(user_id, r2_key) DO NOTHING`
    ).bind(session.userId),
    env.DB.prepare(
      `INSERT INTO pending_r2_prefix_purges (user_id, prefixes_json)
       VALUES (?, ?)
       ON CONFLICT(user_id) DO UPDATE SET prefixes_json = excluded.prefixes_json`
    ).bind(session.userId, JSON.stringify(r2Prefixes)),
    env.DB.prepare("DELETE FROM user_chat_sessions WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM chat_session_states WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM session_branches WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM session_commits WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM session_assets WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM dag_run_plans WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM asset_perceptual_cache WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM dag_execution_cache WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM pending_billing_settlements WHERE user_id = ?").bind(
      session.userId
    ),
    env.DB.prepare("DELETE FROM run_billing_settlements WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM dag_handshakes WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM user_oauth_bindings WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM user_passkeys WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM notifications WHERE user_id = ?").bind(session.userId),
    env.DB.prepare("DELETE FROM broadcast_reads WHERE user_id = ?").bind(session.userId)
  ]);

  // 5. Cascade cleanup of user assets & prefixes in R2; pending queues remain until full deletion succeeds
  await sweepPendingR2Cleanups(env, session.userId);

  // Clear cookie
  const response = Response.json({ success: true });
  response.headers.set(
    "Set-Cookie",
    `session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`
  );
  return response;
}

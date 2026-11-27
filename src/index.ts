import { Env } from "./types";
import {
  handleRegister,
  handleLogin,
  handleSendCode,
  handleLogout,
  handleMe,
  handleGitHubRedirect,
  handleGoogleRedirect,
  handleGitHubCallback,
  handleGoogleCallback,
  handleGetBindings,
  handleUnbindOAuth,
  handleForgotPassword,
  handleResetPassword
} from "./api/auth";
import { getSession } from "./auth/middleware";
import { retryPendingBillingSettlements } from "./api/session";

function getCorsHeaders(env: Env) {
  return {
    "Access-Control-Allow-Origin": env.FRONTEND_URL,
    "Access-Control-Allow-Methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, Cookie, X-History-Account",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin"
  };
}

function applySecurityHeaders(res: Response, isAdmin: boolean = false): Response {
  res.headers.set("X-Content-Type-Options", "nosniff");
  res.headers.set("X-Frame-Options", isAdmin ? "DENY" : "SAMEORIGIN");
  res.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
  res.headers.set("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  res.headers.set(
    "Content-Security-Policy",
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://challenges.cloudflare.com https://cdn.jsdelivr.net; " +
      "worker-src 'self' blob: https://cdn.jsdelivr.net; " +
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src 'self' https://fonts.gstatic.com; " +
      "img-src 'self' data: blob: https:; " +
      "connect-src 'self' https://challenges.cloudflare.com https://huggingface.co https://*.huggingface.co https://*.cdn.hf.co https://hf-mirror.com https://cdn.jsdelivr.net https://*.r2.cloudflarestorage.com; " +
      "frame-src https://challenges.cloudflare.com; " +
      `frame-ancestors ${isAdmin ? "'none'" : "'self'"}; ` +
      "object-src 'none'; base-uri 'self';"
  );
  return res;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: getCorsHeaders(env) });
    }

    try {
      if (url.pathname.startsWith("/api/")) {
        let res: Response;
        const cleanPath =
          url.pathname.length > 1 && url.pathname.endsWith("/")
            ? url.pathname.replace(/\/+$/, "")
            : url.pathname;

        if (cleanPath.startsWith("/api/auth/oauth/")) {
          if (request.method !== "DELETE") {
            res = Response.json({ error: "Method not allowed" }, { status: 405 });
          } else {
            const provider = cleanPath.split("/").pop();
            res = await handleUnbindOAuth(request, env, provider || "");
          }
        } else if (cleanPath.startsWith("/api/admin/")) {
          const admin = await import("./api/admin");
          const adminPath = cleanPath;
          if (adminPath === "/api/admin/login")
            res = await admin.handleAdminLogin(request, env, ctx);
          else if (adminPath === "/api/admin/logout")
            res = await admin.handleAdminLogout(request, env);
          // Compute Topology Nodes
          else if (adminPath === "/api/admin/nodes" && request.method === "GET")
            res = await admin.handleAdminListNodes(request, env);
          else if (adminPath === "/api/admin/nodes" && request.method === "POST")
            res = await admin.handleAdminCreateNode(request, env);
          else if (adminPath.startsWith("/api/admin/nodes/") && request.method === "PATCH") {
            const nodeId = adminPath.slice("/api/admin/nodes/".length);
            res = await admin.handleAdminUpdateNode(request, env, nodeId);
          } else if (adminPath.startsWith("/api/admin/nodes/") && request.method === "DELETE") {
            const nodeId = adminPath.slice("/api/admin/nodes/".length);
            res = await admin.handleAdminDeleteNode(request, env, nodeId);
          } else if (adminPath === "/api/admin/nodes/upload-light" && request.method === "POST") {
            res = await admin.handleAdminUploadLightNode(request, env);
          }
          // Role Dictionary & Competence Health Matrix
          else if (adminPath === "/api/admin/roles" && request.method === "GET")
            res = await admin.handleAdminListRoles(request, env);
          else if (adminPath === "/api/admin/roles" && request.method === "POST")
            res = await admin.handleAdminCreateOrUpdateRole(request, env);
          else if (adminPath === "/api/admin/competence-matrix" && request.method === "GET")
            res = await admin.handleAdminCompetenceMatrix(request, env);
          // Linear Workflow Templates
          else if (adminPath === "/api/admin/templates" && request.method === "GET")
            res = await admin.handleAdminListTemplates(request, env);
          else if (adminPath === "/api/admin/templates" && request.method === "POST")
            res = await admin.handleAdminCreateOrUpdateTemplate(request, env);
          else if (
            adminPath.startsWith("/api/admin/templates/") &&
            adminPath.endsWith("/toggle") &&
            request.method === "POST"
          ) {
            const parts = adminPath.split("/");
            const templateId = parts[parts.length - 2];
            res = await admin.handleAdminToggleTemplate(request, env, templateId);
          } else if (adminPath.startsWith("/api/admin/templates/") && request.method === "DELETE") {
            const templateId = adminPath.slice("/api/admin/templates/".length);
            res = await admin.handleAdminDeleteTemplate(request, env, templateId);
          }
          // Gift codes & notifications & legacy compat
          else if (adminPath === "/api/admin/models" && request.method === "GET")
            res = await admin.handleAdminListModels(request, env);
          else if (
            adminPath.startsWith("/api/admin/models/") &&
            adminPath.endsWith("/download") &&
            request.method === "GET"
          )
            res = await admin.handleAdminDownload(request, env);
          else if (adminPath === "/api/admin/gift-codes" && request.method === "POST")
            res = await admin.handleAdminCreateGiftCodes(request, env);
          else if (adminPath === "/api/admin/gift-codes" && request.method === "GET")
            res = await admin.handleAdminListGiftCodes(request, env);
          else if (
            adminPath.startsWith("/api/admin/gift-codes/") &&
            adminPath.endsWith("/revoke") &&
            request.method === "POST"
          )
            res = await admin.handleAdminRevokeGiftCode(request, env);
          else if (adminPath === "/api/admin/gift-codes/revoke-batch" && request.method === "POST")
            res = await admin.handleAdminRevokeBatch(request, env);
          else if (adminPath === "/api/admin/notifications" && request.method === "GET") {
            const notif = await import("./api/notifications");
            res = await notif.handleAdminListNotifications(request, env);
          } else if (adminPath === "/api/admin/notifications" && request.method === "POST") {
            const notif = await import("./api/notifications");
            res = await notif.handleAdminSendNotification(request, env);
          } else if (
            adminPath.startsWith("/api/admin/notifications/") &&
            request.method === "DELETE"
          ) {
            const notif = await import("./api/notifications");
            res = await notif.handleAdminRevokeNotification(request, env);
          } else if (adminPath.startsWith("/api/admin/models/") && request.method === "PATCH")
            res = await admin.handleAdminUpdateModel(request, env);
          else res = new Response("Not Found", { status: 404 });
        } else if (cleanPath === "/api/notifications" && request.method === "GET") {
          const { handleGetNotifications } = await import("./api/notifications");
          res = await handleGetNotifications(request, env);
        } else if (cleanPath === "/api/notifications/read-all" && request.method === "POST") {
          const { handleMarkAllAsRead } = await import("./api/notifications");
          res = await handleMarkAllAsRead(request, env);
        } else if (
          cleanPath.startsWith("/api/notifications/") &&
          cleanPath.endsWith("/read") &&
          request.method === "POST"
        ) {
          const notifId = cleanPath.split("/")[3];
          const { handleMarkAsRead } = await import("./api/notifications");
          res = await handleMarkAsRead(request, env, notifId);
        } else if (cleanPath === "/api/history" && request.method === "GET") {
          const { handleGetHistory } = await import("./api/history");
          res = await handleGetHistory(request, env, ctx);
        } else if (cleanPath === "/api/history" && request.method === "POST") {
          const { handleSaveHistory } = await import("./api/history");
          res = await handleSaveHistory(request, env);
        } else if (cleanPath.startsWith("/api/history/") && request.method === "PATCH") {
          const sessionId = cleanPath.slice("/api/history/".length);
          const { handleUpdateHistoryItem } = await import("./api/history");
          res = await handleUpdateHistoryItem(request, env, sessionId);
        } else if (cleanPath.startsWith("/api/history/") && request.method === "DELETE") {
          const sessionId = cleanPath.slice("/api/history/".length);
          const { handleDeleteHistoryItem } = await import("./api/history");
          res = await handleDeleteHistoryItem(request, env, sessionId, ctx);
        } else if (cleanPath.startsWith("/api/auth/passkey")) {
          const passkey = await import("./api/passkey");
          if (cleanPath === "/api/auth/passkey/register/options" && request.method === "POST") {
            res = await passkey.handlePasskeyRegisterOptions(request, env);
          } else if (
            cleanPath === "/api/auth/passkey/register/verify" &&
            request.method === "POST"
          ) {
            res = await passkey.handlePasskeyRegisterVerify(request, env);
          } else if (cleanPath === "/api/auth/passkey/login/options" && request.method === "POST") {
            res = await passkey.handlePasskeyLoginOptions(request, env);
          } else if (cleanPath === "/api/auth/passkey/login/verify" && request.method === "POST") {
            res = await passkey.handlePasskeyLoginVerify(request, env);
          } else if (
            (cleanPath === "/api/auth/passkey/list" || cleanPath === "/api/auth/passkey") &&
            request.method === "GET"
          ) {
            res = await passkey.handlePasskeyList(request, env);
          } else if (cleanPath.startsWith("/api/auth/passkey/") && request.method === "DELETE") {
            const credentialId = cleanPath.slice("/api/auth/passkey/".length);
            res = await passkey.handlePasskeyDelete(request, env, credentialId);
          } else {
            res = new Response("Not Found", { status: 404 });
          }
        } else if (
          cleanPath.startsWith("/api/session/") &&
          cleanPath.endsWith("/state") &&
          request.method === "GET"
        ) {
          const sessionId = cleanPath.slice("/api/session/".length, -"/state".length);
          const { handleGetSessionState } = await import("./api/session");
          res = await handleGetSessionState(request, env, sessionId);
        } else if (
          cleanPath.startsWith("/api/session/") &&
          cleanPath.endsWith("/commit") &&
          request.method === "POST"
        ) {
          const sessionId = cleanPath.slice("/api/session/".length, -"/commit".length);
          const { handleCommitSessionTurn } = await import("./api/session");
          res = await handleCommitSessionTurn(request, env, sessionId);
        } else if (
          cleanPath.startsWith("/api/session/") &&
          cleanPath.endsWith("/commit-retry") &&
          request.method === "POST"
        ) {
          const sessionId = cleanPath.slice("/api/session/".length, -"/commit-retry".length);
          const { handleCommitRetrySessionTurn } = await import("./api/session");
          res = await handleCommitRetrySessionTurn(request, env, sessionId);
        } else if (
          cleanPath.startsWith("/api/session/") &&
          cleanPath.endsWith("/abandon") &&
          request.method === "POST"
        ) {
          const sessionId = cleanPath.slice("/api/session/".length, -"/abandon".length);
          const { handleAbandonSessionRun } = await import("./api/session");
          res = await handleAbandonSessionRun(request, env, sessionId);
        } else if (
          cleanPath === "/api/asset" ||
          cleanPath === "/api/assets" ||
          cleanPath.startsWith("/api/assets/") ||
          cleanPath.startsWith("/api/asset/")
        ) {
          const { handleGetAsset } = await import("./api/presign");
          res = await handleGetAsset(request, env);
        } else {
          switch (cleanPath) {
            case "/api/auth/register":
              res = await handleRegister(request, env);
              break;
            case "/api/auth/login":
              res = await handleLogin(request, env);
              break;
            case "/api/auth/logout":
              res = await handleLogout(request, env);
              break;
            case "/api/auth/send-code":
              res = await handleSendCode(request, env, ctx);
              break;
            case "/api/auth/forgot-password":
              res = await handleForgotPassword(request, env, ctx);
              break;
            case "/api/auth/reset-password":
              res = await handleResetPassword(request, env, ctx);
              break;
            case "/api/auth/me":
              res = await handleMe(request, env);
              break;
            case "/api/user/bindings":
              res = await handleGetBindings(request, env);
              break;
            case "/api/auth/config": {
              if (request.method !== "GET" && request.method !== "HEAD") {
                res = new Response("Method not allowed", { status: 405 });
              } else {
                res = Response.json({ turnstile_site_key: env.TURNSTILE_SITE_KEY });
              }
              break;
            }
            case "/api/auth/github":
              res = await handleGitHubRedirect(request, env);
              break;
            case "/api/auth/google":
              res = await handleGoogleRedirect(request, env);
              break;
            case "/api/auth/callback/github":
              res = await handleGitHubCallback(request, env);
              break;
            case "/api/auth/callback/google":
              res = await handleGoogleCallback(request, env);
              break;
            case "/api/user/profile": {
              const { handleUpdateProfile } = await import("./api/user");
              res = await handleUpdateProfile(request, env);
              break;
            }
            case "/api/user/delete": {
              const { handleDeleteAccount } = await import("./api/user");
              res = await handleDeleteAccount(request, env);
              break;
            }
            case "/api/user/avatar": {
              const { handleUpdateAvatar } = await import("./api/user");
              res = await handleUpdateAvatar(request, env, ctx);
              break;
            }
            case "/api/user/password": {
              const { handleUpdatePassword } = await import("./api/user");
              res = await handleUpdatePassword(request, env);
              break;
            }
            case "/api/user/ledger": {
              const { handleGetLedger } = await import("./api/billing");
              res = await handleGetLedger(request, env);
              break;
            }
            case "/api/billing/redeem": {
              const { handleRedeem } = await import("./api/billing");
              res = await handleRedeem(request, env, ctx);
              break;
            }
            case "/api/user/credits": {
              if (request.method !== "GET" && request.method !== "HEAD") {
                res = new Response("Method not allowed", { status: 405 });
                break;
              }
              const user = await getSession(request, env);
              if (!user) {
                res = Response.json({ error: "Unauthorized" }, { status: 401 });
                break;
              }
              const dbUser = await env.DB.prepare("SELECT credits FROM users WHERE user_id = ?")
                .bind(user.userId)
                .first<{ credits: number }>();
              res = Response.json({ credits: dbUser?.credits ?? 0 });
              break;
            }
            case "/api/models": {
              const { handleGetPublicModels } = await import("./api/models");
              res = await handleGetPublicModels(request, env);
              break;
            }
            case "/api/chat": {
              const { handleChat } = await import("./api/chat");
              res = await handleChat(request, env, ctx);
              break;
            }
            case "/api/chat/continue": {
              const { handleChatContinue } = await import("./api/chat");
              res = await handleChatContinue(request, env, ctx);
              break;
            }
            case "/api/upload/presign": {
              const { handleChatPresign } = await import("./api/presign");
              res = await handleChatPresign(request, env, ctx);
              break;
            }
            case "/api/upload/file": {
              const { handleChatUpload } = await import("./api/presign");
              res = await handleChatUpload(request, env, ctx);
              break;
            }
            case "/api/health": {
              if (request.method !== "GET" && request.method !== "HEAD") {
                res = new Response("Method not allowed", { status: 405 });
                break;
              }
              const isProd = env.ENVIRONMENT === "production";
              const saltConfigured = !!env.PERSISTENT_DATA_SALT;
              const isReady = !isProd || saltConfigured;
              res = new Response(
                JSON.stringify({
                  status: isReady ? "healthy" : "degraded",
                  environment: env.ENVIRONMENT || "development",
                  salt_ready: saltConfigured
                }),
                {
                  status: isReady ? 200 : 503,
                  headers: { "Content-Type": "application/json" }
                }
              );
              break;
            }
            default:
              res = new Response("Not Found", { status: 404 });
              break;
          }
        }

        // Add CORS headers to API responses
        const existingOrigin =
          res.headers.get("access-control-allow-origin") ||
          res.headers.get("Access-Control-Allow-Origin");
        const isWildcardOrigin = existingOrigin === "*";
        const newRes = new Response(res.body, res);
        Object.entries(getCorsHeaders(env)).forEach(([k, v]) => {
          const lowerKey = k.toLowerCase();
          if (lowerKey === "access-control-allow-origin" && existingOrigin) {
            newRes.headers.set(k, existingOrigin);
          } else if (lowerKey === "access-control-allow-credentials" && isWildcardOrigin) {
            // According to W3C Fetch spec, Allow-Credentials cannot be true when Allow-Origin is wildcard '*'
            newRes.headers.delete(k);
          } else {
            newRes.headers.set(k, v);
          }
        });
        newRes.headers.set("X-Content-Type-Options", "nosniff");
        newRes.headers.set("X-Frame-Options", "DENY");
        newRes.headers.set("Referrer-Policy", "strict-origin-when-cross-origin");
        return newRes;
      }

      if (url.pathname === "/") {
        // Guests are allowed on the index page, no redirect
      }

      if (
        url.pathname === "/terms" ||
        url.pathname === "/terms/" ||
        url.pathname === "/terms.html"
      ) {
        const assetRes = await env.ASSETS.fetch(new Request(new URL("/terms.html", request.url)));
        const res = new Response(assetRes.body, assetRes);
        res.headers.set("X-Robots-Tag", "noindex, follow");
        return applySecurityHeaders(res);
      }

      if (
        url.pathname === "/privacy" ||
        url.pathname === "/privacy/" ||
        url.pathname === "/privacy.html"
      ) {
        const assetRes = await env.ASSETS.fetch(new Request(new URL("/privacy.html", request.url)));
        const res = new Response(assetRes.body, assetRes);
        res.headers.set("X-Robots-Tag", "noindex, follow");
        return applySecurityHeaders(res);
      }

      if (
        url.pathname === "/admin" ||
        url.pathname === "/admin/" ||
        url.pathname === "/admin.html"
      ) {
        const assetRes = await env.ASSETS.fetch(new Request(new URL("/admin.html", request.url)));
        const res = new Response(assetRes.body, assetRes);
        res.headers.set("X-Robots-Tag", "noindex, nofollow");
        return applySecurityHeaders(res, true);
      }

      // Serve R2 Storage (strictly restricted to public avatars)
      if (url.pathname.startsWith("/storage/")) {
        const key = url.pathname.slice("/storage/".length);
        if (!key.startsWith("avatars/")) {
          return new Response("Forbidden", {
            status: 403,
            headers: { "X-Content-Type-Options": "nosniff" }
          });
        }
        const object = await env.R2.get(key);
        if (!object) {
          return new Response("Not Found", {
            status: 404,
            headers: { "X-Content-Type-Options": "nosniff" }
          });
        }

        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set("etag", object.httpEtag);
        // Cache control for immutable assets
        headers.set("cache-control", "public, max-age=31536000, immutable");
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Content-Security-Policy", "default-src 'none'; sandbox");
        headers.set("Cross-Origin-Resource-Policy", "cross-origin");

        return new Response(object.body, { headers });
      }

      // Pass other requests to ASSETS (static site)
      const assetResponse = await env.ASSETS.fetch(request);
      if (assetResponse.status === 404) {
        const notFoundUrl = new URL("/404.html", request.url);
        const fallbackResponse = await env.ASSETS.fetch(new Request(notFoundUrl));
        const notFoundRes = new Response(fallbackResponse.body, {
          status: 404,
          headers: {
            "Content-Type": "text/html;charset=UTF-8"
          }
        });
        return applySecurityHeaders(notFoundRes);
      }
      const secureAssetRes = new Response(assetResponse.body, assetResponse);
      applySecurityHeaders(secureAssetRes);
      if (url.pathname.match(/^\/(favicon|apple-touch-icon|android-chrome|site\.webmanifest)/)) {
        secureAssetRes.headers.set(
          "Cache-Control",
          "public, max-age=604800, stale-while-revalidate=86400"
        );
        secureAssetRes.headers.set("Access-Control-Allow-Origin", "*");
      }
      return secureAssetRes;
    } catch (err: any) {
      console.error("[Unhandled Gateway Exception]:", err);
      const isDev = env.ENVIRONMENT === "development";
      const errorMessage = isDev
        ? err?.message || "Internal Server Error"
        : "Internal Server Error";
      return new Response(JSON.stringify({ error: errorMessage }), {
        status: 500,
        headers: { "Content-Type": "application/json", ...getCorsHeaders(env) }
      });
    }
  },

  /**
   * Scheduled Cron Trigger (daily 03:00 UTC):
   * Automatically purges orphaned R2 tmp/ objects older than 24 hours and stale operational counters (NM-AUD-02).
   */
  async scheduled(_event: ScheduledEvent, env: Env, _ctx: ExecutionContext): Promise<void> {
    const cutoffMs = Date.now() - 24 * 60 * 60 * 1000;

    if (
      env.DB &&
      env.R2 &&
      typeof env.R2.list === "function" &&
      typeof env.R2.delete === "function"
    ) {
      try {
        let cursor: string | undefined = undefined;
        let pages = 0;
        do {
          const listed = await env.R2.list({ prefix: "tmp/", cursor, limit: 1000 });
          const expiredKeys = (listed.objects || [])
            .filter((obj) => obj.uploaded && obj.uploaded.getTime() < cutoffMs)
            .map((obj) => obj.key);
          // Each key is bound twice. Keep the query within D1's binding limit.
          const batchSize = 40;
          for (let offset = 0; offset < expiredKeys.length; offset += batchSize) {
            const keys = expiredKeys.slice(offset, offset + batchSize);
            const placeholders = keys.map(() => "?").join(", ");
            const { results } = await env.DB.prepare(
              `SELECT a.r2_key, a.text_r2_key FROM session_assets a
               WHERE (a.r2_key IN (${placeholders}) OR a.text_r2_key IN (${placeholders}))
                 AND (a.status = 'COMMITTED' OR (a.status IN ('UPLOADED', 'STAGING') AND EXISTS (
                   SELECT 1 FROM chat_session_states s
                   WHERE s.user_id = a.user_id AND s.session_id = a.session_id
                     AND s.deleted_at IS NULL AND s.occupancy_phase IS NOT NULL
                     AND (s.lock_expires_at IS NULL OR datetime(s.lock_expires_at) > datetime('now'))
                 )))`
            )
              .bind(...keys, ...keys)
              .all<{ r2_key: string | null; text_r2_key: string | null }>();
            const protectedKeys = new Set(results.flatMap((row) => [row.r2_key, row.text_r2_key]));
            const orphanedKeys = keys.filter((key) => !protectedKeys.has(key));
            if (orphanedKeys.length > 0) await env.R2.delete(orphanedKeys);
          }
          cursor = listed.truncated ? listed.cursor : undefined;
          pages++;
        } while (cursor && pages < 20);
      } catch (r2Err) {
        console.warn("[Cron] R2 tmp/ cleanup warning:", r2Err);
      }
    }

    if (env.DB) {
      const nowEpoch = Math.floor(Date.now() / 1000);
      await Promise.all([
        retryPendingBillingSettlements(env).catch((err) =>
          console.error("[Cron] Billing retry failed:", err)
        ),
        env.DB.prepare(
          "DELETE FROM verification_codes WHERE expires_at < datetime('now', '-1 day')"
        )
          .run()
          .catch(() => {}),
        env.DB.prepare(
          "DELETE FROM dag_handshakes WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 day')"
        )
          .run()
          .catch(() => {}),
        env.DB.prepare(
          "DELETE FROM system_counters WHERE key LIKE 'presign_daily_%' AND key < 'presign_daily_' || date('now', '-2 days')"
        )
          .run()
          .catch(() => {}),
        env.DB.prepare("DELETE FROM system_counters WHERE key LIKE 'admin_revoked_%' AND value < ?")
          .bind(nowEpoch)
          .run()
          .catch(() => {})
      ]);
    }
  }
};

import { Env } from "../types";
import { getSession } from "../auth/middleware";
import { sweepPendingR2Cleanups, tombstoneAndPurgeSession } from "./session";

function rejectMismatchedHistoryAccount(request: Request, userId: string): Response | null {
  if (request.headers.get("X-History-Account") === userId) return null;
  return Response.json(
    { error: "history_account_mismatch", message: "账号已变更，请刷新页面。" },
    { status: 409 }
  );
}

export async function handleGetHistory(
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

  const accountMismatch = rejectMismatchedHistoryAccount(request, session.userId);
  if (accountMismatch) return accountMismatch;

  try {
    const sweepTask = sweepPendingR2Cleanups(env, session.userId);
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(sweepTask);
    }
    const res = await env.DB.prepare(
      `SELECT session_id, user_id, trace_id, title, cost, duration, nodes_count, cached, pinned, rounds_json, created_at, updated_at
       FROM user_chat_sessions
       WHERE user_id = ?
       ORDER BY pinned DESC, updated_at DESC
       LIMIT 50`
    )
      .bind(session.userId)
      .all<any>();

    const sessions = (res.results || []).map((r) => {
      let rounds = [];
      try {
        rounds = JSON.parse(r.rounds_json || "[]");
      } catch (e) {}

      return {
        id: r.trace_id || r.session_id,
        sessionId: r.session_id,
        title: r.title,
        cost: r.cost,
        duration: r.duration,
        nodesCount: r.nodes_count,
        cached: !!r.cached,
        pinned: !!r.pinned,
        timestamp: new Date(r.updated_at).getTime() || Date.now(),
        rounds
      };
    });

    return new Response(JSON.stringify({ sessions }), {
      headers: { "Content-Type": "application/json", "Cache-Control": "private, no-store" }
    });
  } catch (err: any) {
    console.error("Failed to fetch history:", err);
    const isDev = env.ENVIRONMENT === "development";
    const errorMessage = isDev
      ? err?.message || "Failed to fetch history"
      : "Failed to fetch history";
    return new Response(JSON.stringify({ error: errorMessage }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

export async function handleSaveHistory(request: Request, env: Env): Promise<Response> {
  const session = await getSession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const accountMismatch = rejectMismatchedHistoryAccount(request, session.userId);
  if (accountMismatch) return accountMismatch;

  try {
    let rawBody: any;
    try {
      rawBody = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
      return new Response(JSON.stringify({ error: "Invalid JSON object" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    const body = rawBody;
    const sessionId = body.sessionId || body.session_id;
    if (
      !sessionId ||
      typeof sessionId !== "string" ||
      !sessionId.trim() ||
      sessionId.trim().length > 64
    ) {
      return new Response(
        JSON.stringify({ error: "Invalid sessionId (must be non-empty string <= 64 chars)" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
    const cleanSessionId = sessionId.trim();

    const traceId = body.id || body.trace_id || "trace-" + Date.now();
    const rawTitle = typeof body.title === "string" ? body.title.trim() : "";
    const title = (rawTitle || "多模态任务编排").slice(0, 100);
    const cost = String(body.cost ?? "0").slice(0, 32);
    const duration = String(body.duration ?? "0s").slice(0, 32);
    const nodesCount = Number(body.nodesCount ?? body.nodes_count ?? 1);
    const cached = body.cached ? 1 : 0;
    const pinned = body.pinned ? 1 : 0;

    const fullRounds = Array.isArray(body.rounds) ? body.rounds : [];
    const rawRounds = fullRounds.slice(-100);
    const truncatedOlderCount = Math.max(0, fullRounds.length - rawRounds.length);
    const roundsJson = JSON.stringify(rawRounds);
    if (roundsJson.length > 512 * 1024) {
      return new Response(JSON.stringify({ error: "History payload too large (max 512KB)" }), {
        status: 413,
        headers: { "Content-Type": "application/json" }
      });
    }

    const stateRow = await env.DB.prepare(
      "SELECT deleted_at FROM chat_session_states WHERE user_id = ? AND session_id = ?"
    )
      .bind(session.userId, cleanSessionId)
      .first<{ deleted_at: string | null }>()
      .catch(() => null);
    if (stateRow?.deleted_at) {
      return new Response(JSON.stringify({ error: "session_deleted" }), {
        status: 410,
        headers: { "Content-Type": "application/json" }
      });
    }

    await env.DB.prepare(
      `INSERT INTO user_chat_sessions (session_id, user_id, trace_id, title, cost, duration, nodes_count, cached, pinned, rounds_json, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
       ON CONFLICT(user_id, session_id) DO UPDATE SET
         trace_id = excluded.trace_id,
         title = excluded.title,
         cost = excluded.cost,
         duration = excluded.duration,
         nodes_count = excluded.nodes_count,
         cached = excluded.cached,
         pinned = excluded.pinned,
         rounds_json = excluded.rounds_json,
         updated_at = datetime('now')`
    )
      .bind(
        cleanSessionId,
        session.userId,
        traceId,
        title,
        cost,
        duration,
        nodesCount,
        cached,
        pinned,
        roundsJson
      )
      .run();

    return new Response(
      JSON.stringify({ success: true, sessionId, truncated_older_count: truncatedOlderCount }),
      {
        headers: { "Content-Type": "application/json" }
      }
    );
  } catch (err: any) {
    console.error("Failed to save history:", err);
    const isDev = env.ENVIRONMENT === "development";
    const errorMessage = isDev
      ? err?.message || "Failed to save history"
      : "Failed to save history";
    return new Response(JSON.stringify({ error: errorMessage }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

export async function handleUpdateHistoryItem(
  request: Request,
  env: Env,
  sessionId: string
): Promise<Response> {
  const session = await getSession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const accountMismatch = rejectMismatchedHistoryAccount(request, session.userId);
  if (accountMismatch) return accountMismatch;

  try {
    let rawBody: any;
    try {
      rawBody = await request.json();
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (!rawBody || typeof rawBody !== "object" || Array.isArray(rawBody)) {
      return new Response(JSON.stringify({ error: "Invalid JSON object" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }
    const body = rawBody;
    const updates: string[] = [];
    const values: any[] = [];

    if (body.title !== undefined) {
      const sanitizedTitle = String(body.title).trim().slice(0, 100);
      updates.push("title = ?");
      values.push(sanitizedTitle);
    }
    if (body.pinned !== undefined) {
      updates.push("pinned = ?");
      values.push(body.pinned ? 1 : 0);
    }

    if (updates.length === 0) {
      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" }
      });
    }

    updates.push("updated_at = datetime('now')");
    values.push(sessionId);
    values.push(session.userId);

    await env.DB.prepare(
      `UPDATE user_chat_sessions SET ${updates.join(", ")} WHERE session_id = ? AND user_id = ?`
    )
      .bind(...values)
      .run();

    return new Response(JSON.stringify({ success: true }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (err: any) {
    console.error("Failed to update history item:", err);
    const isDev = env.ENVIRONMENT === "development";
    const errorMessage = isDev
      ? err?.message || "Failed to update history"
      : "Failed to update history";
    return new Response(JSON.stringify({ error: errorMessage }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

export async function handleDeleteHistoryItem(
  request: Request,
  env: Env,
  sessionId: string,
  ctx?: ExecutionContext
): Promise<Response> {
  const session = await getSession(request, env);
  if (!session) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" }
    });
  }

  const accountMismatch = rejectMismatchedHistoryAccount(request, session.userId);
  if (accountMismatch) return accountMismatch;

  try {
    const deleteRes = await tombstoneAndPurgeSession(env, session.userId, sessionId, ctx);
    if (deleteRes.busy) {
      return new Response(
        JSON.stringify({
          error: "session_busy",
          occupancy_phase: deleteRes.occupancyPhase || "EXECUTING",
          active_run_id: deleteRes.activeRunId || null,
          message:
            deleteRes.occupancyPhase === "AWAITING_COMMIT"
              ? "当前会话有待保存结果，请先重试保存或放弃后再删除。"
              : "当前会话正在运行中，请完成后再删除。"
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    return new Response(JSON.stringify({ success: true }), {
      headers: { "Content-Type": "application/json" }
    });
  } catch (err: any) {
    console.error("Failed to delete history item:", err);
    const isDev = env.ENVIRONMENT === "development";
    const errorMessage = isDev
      ? err?.message || "Failed to delete history"
      : "Failed to delete history";
    return new Response(JSON.stringify({ error: errorMessage }), {
      status: 500,
      headers: { "Content-Type": "application/json" }
    });
  }
}

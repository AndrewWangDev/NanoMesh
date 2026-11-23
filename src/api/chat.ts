// src/api/chat.ts
import { Env } from "../types";
import { getSession } from "../auth/middleware";
import { verifyJWT } from "../auth/jwt";
import { runOrchestrationPipeline, OrchestrationOptions } from "../orchestration/orchestrator";
import { executeDAGStream, sanitizeClientStepOutput } from "../orchestration/dispatcher";
import { UnifiedProtocolEnvelope } from "../orchestration/types";

/**
 * Lazy sweep for expired orphan handshake records.
 * Uses ctx.waitUntil() to execute asynchronously in background without blocking edge response.
 */
export function triggerLazyHandshakeSweep(env: Env, ctx?: ExecutionContext) {
  if (ctx && typeof ctx.waitUntil === 'function') {
    const sweepPromise = env.DB.prepare(
      "DELETE FROM dag_handshakes WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hour')"
    ).run().catch((e) => console.warn("[HandshakeSweep] lazy cleanup error:", e));
    ctx.waitUntil(sweepPromise);
  }
}

// --- Rate Limiting: In-Memory Sliding-Window Token Bucket ---
// Non-aggressive: Allows a burst of up to 3 requests, refills 1 token every 5 seconds (~12 req/min sustained).
interface RateLimitBucket {
  tokens: number;
  lastRefill: number; // timestamp ms
}

// NM-BUG-04 Architecture Note:
// rateLimitMap is a per-isolate L1 Anti-Hammering Buffer (0ms in-memory latency) designed to absorb
// burst double-click duplicate requests. Global abuse and quota exhaustion are strictly prevented by
// D1 atomic credit ledger pre-deduction. Comprehensive edge-wide IP rate limiting is enforced via Cloudflare WAF.
const RATE_LIMIT_CAPACITY = 3;
const REFILL_INTERVAL_MS = 5000;
const rateLimitMap = new Map<string, RateLimitBucket>();

function checkRateLimit(userId: string): { allowed: boolean; retryAfter: number } {
  const now = Date.now();
  let bucket = rateLimitMap.get(userId);

  if (!bucket) {
    bucket = { tokens: RATE_LIMIT_CAPACITY, lastRefill: now };
    rateLimitMap.set(userId, bucket);
  }

  // Refill tokens based on elapsed time
  const elapsed = now - bucket.lastRefill;
  if (elapsed >= REFILL_INTERVAL_MS) {
    const tokensToAdd = Math.floor(elapsed / REFILL_INTERVAL_MS);
    bucket.tokens = Math.min(RATE_LIMIT_CAPACITY, bucket.tokens + tokensToAdd);
    bucket.lastRefill = now - (elapsed % REFILL_INTERVAL_MS);
  }

  // Periodic pruning of stale records if map grows large (> 2000 entries)
  if (rateLimitMap.size > 2000) {
    const pruneThreshold = now - 60000;
    for (const [key, b] of rateLimitMap.entries()) {
      if (b.lastRefill < pruneThreshold) {
        rateLimitMap.delete(key);
      }
    }
  }

  if (bucket.tokens >= 1) {
    bucket.tokens -= 1;
    return { allowed: true, retryAfter: 0 };
  } else {
    const msUntilRefill = REFILL_INTERVAL_MS - (now - bucket.lastRefill);
    const retryAfter = Math.max(1, Math.ceil(msUntilRefill / 1000));
    return { allowed: false, retryAfter };
  }
}

export async function handleChat(request: Request, env: Env, ctx?: ExecutionContext): Promise<Response> {
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

  // 1. Sliding-Window Rate Limit Check (Non-aggressive Demo Protection)
  const rateLimit = checkRateLimit(session.userId);
  if (!rateLimit.allowed) {
    return new Response(JSON.stringify({ 
      error: "rate_limited", 
      retry_after: rateLimit.retryAfter,
      message: `请求过于频繁，请稍候 ${rateLimit.retryAfter} 秒后再试（Demo 环境保护）` 
    }), { 
      status: 429, 
      headers: { 
        "Content-Type": "application/json; charset=utf-8",
        "Retry-After": String(rateLimit.retryAfter)
      } 
    });
  }

  // 2. Parse & Validate Payload FIRST (fail-fast on malformed input without reserving/deducting quota)
  let body: {
    envelope: UnifiedProtocolEnvelope;
    reRouteMode?: 'normal' | 'switch_template' | 'switch_model';
    chosenTemplateId?: string;
    chosenRoleModels?: Record<string, string>;
    customRolePrompts?: Record<string, string>;
    customNodePrompt?: string;
    hasPreviousRound?: boolean;
    previousRoundSummary?: string;
    hadMediaAssets?: boolean;
    hasNewUploads?: boolean;
    newUploadModalities?: string[];
    sessionAssetLedger?: Array<{
      asset_id: string;
      filename?: string;
      modality: string;
      introduced_round?: number;
      branch_id?: string;
      r2_key?: string;
      origin?: string;
    }>;
    activeBranchId?: string;
    activeBranchSummary?: string;
    branchCatalog?: Array<{
      branch_id: string;
      topic?: string;
      is_media?: boolean;
      last_summary?: string;
      is_active?: boolean;
    }>;
    disableBrowserInference?: boolean;
    capabilities?: {
      webgpu_handover_v3?: boolean;
    };
  };

  try {
    body = await request.json();
    if (!body || typeof body !== 'object') throw new Error("Not an object");
  } catch (err) {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), { 
      status: 400, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  const envelope = body.envelope;
  if (!envelope || !envelope.instruction_payload || typeof envelope.instruction_payload !== 'string' || !envelope.instruction_payload.trim()) {
    return new Response(JSON.stringify({ error: "Missing or invalid instruction_payload: must be a non-empty string" }), { 
      status: 400, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  // NM-AUDIT-01: Hard security limit on chat instruction payload to prevent Worker 128MB OOM / DoS
  const MAX_INSTRUCTION_PAYLOAD_CHARS = 512 * 1024; // 512KB
  if (envelope.instruction_payload.length > MAX_INSTRUCTION_PAYLOAD_CHARS) {
    return new Response(JSON.stringify({ 
      error: "payload_too_large", 
      message: "instruction_payload exceeds maximum allowed limit (512KB)" 
    }), { 
      status: 413, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  const hasNewUploads = body.hasNewUploads ?? envelope.metadata?.has_new_upload ?? (envelope.assets_manifest || []).some(a => a.is_new);
  const newUploadModalities = body.newUploadModalities ?? envelope.metadata?.new_upload_modalities ?? (envelope.assets_manifest || []).filter(a => a.is_new).map(a => a.modality);

  const orchestrationOptions: OrchestrationOptions = {
    reRouteMode: body.reRouteMode,
    chosenTemplateId: body.chosenTemplateId,
    chosenRoleModels: body.chosenRoleModels,
    customRolePrompts: body.customRolePrompts,
    customNodePrompt: body.customNodePrompt,
    hasPreviousRound: body.hasPreviousRound,
    previousRoundSummary: body.previousRoundSummary,
    hadMediaAssets: body.hadMediaAssets,
    hasNewUploads,
    newUploadModalities,
    sessionAssetLedger: body.sessionAssetLedger,
    activeBranchId: body.activeBranchId,
    activeBranchSummary: body.activeBranchSummary,
    branchCatalog: body.branchCatalog,
    disableBrowserInference: !!body.disableBrowserInference || (body.capabilities?.webgpu_handover_v3 === false)
  };

  // 3. Run Gateway 3-Step Arbitration & Instantiate DAG FIRST
  let dag;
  try {
    dag = await runOrchestrationPipeline(env, envelope, orchestrationOptions);
  } catch (err: any) {
    console.error("Orchestration error:", err);
    return new Response(JSON.stringify({ 
      error: "orchestration_failed", 
      message: err.message || "Failed to orchestrate task" 
    }), { 
      status: 500, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  // 4. Dynamic Billing Alignment: Worst-Case Cloud Pre-Deduction & WebGPU Zero Pre-Deduction (BUG-01 Fix)
  let hasReservedCredit = false;
  if (!dag.is_security_violation && !dag.is_unreachable) {
    const hasAnyCloudNode = dag.nodes.some(n => n.selected_model?.inference_target !== 'browser');
    const firstNodeHasCloudStandby = (dag.nodes[0]?.standby_models || []).some(m => m.inference_target !== 'browser');
    const clientSupportsWebGPU = body.capabilities?.webgpu_handover_v3 ?? !body.disableBrowserInference;
    
    // We must reserve 1 credit if:
    // 1) The first node is cloud/heavy, OR
    // 2) Any downstream intermediate or tail node is cloud/heavy, OR
    // 3) First node is browser but client cannot execute WebGPU handover (will fallback to cloud standby)
    const requiresPreDeduction = hasAnyCloudNode || (!clientSupportsWebGPU && firstNodeHasCloudStandby);

    if (requiresPreDeduction) {
      // Cloud / Multi-Node / Fallback execution: atomic reservation of 1 credit
      const reserveResult = await env.DB.prepare(
        "UPDATE users SET credits = credits - 1 WHERE user_id = ? AND credits >= 1"
      ).bind(session.userId).run();

      if (!reserveResult.meta.changes || reserveResult.meta.changes === 0) {
        return new Response(JSON.stringify({ 
          error: "insufficient_quota", 
          message: "可用积分不足或并发请求额度受限，请先充值额度。" 
        }), { 
          status: 403, 
          headers: { "Content-Type": "application/json" } 
        });
      }
      hasReservedCredit = true;
    }
  }

  try {
    // 5. Return SSE Stream (with pre-deduction tracking for atomic billing)
    const stream = await executeDAGStream(env, dag, envelope, { 
      userId: session.userId, 
      hasPreDeducted: hasReservedCredit,
      ctx,
      clientCapabilities: {
        webgpu_handover_v3: body.capabilities?.webgpu_handover_v3 ?? !body.disableBrowserInference
      }
    });

    triggerLazyHandshakeSweep(env, ctx);

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
      }
    });
  } catch (err: any) {
    console.error("Execution error:", err);
    // Refund reserved credit if execution setup failed
    if (hasReservedCredit) {
      try {
        await env.DB.prepare(
          "UPDATE users SET credits = credits + 1 WHERE user_id = ?"
        ).bind(session.userId).run();
      } catch (refundErr) {
        console.error("[Chat] Failed to refund reserved credit on execution error:", refundErr);
      }
    }
    return new Response(JSON.stringify({ 
      error: "execution_failed", 
      message: err.message || "Failed to execute task stream" 
    }), { 
      status: 500, 
      headers: { "Content-Type": "application/json" } 
    });
  }
}

/**
 * Handles resumption of multi-step DAG after client-side WebGPU execution finishes.
 * Features D1 Atomic CAS Anti-Replay Defense, Phase 2 Quota Settlement, and Standby Failover.
 */
export async function handleChatContinue(
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

  let body: {
    continuation_token: string;
    status: 'success' | 'candidate_failed';
    client_step_output?: string;
    failed_model_id?: string;
    error_reason?: string;
    upstream_context?: string;
    envelope: UnifiedProtocolEnvelope;
    orchestration_options?: OrchestrationOptions;
  };

  try {
    body = await request.json();
    if (!body || typeof body !== 'object') throw new Error("Not an object");
  } catch (err) {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), { 
      status: 400, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  if (!body.continuation_token || !body.status || !body.envelope) {
    return new Response(JSON.stringify({ error: "Missing required continuation parameters" }), { 
      status: 400, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  // NM-BUG-03: Explicit security boundary on continuation step outputs to prevent Worker 128MB OOM
  const MAX_CONTINUATION_PAYLOAD_CHARS = 512 * 1024;
  if (typeof body.client_step_output === 'string' && body.client_step_output.length > MAX_CONTINUATION_PAYLOAD_CHARS) {
    return new Response(JSON.stringify({ 
      error: "payload_too_large", 
      message: "Client step output exceeds maximum allowed limit (512KB)" 
    }), { 
      status: 413, 
      headers: { "Content-Type": "application/json" } 
    });
  }
  if (typeof body.upstream_context === 'string' && body.upstream_context.length > MAX_CONTINUATION_PAYLOAD_CHARS) {
    return new Response(JSON.stringify({ 
      error: "payload_too_large", 
      message: "Upstream context exceeds maximum allowed limit (512KB)" 
    }), { 
      status: 413, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  // 1. Verify continuation JWT token
  const claims = await verifyJWT(body.continuation_token, env.JWT_SECRET);
  if (!claims || !claims.jti || !claims.sub || claims.nxt === undefined) {
    return new Response(JSON.stringify({ 
      error: "invalid_or_expired_token", 
      message: "续接令牌无效或已过期，请重新发起会话。" 
    }), { 
      status: 401, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  if (claims.sub !== session.userId) {
    return new Response(JSON.stringify({ 
      error: "forbidden", 
      message: "跨用户非法续接访问。" 
    }), { 
      status: 403, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  // 2. Validate Handshake Record Pre-condition (Read-only check before DAG compilation & billing - BUG-05 Fix)
  const handshakeRecord = await env.DB.prepare(`
    SELECT status, expires_at FROM dag_handshakes
    WHERE handshake_id = ? AND user_id = ?
  `).bind(claims.jti, session.userId).first<any>();

  if (!handshakeRecord || handshakeRecord.status !== 'ISSUED' || new Date(handshakeRecord.expires_at) <= new Date()) {
    return new Response(JSON.stringify({ 
      error: "handshake_already_consumed_or_expired", 
      message: "该任务接力握手已被消费或已超时，严禁重放执行。" 
    }), { 
      status: 409, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  // Trigger lazy sweep for expired orphan records in background
  triggerLazyHandshakeSweep(env, ctx);

  // 3. Re-instantiate DAG
  const orchestrationOpts: OrchestrationOptions = {
    ...(body.orchestration_options || {}),
    chosenTemplateId: claims.tid,
    chosenRoleModels: claims.mids || body.orchestration_options?.chosenRoleModels,
    reRouteMode: 'switch_model'
  };

  let dag;
  try {
    dag = await runOrchestrationPipeline(env, body.envelope, orchestrationOpts);
  } catch (err: any) {
    console.error("[ChatContinue] Orchestration error:", err);
    return new Response(JSON.stringify({ 
      error: "orchestration_failed", 
      message: err.message || "Failed to re-instantiate continuation pipeline" 
    }), { 
      status: 500, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  let startStepIndex = Number(claims.nxt);
  let injectedUpstreamText = '';

  if (body.status === 'candidate_failed') {
    // Standby Failover: The node that failed was step (claims.nxt - 1)
    const failedStepIdx = Math.max(0, startStepIndex - 1);
    const targetNode = dag.nodes[failedStepIdx];
    if (!targetNode) {
      return new Response(JSON.stringify({ error: "invalid_step_index", message: "续接步骤索引越界" }), { status: 400 });
    }

    const failedModelId = body.failed_model_id || targetNode.selected_model.model_id;
    const availableStandbys = (targetNode.standby_models || []).filter(
      m => m.model_id !== failedModelId && m.inference_target !== 'browser'
    );

    if (availableStandbys.length === 0) {
      return new Response(JSON.stringify({ 
        error: "no_standby_models_available", 
        message: `岗位【${targetNode.role.name_zh}】首选端侧模型异常，且无可用云端备选模型。任务无法容灾。` 
      }), { 
        status: 500, 
        headers: { "Content-Type": "application/json" } 
      });
    }

    // Transparently advance to Top Standby cloud model
    targetNode.selected_model = availableStandbys[0];
    targetNode.standby_models = availableStandbys.slice(1);
    targetNode.downgraded = true;
    startStepIndex = failedStepIdx;
    injectedUpstreamText = sanitizeClientStepOutput(body.upstream_context || '');
  } else {
    // Success path: Sanitize client step output before feeding downstream
    injectedUpstreamText = sanitizeClientStepOutput(body.client_step_output || '');
  }

  if (startStepIndex >= dag.nodes.length) {
    return new Response(JSON.stringify({ error: "step_already_completed", message: "流水线所有步骤已完成" }), { status: 400 });
  }

  // 4. Two-Phase Commit for Phase 2: Credit Reservation followed by Atomic Handshake Transition (BUG-05 Fix)
  let hasReservedCredit = false;
  const nextExecutingNode = dag.nodes[startStepIndex];
  if (nextExecutingNode.selected_model.inference_target !== 'browser') {
    const reserveResult = await env.DB.prepare(
      "UPDATE users SET credits = credits - 1 WHERE user_id = ? AND credits >= 1"
    ).bind(session.userId).run();

    if (!reserveResult.meta.changes || reserveResult.meta.changes === 0) {
      // NOTE: Handshake record remains 'ISSUED'! User can recharge and retry safely without burning handshake token!
      return new Response(JSON.stringify({ 
        error: "insufficient_quota", 
        message: "当前可用积分不足，无法执行后续云端任务，请先充值额度。" 
      }), { 
        status: 403, 
        headers: { "Content-Type": "application/json" } 
      });
    }
    hasReservedCredit = true;
  }

  // Phase 2: Atomically advance handshake state to 'CONSUMED' with CAS Anti-Replay
  const casResult = await env.DB.prepare(`
    UPDATE dag_handshakes
    SET status = 'CONSUMED'
    WHERE handshake_id = ? AND user_id = ? AND status = 'ISSUED' AND datetime(expires_at) > datetime('now')
  `).bind(claims.jti, session.userId).run();

  if (!casResult.meta.changes || casResult.meta.changes === 0) {
    // If CAS failed (concurrent replay attack), roll back the reserved credit compensation!
    if (hasReservedCredit) {
      await env.DB.prepare("UPDATE users SET credits = credits + 1 WHERE user_id = ?").bind(session.userId).run();
      hasReservedCredit = false;
    }
    return new Response(JSON.stringify({ 
      error: "handshake_already_consumed_or_expired", 
      message: "该任务接力握手已被消费或已超时，严禁重放执行。" 
    }), { 
      status: 409, 
      headers: { "Content-Type": "application/json" } 
    });
  }

  // 5. Execute resumed DAG stream
  try {
    const stream = await executeDAGStream(env, dag, body.envelope, {
      userId: session.userId,
      hasPreDeducted: hasReservedCredit,
      startStepIndex,
      injectedUpstreamText,
      continuationHandshakeId: claims.jti,
      ctx,
      clientCapabilities: { webgpu_handover_v3: true }
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache",
        "Connection": "keep-alive"
      }
    });
  } catch (err: any) {
    console.error("[ChatContinue] Stream execution error:", err);
    if (hasReservedCredit) {
      try {
        await env.DB.prepare(
          "UPDATE users SET credits = credits + 1 WHERE user_id = ?"
        ).bind(session.userId).run();
      } catch (refundErr) {
        console.error("[ChatContinue] Failed to refund reserved credit:", refundErr);
      }
    }
    return new Response(JSON.stringify({ 
      error: "execution_failed", 
      message: err.message || "Failed to execute continuation stream" 
    }), { 
      status: 500, 
      headers: { "Content-Type": "application/json" } 
    });
  }
}

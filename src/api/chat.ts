// src/api/chat.ts
import { Env } from "../types";
import { getSession } from "../auth/middleware";
import { verifyJWT } from "../auth/jwt";
import { runOrchestrationPipeline, OrchestrationOptions } from "../orchestration/orchestrator";
import {
  executeDAGStream,
  sanitizeClientStepOutput,
  calculateExpectedNodeCost
} from "../orchestration/dispatcher";
import {
  AssetOrigin,
  Modality,
  SessionAssetLedgerItem,
  UnifiedProtocolEnvelope
} from "../orchestration/types";
import {
  acquireBrowserTailCredential,
  acquireSessionExecutionLock,
  buildPublicSessionSnapshot,
  claimCloudFailoverOwnership,
  claimSessionUploads,
  commitAuthoritativeSessionTurn,
  computeClientOpRequestDigest,
  computePlanHash,
  ensureActiveSessionState,
  finishRunWithoutCommit,
  hydrateDocumentTextBodies,
  loadAndVerifyDagRunPlan,
  loadAuthoritativeSessionState,
  markSessionAwaitingCommit,
  persistDagStepOutputs,
  registerAndFreezeDagRunPlan,
  registerStagingGeneratedAsset,
  renewSessionExecutionLock,
  restoreFrozenInputsForBaseCommit,
  saveCloudTailResult,
  SessionDeletedError,
  settleRunBillingPhase,
  StorageUnavailableError,
  sweepPendingR2Cleanups,
  verifySessionAssetR2Access
} from "./session";

/**
 * Lazy sweep for expired orphan handshake records and deferred R2 deletions.
 * Uses ctx.waitUntil() to execute asynchronously in background without blocking edge response.
 */
export function triggerLazyHandshakeSweep(env: Env, ctx?: ExecutionContext, userId?: string) {
  if (ctx && typeof ctx.waitUntil === "function") {
    const sweepPromise = (async () => {
      try {
        await env.DB.prepare(
          "DELETE FROM dag_handshakes WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%SZ', 'now', '-1 hour')"
        ).run();
      } catch (e) {
        console.warn("[HandshakeSweep] lazy cleanup error:", e);
      }
      await sweepPendingR2Cleanups(env, userId);
    })();
    ctx.waitUntil(sweepPromise);
  }
}

// --- Rate Limiting: In-Memory Sliding-Window Token Bucket ---
// Non-aggressive: Allows a burst of up to 3 requests, refills 1 token every 5 seconds (~12 req/min sustained).
interface RateLimitBucket {
  tokens: number;
  lastRefill: number; // timestamp ms
}

// Rate Limiting Architecture Note:
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

export async function handleChat(
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

  // 1. Sliding-Window Rate Limit Check (Non-aggressive Demo Protection)
  const rateLimit = checkRateLimit(session.userId);
  if (!rateLimit.allowed) {
    return new Response(
      JSON.stringify({
        error: "rate_limited",
        retry_after: rateLimit.retryAfter,
        message: `请求过于频繁，请稍候 ${rateLimit.retryAfter} 秒后再试（Demo 环境保护）`
      }),
      {
        status: 429,
        headers: {
          "Content-Type": "application/json; charset=utf-8",
          "Retry-After": String(rateLimit.retryAfter)
        }
      }
    );
  }

  // 2. Parse & Validate Payload FIRST (fail-fast on malformed input without reserving/deducting quota)
  let body: {
    envelope: UnifiedProtocolEnvelope;
    reRouteMode?: "normal" | "switch_template" | "switch_model";
    chosenTemplateId?: string;
    chosenRoleModels?: Record<string, string>;
    customRolePrompts?: Record<string, string>;
    customNodePrompt?: string;
    hasPreviousRound?: boolean;
    previousRoundSummary?: string;
    hadMediaAssets?: boolean;
    hasNewUploads?: boolean;
    newUploadModalities?: string[];
    sessionAssetLedger?: SessionAssetLedgerItem[];
    activeBranchId?: string;
    activeBranchSummary?: string;
    branchCatalog?: Array<{
      branch_id: string;
      topic?: string;
      is_media?: boolean;
      last_summary?: string;
      is_active?: boolean;
      lineage_asset_ids?: string[];
      head_commit_id?: string;
    }>;
    perceptualCache?: Record<string, any>;
    resolvedClarificationTargetBranchId?: string;
    candidateBudgetK?: number;
    frozenResolvedPlan?: any;
    disableBrowserInference?: boolean;
    clientOpId?: string;
    client_op_id?: string;
    isReRun?: boolean;
    baseCommitId?: string;
    capabilities?: {
      webgpu_handover_v3?: boolean;
    };
  };

  try {
    body = await request.json();
    if (!body || typeof body !== "object") throw new Error("Not an object");
  } catch (err) {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const envelope = body.envelope;
  if (
    !envelope ||
    !envelope.instruction_payload ||
    typeof envelope.instruction_payload !== "string" ||
    !envelope.instruction_payload.trim()
  ) {
    return new Response(
      JSON.stringify({
        error: "Missing or invalid instruction_payload: must be a non-empty string"
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // Enforce payload length boundary to protect Worker 128MB memory constraints
  const MAX_INSTRUCTION_PAYLOAD_CHARS = 512 * 1024; // 512KB
  if (envelope.instruction_payload.length > MAX_INSTRUCTION_PAYLOAD_CHARS) {
    return new Response(
      JSON.stringify({
        error: "payload_too_large",
        message: "instruction_payload exceeds maximum allowed limit (512KB)"
      }),
      {
        status: 413,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // Normalize assets_manifest to ensure an array is always provided to the orchestrator
  if (!Array.isArray(envelope.assets_manifest)) {
    envelope.assets_manifest = [];
  }

  const rawSessionId = typeof envelope.session_id === "string" ? envelope.session_id.trim() : "";
  if (!rawSessionId || rawSessionId.length > 64) {
    return new Response(
      JSON.stringify({ error: "invalid_session_id", message: "缺少或非法的 session_id" }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
  envelope.session_id = rawSessionId;

  // Always mint authoritative server run_id (NM-STATE-01) and track client_op_id idempotency (REV-02)
  const runId = crypto.randomUUID();
  const isReRun = !!(body as any).isReRun;
  const requestedBaseCommitId =
    typeof (body as any).baseCommitId === "string" && (body as any).baseCommitId.trim()
      ? (body as any).baseCommitId.trim()
      : undefined;
  const rawClientOpId = body.clientOpId || body.client_op_id;
  const clientOpId = String(
    typeof rawClientOpId === "string" && rawClientOpId.trim() ? rawClientOpId : crypto.randomUUID()
  )
    .trim()
    .slice(0, 128);

  const requestDigest = await computeClientOpRequestDigest({
    instructionPayload: envelope.instruction_payload,
    assets: envelope.assets_manifest,
    isReRun,
    baseCommitId: requestedBaseCommitId,
    reRouteMode: body.reRouteMode,
    chosenTemplateId: body.chosenTemplateId,
    chosenRoleModels: body.chosenRoleModels,
    customRolePrompts: body.customRolePrompts,
    customNodePrompt: body.customNodePrompt,
    resolvedClarificationTargetBranchId: body.resolvedClarificationTargetBranchId
  });

  // Fail-closed session state + client_op_id pre-check BEFORE session lock acquisition, credit reservation, or upload claim (REV-02, PLAN-04, R04)
  try {
    await ensureActiveSessionState(env, session.userId, envelope.session_id);
    const existingOp = await env.DB.prepare(
      `SELECT run_id, request_digest, commit_state, status, tail_result_json, failure_status, failure_code, failure_message
       FROM dag_run_plans
       WHERE user_id = ? AND session_id = ? AND client_op_id = ?`
    )
      .bind(session.userId, envelope.session_id, clientOpId)
      .first<any>();

    if (existingOp) {
      if (existingOp.request_digest !== requestDigest) {
        return new Response(
          JSON.stringify({
            error: "client_op_conflict",
            message: "同一操作幂等键对应了不同的请求参数，已拒绝重复使用。"
          }),
          {
            status: 409,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
      if (existingOp.commit_state === "COMMITTED") {
        const snap = await loadAuthoritativeSessionState(env, session.userId, envelope.session_id);
        let parsedTail: any = {};
        try {
          parsedTail = existingOp.tail_result_json ? JSON.parse(existingOp.tail_result_json) : {};
        } catch {}
        return new Response(
          JSON.stringify({
            already_completed: true,
            run_id: existingOp.run_id,
            final_output: String(parsedTail?.finalOutput || ""),
            authoritative_git_state: buildPublicSessionSnapshot(snap)
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
      if (existingOp.commit_state === "FAILED" || existingOp.commit_state === "ABORTED") {
        const storedStatus = Number(existingOp.failure_status || 409);
        return new Response(
          JSON.stringify({
            error: existingOp.failure_code || "run_aborted",
            run_id: existingOp.run_id,
            message: existingOp.failure_message || "该操作此前已失败或被中止，请重新发起请求。"
          }),
          {
            status: storedStatus >= 400 && storedStatus < 600 ? storedStatus : 409,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
      const isAwaitingCommit = existingOp.status === "AWAITING_COMMIT";
      return new Response(
        JSON.stringify({
          error: "run_already_in_progress",
          awaiting_commit: isAwaitingCommit,
          run_id: existingOp.run_id,
          message: isAwaitingCommit
            ? "该请求的结果正在等待保存确认，请点击重试保存或放弃。"
            : "该请求正在执行中，请勿重复提交。"
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  } catch (err: any) {
    if (err instanceof SessionDeletedError) {
      return new Response(JSON.stringify({ error: "session_deleted", message: err.message }), {
        status: 410,
        headers: { "Content-Type": "application/json" }
      });
    }
    return new Response(
      JSON.stringify({
        error: "storage_unavailable",
        message: err?.message || "Storage unavailable"
      }),
      {
        status: 503,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // Acquire authoritative per-session execution occupancy lock BEFORE arbitration, orchestration, or asset claim (NM-STATE-R01 ~ R04)
  let hasSessionLock = false;
  const releaseLockOnAbort = async (abortInfo: {
    outcome: "FAILED" | "ABORTED";
    failureStatus?: number | null;
    failureCode?: string | null;
    failureMessage?: string | null;
  }) => {
    if (!hasSessionLock) return;
    hasSessionLock = false;
    await finishRunWithoutCommit(env, {
      userId: session.userId,
      sessionId: envelope.session_id,
      runId,
      ...abortInfo
    });
  };

  try {
    const lockRes = await acquireSessionExecutionLock(env, {
      userId: session.userId,
      sessionId: envelope.session_id,
      runId,
      clientOpId
    });
    if (!lockRes.ok) {
      return new Response(
        JSON.stringify({
          error: "session_busy",
          occupancy_phase: lockRes.occupancyPhase,
          awaiting_commit: lockRes.awaitingCommit,
          active_run_id: lockRes.activeRunId,
          message: lockRes.awaitingCommit
            ? "当前会话有待保存结果，请先重试保存或放弃后再发起新请求。"
            : "当前会话正在执行另一项任务，请等待完成后再试。"
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
    hasSessionLock = true;
  } catch (lockErr: any) {
    if (lockErr instanceof SessionDeletedError) {
      return new Response(JSON.stringify({ error: "session_deleted", message: lockErr.message }), {
        status: 410,
        headers: { "Content-Type": "application/json" }
      });
    }
    return new Response(
      JSON.stringify({
        error: "storage_unavailable",
        message: lockErr?.message || "Storage unavailable"
      }),
      {
        status: 503,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // Bind new uploads strictly to this session and block cross-session R2 claims early
  const claimRes = await claimSessionUploads(
    env,
    session.userId,
    envelope.session_id,
    envelope.assets_manifest,
    Number(envelope.round_index || 1)
  );
  if (!claimRes.ok) {
    await releaseLockOnAbort({
      outcome: "ABORTED",
      failureStatus: claimRes.httpStatus,
      failureCode: claimRes.code,
      failureMessage: claimRes.reason
    });
    return new Response(
      JSON.stringify({
        error: claimRes.code,
        message: claimRes.reason
      }),
      {
        status: claimRes.httpStatus,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  let authoritativeState;
  try {
    authoritativeState = await loadAuthoritativeSessionState(
      env,
      session.userId,
      envelope.session_id
    );
    await hydrateDocumentTextBodies(
      env,
      session.userId,
      envelope.session_id,
      authoritativeState.session_asset_ledger
    );
  } catch (err: any) {
    if (err instanceof SessionDeletedError) {
      await releaseLockOnAbort({
        outcome: "ABORTED",
        failureStatus: 410,
        failureCode: "session_deleted",
        failureMessage: err.message
      });
      return new Response(JSON.stringify({ error: "session_deleted", message: err.message }), {
        status: 410,
        headers: { "Content-Type": "application/json" }
      });
    }
    await releaseLockOnAbort({
      outcome: "FAILED",
      failureStatus: 503,
      failureCode: "storage_unavailable",
      failureMessage: err?.message || "Storage unavailable"
    });
    return new Response(
      JSON.stringify({
        error: "storage_unavailable",
        message: err?.message || "Storage unavailable"
      }),
      {
        status: 503,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  const ledgerById = new Map(authoritativeState.session_asset_ledger.map((a) => [a.asset_id, a]));
  envelope.assets_manifest.forEach((a) => {
    if (!a.in_memory_text && a.modality === "text_doc") {
      const hydrated = ledgerById.get(a.asset_id)?.in_memory_text;
      if (hydrated) a.in_memory_text = hydrated;
    }
  });

  const hasServerHistory = authoritativeState.commit_order.length > 0;
  const isNormalFlow = !body.reRouteMode || body.reRouteMode === "normal";
  const effectiveIsReRun =
    isReRun ||
    (hasServerHistory &&
      (body.reRouteMode === "switch_template" || body.reRouteMode === "switch_model"));

  let resolvedBaseCommitId: string | undefined = undefined;
  let expectedParentCommitId: string | null = null;
  let expectedBaseRevision: number | null = null;
  let restoredReRunPlan: any = undefined;

  if (effectiveIsReRun) {
    const hasUnsubmittedUpload = (envelope.assets_manifest || []).some(
      (a) => a.is_new === true && !!a.r2_key && !authoritativeState.committed_r2_keys.has(a.r2_key)
    );
    if (hasUnsubmittedUpload) {
      await releaseLockOnAbort({
        outcome: "ABORTED",
        failureStatus: 400,
        failureCode: "rerun_new_upload_forbidden",
        failureMessage: "画布微调模式禁止夹带未提交的新上传附件。"
      });
      return new Response(
        JSON.stringify({
          error: "rerun_new_upload_forbidden",
          message: "画布微调模式禁止夹带未提交的新上传附件。"
        }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    resolvedBaseCommitId =
      requestedBaseCommitId ||
      authoritativeState.branches[authoritativeState.active_branch_id]?.head_commit_id ||
      authoritativeState.commit_order[authoritativeState.commit_order.length - 1];
    const baseCommit = resolvedBaseCommitId
      ? authoritativeState.commits[resolvedBaseCommitId]
      : undefined;
    if (!resolvedBaseCommitId || !baseCommit) {
      await releaseLockOnAbort({
        outcome: "FAILED",
        failureStatus: 409,
        failureCode: "base_commit_not_found",
        failureMessage: "指定的基准修订提交不存在，无法执行画布微调。"
      });
      return new Response(
        JSON.stringify({
          error: "base_commit_not_found",
          message: "指定的基准修订提交不存在，无法执行画布微调。"
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
    expectedBaseRevision = Number(baseCommit.revision ?? 1);
    expectedParentCommitId = null;

    // Server-authoritative frozen input & recalled asset restoration BEFORE orchestration (NM-STATE-R05)
    const restored = await restoreFrozenInputsForBaseCommit(env, {
      userId: session.userId,
      sessionId: envelope.session_id,
      baseCommit,
      snapshot: authoritativeState,
      targetLanguage: envelope.constraint_context?.target_language,
      outputStyle: envelope.constraint_context?.output_style
    });
    envelope.instruction_payload = restored.instructionPayload;
    envelope.round_index = restored.roundIndex;
    envelope.constraint_context = restored.constraintContext;
    envelope.assets_manifest = restored.assetsManifest;
    restoredReRunPlan = restored.frozenResolvedPlan;
  } else if (hasServerHistory && isNormalFlow) {
    envelope.assets_manifest = envelope.assets_manifest.filter(
      (a) =>
        a.is_new === true ||
        a.asset_id === "virtual-text-asset" ||
        ledgerById.has(a.asset_id) ||
        (!!a.r2_key && authoritativeState.committed_r2_keys.has(a.r2_key))
    );
  }

  const hasNewUploads = effectiveIsReRun
    ? false
    : (body.hasNewUploads ??
      envelope.metadata?.has_new_upload ??
      (envelope.assets_manifest || []).some((a) => a.is_new));
  const newUploadModalities = effectiveIsReRun
    ? []
    : (body.newUploadModalities ??
      envelope.metadata?.new_upload_modalities ??
      (envelope.assets_manifest || []).filter((a) => a.is_new).map((a) => a.modality));

  const authActiveBranch = effectiveIsReRun
    ? authoritativeState.commits[resolvedBaseCommitId!]?.branch_id ||
      authoritativeState.active_branch_id
    : hasServerHistory && isNormalFlow
      ? authoritativeState.active_branch_id
      : body.activeBranchId;
  const authBranchSummary = effectiveIsReRun
    ? undefined
    : hasServerHistory && isNormalFlow
      ? authoritativeState.branches[authActiveBranch || "main"]?.last_summary ||
        body.activeBranchSummary
      : body.activeBranchSummary;

  const orchestrationOptions: OrchestrationOptions = {
    reRouteMode: effectiveIsReRun
      ? body.reRouteMode === "switch_template"
        ? "switch_template"
        : "switch_model"
      : body.reRouteMode,
    chosenTemplateId: body.chosenTemplateId,
    chosenRoleModels: body.chosenRoleModels,
    customRolePrompts: body.customRolePrompts,
    customNodePrompt: body.customNodePrompt,
    hasPreviousRound: effectiveIsReRun
      ? false
      : hasServerHistory && isNormalFlow
        ? true
        : body.hasPreviousRound,
    previousRoundSummary: effectiveIsReRun
      ? undefined
      : hasServerHistory && isNormalFlow
        ? authBranchSummary || body.previousRoundSummary
        : body.previousRoundSummary,
    hadMediaAssets: effectiveIsReRun
      ? authoritativeState.session_asset_ledger.some(
          (a) => a.modality === "image" || a.modality === "audio" || a.modality === "text_doc"
        )
      : hasServerHistory && isNormalFlow
        ? authoritativeState.session_asset_ledger.some(
            (a) => a.modality === "image" || a.modality === "audio" || a.modality === "text_doc"
          )
        : body.hadMediaAssets,
    hasNewUploads,
    newUploadModalities,
    sessionAssetLedger: effectiveIsReRun
      ? authoritativeState.session_asset_ledger
      : hasServerHistory && isNormalFlow
        ? authoritativeState.session_asset_ledger
        : body.sessionAssetLedger,
    activeBranchId: authActiveBranch,
    activeBranchSummary: authBranchSummary,
    branchCatalog: effectiveIsReRun
      ? authoritativeState.branch_catalog
      : hasServerHistory && isNormalFlow
        ? authoritativeState.branch_catalog
        : body.branchCatalog,
    perceptualCache: effectiveIsReRun
      ? { ...authoritativeState.perceptual_cache }
      : hasServerHistory && isNormalFlow
        ? { ...authoritativeState.perceptual_cache }
        : body.perceptualCache,
    resolvedClarificationTargetBranchId: effectiveIsReRun
      ? undefined
      : body.resolvedClarificationTargetBranchId,
    candidateBudgetK: body.candidateBudgetK,
    frozenResolvedPlan: effectiveIsReRun ? restoredReRunPlan : body.frozenResolvedPlan,
    disableBrowserInference:
      !!body.disableBrowserInference || body.capabilities?.webgpu_handover_v3 === false
  };

  // 3. Run Gateway 3-Step Arbitration & Instantiate DAG FIRST
  const originalEnvelopeSnapshot = structuredClone(envelope);
  let dag;
  try {
    dag = await runOrchestrationPipeline(env, envelope, orchestrationOptions);
  } catch (err: any) {
    console.error("Orchestration error:", err);
    const safeMsg =
      env.ENVIRONMENT === "production"
        ? "Failed to orchestrate task"
        : err.message || "Failed to orchestrate task";
    await releaseLockOnAbort({
      outcome: "FAILED",
      failureStatus: 500,
      failureCode: "orchestration_failed",
      failureMessage: safeMsg
    });
    return new Response(
      JSON.stringify({
        error: "orchestration_failed",
        message: safeMsg
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  let planHash: string | undefined = undefined;

  if (!dag.is_security_violation && !dag.is_unreachable && !dag.is_clarification_required) {
    planHash = await computePlanHash(dag);
    dag.reasoning_trace.plan_hash = planHash;

    const targetBranchId = dag.reasoning_trace?.target_branch_id || "main";
    if (!effectiveIsReRun) {
      expectedParentCommitId = authoritativeState.branches[targetBranchId]?.head_commit_id || null;
    }

    try {
      const freezeRes = await registerAndFreezeDagRunPlan(env, {
        runId,
        userId: session.userId,
        sessionId: envelope.session_id,
        clientOpId,
        requestDigest,
        planHash,
        dag,
        originalEnvelope: originalEnvelopeSnapshot,
        resolvedEnvelope: envelope,
        isReRun: effectiveIsReRun,
        baseCommitId: resolvedBaseCommitId,
        expectedParentCommitId,
        expectedBaseRevision
      });

      if (freezeRes.outcome === "op_conflict") {
        await releaseLockOnAbort({
          outcome: "ABORTED",
          failureStatus: 409,
          failureCode: "client_op_conflict",
          failureMessage: "同一操作幂等键对应了不同的请求参数，已拒绝重复使用。"
        });
        return new Response(
          JSON.stringify({
            error: "client_op_conflict",
            message: "同一操作幂等键对应了不同的请求参数，已拒绝重复使用。"
          }),
          {
            status: 409,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
      if (freezeRes.outcome === "already_completed") {
        await releaseLockOnAbort({
          outcome: "ABORTED",
          failureStatus: 200,
          failureCode: "already_completed",
          failureMessage: "Duplicate replay resolved"
        });
        return new Response(
          JSON.stringify({
            already_completed: true,
            run_id: freezeRes.runId,
            final_output: freezeRes.finalOutput,
            authoritative_git_state: buildPublicSessionSnapshot(freezeRes.snapshot)
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
      if (freezeRes.outcome === "failed_terminal") {
        await releaseLockOnAbort({
          outcome: "FAILED",
          failureStatus: freezeRes.failureStatus || 409,
          failureCode: freezeRes.failureCode || "run_aborted",
          failureMessage: freezeRes.failureMessage || "该操作已失败或被中止。"
        });
        return new Response(
          JSON.stringify({
            error: freezeRes.failureCode || "run_aborted",
            run_id: freezeRes.runId,
            message: freezeRes.failureMessage || "该操作已失败或被中止。"
          }),
          {
            status: freezeRes.failureStatus || 409,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
      if (freezeRes.outcome === "in_progress") {
        await releaseLockOnAbort({
          outcome: "ABORTED",
          failureStatus: 409,
          failureCode: "run_already_in_progress",
          failureMessage: "该请求正在执行中，请勿重复提交。"
        });
        return new Response(
          JSON.stringify({
            error: "run_already_in_progress",
            run_id: freezeRes.runId,
            message: "该请求正在执行中，请勿重复提交。"
          }),
          {
            status: 409,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
    } catch (freezeErr: any) {
      if (freezeErr instanceof SessionDeletedError) {
        await releaseLockOnAbort({
          outcome: "ABORTED",
          failureStatus: 410,
          failureCode: "session_deleted",
          failureMessage: freezeErr.message
        });
        return new Response(
          JSON.stringify({ error: "session_deleted", message: freezeErr.message }),
          {
            status: 410,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
      await releaseLockOnAbort({
        outcome: "FAILED",
        failureStatus: 503,
        failureCode: "plan_freeze_failed",
        failureMessage: freezeErr?.message || "冻结运行计划保存失败，已中止调度。"
      });
      return new Response(
        JSON.stringify({
          error: "plan_freeze_failed",
          message: freezeErr?.message || "冻结运行计划保存失败，已中止调度。"
        }),
        {
          status: 503,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  }

  // 4. Dynamic billing alignment: pre-deduct credits for cloud models, zero pre-deduction for WebGPU
  let hasReservedCredit = false;
  let expectedCloudCost = 0;
  if (!dag.is_security_violation && !dag.is_unreachable && !dag.is_clarification_required) {
    const isFirstNodeWebGPU = dag.nodes[0]?.selected_model?.inference_target === "browser";
    const firstNodeHasCloudStandby = (dag.nodes[0]?.standby_models || []).some(
      (m) => m.inference_target !== "browser"
    );
    const clientSupportsWebGPU =
      body.capabilities?.webgpu_handover_v3 ?? !body.disableBrowserInference;

    // Zero Pre-Deduction Law:
    // If the first node is executed client-side via WebGPU, Phase 1 MUST NOT pre-deduct any credits!
    if (!isFirstNodeWebGPU || !clientSupportsWebGPU) {
      for (const n of dag.nodes) {
        if (n.is_reducer || n.perceptual_cache_hit) {
          continue;
        }
        if (n.selected_model && n.selected_model.inference_target !== "browser") {
          expectedCloudCost += calculateExpectedNodeCost(n.selected_model);
        } else if (clientSupportsWebGPU) {
          // Reached a client WebGPU node, execution will handover here
          break;
        }
      }
      if (expectedCloudCost === 0 && firstNodeHasCloudStandby) {
        expectedCloudCost = 1;
      }
    }

    if (expectedCloudCost > 0) {
      // Cloud / Multi-Node / Fallback execution: atomic reservation of expected credits
      const reserveResult = await env.DB.prepare(
        "UPDATE users SET credits = credits - ? WHERE user_id = ? AND credits >= ?"
      )
        .bind(expectedCloudCost, session.userId, expectedCloudCost)
        .run();

      if (!reserveResult.meta.changes || reserveResult.meta.changes === 0) {
        const quotaMsg = `可用积分不足，执行该工作流需预扣 ${expectedCloudCost} 积分，请先充值额度。`;
        await releaseLockOnAbort({
          outcome: "FAILED",
          failureStatus: 403,
          failureCode: "insufficient_quota",
          failureMessage: quotaMsg
        });
        return new Response(
          JSON.stringify({
            error: "insufficient_quota",
            message: quotaMsg
          }),
          {
            status: 403,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
      hasReservedCredit = true;
    }
  }

  try {
    // 5. Return SSE Stream (with pre-deduction tracking for atomic billing + plan identity + occupancy lifecycle)
    const stream = await executeDAGStream(env, dag, envelope, {
      userId: session.userId,
      sessionId: envelope.session_id,
      hasPreDeducted: hasReservedCredit,
      preDeductedCredits: hasReservedCredit ? expectedCloudCost : 0,
      billingPhaseLabel: "initial_stream",
      runId,
      planHash,
      verifyAssetAccess: (asset) =>
        verifySessionAssetR2Access(env, session.userId, envelope.session_id, asset),
      onStepOutputsPersist: (stepOutputs) =>
        persistDagStepOutputs(env, runId, session.userId, stepOutputs),
      onIssueBrowserTailToken: () =>
        acquireBrowserTailCredential(env, session.userId, envelope.session_id, runId),
      onRegisterStagingAsset: (info) =>
        registerStagingGeneratedAsset(env, {
          userId: session.userId,
          sessionId: envelope.session_id,
          ...info
        }),
      onSettlePhaseBilling: (phaseParams) =>
        settleRunBillingPhase(env, {
          userId: session.userId,
          runId,
          templateNameZh: dag.template.name_zh,
          ...phaseParams
        }),
      onSaveCloudTailResult: (tailPayload) =>
        saveCloudTailResult(env, {
          userId: session.userId,
          sessionId: envelope.session_id,
          runId,
          ...tailPayload
        }),
      onCompleteStateCommit: (payload) =>
        commitAuthoritativeSessionTurn(env, {
          userId: session.userId,
          sessionId: envelope.session_id,
          runId,
          envelope,
          dag: payload.dag,
          finalOutput: payload.finalOutput,
          generatedMedia: payload.generatedMedia,
          perceptualCacheUpdates: payload.perceptualCacheUpdates,
          authMode: "cloud",
          isReRun: effectiveIsReRun,
          baseCommitId: resolvedBaseCommitId,
          expectedParentCommitId,
          expectedBaseRevision
        }),
      onMarkAwaitingCommit: () =>
        markSessionAwaitingCommit(env, session.userId, envelope.session_id, runId),
      onFinishWithoutCommit: async (finishParams) => {
        await finishRunWithoutCommit(env, {
          userId: session.userId,
          sessionId: envelope.session_id,
          runId,
          ...finishParams
        });
      },
      ctx,
      clientCapabilities: {
        webgpu_handover_v3: body.capabilities?.webgpu_handover_v3 ?? !body.disableBrowserInference
      }
    });

    triggerLazyHandshakeSweep(env, ctx, session.userId);

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache",
        Connection: "keep-alive"
      }
    });
  } catch (err: any) {
    console.error("Execution error:", err);
    // Refund reserved credit if execution setup failed
    if (hasReservedCredit) {
      try {
        await env.DB.prepare("UPDATE users SET credits = credits + ? WHERE user_id = ?")
          .bind(expectedCloudCost, session.userId)
          .run();
      } catch (refundErr) {
        console.error("[Chat] Failed to refund reserved credit on execution error:", refundErr);
      }
    }
    const execErrMsg =
      env.ENVIRONMENT === "production"
        ? "Failed to execute task stream"
        : err.message || "Failed to execute task stream";
    await releaseLockOnAbort({
      outcome: "FAILED",
      failureStatus: 500,
      failureCode: "execution_failed",
      failureMessage: execErrMsg
    });
    return new Response(
      JSON.stringify({
        error: "execution_failed",
        message: execErrMsg
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
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
    status: "success" | "candidate_failed";
    client_step_output?: string;
    failed_model_id?: string;
    error_reason?: string;
    upstream_context?: string;
    envelope: UnifiedProtocolEnvelope;
    orchestration_options?: OrchestrationOptions;
  };

  try {
    body = await request.json();
    if (!body || typeof body !== "object") throw new Error("Not an object");
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

  // Enforce security boundary on continuation step outputs to prevent memory exhaustion
  const MAX_CONTINUATION_PAYLOAD_CHARS = 512 * 1024;
  if (
    typeof body.client_step_output === "string" &&
    body.client_step_output.length > MAX_CONTINUATION_PAYLOAD_CHARS
  ) {
    return new Response(
      JSON.stringify({
        error: "payload_too_large",
        message: "Client step output exceeds maximum allowed limit (512KB)"
      }),
      {
        status: 413,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
  if (
    typeof body.upstream_context === "string" &&
    body.upstream_context.length > MAX_CONTINUATION_PAYLOAD_CHARS
  ) {
    return new Response(
      JSON.stringify({
        error: "payload_too_large",
        message: "Upstream context exceeds maximum allowed limit (512KB)"
      }),
      {
        status: 413,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // 1. Verify continuation JWT token
  const claims = await verifyJWT(body.continuation_token, env.JWT_SECRET);
  if (!claims || !claims.jti || !claims.sub || claims.nxt === undefined) {
    return new Response(
      JSON.stringify({
        error: "invalid_or_expired_token",
        message: "续接令牌无效或已过期，请重新发起会话。"
      }),
      {
        status: 401,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  if (claims.sub !== session.userId) {
    return new Response(
      JSON.stringify({
        error: "forbidden",
        message: "跨用户非法续接访问。"
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // 2. Validate handshake record pre-condition before DAG compilation and billing
  const handshakeRecord = await env.DB.prepare(
    `
    SELECT status, expires_at FROM dag_handshakes
    WHERE handshake_id = ? AND user_id = ?
  `
  )
    .bind(claims.jti, session.userId)
    .first<any>();

  if (
    !handshakeRecord ||
    handshakeRecord.status !== "ISSUED" ||
    new Date(handshakeRecord.expires_at) <= new Date()
  ) {
    return new Response(
      JSON.stringify({
        error: "handshake_already_consumed_or_expired",
        message: "该任务接力握手已被消费或已超时，严禁重放执行。"
      }),
      {
        status: 409,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  if (!body.envelope || claims.sid !== body.envelope.session_id) {
    return new Response(
      JSON.stringify({
        error: "session_mismatch",
        message: "接力令牌与当前会话不匹配，严禁跨会话接力。"
      }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // Trigger lazy sweep for expired orphan records & deferred R2 cleanups in background
  triggerLazyHandshakeSweep(env, ctx, session.userId);

  // 3. Restore frozen DAG plan by (run_id, plan_hash) when present (prevents client plan drift/tampering)
  let dag;
  let effectiveEnvelope = body.envelope;
  let storedStepOutputs: Record<string, string> = {};
  let planIsReRun = false;
  let planBaseCommitId: string | undefined = undefined;
  let planExpectedParentCommitId: string | null = null;
  let planExpectedBaseRevision: number | null = null;
  let planExecOwner = "CLOUD";
  const planRunId: string | undefined = typeof claims.rid === "string" ? claims.rid : undefined;
  const planHash: string | undefined = typeof claims.ph === "string" ? claims.ph : undefined;

  if (planRunId) {
    const frozenPlan = await loadAndVerifyDagRunPlan(
      env,
      session.userId,
      planRunId,
      planHash || "",
      body.envelope.session_id
    );
    if (!frozenPlan) {
      return new Response(
        JSON.stringify({
          error: "plan_identity_mismatch",
          message: "续接计划签名与冻结执行图不一致或已失效，禁止跨图续接。"
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
    dag = frozenPlan.dag;
    effectiveEnvelope = frozenPlan.resolvedEnvelope || frozenPlan.envelope;
    storedStepOutputs = frozenPlan.stepOutputs || {};
    planIsReRun = frozenPlan.isReRun;
    planBaseCommitId = frozenPlan.baseCommitId;
    planExpectedParentCommitId = frozenPlan.expectedParentCommitId;
    planExpectedBaseRevision = frozenPlan.expectedBaseRevision;
    planExecOwner = frozenPlan.execOwner;
    if (frozenPlan.commitState === "COMMITTED") {
      return new Response(
        JSON.stringify({
          error: "already_committed",
          message: "该运行已完成状态提交，禁止重放执行。"
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
    if (frozenPlan.commitState === "FAILED" || frozenPlan.commitState === "ABORTED") {
      return new Response(
        JSON.stringify({
          error: "run_aborted",
          message: "该运行已失败或已被用户放弃，无法继续执行。"
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
    const renewRes = await renewSessionExecutionLock(env, {
      userId: session.userId,
      sessionId: effectiveEnvelope.session_id,
      runId: planRunId
    });
    if (!renewRes.ok) {
      return new Response(
        JSON.stringify({
          error: renewRes.reason,
          message:
            renewRes.reason === "session_deleted"
              ? "会话已被永久删除，禁止继续执行。"
              : "当前会话占用已变更或被其他运行接管。"
        }),
        {
          status: renewRes.reason === "session_deleted" ? 410 : 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  } else {
    const orchestrationOpts: OrchestrationOptions = {
      ...(body.orchestration_options || {}),
      chosenTemplateId: claims.tid,
      chosenRoleModels: claims.mids || body.orchestration_options?.chosenRoleModels,
      continuationMode: true
    };

    try {
      dag = await runOrchestrationPipeline(env, body.envelope, orchestrationOpts);
    } catch (err: any) {
      console.error("[ChatContinue] Orchestration error:", err);
      return new Response(
        JSON.stringify({
          error: "orchestration_failed",
          message:
            env.ENVIRONMENT === "production"
              ? "Failed to re-instantiate continuation pipeline"
              : err.message || "Failed to re-instantiate continuation pipeline"
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  }

  let startStepIndex = Number(claims.nxt);
  let injectedUpstreamText = "";

  if (body.status === "candidate_failed") {
    // Standby Failover: The node that failed was step (claims.nxt - 1)
    const failedStepIdx = Math.max(0, startStepIndex - 1);
    const targetNode = dag.nodes[failedStepIdx];
    if (!targetNode) {
      return new Response(
        JSON.stringify({ error: "invalid_step_index", message: "续接步骤索引越界" }),
        { status: 400 }
      );
    }

    const failedModelId = body.failed_model_id || targetNode.selected_model.model_id;
    const availableStandbys = (targetNode.standby_models || []).filter(
      (m) => m.model_id !== failedModelId && m.inference_target !== "browser"
    );

    if (availableStandbys.length === 0) {
      const noStandbyMsg = `岗位【${targetNode.role.name_zh}】首选端侧模型异常，且无可用云端备选模型。任务无法容灾。`;
      if (planRunId) {
        await finishRunWithoutCommit(env, {
          userId: session.userId,
          sessionId: effectiveEnvelope.session_id,
          runId: planRunId,
          outcome: "FAILED",
          failureStatus: 500,
          failureCode: "no_standby_models_available",
          failureMessage: noStandbyMsg
        });
      }
      return new Response(
        JSON.stringify({
          error: "no_standby_models_available",
          message: noStandbyMsg
        }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    // Transparently advance to Top Standby cloud model
    targetNode.selected_model = availableStandbys[0];
    targetNode.standby_models = availableStandbys.slice(1);
    targetNode.downgraded = true;
    startStepIndex = failedStepIdx;
    injectedUpstreamText = sanitizeClientStepOutput(body.upstream_context || "");
  } else {
    // Success path: Sanitize client step output before feeding downstream
    injectedUpstreamText = sanitizeClientStepOutput(body.client_step_output || "");
  }

  if (startStepIndex >= dag.nodes.length) {
    return new Response(
      JSON.stringify({ error: "step_already_completed", message: "流水线所有步骤已完成" }),
      { status: 400 }
    );
  }

  // 4. Two-Phase Commit (2PC) for Phase 2: credit reservation followed by atomic handshake transition
  let hasReservedCredit = false;
  const remainingNodes = dag.nodes.slice(startStepIndex);
  let expectedContinueCost = 0;
  const clientSupportsWebGPU =
    (body as any).capabilities?.webgpu_handover_v3 ??
    (body as any).orchestration_options?.capabilities?.webgpu_handover_v3 ??
    true;

  for (const n of remainingNodes) {
    if (n.selected_model && n.selected_model.inference_target !== "browser") {
      expectedContinueCost += calculateExpectedNodeCost(n.selected_model);
    } else if (clientSupportsWebGPU) {
      // Reached next client WebGPU step, execution will handover here
      break;
    }
  }

  if (expectedContinueCost > 0) {
    const reserveResult = await env.DB.prepare(
      "UPDATE users SET credits = credits - ? WHERE user_id = ? AND credits >= ?"
    )
      .bind(expectedContinueCost, session.userId, expectedContinueCost)
      .run();

    if (!reserveResult.meta.changes || reserveResult.meta.changes === 0) {
      // Note: Handshake record remains 'ISSUED', allowing safe retry without burning the token
      return new Response(
        JSON.stringify({
          error: "insufficient_quota",
          message: `当前可用积分不足，执行后续云端任务需 ${expectedContinueCost} 积分，请先充值额度。`
        }),
        {
          status: 403,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
    hasReservedCredit = true;
  }

  // Phase 2: Atomically advance handshake state to 'CONSUMED' with CAS Anti-Replay
  const casResult = await env.DB.prepare(
    `
    UPDATE dag_handshakes
    SET status = 'CONSUMED'
    WHERE handshake_id = ? AND user_id = ? AND status = 'ISSUED' AND datetime(expires_at) > datetime('now')
  `
  )
    .bind(claims.jti, session.userId)
    .run();

  if (!casResult.meta.changes || casResult.meta.changes === 0) {
    // If CAS failed (concurrent replay attempt), roll back the reserved credit compensation
    if (hasReservedCredit) {
      await env.DB.prepare("UPDATE users SET credits = credits + ? WHERE user_id = ?")
        .bind(expectedContinueCost, session.userId)
        .run();
      hasReservedCredit = false;
    }
    return new Response(
      JSON.stringify({
        error: "handshake_already_consumed_or_expired",
        message: "该任务接力握手已被消费或已超时，严禁重放执行。"
      }),
      {
        status: 409,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  // Tail failover ownership handover (REV-01): invalidate browser tail nonce when cloud takes over
  if (body.status === "candidate_failed" && planRunId && planExecOwner === "BROWSER_TAIL") {
    const claimedTakeover = await claimCloudFailoverOwnership(
      env,
      session.userId,
      effectiveEnvelope.session_id,
      planRunId
    );
    if (!claimedTakeover) {
      if (hasReservedCredit) {
        await env.DB.prepare("UPDATE users SET credits = credits + ? WHERE user_id = ?")
          .bind(expectedContinueCost, session.userId)
          .run();
        hasReservedCredit = false;
      }
      return new Response(
        JSON.stringify({
          error: "already_committed_or_taken_over",
          message: "该尾节点已被端侧提交或已被另一云端接管流程接手。"
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  }

  // 5. Execute resumed DAG stream
  try {
    const resumePhaseLabel = `resume_${claims.jti}`;
    const stream = await executeDAGStream(env, dag, effectiveEnvelope, {
      userId: session.userId,
      sessionId: effectiveEnvelope.session_id,
      hasPreDeducted: hasReservedCredit,
      preDeductedCredits: hasReservedCredit ? expectedContinueCost : 0,
      billingPhaseLabel: resumePhaseLabel,
      startStepIndex,
      injectedUpstreamText,
      continuationHandshakeId: claims.jti,
      runId: planRunId,
      planHash,
      stepOutputs: storedStepOutputs,
      verifyAssetAccess: (asset) =>
        verifySessionAssetR2Access(env, session.userId, effectiveEnvelope.session_id, asset),
      onStepOutputsPersist: planRunId
        ? (stepOutputs) => persistDagStepOutputs(env, planRunId, session.userId, stepOutputs)
        : undefined,
      onIssueBrowserTailToken: planRunId
        ? () =>
            acquireBrowserTailCredential(
              env,
              session.userId,
              effectiveEnvelope.session_id,
              planRunId
            )
        : undefined,
      onRegisterStagingAsset: (info) =>
        registerStagingGeneratedAsset(env, {
          userId: session.userId,
          sessionId: effectiveEnvelope.session_id,
          ...info
        }),
      onSettlePhaseBilling: planRunId
        ? (phaseParams) =>
            settleRunBillingPhase(env, {
              userId: session.userId,
              runId: planRunId,
              templateNameZh: dag.template.name_zh,
              ...phaseParams
            })
        : undefined,
      onSaveCloudTailResult: planRunId
        ? (tailPayload) =>
            saveCloudTailResult(env, {
              userId: session.userId,
              sessionId: effectiveEnvelope.session_id,
              runId: planRunId,
              ...tailPayload
            })
        : undefined,
      onCompleteStateCommit: planRunId
        ? (payload) =>
            commitAuthoritativeSessionTurn(env, {
              userId: session.userId,
              sessionId: effectiveEnvelope.session_id,
              runId: planRunId,
              envelope: effectiveEnvelope,
              dag: payload.dag,
              finalOutput: payload.finalOutput,
              generatedMedia: payload.generatedMedia,
              perceptualCacheUpdates: payload.perceptualCacheUpdates,
              authMode: "cloud",
              isReRun: planIsReRun,
              baseCommitId: planBaseCommitId,
              expectedParentCommitId: planExpectedParentCommitId,
              expectedBaseRevision: planExpectedBaseRevision
            })
        : undefined,
      onMarkAwaitingCommit: planRunId
        ? () =>
            markSessionAwaitingCommit(env, session.userId, effectiveEnvelope.session_id, planRunId)
        : undefined,
      onFinishWithoutCommit: planRunId
        ? async (finishParams) => {
            await finishRunWithoutCommit(env, {
              userId: session.userId,
              sessionId: effectiveEnvelope.session_id,
              runId: planRunId,
              ...finishParams
            });
          }
        : undefined,
      ctx,
      clientCapabilities: { webgpu_handover_v3: true }
    });

    return new Response(stream, {
      headers: {
        "Content-Type": "text/event-stream; charset=utf-8",
        "Cache-Control": "no-cache",
        Connection: "keep-alive"
      }
    });
  } catch (err: any) {
    console.error("[ChatContinue] Stream execution error:", err);
    if (hasReservedCredit) {
      try {
        await env.DB.prepare("UPDATE users SET credits = credits + ? WHERE user_id = ?")
          .bind(expectedContinueCost, session.userId)
          .run();
      } catch (refundErr) {
        console.error("[ChatContinue] Failed to refund reserved credit:", refundErr);
      }
    }
    const contErrMsg =
      env.ENVIRONMENT === "production"
        ? "Failed to execute continuation stream"
        : err.message || "Failed to execute continuation stream";
    if (planRunId) {
      await finishRunWithoutCommit(env, {
        userId: session.userId,
        sessionId: effectiveEnvelope.session_id,
        runId: planRunId,
        outcome: "FAILED",
        failureStatus: 500,
        failureCode: "execution_failed",
        failureMessage: contErrMsg
      });
    }
    return new Response(
      JSON.stringify({
        error: "execution_failed",
        message: contErrMsg
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}

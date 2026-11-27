// src/api/session.ts
import { Env } from "../types";
import { getSession } from "../auth/middleware";
import {
  AssetBindMode,
  AssetDescriptor,
  CommitNode,
  InstantiatedDAG,
  MediaArtifact,
  PerceptualCacheEntry,
  SessionAssetLedgerItem,
  SourceRefEntry,
  UnifiedProtocolEnvelope
} from "../orchestration/types";

export class StorageUnavailableError extends Error {
  constructor(message = "权威状态存储服务暂时不可用，请稍后重试。") {
    super(message);
    this.name = "StorageUnavailableError";
  }
}

export class SessionDeletedError extends Error {
  constructor(message = "该会话已被永久删除，禁止恢复或继续写入。") {
    super(message);
    this.name = "SessionDeletedError";
  }
}

export interface AuthoritativeBranchSummary {
  branch_id: string;
  topic: string;
  is_active: boolean;
  head_commit_id: string;
  dominant_modalities: string[];
  has_summary: boolean;
  last_summary: string;
  lineage_asset_ids: string[];
}

export interface AuthoritativeSessionSnapshot {
  session_id: string;
  active_branch_id: string;
  version: number;
  deleted: boolean;
  occupancy_phase: "EXECUTING" | "AWAITING_COMMIT" | null;
  active_run_id: string | null;
  awaiting_commit: {
    run_id: string;
    exec_owner: string;
    can_retry_commit: boolean;
    message?: string;
  } | null;
  branches: Record<string, AuthoritativeBranchSummary>;
  branch_catalog: AuthoritativeBranchSummary[];
  commits: Record<string, CommitNode>;
  commit_order: string[];
  session_asset_ledger: SessionAssetLedgerItem[];
  perceptual_cache: Record<string, PerceptualCacheEntry>;
  committed_r2_keys: Set<string>;
}

export type VerifyAssetAccessResult =
  | { status: "allowed" }
  | { status: "denied_unowned"; reason: string }
  | { status: "storage_unavailable"; reason: string };

export type CommitTurnResult =
  | { ok: true; snapshot: AuthoritativeSessionSnapshot; idempotentReplay?: boolean }
  | {
      ok: false;
      code:
        | "version_conflict"
        | "session_deleted"
        | "already_taken_over"
        | "conflicting_payload"
        | "invalid_credentials"
        | "storage_error";
      retryable: boolean;
      message: string;
    };

function safeJsonParse<T>(raw: any, fallback: T): T {
  if (raw === null || raw === undefined) return fallback;
  if (typeof raw !== "string") return raw as T;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function computeScopedPerceptKey(params: {
  userId: string;
  sessionId: string;
  sourceDigest: string;
  roleId: string;
  modelId: string;
  taskScope: string;
  promptDigest: string;
}): Promise<string> {
  return sha256Hex(
    `${params.userId}::${params.sessionId}::${params.sourceDigest}::${params.roleId}::${params.modelId}::${params.taskScope}::${params.promptDigest}`
  );
}

/**
 * Computes an integrity digest for an instantiated DAG plan covering full execution semantics (NM-STATE-13).
 */
export async function computePlanHash(
  dag: InstantiatedDAG,
  envelope?: UnifiedProtocolEnvelope
): Promise<string> {
  const instructionDigest = envelope?.instruction_payload
    ? await sha256Hex(envelope.instruction_payload)
    : "";
  const slices = await Promise.all(
    (dag.reasoning_trace?.inherited_context_slices || []).map(async (s) => ({
      branch_id: s.branch_id,
      commit_id: s.commit_id || "",
      summary_digest: await sha256Hex(s.summary || "")
    }))
  );
  const nodes = await Promise.all(
    (dag.nodes || []).map(async (n) => ({
      node_id: n.node_id || n.role.role_id,
      role_id: n.role.role_id,
      stage_group: n.stage_group || "synthesis_output",
      depends_on: n.depends_on || [],
      selected_model_id: n.selected_model?.model_id || "",
      standby_model_ids: (n.standby_models || []).map((m) => m.model_id),
      custom_prompt: n.custom_prompt || "",
      focus_hint: n.focus_hint || "",
      compensation_prompt: n.compensation_prompt || "",
      cached_output_digest: n.cached_output ? await sha256Hex(n.cached_output) : "",
      claimed_assets: (n.claimed_assets || []).map((a) => ({
        asset_id: a.asset_id,
        bind_mode: a.bind_mode || "RAW_MEDIA",
        r2_key: a.r2_key || "",
        source_digest: a.source_digest || ""
      })),
      is_reducer: !!n.is_reducer,
      perceptual_cache_hit: !!n.perceptual_cache_hit,
      task_scope: n.task_scope || "objective_full"
    }))
  );
  const canonical = {
    plan_schema: "v2",
    template_id: dag.template?.template_id || "",
    topology_mode: dag.topology_mode || "standard",
    target_branch_id: dag.reasoning_trace?.target_branch_id || "main",
    intent_state: dag.reasoning_trace?.intent_state || null,
    instruction_digest: instructionDigest,
    constraint_context: envelope?.constraint_context || null,
    inherited_context_slices: slices,
    nodes
  };
  return sha256Hex(JSON.stringify(canonical));
}

export async function computeTailResultHash(params: {
  finalOutput: string;
  generatedMedia: MediaArtifact[];
}): Promise<string> {
  const canonicalMedia = (params.generatedMedia || []).map((m) => ({
    asset_id: m.asset_id,
    r2_key: m.r2_key,
    source_digest: m.source_digest
  }));
  return sha256Hex(
    JSON.stringify({
      final_output: params.finalOutput || "",
      generated_media: canonicalMedia
    })
  );
}

export async function registerPresignedAssetTicket(
  env: Env,
  params: {
    assetId: string;
    userId: string;
    filename?: string;
    modality: string;
    mimeType?: string;
    fileSize?: number;
    r2Key: string;
    origin?: "upload" | "generated";
  }
): Promise<void> {
  if (!env?.DB) {
    throw new StorageUnavailableError("数据库不可用，无法登记上传凭据。");
  }
  await env.DB.prepare(
    `INSERT INTO session_assets
     (asset_id, session_id, user_id, branch_id, commit_id, filename, modality, mime_type, file_size, r2_key, source_digest, origin, introduced_round, status, summary_snippet)
     VALUES (?, '__UNBOUND__', ?, NULL, NULL, ?, ?, ?, ?, ?, NULL, ?, 0, 'UPLOADED', '')
     ON CONFLICT(user_id, asset_id) DO NOTHING`
  )
    .bind(
      params.assetId,
      params.userId,
      params.filename || params.assetId,
      params.modality || "image",
      params.mimeType || "application/octet-stream",
      Math.max(0, Math.floor(params.fileSize || 0)),
      params.r2Key,
      params.origin || "upload"
    )
    .run();
}

export const DEFAULT_EXECUTING_LEASE_SECONDS = 180;
export const AWAITING_COMMIT_LEASE_SECONDS = 900;

export function parseUtcTimestampMs(ts?: string | null): number | null {
  if (!ts || typeof ts !== "string") return null;
  const trimmed = ts.trim();
  if (!trimmed) return null;
  const normalized = trimmed.includes("T") ? trimmed : trimmed.replace(" ", "T") + "Z";
  const ms = new Date(normalized).getTime();
  return Number.isFinite(ms) ? ms : null;
}

export function isOccupancyLockActive(
  occupancyPhase?: string | null,
  lockExpiresAt?: string | null
): boolean {
  if (!occupancyPhase) return false;
  const expMs = parseUtcTimestampMs(lockExpiresAt);
  if (expMs === null) return true;
  return expMs > Date.now();
}

export async function acquireSessionExecutionLock(
  env: Env,
  params: {
    userId: string;
    sessionId: string;
    runId: string;
    clientOpId: string;
    leaseSeconds?: number;
  }
): Promise<
  | { ok: true }
  | {
      ok: false;
      reason: "session_busy";
      occupancyPhase: string | null;
      activeRunId: string | null;
      activeClientOpId: string | null;
      awaitingCommit: boolean;
    }
> {
  if (!env?.DB || !params.userId || !params.sessionId) {
    throw new StorageUnavailableError();
  }
  await ensureActiveSessionState(env, params.userId, params.sessionId);

  const leaseSec = Math.max(30, params.leaseSeconds ?? DEFAULT_EXECUTING_LEASE_SECONDS);
  const lockExpiresAt = new Date(Date.now() + leaseSec * 1000).toISOString();

  const lockRes = await env.DB.prepare(
    `UPDATE chat_session_states
     SET active_run_id = ?,
         active_client_op_id = ?,
         occupancy_phase = 'EXECUTING',
         lock_expires_at = ?,
         updated_at = CURRENT_TIMESTAMP
     WHERE user_id = ? AND session_id = ?
       AND deleted_at IS NULL
       AND (
         occupancy_phase IS NULL
         OR (lock_expires_at IS NOT NULL AND datetime(lock_expires_at) <= datetime('now'))
       )`
  )
    .bind(params.runId, params.clientOpId, lockExpiresAt, params.userId, params.sessionId)
    .run();

  if (lockRes.meta?.changes && lockRes.meta.changes > 0) {
    // Abort any stale expired PENDING runs from previous crashed leases on this session
    await env.DB.prepare(
      `UPDATE dag_run_plans
       SET commit_state = 'ABORTED',
           status = 'ABORTED',
           failure_status = 409,
           failure_code = 'session_lock_expired',
           failure_message = '上次运行占用租约已过期，已自动清理。',
           client_commit_nonce_hash = NULL,
           updated_at = CURRENT_TIMESTAMP
       WHERE user_id = ? AND session_id = ? AND commit_state = 'PENDING' AND run_id != ?`
    )
      .bind(params.userId, params.sessionId, params.runId)
      .run();
    return { ok: true };
  }

  const stateRow = await env.DB.prepare(
    "SELECT deleted_at, active_run_id, active_client_op_id, occupancy_phase FROM chat_session_states WHERE user_id = ? AND session_id = ?"
  )
    .bind(params.userId, params.sessionId)
    .first<{
      deleted_at: string | null;
      active_run_id: string | null;
      active_client_op_id: string | null;
      occupancy_phase: string | null;
    }>();

  if (stateRow?.deleted_at) {
    throw new SessionDeletedError();
  }

  const phase = stateRow?.occupancy_phase || "EXECUTING";
  return {
    ok: false,
    reason: "session_busy",
    occupancyPhase: phase,
    activeRunId: stateRow?.active_run_id || null,
    activeClientOpId: stateRow?.active_client_op_id || null,
    awaitingCommit: phase === "AWAITING_COMMIT"
  };
}

export async function renewSessionExecutionLock(
  env: Env,
  params: {
    userId: string;
    sessionId: string;
    runId: string;
    leaseSeconds?: number;
  }
): Promise<{ ok: true } | { ok: false; reason: "session_deleted" | "session_busy" }> {
  if (!env?.DB || !params.userId || !params.sessionId || !params.runId) {
    throw new StorageUnavailableError();
  }
  const leaseSec = Math.max(30, params.leaseSeconds ?? DEFAULT_EXECUTING_LEASE_SECONDS);
  const lockExpiresAt = new Date(Date.now() + leaseSec * 1000).toISOString();

  const res = await env.DB.prepare(
    `UPDATE chat_session_states
     SET active_run_id = ?,
         occupancy_phase = 'EXECUTING',
         lock_expires_at = ?,
         updated_at = CURRENT_TIMESTAMP
     WHERE user_id = ? AND session_id = ?
       AND deleted_at IS NULL
       AND (active_run_id = ? OR active_run_id IS NULL)`
  )
    .bind(params.runId, lockExpiresAt, params.userId, params.sessionId, params.runId)
    .run();

  if (res.meta?.changes && res.meta.changes > 0) {
    return { ok: true };
  }
  const row = await env.DB.prepare(
    "SELECT deleted_at FROM chat_session_states WHERE user_id = ? AND session_id = ?"
  )
    .bind(params.userId, params.sessionId)
    .first<{ deleted_at: string | null }>();
  if (row?.deleted_at) return { ok: false, reason: "session_deleted" };
  return { ok: false, reason: "session_busy" };
}

export async function markSessionAwaitingCommit(
  env: Env,
  userId: string,
  sessionId: string,
  runId: string,
  clientCommitToken?: string
): Promise<boolean> {
  if (!env?.DB || !userId || !sessionId || !runId) return false;
  const lockExpiresAt = new Date(Date.now() + AWAITING_COMMIT_LEASE_SECONDS * 1000).toISOString();
  try {
    const nonceHash = clientCommitToken ? await sha256Hex(clientCommitToken) : null;
    const batch = await env.DB.batch([
      env.DB.prepare(
        `UPDATE dag_run_plans
         SET status = 'AWAITING_COMMIT',
             updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ? AND session_id = ? AND run_id = ? AND commit_state = 'PENDING'
           AND (? IS NULL OR (exec_owner = 'BROWSER_TAIL' AND client_commit_nonce_hash = ?))
           AND EXISTS (
             SELECT 1 FROM chat_session_states
             WHERE user_id = ? AND session_id = ? AND active_run_id = ? AND deleted_at IS NULL
           )`
      ).bind(userId, sessionId, runId, nonceHash, nonceHash, userId, sessionId, runId),
      env.DB.prepare(
        `UPDATE chat_session_states
         SET occupancy_phase = 'AWAITING_COMMIT',
             active_run_id = ?,
             lock_expires_at = ?,
             updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ? AND session_id = ?
           AND deleted_at IS NULL AND active_run_id = ? AND changes() = 1`
      ).bind(runId, lockExpiresAt, userId, sessionId, runId)
    ]);
    return batch[0]?.meta.changes === 1 && batch[1]?.meta.changes === 1;
  } catch (err) {
    console.error("[SessionState] markSessionAwaitingCommit failed:", err);
    return false;
  }
}

export async function finishRunWithoutCommit(
  env: Env,
  params: {
    userId: string;
    sessionId: string;
    runId: string;
    outcome: "FAILED" | "ABORTED";
    expectedOccupancyPhase?: string;
    failureStatus?: number | null;
    failureCode?: string | null;
    failureMessage?: string | null;
  }
): Promise<{ success: boolean; sessionChanges: number; planChanges: number }> {
  if (!env?.DB || !params.userId || !params.sessionId || !params.runId) {
    return { success: false, sessionChanges: 0, planChanges: 0 };
  }
  try {
    const sessionUpdateSql = params.expectedOccupancyPhase
      ? `UPDATE chat_session_states
         SET active_run_id = NULL,
             active_client_op_id = NULL,
             occupancy_phase = NULL,
             lock_expires_at = NULL,
             updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ? AND session_id = ? AND active_run_id = ? AND occupancy_phase = ?
           AND changes() = 1`
      : `UPDATE chat_session_states
         SET active_run_id = NULL,
             active_client_op_id = NULL,
             occupancy_phase = NULL,
             lock_expires_at = NULL,
             updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ? AND session_id = ? AND active_run_id = ?`;

    const planUpdateSql = params.expectedOccupancyPhase
      ? `UPDATE dag_run_plans
         SET commit_state = ?,
             status = ?,
             failure_status = COALESCE(?, failure_status),
             failure_code = COALESCE(?, failure_code),
             failure_message = COALESCE(?, failure_message),
             client_commit_nonce_hash = NULL,
             updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ? AND session_id = ? AND run_id = ? AND commit_state = 'PENDING'
           AND EXISTS (
             SELECT 1 FROM chat_session_states
             WHERE user_id = ? AND session_id = ? AND active_run_id = ? AND occupancy_phase = ?
               AND deleted_at IS NULL
           )`
      : `UPDATE dag_run_plans
         SET commit_state = ?,
             status = ?,
             failure_status = COALESCE(?, failure_status),
             failure_code = COALESCE(?, failure_code),
             failure_message = COALESCE(?, failure_message),
             client_commit_nonce_hash = NULL,
             updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ? AND session_id = ? AND run_id = ? AND commit_state = 'PENDING'`;

    const planStmt = params.expectedOccupancyPhase
      ? env.DB.prepare(planUpdateSql).bind(
          params.outcome,
          params.outcome,
          params.failureStatus ?? null,
          params.failureCode ?? null,
          params.failureMessage ?? null,
          params.userId,
          params.sessionId,
          params.runId,
          params.userId,
          params.sessionId,
          params.runId,
          params.expectedOccupancyPhase
        )
      : env.DB.prepare(planUpdateSql).bind(
          params.outcome,
          params.outcome,
          params.failureStatus ?? null,
          params.failureCode ?? null,
          params.failureMessage ?? null,
          params.userId,
          params.sessionId,
          params.runId
        );

    const sessionStmt = params.expectedOccupancyPhase
      ? env.DB.prepare(sessionUpdateSql).bind(
          params.userId,
          params.sessionId,
          params.runId,
          params.expectedOccupancyPhase
        )
      : env.DB.prepare(sessionUpdateSql).bind(params.userId, params.sessionId, params.runId);

    const batchResults = await env.DB.batch([planStmt, sessionStmt]);
    const planChanges = Number(batchResults[0]?.meta?.changes ?? 0);
    const sessionChanges = Number(batchResults[1]?.meta?.changes ?? 0);

    return {
      success: params.expectedOccupancyPhase
        ? planChanges > 0 && sessionChanges > 0
        : sessionChanges > 0 || planChanges > 0,
      sessionChanges,
      planChanges
    };
  } catch (err) {
    console.error("[SessionState] finishRunWithoutCommit failed:", err);
    return { success: false, sessionChanges: 0, planChanges: 0 };
  }
}

/**
 * Restores server-authoritative frozen round inputs & mounted historical bindings
 * by baseCommitId before entering runOrchestrationPipeline (NM-STATE-R05).
 */
export async function restoreFrozenInputsForBaseCommit(
  env: Env,
  params: {
    userId: string;
    sessionId: string;
    baseCommit: CommitNode;
    snapshot: AuthoritativeSessionSnapshot;
    targetLanguage?: string;
    outputStyle?: string;
  }
): Promise<{
  instructionPayload: string;
  roundIndex: number;
  constraintContext: {
    target_language: "auto" | "zh" | "en";
    output_style: "concise" | "detailed" | "creative";
  };
  assetsManifest: AssetDescriptor[];
  frozenResolvedPlan: {
    intent_state: any;
    target_branch_id?: string;
    source_branch_ids?: string[];
    inherited_context_slices?: any[];
    mounted_asset_bindings?: any[];
  };
}> {
  const { userId, sessionId, baseCommit, snapshot } = params;
  const ledgerById = new Map(snapshot.session_asset_ledger.map((a) => [a.asset_id, a]));

  const enrichAssetFromLedger = (
    rawAsset: Partial<AssetDescriptor> & { asset_id: string }
  ): AssetDescriptor => {
    const ledger = ledgerById.get(rawAsset.asset_id);
    const modality =
      ((rawAsset.modality || ledger?.modality || "text_doc") as any) === "pdf"
        ? "text_doc"
        : rawAsset.modality || ledger?.modality || "text_doc";
    return {
      asset_id: rawAsset.asset_id,
      modality,
      mime_type: rawAsset.mime_type || ledger?.mime_type || "application/octet-stream",
      file_size: Number(rawAsset.file_size ?? ledger?.file_size ?? 0),
      r2_key: rawAsset.r2_key || ledger?.r2_key,
      in_memory_text: rawAsset.in_memory_text || ledger?.in_memory_text,
      consumed: false,
      source_digest:
        rawAsset.source_digest || ledger?.source_digest || ledger?.r2_key || rawAsset.asset_id,
      is_new: false,
      filename: rawAsset.filename || ledger?.filename || rawAsset.asset_id,
      origin: rawAsset.origin || ledger?.origin || "upload",
      branch_id: rawAsset.branch_id || ledger?.branch_id || baseCommit.branch_id,
      introduced_round:
        rawAsset.introduced_round ?? ledger?.introduced_round ?? baseCommit.round_index,
      introduced_commit_id:
        rawAsset.introduced_commit_id ?? ledger?.introduced_commit_id ?? baseCommit.commit_id,
      bind_mode: rawAsset.bind_mode || "RAW_MEDIA",
      summary_snippet: rawAsset.summary_snippet || ledger?.summary_snippet,
      cached_perceptual_text: rawAsset.cached_perceptual_text || ledger?.cached_perceptual_text
    };
  };

  let planRow: any = null;
  if (env?.DB && baseCommit.commit_id) {
    planRow = await env.DB.prepare(
      `SELECT dag_json, envelope_json, resolved_envelope_json
       FROM dag_run_plans
       WHERE user_id = ? AND run_id = ? AND session_id = ?`
    )
      .bind(userId, baseCommit.commit_id, sessionId)
      .first<any>()
      .catch(() => null);
  }

  const origEnv = planRow
    ? safeJsonParse<UnifiedProtocolEnvelope | null>(planRow.envelope_json, null)
    : null;
  const resolvedEnv = planRow
    ? safeJsonParse<UnifiedProtocolEnvelope | null>(planRow.resolved_envelope_json, null)
    : null;
  const baseDag = planRow ? safeJsonParse<InstantiatedDAG | null>(planRow.dag_json, null) : null;

  if (origEnv && baseDag) {
    const trace = baseDag.reasoning_trace || ({} as any);
    const traceBindings = Array.isArray(trace.mounted_asset_bindings)
      ? trace.mounted_asset_bindings
      : [];
    const manifestSource =
      resolvedEnv?.assets_manifest && resolvedEnv.assets_manifest.length > 0
        ? resolvedEnv.assets_manifest
        : origEnv.assets_manifest || [];

    const hydratedManifest: AssetDescriptor[] = [];
    for (const a of manifestSource) {
      if (!a || a.asset_id === "virtual-text-asset") continue;
      hydratedManifest.push(enrichAssetFromLedger(a));
    }

    // Also synthesize any bound ledger assets that were recalled into mounted_asset_bindings
    const seenIds = new Set(hydratedManifest.map((a) => a.asset_id));
    for (const b of traceBindings) {
      if (!b || b.bind_mode === "DROP" || seenIds.has(b.asset_id)) continue;
      const ledgerItem = ledgerById.get(b.asset_id);
      if (ledgerItem) {
        hydratedManifest.push(enrichAssetFromLedger({ ...ledgerItem, bind_mode: b.bind_mode }));
        seenIds.add(b.asset_id);
      }
    }

    const effectiveBindings =
      traceBindings.length > 0
        ? traceBindings
        : hydratedManifest.map((a) => ({
            asset_id: a.asset_id,
            bind_mode: (a.bind_mode || "RAW_MEDIA") as AssetBindMode
          }));

    return {
      instructionPayload: origEnv.instruction_payload || baseCommit.user_prompt || "",
      roundIndex: Number(origEnv.round_index || baseCommit.round_index || 1),
      constraintContext: {
        target_language:
          (origEnv.constraint_context?.target_language as any) ||
          (params.targetLanguage as any) ||
          "auto",
        output_style:
          (origEnv.constraint_context?.output_style as any) ||
          (params.outputStyle as any) ||
          "concise"
      },
      assetsManifest: hydratedManifest,
      frozenResolvedPlan: {
        intent_state: trace.intent_state ?? baseCommit.intent_op ?? null,
        target_branch_id: trace.target_branch_id || baseCommit.branch_id,
        source_branch_ids: trace.source_branch_ids || baseCommit.evidence_source_branches || [],
        inherited_context_slices: trace.inherited_context_slices || [],
        mounted_asset_bindings: effectiveBindings
      }
    };
  }

  // Fallback for pre-0025 migrated commits without dag_run_plans rows
  const fallbackBindings: Array<{ asset_id: string; bind_mode: Exclude<AssetBindMode, "DROP"> }> =
    [];
  const seenFallback = new Set<string>();
  for (const m of baseCommit.mounted_assets || []) {
    if (!m?.asset_id || seenFallback.has(m.asset_id)) continue;
    seenFallback.add(m.asset_id);
    fallbackBindings.push({ asset_id: m.asset_id, bind_mode: m.bind_mode || "RAW_MEDIA" });
  }
  for (const introId of baseCommit.introduced_asset_ids || []) {
    if (!introId || seenFallback.has(introId)) continue;
    seenFallback.add(introId);
    fallbackBindings.push({ asset_id: introId, bind_mode: "RAW_MEDIA" });
  }

  const fallbackManifest: AssetDescriptor[] = [];
  for (const b of fallbackBindings) {
    const ledgerItem = ledgerById.get(b.asset_id);
    if (ledgerItem) {
      fallbackManifest.push(enrichAssetFromLedger({ ...ledgerItem, bind_mode: b.bind_mode }));
    }
  }

  const fallbackSlices: Array<{
    branch_id: string;
    topic: string;
    commit_id?: string;
    summary: string;
    relation: "active" | "recalled" | "evidence";
  }> = [];
  const parentCommit = baseCommit.parents?.[0]
    ? snapshot.commits[baseCommit.parents[0]]
    : undefined;
  if (parentCommit?.output_summary) {
    fallbackSlices.push({
      branch_id: baseCommit.branch_id,
      topic: snapshot.branches[baseCommit.branch_id]?.topic || "前序任务产物",
      commit_id: parentCommit.commit_id,
      summary: parentCommit.output_summary,
      relation: "active"
    });
  }
  for (const srcBranch of baseCommit.evidence_source_branches || []) {
    const br = snapshot.branches[srcBranch];
    if (br?.last_summary) {
      fallbackSlices.push({
        branch_id: srcBranch,
        topic: br.topic || "历史分支",
        commit_id: br.head_commit_id || undefined,
        summary: br.last_summary,
        relation: "evidence"
      });
    }
  }

  return {
    instructionPayload: baseCommit.user_prompt || "",
    roundIndex: Number(baseCommit.round_index || 1),
    constraintContext: {
      target_language: (params.targetLanguage as any) || "auto",
      output_style: (params.outputStyle as any) || "concise"
    },
    assetsManifest: fallbackManifest,
    frozenResolvedPlan: {
      intent_state: baseCommit.intent_op ?? null,
      target_branch_id: baseCommit.branch_id,
      source_branch_ids: baseCommit.evidence_source_branches || [],
      inherited_context_slices: fallbackSlices,
      mounted_asset_bindings: fallbackBindings
    }
  };
}

/**
 * Ensures an active (non-deleted) chat_session_states row exists for (userId, sessionId).
 * Fails closed on deleted sessions or DB errors.
 */
export async function ensureActiveSessionState(
  env: Env,
  userId: string,
  sessionId: string
): Promise<void> {
  if (!env?.DB || !userId || !sessionId) {
    throw new StorageUnavailableError();
  }
  const existing = await env.DB.prepare(
    "SELECT deleted_at FROM chat_session_states WHERE user_id = ? AND session_id = ?"
  )
    .bind(userId, sessionId)
    .first<{ deleted_at: string | null }>();

  if (existing?.deleted_at) {
    throw new SessionDeletedError();
  }
  if (!existing) {
    await env.DB.prepare(
      `INSERT INTO chat_session_states (session_id, user_id, active_branch_id, version, deleted_at)
       VALUES (?, ?, 'main', 1, NULL)
       ON CONFLICT(user_id, session_id) DO NOTHING`
    )
      .bind(sessionId, userId)
      .run();
  }
}

/**
 * Loads the server-authoritative Git tree, asset ledger, and scoped L1 perceptual cache.
 * Fail-closed on DB errors or tombstoned (deleted) sessions.
 */
export async function loadAuthoritativeSessionState(
  env: Env,
  userId: string,
  sessionId: string
): Promise<AuthoritativeSessionSnapshot> {
  if (!env?.DB || !sessionId || !userId) {
    throw new StorageUnavailableError();
  }

  const stateRow = await env.DB.prepare(
    "SELECT active_branch_id, version, deleted_at, active_run_id, occupancy_phase, lock_expires_at FROM chat_session_states WHERE user_id = ? AND session_id = ?"
  )
    .bind(userId, sessionId)
    .first<{
      active_branch_id: string;
      version: number;
      deleted_at: string | null;
      active_run_id?: string | null;
      occupancy_phase?: string | null;
      lock_expires_at?: string | null;
    }>();

  if (stateRow?.deleted_at) {
    throw new SessionDeletedError();
  }

  const activeBranchId = stateRow?.active_branch_id || "main";
  const version = Number(stateRow?.version || 1);
  const lockActive = isOccupancyLockActive(stateRow?.occupancy_phase, stateRow?.lock_expires_at);
  const occupancyPhase: "EXECUTING" | "AWAITING_COMMIT" | null =
    lockActive &&
    (stateRow?.occupancy_phase === "EXECUTING" || stateRow?.occupancy_phase === "AWAITING_COMMIT")
      ? stateRow.occupancy_phase
      : null;
  const activeRunId = occupancyPhase ? stateRow?.active_run_id || null : null;

  let awaitingCommit: AuthoritativeSessionSnapshot["awaiting_commit"] = null;
  if (occupancyPhase === "AWAITING_COMMIT" && activeRunId) {
    const pendingPlan = await env.DB.prepare(
      "SELECT exec_owner, commit_state, tail_result_hash FROM dag_run_plans WHERE user_id = ? AND run_id = ? AND session_id = ?"
    )
      .bind(userId, activeRunId, sessionId)
      .first<{ exec_owner: string; commit_state: string; tail_result_hash?: string | null }>()
      .catch(() => null);
    if (pendingPlan && pendingPlan.commit_state === "PENDING") {
      awaitingCommit = {
        run_id: activeRunId,
        exec_owner: String(pendingPlan.exec_owner || "CLOUD"),
        can_retry_commit:
          pendingPlan.exec_owner !== "BROWSER_TAIL" ? !!pendingPlan.tail_result_hash : false
      };
    }
  }

  const branchRows = await env.DB.prepare(
    "SELECT * FROM session_branches WHERE user_id = ? AND session_id = ?"
  )
    .bind(userId, sessionId)
    .all<any>();

  const commitRows = await env.DB.prepare(
    "SELECT * FROM session_commits WHERE user_id = ? AND session_id = ? ORDER BY round_index ASC, created_at ASC"
  )
    .bind(userId, sessionId)
    .all<any>();

  const assetRows = await env.DB.prepare(
    "SELECT * FROM session_assets WHERE user_id = ? AND session_id = ? ORDER BY introduced_round ASC, created_at ASC"
  )
    .bind(userId, sessionId)
    .all<any>();

  const cacheRows = await env.DB.prepare(
    "SELECT * FROM asset_perceptual_cache WHERE user_id = ? AND session_id = ? ORDER BY updated_at DESC"
  )
    .bind(userId, sessionId)
    .all<any>();

  const branches: Record<string, AuthoritativeBranchSummary> = {};
  const branchCatalog: AuthoritativeBranchSummary[] = [];
  for (const r of branchRows.results || []) {
    const summaryStr = String(r.last_summary || "");
    const br: AuthoritativeBranchSummary = {
      branch_id: r.branch_id,
      topic: r.topic || "主线任务",
      is_active: r.branch_id === activeBranchId,
      head_commit_id: r.head_commit_id || "",
      dominant_modalities: safeJsonParse<string[]>(r.dominant_modalities, []),
      has_summary: summaryStr.trim().length > 0,
      last_summary: summaryStr,
      lineage_asset_ids: safeJsonParse<string[]>(r.lineage_asset_ids, [])
    };
    branches[r.branch_id] = br;
    branchCatalog.push(br);
  }

  const commits: Record<string, CommitNode> = {};
  const commitOrder: string[] = [];
  for (const c of commitRows.results || []) {
    const sourceRefs = safeJsonParse<SourceRefEntry[]>(c.source_refs_json, []);
    const node: CommitNode = {
      commit_id: c.commit_id,
      parents: c.parent_commit_id ? [c.parent_commit_id] : [],
      branch_id: c.branch_id,
      evidence_source_branches: Array.from(
        new Set(sourceRefs.map((s) => s.branch_id).filter((b) => b && b !== c.branch_id))
      ),
      source_refs: sourceRefs,
      round_index: Number(c.round_index || 1),
      revision: Number(c.revision || 1),
      intent_op: c.intent_op || null,
      user_prompt: c.user_prompt || "",
      mounted_assets: safeJsonParse<any[]>(c.mounted_assets_json, []),
      introduced_asset_ids: safeJsonParse<string[]>(c.introduced_asset_ids_json, []),
      generated_asset_ids: safeJsonParse<string[]>(c.generated_asset_ids_json, []),
      template_id: c.template_id || undefined,
      output_summary: c.output_summary || "",
      timestamp: Number(c.created_at || Date.now())
    };
    commits[c.commit_id] = node;
    commitOrder.push(c.commit_id);
  }

  const perceptualCache: Record<string, PerceptualCacheEntry> = {};
  const objectiveByDigest = new Map<string, PerceptualCacheEntry>();
  for (const pc of cacheRows.results || []) {
    const entry: PerceptualCacheEntry = {
      source_digest: pc.source_digest,
      modality: pc.modality === "audio" ? "audio" : "image",
      role_id: pc.role_id,
      model_id: pc.model_id,
      task_scope: pc.task_scope === "focused_or_custom" ? "focused_or_custom" : "objective_full",
      prompt_digest: pc.prompt_digest || "default",
      percept_key: pc.percept_key,
      extracted_text: pc.extracted_text || "",
      summary_snippet: pc.summary_snippet || "",
      updated_at: Number(pc.updated_at || Date.now())
    };
    perceptualCache[pc.percept_key] = entry;
    if (entry.task_scope === "objective_full" && !objectiveByDigest.has(entry.source_digest)) {
      perceptualCache[entry.source_digest] = entry;
      objectiveByDigest.set(entry.source_digest, entry);
    }
  }

  const sessionAssetLedger: SessionAssetLedgerItem[] = [];
  const committedR2Keys = new Set<string>();
  for (const a of assetRows.results || []) {
    if (a.status !== "COMMITTED") continue;
    if (a.r2_key) committedR2Keys.add(a.r2_key);
    if (a.text_r2_key) committedR2Keys.add(a.text_r2_key);
    const cachedHit = a.source_digest ? objectiveByDigest.get(a.source_digest) : undefined;
    sessionAssetLedger.push({
      asset_id: a.asset_id,
      filename: a.filename || a.asset_id,
      modality: (a.modality || "image") as any,
      mime_type: a.mime_type || "application/octet-stream",
      file_size: Number(a.file_size || 0),
      introduced_round: Number(a.introduced_round || 1),
      introduced_commit_id: a.commit_id || undefined,
      branch_id: a.branch_id || activeBranchId,
      r2_key: a.r2_key || undefined,
      text_r2_key: a.text_r2_key || undefined,
      in_memory_text: typeof a.in_memory_text === "string" ? a.in_memory_text : undefined,
      source_digest: a.source_digest || a.r2_key || a.asset_id,
      origin: (a.origin || "upload") as any,
      summary_snippet: cachedHit?.summary_snippet || a.summary_snippet || "",
      cached_perceptual_text: cachedHit?.extracted_text || undefined
    });
  }

  return {
    session_id: sessionId,
    active_branch_id: activeBranchId,
    version,
    deleted: false,
    occupancy_phase: occupancyPhase,
    active_run_id: activeRunId,
    awaiting_commit: awaitingCommit,
    branches,
    branch_catalog: branchCatalog,
    commits,
    commit_order: commitOrder,
    session_asset_ledger: sessionAssetLedger,
    perceptual_cache: perceptualCache,
    committed_r2_keys: committedR2Keys
  };
}

/**
 * Strips heavy inline document text from public /state HTTP JSON responses to minimize payload size.
 */
export function buildPublicSessionSnapshot(snapshot: AuthoritativeSessionSnapshot) {
  return {
    ...snapshot,
    committed_r2_keys: Array.from(snapshot.committed_r2_keys),
    session_asset_ledger: snapshot.session_asset_ledger.map(
      ({ in_memory_text, text_r2_key: _tr2, ...rest }) => ({
        ...rest,
        has_text_body: !!(in_memory_text || _tr2)
      })
    )
  };
}

/**
 * Hydrates persisted Shift-Left text_doc body from R2 when missing inline on a mounted asset descriptor.
 */
export async function hydrateDocumentTextBodies(
  env: Env,
  userId: string,
  sessionId: string,
  assets: Array<AssetDescriptor | SessionAssetLedgerItem>
): Promise<void> {
  if (!assets || assets.length === 0) return;
  for (const a of assets) {
    if (a.modality !== "text_doc" && (a.modality as string) !== "text") continue;
    if (a.in_memory_text && a.in_memory_text.trim().length > 0) continue;

    const row = await env.DB.prepare(
      "SELECT in_memory_text, text_r2_key FROM session_assets WHERE user_id = ? AND session_id = ? AND asset_id = ? AND status = 'COMMITTED'"
    )
      .bind(userId, sessionId, a.asset_id)
      .first<{ in_memory_text: string | null; text_r2_key: string | null }>();

    if (row?.in_memory_text && row.in_memory_text.trim().length > 0) {
      a.in_memory_text = row.in_memory_text;
      continue;
    }

    if (row?.text_r2_key && env.R2) {
      const auth = await verifySessionAssetR2Access(env, userId, sessionId, {
        asset_id: a.asset_id,
        filename: a.filename,
        modality: a.modality,
        mime_type: a.mime_type || "text/plain",
        file_size: a.file_size || 0,
        source_digest: a.source_digest || a.asset_id,
        consumed: false,
        r2_key: row.text_r2_key
      });
      if (auth.status === "storage_unavailable") {
        throw new StorageUnavailableError(auth.reason);
      }
      if (auth.status === "denied_unowned") {
        throw new Error(`安全违规：拒绝读取未授权的文档正文对象 (${a.asset_id})`);
      }
      const r2Obj = await env.R2.get(row.text_r2_key);
      if (r2Obj) {
        a.in_memory_text = await r2Obj.text();
      }
    }

    const bindMode = "bind_mode" in a ? a.bind_mode : undefined;
    if (
      (a.modality === "text_doc" ||
        ((a.modality as string) === "text" && a.asset_id !== "virtual-text-asset")) &&
      bindMode !== "DROP" &&
      !a.in_memory_text
    ) {
      throw new Error(
        `历史文档【${a.filename || a.asset_id}】正文不可用或已过期，请重新上传后再继续处理。`
      );
    }
  }
}

/**
 * Atomically binds presigned/uploaded R2 tickets from '__UNBOUND__' into (userId, sessionId).
 * Also re-mints fresh server UUIDs for newly submitted Shift-Left inline documents (no R2 key)
 * so client-chosen asset_ids can never collide with existing rows.
 */
export async function claimSessionUploads(
  env: Env,
  userId: string,
  sessionId: string,
  assets: AssetDescriptor[],
  roundIndex: number
): Promise<
  { ok: true } | { ok: false; httpStatus: 403 | 409 | 503; code: string; reason: string }
> {
  if (!env?.DB) {
    return {
      ok: false,
      httpStatus: 503,
      code: "storage_unavailable",
      reason: "资产所有权数据库不可用，请稍后重试。"
    };
  }
  if (!assets || assets.length === 0) return { ok: true };

  const safePrefix = `tmp/${userId}/`;

  for (const asset of assets) {
    // Assign canonical digest for Shift-Left inline documents before downstream hashing
    if (
      (asset.modality === "text_doc" || asset.modality === "text") &&
      asset.in_memory_text &&
      asset.asset_id !== "virtual-text-asset"
    ) {
      asset.source_digest = await sha256Hex(asset.in_memory_text);
    }

    if (!asset.r2_key) {
      // Shift-Left inline document (no R2 object): mint fresh server asset_id on new uploads to prevent PK spoofing
      if (asset.is_new === true && asset.asset_id !== "virtual-text-asset") {
        const collision = await env.DB.prepare(
          "SELECT session_id FROM session_assets WHERE user_id = ? AND asset_id = ?"
        )
          .bind(userId, asset.asset_id)
          .first<{ session_id: string }>();
        if (collision && collision.session_id !== sessionId) {
          asset.asset_id = crypto.randomUUID();
        }
      }
      continue;
    }

    if (!asset.r2_key.startsWith(safePrefix)) {
      return {
        ok: false,
        httpStatus: 403,
        code: "asset_ownership_violation",
        reason: `禁止读取越权路径对象: ${asset.r2_key}`
      };
    }

    if (asset.is_new === true) {
      // Conditional atomic claim strictly from '__UNBOUND__' -> target sessionId for the matching userId & r2_key
      const updateRes = await env.DB.prepare(
        `UPDATE session_assets
         SET session_id = ?,
             source_digest = COALESCE(source_digest, ?),
             introduced_round = ?
         WHERE user_id = ?
           AND asset_id = ?
           AND r2_key = ?
           AND session_id = '__UNBOUND__'`
      )
        .bind(
          sessionId,
          asset.source_digest || asset.r2_key,
          Math.max(1, roundIndex || 1),
          userId,
          asset.asset_id,
          asset.r2_key
        )
        .run();

      if (!updateRes.meta?.changes || updateRes.meta.changes === 0) {
        // Inspect authoritative state: only allow idempotent claim by the SAME (userId, sessionId, assetId, r2Key)
        const existing = await env.DB.prepare(
          "SELECT asset_id, session_id, user_id, r2_key, status FROM session_assets WHERE user_id = ? AND (r2_key = ? OR asset_id = ?)"
        )
          .bind(userId, asset.r2_key, asset.asset_id)
          .first<{
            asset_id: string;
            session_id: string;
            user_id: string;
            r2_key: string;
            status: string;
          }>();

        if (!existing) {
          return {
            ok: false,
            httpStatus: 403,
            code: "asset_ownership_violation",
            reason: `未登记的临时上传对象，拒绝未经预签/直传登记直接认领: ${asset.r2_key}`
          };
        }
        if (
          existing.session_id !== sessionId ||
          existing.asset_id !== asset.asset_id ||
          existing.r2_key !== asset.r2_key
        ) {
          return {
            ok: false,
            httpStatus: existing.session_id === "__UNBOUND__" ? 403 : 409,
            code: "asset_ownership_violation",
            reason: `安全违规：资产对象已被占用或属于其他会话 (${existing.session_id})`
          };
        }
      }
    } else {
      // Historical reference: verify strictly committed in this (userId, sessionId)
      const existing = await env.DB.prepare(
        "SELECT asset_id, session_id FROM session_assets WHERE user_id = ? AND r2_key = ?"
      )
        .bind(userId, asset.r2_key)
        .first<{ asset_id: string; session_id: string }>();

      if (!existing || existing.session_id !== sessionId) {
        return {
          ok: false,
          httpStatus: 403,
          code: "asset_ownership_violation",
          reason: `安全违规：拒绝跨会话或未经登记引用历史资产 (${asset.r2_key})`
        };
      }
    }
  }

  return { ok: true };
}

/**
 * Discriminated fail-closed R2 asset ownership check before any R2 read or cache lookup.
 */
export async function verifySessionAssetR2Access(
  env: Env,
  userId: string,
  sessionId: string,
  asset: AssetDescriptor
): Promise<VerifyAssetAccessResult> {
  if (!asset.r2_key) return { status: "allowed" };

  const safePrefix = `tmp/${userId}/`;
  if (!asset.r2_key.startsWith(safePrefix)) {
    return { status: "denied_unowned", reason: "禁止访问跨账户 R2 路径对象" };
  }
  if (!env?.DB) {
    return { status: "storage_unavailable", reason: "资产归属数据库不可用" };
  }

  try {
    const row = await env.DB.prepare(
      "SELECT user_id, session_id, status FROM session_assets WHERE user_id = ? AND (r2_key = ? OR text_r2_key = ?)"
    )
      .bind(userId, asset.r2_key, asset.r2_key)
      .first<{ user_id: string; session_id: string; status: string }>();

    if (!row) {
      return { status: "denied_unowned", reason: "资产对象未在当前会话登记授权" };
    }
    if (row.session_id === sessionId) {
      return { status: "allowed" };
    }
    if (row.session_id === "__UNBOUND__" && asset.is_new === true) {
      return { status: "allowed" };
    }
    return { status: "denied_unowned", reason: `禁止跨会话读取资产 (${row.session_id})` };
  } catch (err) {
    console.error("[SessionState] verifySessionAssetR2Access DB failure:", err);
    return { status: "storage_unavailable", reason: "资产归属验证存储服务不可用" };
  }
}

export async function registerStagingGeneratedAsset(
  env: Env,
  params: {
    userId: string;
    sessionId: string;
    assetId: string;
    modality: "image" | "audio" | "text_doc";
    mimeType: string;
    r2Key?: string;
    textR2Key?: string;
    fileSize?: number;
  }
): Promise<void> {
  if (!env?.DB) throw new StorageUnavailableError();
  const res = await env.DB.prepare(
    `INSERT INTO session_assets
     (asset_id, session_id, user_id, branch_id, commit_id, filename, modality, mime_type, file_size, r2_key, text_r2_key, origin, introduced_round, status, summary_snippet)
     SELECT ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?, ?, 'generated', 0, 'STAGING', ''
     WHERE EXISTS (
       SELECT 1 FROM chat_session_states s
       WHERE s.user_id = ? AND s.session_id = ? AND s.deleted_at IS NULL
     )`
  )
    .bind(
      params.assetId,
      params.sessionId,
      params.userId,
      `${params.assetId}.bin`,
      params.modality,
      params.mimeType,
      Math.max(0, Math.floor(params.fileSize || 0)),
      params.r2Key || "",
      params.textR2Key || null,
      params.userId,
      params.sessionId
    )
    .run();

  if (!res.meta?.changes || res.meta.changes === 0) {
    throw new SessionDeletedError("会话已删除或不存在，中止写入临时对象。");
  }
}

/**
 * Computes canonical request digest for first-submit idempotency verification (REV-02).
 */
export async function computeClientOpRequestDigest(params: {
  instructionPayload: string;
  assets: AssetDescriptor[];
  isReRun: boolean;
  baseCommitId?: string;
  reRouteMode?: string;
  chosenTemplateId?: string;
  chosenRoleModels?: Record<string, string>;
  customRolePrompts?: Record<string, string>;
  customNodePrompt?: string;
  resolvedClarificationTargetBranchId?: string;
}): Promise<string> {
  return sha256Hex(
    JSON.stringify({
      instruction: params.instructionPayload || "",
      assets: (params.assets || []).map((a) => ({
        id: a.asset_id,
        digest: a.source_digest || "",
        r2: a.r2_key || "",
        is_new: !!a.is_new
      })),
      is_rerun: !!params.isReRun,
      base_commit_id: params.baseCommitId || "",
      reroute: params.reRouteMode || "normal",
      tpl: params.chosenTemplateId || "",
      models: params.chosenRoleModels || null,
      prompts: params.customRolePrompts || null,
      node_prompt: params.customNodePrompt || "",
      clarify_target: params.resolvedClarificationTargetBranchId || ""
    })
  );
}

/**
 * Atomically registers client_op_id & persists the frozen DAG plan BEFORE pre-deduction & dispatch (REV-02).
 * Throws StorageUnavailableError on D1 error (fail-closed, never silently continues!).
 */
export async function registerAndFreezeDagRunPlan(
  env: Env,
  params: {
    runId: string;
    userId: string;
    sessionId: string;
    clientOpId: string;
    requestDigest: string;
    planHash: string;
    dag: InstantiatedDAG;
    originalEnvelope: UnifiedProtocolEnvelope;
    resolvedEnvelope: UnifiedProtocolEnvelope;
    isReRun: boolean;
    baseCommitId?: string;
    expectedParentCommitId: string | null;
    expectedBaseRevision: number | null;
  }
): Promise<
  | { outcome: "created"; runId: string }
  | { outcome: "op_conflict" }
  | {
      outcome: "already_completed";
      runId: string;
      snapshot: AuthoritativeSessionSnapshot;
      finalOutput: string;
    }
  | { outcome: "in_progress"; runId: string }
  | {
      outcome: "failed_terminal";
      runId: string;
      failureStatus?: number;
      failureCode?: string;
      failureMessage?: string;
    }
> {
  if (!env?.DB) throw new StorageUnavailableError();

  await ensureActiveSessionState(env, params.userId, params.sessionId);

  const insertRes = await env.DB.prepare(
    `INSERT INTO dag_run_plans
     (run_id, user_id, session_id, client_op_id, request_digest, plan_hash, dag_json, envelope_json, resolved_envelope_json, step_outputs_json,
      is_rerun, base_commit_id, expected_parent_commit_id, expected_base_revision, exec_owner, commit_state, status, updated_at)
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', ?, ?, ?, ?, 'CLOUD', 'PENDING', 'RUNNING', CURRENT_TIMESTAMP
     WHERE EXISTS (
       SELECT 1 FROM chat_session_states s
       WHERE s.user_id = ? AND s.session_id = ? AND s.deleted_at IS NULL
     )
     ON CONFLICT(user_id, session_id, client_op_id) DO NOTHING`
  )
    .bind(
      params.runId,
      params.userId,
      params.sessionId,
      params.clientOpId,
      params.requestDigest,
      params.planHash,
      JSON.stringify(params.dag),
      JSON.stringify(params.originalEnvelope),
      JSON.stringify(params.resolvedEnvelope),
      params.isReRun ? 1 : 0,
      params.baseCommitId || null,
      params.expectedParentCommitId,
      params.expectedBaseRevision,
      params.userId,
      params.sessionId
    )
    .run();

  if (insertRes.meta?.changes && insertRes.meta.changes > 0) {
    return { outcome: "created", runId: params.runId };
  }

  // Either session was just deleted, or client_op_id collided
  const sRow = await env.DB.prepare(
    "SELECT deleted_at FROM chat_session_states WHERE user_id = ? AND session_id = ?"
  )
    .bind(params.userId, params.sessionId)
    .first<{ deleted_at: string | null }>();
  if (sRow?.deleted_at) {
    throw new SessionDeletedError();
  }

  const existing = await env.DB.prepare(
    "SELECT run_id, request_digest, commit_state, tail_result_json, failure_status, failure_code, failure_message FROM dag_run_plans WHERE user_id = ? AND session_id = ? AND client_op_id = ?"
  )
    .bind(params.userId, params.sessionId, params.clientOpId)
    .first<any>();

  if (!existing) {
    throw new StorageUnavailableError("冻结运行计划登记异常，请重试。");
  }
  if (existing.request_digest !== params.requestDigest) {
    return { outcome: "op_conflict" };
  }
  if (existing.commit_state === "COMMITTED") {
    const snap = await loadAuthoritativeSessionState(env, params.userId, params.sessionId);
    const parsedTail = safeJsonParse<any>(existing.tail_result_json, {});
    return {
      outcome: "already_completed",
      runId: existing.run_id,
      snapshot: snap,
      finalOutput: parsedTail?.finalOutput || ""
    };
  }
  if (existing.commit_state === "FAILED" || existing.commit_state === "ABORTED") {
    return {
      outcome: "failed_terminal" as any,
      runId: existing.run_id,
      failureStatus: Number(existing.failure_status || 409),
      failureCode: String(existing.failure_code || "run_aborted"),
      failureMessage: String(
        existing.failure_message || "该操作已失败或被中止，请使用新请求重新发起。"
      )
    };
  }
  return { outcome: "in_progress", runId: existing.run_id };
}

export async function loadAndVerifyDagRunPlan(
  env: Env,
  userId: string,
  runId: string,
  expectedPlanHash: string,
  expectedSessionId: string
): Promise<{
  dag: InstantiatedDAG;
  envelope: UnifiedProtocolEnvelope;
  resolvedEnvelope: UnifiedProtocolEnvelope;
  stepOutputs: Record<string, string>;
  isReRun: boolean;
  baseCommitId?: string;
  expectedParentCommitId: string | null;
  expectedBaseRevision: number | null;
  execOwner: string;
  commitState: string;
  clientCommitNonceHash: string | null;
  tailResultJson: any | null;
  tailResultHash: string | null;
} | null> {
  if (!env?.DB || !runId || !userId) return null;

  const sRow = await env.DB.prepare(
    "SELECT deleted_at FROM chat_session_states WHERE user_id = ? AND session_id = ?"
  )
    .bind(userId, expectedSessionId)
    .first<{ deleted_at: string | null }>();
  if (sRow?.deleted_at) {
    return null;
  }

  const row = await env.DB.prepare(
    `SELECT user_id, session_id, plan_hash, dag_json, envelope_json, resolved_envelope_json, step_outputs_json,
            is_rerun, base_commit_id, expected_parent_commit_id, expected_base_revision,
            exec_owner, commit_state, client_commit_nonce_hash, tail_result_json, tail_result_hash
     FROM dag_run_plans
     WHERE user_id = ? AND run_id = ? AND session_id = ?`
  )
    .bind(userId, runId, expectedSessionId)
    .first<any>();

  if (!row) return null;
  if (expectedPlanHash && row.plan_hash !== expectedPlanHash) return null;

  const dag = safeJsonParse<InstantiatedDAG | null>(row.dag_json, null);
  const envelope = safeJsonParse<UnifiedProtocolEnvelope | null>(row.envelope_json, null);
  const resolvedEnvelope =
    safeJsonParse<UnifiedProtocolEnvelope | null>(row.resolved_envelope_json, null) || envelope;
  if (!dag || !envelope || !resolvedEnvelope) return null;

  return {
    dag,
    envelope,
    resolvedEnvelope,
    stepOutputs: safeJsonParse<Record<string, string>>(row.step_outputs_json, {}),
    isReRun: Number(row.is_rerun || 0) === 1,
    baseCommitId: row.base_commit_id || undefined,
    expectedParentCommitId: row.expected_parent_commit_id || null,
    expectedBaseRevision:
      row.expected_base_revision !== null && row.expected_base_revision !== undefined
        ? Number(row.expected_base_revision)
        : null,
    execOwner: String(row.exec_owner || "CLOUD"),
    commitState: String(row.commit_state || "PENDING"),
    clientCommitNonceHash: row.client_commit_nonce_hash || null,
    tailResultJson: safeJsonParse<any>(row.tail_result_json, null),
    tailResultHash: row.tail_result_hash || null
  };
}

export async function persistDagStepOutputs(
  env: Env,
  runId: string,
  userId: string,
  stepOutputs: Record<string, string>
): Promise<void> {
  if (!env?.DB || !runId || !userId) return;
  await env.DB.prepare(
    "UPDATE dag_run_plans SET step_outputs_json = ?, updated_at = CURRENT_TIMESTAMP WHERE user_id = ? AND run_id = ?"
  )
    .bind(JSON.stringify(stepOutputs), userId, runId)
    .run();
}

export async function acquireBrowserTailCredential(
  env: Env,
  userId: string,
  sessionId: string,
  runId: string
): Promise<string> {
  if (!env?.DB || !runId || !userId) throw new StorageUnavailableError();
  const token = `${crypto.randomUUID()}.${crypto.randomUUID()}`;
  const nonceHash = await sha256Hex(token);
  const res = await env.DB.prepare(
    `UPDATE dag_run_plans
     SET exec_owner = 'BROWSER_TAIL',
         client_commit_nonce_hash = ?,
         updated_at = CURRENT_TIMESTAMP
     WHERE user_id = ? AND run_id = ? AND session_id = ? AND commit_state = 'PENDING'
       AND EXISTS (
         SELECT 1 FROM chat_session_states s
         WHERE s.user_id = ? AND s.session_id = ? AND s.deleted_at IS NULL
       )`
  )
    .bind(nonceHash, userId, runId, sessionId, userId, sessionId)
    .run();
  if (!res.meta?.changes || res.meta.changes === 0) {
    throw new Error("无法锁定浏览器尾节点交付凭据（运行已被接管、提交或删除）。");
  }
  return token;
}

export async function claimCloudFailoverOwnership(
  env: Env,
  userId: string,
  sessionId: string,
  runId: string
): Promise<boolean> {
  if (!env?.DB || !runId || !userId) return false;
  const res = await env.DB.prepare(
    `UPDATE dag_run_plans
     SET exec_owner = 'CLOUD_FAILOVER',
         client_commit_nonce_hash = NULL,
         updated_at = CURRENT_TIMESTAMP
     WHERE user_id = ? AND run_id = ? AND session_id = ?
       AND exec_owner = 'BROWSER_TAIL'
       AND commit_state = 'PENDING'`
  )
    .bind(userId, runId, sessionId)
    .run();
  return !!(res.meta?.changes && res.meta.changes > 0);
}

/**
 * Records per-stage idempotent compute billing settlement inside a D1 batch (REV-03).
 */
interface BillingPhaseParams {
  userId: string;
  runId: string;
  phase: string;
  actualCost: number;
  reservedCredits: number;
  templateNameZh?: string;
  detailLabel?: string;
}

export async function settleRunBillingPhase(
  env: Env,
  params: BillingPhaseParams,
  fromQueue = false
): Promise<boolean> {
  if (!env?.DB) return false;
  const { userId, runId, phase, actualCost, reservedCredits } = params;
  const key = [userId, runId, phase] as const;
  const pending = fromQueue
    ? "EXISTS (SELECT 1 FROM pending_billing_settlements WHERE user_id = ? AND run_id = ? AND phase = ?)"
    : "1";
  const gateArgs = fromQueue ? key : [];
  try {
    const statements = [
      env.DB.prepare(
        `INSERT INTO run_billing_settlements (user_id, run_id, phase, amount, reserved_credits)
         SELECT ?, ?, ?, ?, ? WHERE ${pending}`
      ).bind(...key, actualCost, reservedCredits, ...gateArgs)
    ];
    const refundDelta = reservedCredits - actualCost;
    if (refundDelta > 0) {
      statements.push(
        env.DB.prepare(
          `UPDATE users SET credits = credits + ? WHERE user_id = ? AND ${pending}`
        ).bind(refundDelta, userId, ...gateArgs)
      );
    } else if (refundDelta < 0) {
      statements.push(
        env.DB.prepare(
          `UPDATE users SET credits = MAX(0, credits - ?) WHERE user_id = ? AND ${pending}`
        ).bind(Math.abs(refundDelta), userId, ...gateArgs)
      );
    }
    if (actualCost > 0) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO credit_ledger
           (ledger_id, user_id, category, amount, balance, title, detail, created_at)
           SELECT ?, ?, 'compute_cost', ?, (SELECT credits FROM users WHERE user_id = ?), 'DAG智能编排调用', ?, datetime('now')
           WHERE ${pending}`
        ).bind(
          crypto.randomUUID(),
          userId,
          -actualCost,
          userId,
          params.detailLabel || `执行模板: ${params.templateNameZh}`,
          ...gateArgs
        )
      );
    }
    await env.DB.batch(statements);
    return true;
  } catch (err) {
    // A conflicting plain INSERT rolls back the batch, including balance and ledger writes.
    try {
      const existing = await env.DB.prepare(
        "SELECT amount, reserved_credits FROM run_billing_settlements WHERE user_id = ? AND run_id = ? AND phase = ?"
      )
        .bind(...key)
        .first<{ amount: number; reserved_credits: number | null }>();
      if (
        existing &&
        existing.amount === actualCost &&
        (existing.reserved_credits == null || existing.reserved_credits === reservedCredits)
      ) {
        return true;
      }
    } catch (lookupErr) {
      console.error("[BillingPhase] Failed to confirm prior settlement:", lookupErr);
    }
    console.error(`[BillingPhase] Failed to settle phase=${phase} run=${runId}:`, err);
    return false;
  }
}

export async function settleOrQueueBillingPhase(
  env: Env,
  params: BillingPhaseParams
): Promise<"settled" | "pending" | "unconfirmed"> {
  if ((await settleRunBillingPhase(env, params)) || (await settleRunBillingPhase(env, params))) {
    return "settled";
  }
  try {
    await env.DB.prepare(
      `INSERT INTO pending_billing_settlements
       (user_id, run_id, phase, actual_cost, reserved_credits, detail_label)
       VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT(user_id, run_id, phase) DO NOTHING`
    )
      .bind(
        params.userId,
        params.runId,
        params.phase,
        params.actualCost,
        params.reservedCredits,
        params.detailLabel || `执行模板: ${params.templateNameZh}`
      )
      .run();
    return "pending";
  } catch (err) {
    console.error(
      `[BillingPhase] Could not persist unsettled phase=${params.phase} run=${params.runId}:`,
      err
    );
    return "unconfirmed";
  }
}

export async function retryPendingBillingSettlements(env: Env): Promise<void> {
  const rows = await env.DB.prepare(
    `SELECT user_id, run_id, phase, actual_cost, reserved_credits, detail_label
     FROM pending_billing_settlements ORDER BY created_at LIMIT 50`
  ).all<{
    user_id: string;
    run_id: string;
    phase: string;
    actual_cost: number;
    reserved_credits: number;
    detail_label: string;
  }>();
  for (const row of rows.results) {
    if (
      await settleRunBillingPhase(
        env,
        {
          userId: row.user_id,
          runId: row.run_id,
          phase: row.phase,
          actualCost: row.actual_cost,
          reservedCredits: row.reserved_credits,
          detailLabel: row.detail_label
        },
        true
      )
    ) {
      await env.DB.prepare(
        "DELETE FROM pending_billing_settlements WHERE user_id = ? AND run_id = ? AND phase = ?"
      )
        .bind(row.user_id, row.run_id, row.phase)
        .run();
    } else {
      await env.DB.prepare(
        "UPDATE pending_billing_settlements SET created_at = CURRENT_TIMESTAMP WHERE user_id = ? AND run_id = ? AND phase = ?"
      )
        .bind(row.user_id, row.run_id, row.phase)
        .run();
    }
  }
}

export async function saveCloudTailResult(
  env: Env,
  params: {
    userId: string;
    sessionId: string;
    runId: string;
    finalOutput: string;
    generatedMedia: MediaArtifact[];
    perceptualCacheUpdates: PerceptualCacheEntry[];
  }
): Promise<{ ok: true; tailResultHash: string } | { ok: false }> {
  if (!env?.DB) return { ok: false };
  try {
    const payload = {
      finalOutput: params.finalOutput,
      generatedMedia: params.generatedMedia || [],
      perceptualCacheUpdates: params.perceptualCacheUpdates || []
    };
    const tailHash = await computeTailResultHash({
      finalOutput: params.finalOutput,
      generatedMedia: params.generatedMedia || []
    });
    const res = await env.DB.prepare(
      `UPDATE dag_run_plans
       SET tail_result_json = ?,
           tail_result_hash = ?,
           updated_at = CURRENT_TIMESTAMP
       WHERE user_id = ? AND run_id = ? AND session_id = ?
         AND exec_owner IN ('CLOUD', 'CLOUD_FAILOVER')
         AND commit_state = 'PENDING'`
    )
      .bind(JSON.stringify(payload), tailHash, params.userId, params.runId, params.sessionId)
      .run();
    return res.meta?.changes && res.meta.changes > 0
      ? { ok: true, tailResultHash: tailHash }
      : { ok: false };
  } catch (err) {
    console.error("[SessionState] saveCloudTailResult failed:", err);
    return { ok: false };
  }
}

/**
 * Atomic per-attempt CAS commit into D1 session Git DAG (REV-01, PLAN-02, NM-STATE-07).
 * Zero side effects across every table if Statement 0 fails (conflict, takeover, or deleted session).
 */
export async function commitAuthoritativeSessionTurn(
  env: Env,
  params: {
    userId: string;
    sessionId: string;
    runId: string;
    envelope: UnifiedProtocolEnvelope;
    dag: InstantiatedDAG;
    finalOutput: string;
    generatedMedia: MediaArtifact[];
    perceptualCacheUpdates: PerceptualCacheEntry[];
    authMode: "cloud" | "browser_tail";
    clientCommitToken?: string;
    isReRun?: boolean;
    baseCommitId?: string;
    expectedParentCommitId?: string | null;
    expectedBaseRevision?: number | null;
    topicOverride?: string;
  }
): Promise<CommitTurnResult> {
  if (!env?.DB || !params.sessionId || !params.userId) {
    return {
      ok: false,
      code: "storage_error",
      retryable: true,
      message: "会话存储服务不可用。"
    };
  }

  const { userId, sessionId, runId, envelope, dag, finalOutput } = params;
  const intentOp = dag.reasoning_trace?.intent_state ?? null;
  const targetBranchId = dag.reasoning_trace?.target_branch_id || "main";
  const isReRun = !!params.isReRun;

  let nonceHash: string | null = null;
  if (params.authMode === "browser_tail") {
    if (!params.clientCommitToken) {
      return {
        ok: false,
        code: "invalid_credentials",
        retryable: false,
        message: "缺少端侧尾节点提交凭据。"
      };
    }
    nonceHash = await sha256Hex(params.clientCommitToken);
  }

  const incomingHash = await computeTailResultHash({
    finalOutput,
    generatedMedia: params.generatedMedia || []
  });

  try {
    // 1. Pre-check deleted tombstone & existing plan commit_state (for safe idempotent replay)
    const stateRow = await env.DB.prepare(
      "SELECT version, deleted_at FROM chat_session_states WHERE user_id = ? AND session_id = ?"
    )
      .bind(userId, sessionId)
      .first<{ version: number; deleted_at: string | null }>();

    if (stateRow?.deleted_at) {
      return {
        ok: false,
        code: "session_deleted",
        retryable: false,
        message: "会话已被删除，禁止提交状态。"
      };
    }

    const planRow = await env.DB.prepare(
      `SELECT commit_state, exec_owner, client_commit_nonce_hash, tail_result_hash,
              is_rerun, base_commit_id, expected_parent_commit_id, expected_base_revision
       FROM dag_run_plans
       WHERE user_id = ? AND run_id = ? AND session_id = ?`
    )
      .bind(userId, runId, sessionId)
      .first<any>();

    if (!planRow) {
      return {
        ok: false,
        code: "invalid_credentials",
        retryable: false,
        message: "未找到对应的服务端冻结计划。"
      };
    }

    if (planRow.commit_state === "COMMITTED") {
      if (planRow.tail_result_hash === incomingHash) {
        const snap = await loadAuthoritativeSessionState(env, userId, sessionId);
        return { ok: true, snapshot: snap, idempotentReplay: true };
      }
      return {
        ok: false,
        code: "conflicting_payload",
        retryable: false,
        message: "该运行已完成提交，拒绝使用不同输出重复覆盖。"
      };
    }

    if (planRow.commit_state === "FAILED" || planRow.commit_state === "ABORTED") {
      return {
        ok: false,
        code: "invalid_credentials",
        retryable: false,
        message: "该运行已失败或已被用户放弃，无法再提交。"
      };
    }

    if (params.authMode === "browser_tail") {
      if (planRow.exec_owner !== "BROWSER_TAIL" || planRow.client_commit_nonce_hash !== nonceHash) {
        return {
          ok: false,
          code: "already_taken_over",
          retryable: false,
          message: "端侧交付凭据已失效或该运行已被云端备用链路接管。"
        };
      }
    }

    const effIsReRun = Number(planRow.is_rerun || 0) === 1 || isReRun;
    const effBaseCommitId = planRow.base_commit_id || params.baseCommitId || "";
    const effExpectedParent =
      planRow.expected_parent_commit_id !== undefined
        ? planRow.expected_parent_commit_id
        : (params.expectedParentCommitId ?? null);
    const effExpectedBaseRev =
      planRow.expected_base_revision !== null && planRow.expected_base_revision !== undefined
        ? Number(planRow.expected_base_revision)
        : (params.expectedBaseRevision ?? null);

    // 2. Load snapshot only for computing derived fields & source_refs
    const snapshot = await loadAuthoritativeSessionState(env, userId, sessionId);
    const now = Date.now();
    const summaryText = finalOutput.replace(/\s+/g, " ").trim().slice(0, 600);
    const attemptId = crypto.randomUUID();
    const tailPayloadJson = JSON.stringify({
      finalOutput,
      generatedMedia: params.generatedMedia || [],
      perceptualCacheUpdates: params.perceptualCacheUpdates || []
    });

    // 3. Stage any oversized Shift-Left text_doc body (>16KB) into R2 BEFORE batch
    const introducedAssets = (envelope.assets_manifest || []).filter((a) => a.is_new);
    const docTextStorageMap = new Map<
      string,
      { inlineText: string | null; textR2Key: string | null; sourceDigest: string }
    >();
    const DOC_INLINE_MAX_BYTES = 16 * 1024;
    for (const a of introducedAssets) {
      if (a.in_memory_text && a.asset_id !== "virtual-text-asset") {
        const digest = await sha256Hex(a.in_memory_text);
        const textBytes = new TextEncoder().encode(a.in_memory_text);
        if (textBytes.byteLength > DOC_INLINE_MAX_BYTES && env.R2) {
          const cleanSess = sessionId.replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 64);
          const textR2Key = `tmp/${userId}/docs/${cleanSess}/${a.asset_id}.txt`;
          await registerStagingGeneratedAsset(env, {
            userId,
            sessionId,
            assetId: a.asset_id,
            modality: "text_doc",
            mimeType: a.mime_type || "text/plain",
            textR2Key,
            fileSize: textBytes.byteLength
          });
          await env.R2.put(textR2Key, textBytes, {
            httpMetadata: { contentType: "text/plain; charset=utf-8" },
            customMetadata: { userId, sessionId, assetId: a.asset_id }
          });
          docTextStorageMap.set(a.asset_id, {
            inlineText: null,
            textR2Key,
            sourceDigest: digest
          });
        } else {
          docTextStorageMap.set(a.asset_id, {
            inlineText: a.in_memory_text,
            textR2Key: null,
            sourceDigest: digest
          });
        }
      }
    }

    // Re-ensure chat_session_states row exists safely (does nothing if already active)
    await ensureActiveSessionState(env, userId, sessionId);

    const statements: D1PreparedStatement[] = [];
    const expectedParentForGate = intentOp === "DETACH_RESET" ? null : effExpectedParent;
    const expectedRevForGate = effExpectedBaseRev ?? 1;

    // Stmt 0: Per-attempt CAS write gate verifying run PENDING + exec_owner + nonce + not deleted + active occupancy owner + branch head / base revision
    statements.push(
      env.DB.prepare(
        `UPDATE chat_session_states
         SET version = version + 1,
             active_branch_id = CASE WHEN ? = 1 THEN active_branch_id ELSE ? END,
             last_tx_attempt_id = ?,
             active_run_id = NULL,
             active_client_op_id = NULL,
             occupancy_phase = NULL,
             lock_expires_at = NULL,
             updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ?
           AND session_id = ?
           AND deleted_at IS NULL
           AND EXISTS (
             SELECT 1 FROM dag_run_plans p
             WHERE p.user_id = ? AND p.run_id = ? AND p.session_id = ?
               AND p.commit_state = 'PENDING'
               AND (
                 (? = 'browser_tail' AND p.exec_owner = 'BROWSER_TAIL' AND p.client_commit_nonce_hash = ?)
                 OR (? = 'cloud' AND p.exec_owner IN ('CLOUD', 'CLOUD_FAILOVER'))
               )
           )
           AND (
             (? = 1 AND EXISTS (
               SELECT 1 FROM session_commits c
               WHERE c.user_id = ? AND c.session_id = ? AND c.commit_id = ? AND c.revision = ?
             ))
             OR (? = 0 AND COALESCE(
               (SELECT b.head_commit_id FROM session_branches b
                WHERE b.user_id = ? AND b.session_id = ? AND b.branch_id = ?), ''
             ) = COALESCE(?, ''))
           )
           AND (active_run_id IS NULL OR active_run_id = ?)`
      ).bind(
        effIsReRun ? 1 : 0,
        targetBranchId,
        attemptId,
        userId,
        sessionId,
        userId,
        runId,
        sessionId,
        params.authMode,
        nonceHash,
        params.authMode,
        effIsReRun ? 1 : 0,
        userId,
        sessionId,
        effBaseCommitId,
        expectedRevForGate,
        effIsReRun ? 1 : 0,
        userId,
        sessionId,
        targetBranchId,
        expectedParentForGate || "",
        runId
      )
    );

    const gateSubquery = `EXISTS (
      SELECT 1 FROM chat_session_states s
      WHERE s.user_id = ? AND s.session_id = ? AND s.last_tx_attempt_id = ? AND s.deleted_at IS NULL
    )`;

    // Stmt 1..k: Scoped L1 Perceptual Cache (server-derived SHA-256 percept_key ONLY; ignored when authMode='browser_tail')
    const cacheEntries = params.authMode === "cloud" ? params.perceptualCacheUpdates || [] : [];
    for (const entry of cacheEntries) {
      const scope = entry.task_scope || "objective_full";
      const promptDigest = entry.prompt_digest || "default";
      const perceptKey = await computeScopedPerceptKey({
        userId,
        sessionId,
        sourceDigest: entry.source_digest,
        roleId: entry.role_id,
        modelId: entry.model_id,
        taskScope: scope,
        promptDigest
      });
      statements.push(
        env.DB.prepare(
          `INSERT INTO asset_perceptual_cache
           (percept_key, user_id, session_id, source_digest, modality, role_id, model_id, task_scope, prompt_digest, extracted_text, summary_snippet, updated_at)
           SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
           WHERE ${gateSubquery}
           ON CONFLICT(user_id, session_id, percept_key) DO UPDATE SET
             extracted_text = excluded.extracted_text,
             summary_snippet = excluded.summary_snippet,
             updated_at = excluded.updated_at`
        ).bind(
          perceptKey,
          userId,
          sessionId,
          entry.source_digest,
          entry.modality,
          entry.role_id,
          entry.model_id,
          scope,
          promptDigest,
          entry.extracted_text,
          entry.summary_snippet,
          entry.updated_at || now,
          userId,
          sessionId,
          attemptId
        )
      );
    }

    // Promote generated media from STAGING -> COMMITTED (cloud only)
    const generatedMedia = params.authMode === "cloud" ? params.generatedMedia || [] : [];
    const generatedAssetIds: string[] = [];
    for (const gm of generatedMedia) {
      generatedAssetIds.push(gm.asset_id);
      const gmBranch = effIsReRun
        ? snapshot.commits[effBaseCommitId]?.branch_id || targetBranchId
        : targetBranchId;
      const gmCommit = effIsReRun ? effBaseCommitId || runId : runId;
      statements.push(
        env.DB.prepare(
          `INSERT INTO session_assets
           (asset_id, session_id, user_id, branch_id, commit_id, filename, modality, mime_type, file_size, r2_key, source_digest, origin, introduced_round, status, summary_snippet)
           SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'generated', ?, 'COMMITTED', ?
           WHERE ${gateSubquery}
           ON CONFLICT(user_id, asset_id) DO UPDATE SET
             session_id = excluded.session_id,
             branch_id = excluded.branch_id,
             commit_id = excluded.commit_id,
             r2_key = excluded.r2_key,
             source_digest = excluded.source_digest,
             status = 'COMMITTED',
             summary_snippet = excluded.summary_snippet
           WHERE session_assets.user_id = excluded.user_id
             AND (session_assets.session_id = excluded.session_id OR session_assets.session_id = '__UNBOUND__')`
        ).bind(
          gm.asset_id,
          sessionId,
          userId,
          gmBranch,
          gmCommit,
          `${gm.asset_id}.png`,
          gm.modality,
          gm.mime_type,
          gm.file_size,
          gm.r2_key,
          gm.source_digest,
          Number(envelope.round_index || 1),
          `AI生成 ${gm.modality}`,
          userId,
          sessionId,
          attemptId
        )
      );
    }

    if (effIsReRun) {
      const baseCommit = snapshot.commits[effBaseCommitId];
      if (!baseCommit) {
        return {
          ok: false,
          code: "version_conflict",
          retryable: false,
          message: "基准修订提交不存在，无法执行画布版本更新。"
        };
      }
      const nextRev = expectedRevForGate + 1;
      statements.push(
        env.DB.prepare(
          `UPDATE session_commits
           SET revision = ?, template_id = ?, output_summary = ?
           WHERE user_id = ? AND session_id = ? AND commit_id = ? AND revision = ? AND ${gateSubquery}`
        ).bind(
          nextRev,
          dag.template?.template_id || baseCommit.template_id || null,
          summaryText || baseCommit.output_summary,
          userId,
          sessionId,
          effBaseCommitId,
          expectedRevForGate,
          userId,
          sessionId,
          attemptId
        )
      );

      if (summaryText) {
        statements.push(
          env.DB.prepare(
            `UPDATE session_branches
             SET last_summary = ?, updated_at = CURRENT_TIMESTAMP
             WHERE user_id = ? AND session_id = ? AND branch_id = ? AND head_commit_id = ? AND ${gateSubquery}`
          ).bind(
            summaryText,
            userId,
            sessionId,
            baseCommit.branch_id,
            effBaseCommitId,
            userId,
            sessionId,
            attemptId
          )
        );
      }
    } else {
      // Normal Commit: promote uploaded assets & append single-parent CommitNode + branch head
      const ledgerById = new Map(snapshot.session_asset_ledger.map((a) => [a.asset_id, a]));
      const sourceRefs: SourceRefEntry[] = [];
      const mountedAssets: Array<{ asset_id: string; bind_mode: Exclude<AssetBindMode, "DROP"> }> =
        [];
      for (const b of dag.reasoning_trace?.mounted_asset_bindings || []) {
        if (b.bind_mode === "DROP") continue;
        mountedAssets.push({ asset_id: b.asset_id, bind_mode: b.bind_mode });
        const hist = ledgerById.get(b.asset_id);
        if (hist && hist.branch_id) {
          sourceRefs.push({
            asset_id: b.asset_id,
            branch_id: hist.branch_id,
            commit_id: hist.introduced_commit_id,
            bind_mode: b.bind_mode
          });
        }
      }

      const introducedAssetIds: string[] = [];
      for (const a of introducedAssets) {
        if (!a.r2_key && !a.asset_id) continue;
        if (a.asset_id === "virtual-text-asset") continue;
        introducedAssetIds.push(a.asset_id);
        const docStorage = docTextStorageMap.get(a.asset_id);
        const effDigest = docStorage?.sourceDigest || a.source_digest || a.r2_key || a.asset_id;
        statements.push(
          env.DB.prepare(
            `INSERT INTO session_assets
             (asset_id, session_id, user_id, branch_id, commit_id, filename, modality, mime_type, file_size, r2_key, source_digest, origin, introduced_round, status, summary_snippet, in_memory_text, text_r2_key)
             SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'upload', ?, 'COMMITTED', ?, ?, ?
             WHERE ${gateSubquery}
             ON CONFLICT(user_id, asset_id) DO UPDATE SET
               session_id = excluded.session_id,
               branch_id = excluded.branch_id,
               commit_id = excluded.commit_id,
               source_digest = excluded.source_digest,
               status = 'COMMITTED',
               summary_snippet = excluded.summary_snippet,
               in_memory_text = COALESCE(excluded.in_memory_text, session_assets.in_memory_text),
               text_r2_key = COALESCE(excluded.text_r2_key, session_assets.text_r2_key)
             WHERE session_assets.user_id = excluded.user_id
               AND (session_assets.session_id = excluded.session_id OR session_assets.session_id = '__UNBOUND__')`
          ).bind(
            a.asset_id,
            sessionId,
            userId,
            targetBranchId,
            runId,
            a.filename || a.asset_id,
            a.modality,
            a.mime_type || "application/octet-stream",
            Math.max(0, Math.floor(a.file_size || 0)),
            a.r2_key || "",
            effDigest,
            Number(envelope.round_index || 1),
            a.summary_snippet || a.filename || "",
            docStorage?.inlineText ?? null,
            docStorage?.textR2Key ?? null,
            userId,
            sessionId,
            attemptId
          )
        );
      }

      const parentCommitId = expectedParentForGate || null;
      statements.push(
        env.DB.prepare(
          `INSERT INTO session_commits
           (commit_id, session_id, user_id, run_id, branch_id, parent_commit_id, source_refs_json, round_index, revision, intent_op, user_prompt, mounted_assets_json, introduced_asset_ids_json, generated_asset_ids_json, template_id, output_summary, created_at)
           SELECT ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?
           WHERE ${gateSubquery}`
        ).bind(
          runId,
          sessionId,
          userId,
          runId,
          targetBranchId,
          parentCommitId,
          JSON.stringify(sourceRefs),
          Number(envelope.round_index || snapshot.commit_order.length + 1),
          intentOp,
          envelope.instruction_payload || "",
          JSON.stringify(mountedAssets),
          JSON.stringify(introducedAssetIds),
          JSON.stringify(generatedAssetIds),
          dag.template?.template_id || null,
          summaryText,
          now,
          userId,
          sessionId,
          attemptId
        )
      );

      const targetBranch = snapshot.branches[targetBranchId];
      const existingLineage = targetBranch?.lineage_asset_ids || [];
      const nextLineage = Array.from(
        new Set([...existingLineage, ...introducedAssetIds, ...generatedAssetIds])
      );
      const nextModalities = Array.from(
        new Set([
          ...(targetBranch?.dominant_modalities || []),
          ...(envelope.assets_manifest || [])
            .map((a) => a.modality)
            .filter((m) => m && m !== "text")
        ])
      );
      const topic =
        targetBranch?.topic ||
        params.topicOverride ||
        (envelope.instruction_payload || "").replace(/\s+/g, " ").trim().slice(0, 24) ||
        "主线任务";

      statements.push(
        env.DB.prepare(
          `INSERT INTO session_branches
           (session_id, branch_id, user_id, topic, head_commit_id, dominant_modalities, last_summary, lineage_asset_ids, updated_at)
           SELECT ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
           WHERE ${gateSubquery}
           ON CONFLICT(user_id, session_id, branch_id) DO UPDATE SET
             topic = excluded.topic,
             head_commit_id = excluded.head_commit_id,
             dominant_modalities = excluded.dominant_modalities,
             last_summary = excluded.last_summary,
             lineage_asset_ids = excluded.lineage_asset_ids,
             updated_at = CURRENT_TIMESTAMP`
        ).bind(
          sessionId,
          targetBranchId,
          userId,
          topic,
          runId,
          JSON.stringify(nextModalities),
          summaryText,
          JSON.stringify(nextLineage),
          userId,
          sessionId,
          attemptId
        )
      );
    }

    // Final statement in batch: mark dag_run_plans COMMITTED ONLY when gate succeeded!
    statements.push(
      env.DB.prepare(
        `UPDATE dag_run_plans
         SET commit_state = 'COMMITTED',
             exec_owner = 'COMMITTED',
             client_commit_nonce_hash = NULL,
             tail_result_json = ?,
             tail_result_hash = ?,
             status = 'COMPLETED',
             updated_at = CURRENT_TIMESTAMP
         WHERE user_id = ? AND run_id = ? AND session_id = ? AND ${gateSubquery}`
      ).bind(tailPayloadJson, incomingHash, userId, runId, sessionId, userId, sessionId, attemptId)
    );

    const results = await env.DB.batch(statements);
    const gateChanges = Number(results?.[0]?.meta?.changes || 0);

    if (gateChanges === 0) {
      // Zero side effects occurred across every table; diagnose exact conflict cause
      const freshState = await env.DB.prepare(
        "SELECT deleted_at FROM chat_session_states WHERE user_id = ? AND session_id = ?"
      )
        .bind(userId, sessionId)
        .first<{ deleted_at: string | null }>();
      if (freshState?.deleted_at) {
        return {
          ok: false,
          code: "session_deleted",
          retryable: false,
          message: "会话在提交期间被删除，本次状态提交已安全中止（0 写入）。"
        };
      }
      const freshPlan = await env.DB.prepare(
        "SELECT commit_state, exec_owner, tail_result_hash FROM dag_run_plans WHERE user_id = ? AND run_id = ? AND session_id = ?"
      )
        .bind(userId, runId, sessionId)
        .first<any>();
      if (freshPlan?.commit_state === "COMMITTED") {
        if (freshPlan.tail_result_hash === incomingHash) {
          const snap = await loadAuthoritativeSessionState(env, userId, sessionId);
          return { ok: true, snapshot: snap, idempotentReplay: true };
        }
        return {
          ok: false,
          code: "conflicting_payload",
          retryable: false,
          message: "并发提交已被其他回执抢先落库，且输出不一致。"
        };
      }
      if (params.authMode === "browser_tail" && freshPlan?.exec_owner !== "BROWSER_TAIL") {
        return {
          ok: false,
          code: "already_taken_over",
          retryable: false,
          message: "端侧交付在提交瞬间被云端备用接管，已放弃旧端侧提交（0 写入）。"
        };
      }
      return {
        ok: false,
        code: "version_conflict",
        retryable: false,
        message: "目标分支或基准修订号已被更新的提交推进，当前过期结果无法覆盖新基线（0 写入）。"
      };
    }

    const updatedSnap = await loadAuthoritativeSessionState(env, userId, sessionId);
    return { ok: true, snapshot: updatedSnap };
  } catch (err: any) {
    if (err instanceof SessionDeletedError) {
      return {
        ok: false,
        code: "session_deleted",
        retryable: false,
        message: err.message
      };
    }
    console.error("[SessionState] commitAuthoritativeSessionTurn failed:", err);
    return {
      ok: false,
      code: "storage_error",
      retryable: true,
      message: "权威状态存储事务执行失败，请使用原 run_id 重试提交。"
    };
  }
}

export async function sweepPendingR2Cleanups(env: Env, userId?: string): Promise<void> {
  if (!env?.DB || !env?.R2 || typeof env.R2.delete !== "function") return;
  try {
    const query = userId
      ? "SELECT delete_id, r2_key FROM pending_r2_deletions WHERE user_id = ? LIMIT 100"
      : "SELECT delete_id, r2_key FROM pending_r2_deletions LIMIT 100";
    const rows = userId
      ? await env.DB.prepare(query).bind(userId).all<{ delete_id: string; r2_key: string }>()
      : await env.DB.prepare(query).all<{ delete_id: string; r2_key: string }>();

    for (const row of rows.results || []) {
      if (!row.r2_key) continue;
      try {
        await env.R2.delete(row.r2_key);
        await env.DB.prepare("DELETE FROM pending_r2_deletions WHERE delete_id = ?")
          .bind(row.delete_id)
          .run();
      } catch (r2Err) {
        console.warn(`[R2Purge] Retryable delete failure for ${row.r2_key}:`, r2Err);
      }
    }

    if (typeof env.R2.list === "function") {
      const prefixQuery = userId
        ? "SELECT user_id, prefixes_json FROM pending_r2_prefix_purges WHERE user_id = ? LIMIT 10"
        : "SELECT user_id, prefixes_json FROM pending_r2_prefix_purges LIMIT 10";
      const purgeRows = userId
        ? await env.DB.prepare(prefixQuery)
            .bind(userId)
            .all<{ user_id: string; prefixes_json: string }>()
        : await env.DB.prepare(prefixQuery).all<{ user_id: string; prefixes_json: string }>();

      for (const pr of purgeRows.results || []) {
        const prefixes = safeJsonParse<string[]>(pr.prefixes_json, []);
        let allComplete = true;
        for (const prefix of prefixes) {
          try {
            let cursor: string | undefined = undefined;
            let pages = 0;
            do {
              const listed = await env.R2.list({ prefix, cursor, limit: 1000 });
              if (listed?.objects?.length > 0) {
                await env.R2.delete(listed.objects.map((o) => o.key));
              }
              cursor = listed?.truncated ? listed.cursor : undefined;
              pages++;
            } while (cursor && pages < 20);
            if (cursor) allComplete = false;
          } catch (prefixErr) {
            allComplete = false;
            console.warn(`[R2Purge] Prefix sweep failed for ${prefix}:`, prefixErr);
          }
        }
        if (allComplete) {
          await env.DB.prepare("DELETE FROM pending_r2_prefix_purges WHERE user_id = ?")
            .bind(pr.user_id)
            .run();
        }
      }
    }
  } catch (err) {
    console.warn("[R2Purge] sweepPendingR2Cleanups error:", err);
  }
}

/**
 * Atomically tombstones a session (keeping 1 minimal row in chat_session_states),
 * enqueues both r2_key and text_r2_key from ALL asset statuses into pending_r2_deletions,
 * clears every business/cache table including dag_execution_cache, and asynchronously deletes R2 objects (REV-06).
 */
export async function tombstoneAndPurgeSession(
  env: Env,
  userId: string,
  sessionOrTraceId: string,
  ctx?: ExecutionContext
): Promise<{
  deleted: boolean;
  busy?: boolean;
  occupancyPhase?: string | null;
  activeRunId?: string | null;
}> {
  if (!env?.DB || !userId || !sessionOrTraceId) return { deleted: false };

  // Resolve exact session_id if user passed trace_id from drawer item
  let targetSessionId = sessionOrTraceId;
  const matched = await env.DB.prepare(
    "SELECT session_id FROM user_chat_sessions WHERE user_id = ? AND (session_id = ? OR trace_id = ?)"
  )
    .bind(userId, sessionOrTraceId, sessionOrTraceId)
    .first<{ session_id: string }>();
  if (matched?.session_id) {
    targetSessionId = matched.session_id;
  }

  const tombstoneGate = `EXISTS (
    SELECT 1 FROM chat_session_states s
    WHERE s.user_id = ? AND s.session_id = ? AND s.deleted_at IS NULL
      AND (
        s.occupancy_phase IS NULL
        OR (s.lock_expires_at IS NOT NULL AND datetime(s.lock_expires_at) <= datetime('now'))
      )
  )`;
  // Note: subsequent statements check deleted_at IS NOT NULL after Stmt 0 atomically marks tombstones
  void tombstoneGate;
  const deletedGate = `EXISTS (
    SELECT 1 FROM chat_session_states s
    WHERE s.user_id = ? AND s.session_id = ? AND s.deleted_at IS NOT NULL
  )`;

  const batchResults = await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO chat_session_states (session_id, user_id, active_branch_id, version, last_tx_attempt_id, active_run_id, active_client_op_id, occupancy_phase, lock_expires_at, deleted_at, updated_at)
       VALUES (?, ?, 'main', 1, NULL, NULL, NULL, NULL, NULL, datetime('now'), CURRENT_TIMESTAMP)
       ON CONFLICT(user_id, session_id) DO UPDATE SET
         version = version + 1,
         last_tx_attempt_id = NULL,
         active_run_id = NULL,
         active_client_op_id = NULL,
         occupancy_phase = NULL,
         lock_expires_at = NULL,
         deleted_at = datetime('now'),
         updated_at = CURRENT_TIMESTAMP
       WHERE chat_session_states.deleted_at IS NULL
         AND (
           chat_session_states.occupancy_phase IS NULL
           OR (chat_session_states.lock_expires_at IS NOT NULL AND datetime(chat_session_states.lock_expires_at) <= datetime('now'))
         )`
    ).bind(targetSessionId, userId),
    env.DB.prepare(
      `INSERT INTO pending_r2_deletions (delete_id, user_id, session_id, r2_key)
       SELECT lower(hex(randomblob(16))), user_id, session_id, r2_key
       FROM session_assets
       WHERE user_id = ? AND session_id = ? AND r2_key IS NOT NULL AND r2_key != '' AND ${deletedGate}
       ON CONFLICT(user_id, r2_key) DO NOTHING`
    ).bind(userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `INSERT INTO pending_r2_deletions (delete_id, user_id, session_id, r2_key)
       SELECT lower(hex(randomblob(16))), user_id, session_id, text_r2_key
       FROM session_assets
       WHERE user_id = ? AND session_id = ? AND text_r2_key IS NOT NULL AND text_r2_key != '' AND ${deletedGate}
       ON CONFLICT(user_id, r2_key) DO NOTHING`
    ).bind(userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `DELETE FROM session_branches WHERE user_id = ? AND session_id = ? AND ${deletedGate}`
    ).bind(userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `DELETE FROM session_commits WHERE user_id = ? AND session_id = ? AND ${deletedGate}`
    ).bind(userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `DELETE FROM session_assets WHERE user_id = ? AND session_id = ? AND ${deletedGate}`
    ).bind(userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `DELETE FROM run_billing_settlements WHERE user_id = ? AND ${deletedGate} AND run_id IN (SELECT run_id FROM dag_run_plans WHERE user_id = ? AND session_id = ?) AND NOT EXISTS (SELECT 1 FROM pending_billing_settlements q WHERE q.user_id = run_billing_settlements.user_id AND q.run_id = run_billing_settlements.run_id AND q.phase = run_billing_settlements.phase)`
    ).bind(userId, userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `DELETE FROM dag_run_plans WHERE user_id = ? AND session_id = ? AND ${deletedGate}`
    ).bind(userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `DELETE FROM asset_perceptual_cache WHERE user_id = ? AND session_id = ? AND ${deletedGate}`
    ).bind(userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `DELETE FROM dag_execution_cache WHERE user_id = ? AND session_id = ? AND ${deletedGate}`
    ).bind(userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `DELETE FROM dag_handshakes WHERE user_id = ? AND session_id = ? AND ${deletedGate}`
    ).bind(userId, targetSessionId, userId, targetSessionId),
    env.DB.prepare(
      `DELETE FROM user_chat_sessions WHERE user_id = ? AND (session_id = ? OR trace_id = ?) AND ${deletedGate}`
    ).bind(userId, sessionOrTraceId, sessionOrTraceId, userId, targetSessionId)
  ]);

  const stmt0Changes = Number(batchResults?.[0]?.meta?.changes || 0);
  if (stmt0Changes === 0) {
    const curState = await env.DB.prepare(
      "SELECT deleted_at, occupancy_phase, active_run_id FROM chat_session_states WHERE user_id = ? AND session_id = ?"
    )
      .bind(userId, targetSessionId)
      .first<{
        deleted_at: string | null;
        occupancy_phase: string | null;
        active_run_id: string | null;
      }>();

    if (!curState?.deleted_at && curState?.occupancy_phase) {
      return {
        deleted: false,
        busy: true,
        occupancyPhase: curState.occupancy_phase,
        activeRunId: curState.active_run_id || null
      };
    }
  }

  const purgePromise = sweepPendingR2Cleanups(env, userId);
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(purgePromise);
  } else {
    await purgePromise;
  }
  return { deleted: true };
}

export async function handleGetSessionState(
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
  const cleanId = decodeURIComponent(sessionId || "").trim();
  if (!cleanId) {
    return new Response(JSON.stringify({ error: "Missing session_id" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }
  try {
    const snapshot = await loadAuthoritativeSessionState(env, session.userId, cleanId);
    return new Response(JSON.stringify(buildPublicSessionSnapshot(snapshot)), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
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
}

export async function handleCommitSessionTurn(
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
  const cleanId = decodeURIComponent(sessionId || "").trim();
  if (!cleanId) {
    return new Response(JSON.stringify({ error: "Missing session_id" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const runId = String(body.run_id || "").trim();
  const clientCommitToken = String(body.client_commit_token || "").trim();
  if (!runId || !clientCommitToken) {
    return new Response(
      JSON.stringify({
        error: "missing_commit_credentials",
        message: "缺少运行 ID 或端侧提交凭据"
      }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" }
      }
    );
  }

  const finalOutput = String(body.final_output || "");
  if (finalOutput.length > 512 * 1024) {
    return new Response(JSON.stringify({ error: "payload_too_large" }), {
      status: 413,
      headers: { "Content-Type": "application/json" }
    });
  }

  try {
    const plan = await loadAndVerifyDagRunPlan(env, session.userId, runId, "", cleanId);
    if (!plan) {
      return new Response(JSON.stringify({ error: "run_plan_not_found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
      });
    }

    // Browser tail commits strictly use frozen plan metadata & reject client-forged media/cache entries
    const result = await commitAuthoritativeSessionTurn(env, {
      userId: session.userId,
      sessionId: cleanId,
      runId,
      envelope: plan.resolvedEnvelope,
      dag: plan.dag,
      finalOutput,
      generatedMedia: [],
      perceptualCacheUpdates: [],
      authMode: "browser_tail",
      clientCommitToken,
      isReRun: plan.isReRun,
      baseCommitId: plan.baseCommitId,
      expectedParentCommitId: plan.expectedParentCommitId,
      expectedBaseRevision: plan.expectedBaseRevision
    });

    if (!result.ok) {
      const httpStatus =
        result.code === "session_deleted"
          ? 410
          : result.code === "storage_error"
            ? 503
            : result.code === "invalid_credentials"
              ? 403
              : 409;
      const awaitingCommit =
        result.retryable &&
        (await markSessionAwaitingCommit(env, session.userId, cleanId, runId, clientCommitToken));
      if (
        !result.retryable &&
        result.code !== "already_taken_over" &&
        result.code !== "session_deleted" &&
        result.code !== "invalid_credentials"
      ) {
        await finishRunWithoutCommit(env, {
          userId: session.userId,
          sessionId: cleanId,
          runId,
          outcome: "FAILED",
          failureStatus: httpStatus,
          failureCode: result.code,
          failureMessage: result.message
        });
      }
      return new Response(
        JSON.stringify({
          error: result.code,
          can_retry_commit: result.retryable,
          awaiting_commit: awaitingCommit,
          message: result.message
        }),
        {
          status: httpStatus,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    return new Response(JSON.stringify(buildPublicSessionSnapshot(result.snapshot)), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (err: any) {
    const awaitingCommit = await markSessionAwaitingCommit(
      env,
      session.userId,
      cleanId,
      runId,
      clientCommitToken
    );
    return new Response(
      JSON.stringify({
        error: "storage_error",
        can_retry_commit: true,
        awaiting_commit: awaitingCommit,
        message: err?.message || "Commit storage failure"
      }),
      {
        status: 503,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}

export async function handleCommitRetrySessionTurn(
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
  const cleanId = decodeURIComponent(sessionId || "").trim();
  if (!cleanId) {
    return new Response(JSON.stringify({ error: "Missing session_id" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  let body: any;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  const runId = String(body.run_id || "").trim();
  if (!runId) {
    return new Response(JSON.stringify({ error: "Missing run_id" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  try {
    const plan = await loadAndVerifyDagRunPlan(env, session.userId, runId, "", cleanId);
    if (!plan) {
      return new Response(JSON.stringify({ error: "run_plan_not_found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" }
      });
    }
    if (!plan.tailResultJson || !plan.tailResultHash) {
      return new Response(
        JSON.stringify({
          error: "result_staging_failed",
          can_retry_commit: false,
          message: "该运行未保存服务端计算产出，无法仅重试提交。"
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    const result = await commitAuthoritativeSessionTurn(env, {
      userId: session.userId,
      sessionId: cleanId,
      runId,
      envelope: plan.resolvedEnvelope,
      dag: plan.dag,
      finalOutput: String(plan.tailResultJson.finalOutput || ""),
      generatedMedia: Array.isArray(plan.tailResultJson.generatedMedia)
        ? plan.tailResultJson.generatedMedia
        : [],
      perceptualCacheUpdates: Array.isArray(plan.tailResultJson.perceptualCacheUpdates)
        ? plan.tailResultJson.perceptualCacheUpdates
        : [],
      authMode: "cloud",
      isReRun: plan.isReRun,
      baseCommitId: plan.baseCommitId,
      expectedParentCommitId: plan.expectedParentCommitId,
      expectedBaseRevision: plan.expectedBaseRevision
    });

    if (!result.ok) {
      const httpStatus =
        result.code === "session_deleted" ? 410 : result.code === "storage_error" ? 503 : 409;
      const awaitingCommit =
        result.retryable && (await markSessionAwaitingCommit(env, session.userId, cleanId, runId));
      if (
        !result.retryable &&
        result.code !== "session_deleted" &&
        result.code !== "invalid_credentials"
      ) {
        await finishRunWithoutCommit(env, {
          userId: session.userId,
          sessionId: cleanId,
          runId,
          outcome: "FAILED",
          failureStatus: httpStatus,
          failureCode: result.code,
          failureMessage: result.message
        });
      }
      return new Response(
        JSON.stringify({
          error: result.code,
          can_retry_commit: result.retryable,
          awaiting_commit: awaitingCommit,
          message: result.message
        }),
        {
          status: httpStatus,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    return new Response(JSON.stringify(buildPublicSessionSnapshot(result.snapshot)), {
      status: 200,
      headers: { "Content-Type": "application/json" }
    });
  } catch (err: any) {
    return new Response(
      JSON.stringify({
        error: "storage_error",
        can_retry_commit: true,
        awaiting_commit: false,
        message: err?.message || "Commit retry failed"
      }),
      {
        status: 503,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}

export async function handleAbandonSessionRun(
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
  const cleanId = decodeURIComponent(sessionId || "").trim();
  if (!cleanId) {
    return new Response(JSON.stringify({ error: "Missing session_id" }), {
      status: 400,
      headers: { "Content-Type": "application/json" }
    });
  }

  let body: any = {};
  try {
    body = await request.json();
  } catch {
    body = {};
  }

  try {
    const stateRow = await env.DB.prepare(
      "SELECT deleted_at, active_run_id, occupancy_phase FROM chat_session_states WHERE user_id = ? AND session_id = ?"
    )
      .bind(session.userId, cleanId)
      .first<{
        deleted_at: string | null;
        active_run_id: string | null;
        occupancy_phase: string | null;
      }>();

    if (stateRow?.deleted_at) {
      return new Response(JSON.stringify({ error: "session_deleted" }), {
        status: 410,
        headers: { "Content-Type": "application/json" }
      });
    }

    const runId = String(body?.run_id || stateRow?.active_run_id || "").trim();
    if (!runId) {
      return new Response(JSON.stringify({ error: "Missing run_id" }), {
        status: 400,
        headers: { "Content-Type": "application/json" }
      });
    }

    const planRow = await env.DB.prepare(
      "SELECT commit_state FROM dag_run_plans WHERE user_id = ? AND session_id = ? AND run_id = ?"
    )
      .bind(session.userId, cleanId, runId)
      .first<{ commit_state: string }>();

    if (planRow?.commit_state === "COMMITTED") {
      const snapshot = await loadAuthoritativeSessionState(env, session.userId, cleanId);
      return new Response(
        JSON.stringify({
          error: "already_committed",
          message: "该运行已完成提交，无法放弃。",
          authoritative_git_state: buildPublicSessionSnapshot(snapshot)
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (stateRow?.occupancy_phase !== "AWAITING_COMMIT") {
      const snapshot = await loadAuthoritativeSessionState(env, session.userId, cleanId);
      return new Response(
        JSON.stringify({
          error: "cannot_abandon_active_run",
          message:
            "只能在等待确认提交状态（AWAITING_COMMIT）下放弃结果，正在执行的任务无法直接放弃。",
          occupancy_phase: stateRow?.occupancy_phase || null,
          authoritative_git_state: buildPublicSessionSnapshot(snapshot)
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    if (
      body?.run_id &&
      stateRow?.active_run_id &&
      String(body.run_id).trim() !== stateRow.active_run_id
    ) {
      const snapshot = await loadAuthoritativeSessionState(env, session.userId, cleanId);
      return new Response(
        JSON.stringify({
          error: "abandon_conflict",
          message: "放弃失败：指定的 run_id 与当前持锁的运行不一致。",
          authoritative_git_state: buildPublicSessionSnapshot(snapshot)
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    const finishRes = await finishRunWithoutCommit(env, {
      userId: session.userId,
      sessionId: cleanId,
      runId,
      outcome: "ABORTED",
      expectedOccupancyPhase: "AWAITING_COMMIT",
      failureStatus: 409,
      failureCode: "abandoned_by_user",
      failureMessage: "用户已放弃本次待保存结果。"
    });

    if (!finishRes.success) {
      const snapshot = await loadAuthoritativeSessionState(env, session.userId, cleanId);
      return new Response(
        JSON.stringify({
          error: "abandon_conflict",
          message: "放弃失败：指定的运行未持有当前待确认占用或状态已变更。",
          authoritative_git_state: buildPublicSessionSnapshot(snapshot)
        }),
        {
          status: 409,
          headers: { "Content-Type": "application/json" }
        }
      );
    }

    const snapshot = await loadAuthoritativeSessionState(env, session.userId, cleanId);
    return new Response(
      JSON.stringify({
        abandoned: true,
        run_id: runId,
        authoritative_git_state: buildPublicSessionSnapshot(snapshot)
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" }
      }
    );
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
        message: err?.message || "Abandon failed"
      }),
      {
        status: 503,
        headers: { "Content-Type": "application/json" }
      }
    );
  }
}

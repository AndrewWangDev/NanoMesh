// tests/sqlite_state_closure_test.ts
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { signJWT } from "../src/auth/jwt";
import { handleChat, handleChatContinue } from "../src/api/chat";
import worker from "../src/index";
import {
  acquireBrowserTailCredential,
  acquireSessionExecutionLock,
  claimCloudFailoverOwnership,
  commitAuthoritativeSessionTurn,
  computeClientOpRequestDigest,
  computePlanHash,
  finishRunWithoutCommit,
  handleAbandonSessionRun,
  handleCommitRetrySessionTurn,
  handleCommitSessionTurn,
  handleGetSessionState,
  hydrateDocumentTextBodies,
  markSessionAwaitingCommit,
  registerAndFreezeDagRunPlan,
  registerPresignedAssetTicket,
  registerStagingGeneratedAsset,
  saveCloudTailResult,
  settleRunBillingPhase,
  settleOrQueueBillingPhase,
  retryPendingBillingSettlements,
  sweepPendingR2Cleanups,
  tombstoneAndPurgeSession,
  verifySessionAssetR2Access
} from "../src/api/session";
import { handleDeleteHistoryItem, handleSaveHistory } from "../src/api/history";
import { handleDeleteAccount } from "../src/api/user";
import {
  computeDeterministicSignature,
  lookupDeterministicCache,
  storeDeterministicCache
} from "../src/orchestration/signature";
import { executeDAGStream } from "../src/orchestration/dispatcher";
import { runOrchestrationPipeline } from "../src/orchestration/orchestrator";
import type { Env } from "../src/types";
import type { InstantiatedDAG, UnifiedProtocolEnvelope } from "../src/orchestration/types";

function createRealSqliteD1(db: DatabaseSync): D1Database {
  const makePrepared = (sql: string) => {
    let bound: any[] = [];
    const prepObj = {
      bind(...args: any[]) {
        bound = args.map((v) => (v === undefined ? null : v));
        return prepObj;
      },
      async first<T = any>(): Promise<T | null> {
        const stmt = db.prepare(sql);
        const row = stmt.get(...bound);
        return (row ?? null) as T | null;
      },
      async all<T = any>(): Promise<{ results: T[] }> {
        const stmt = db.prepare(sql);
        const rows = stmt.all(...bound);
        return { results: rows as T[] };
      },
      async run(): Promise<{ meta: { changes: number } }> {
        const stmt = db.prepare(sql);
        const info = stmt.run(...bound);
        return { meta: { changes: Number(info.changes || 0) } };
      },
      _executeSync(): { meta: { changes: number } } {
        const stmt = db.prepare(sql);
        const info = stmt.run(...bound);
        return { meta: { changes: Number(info.changes || 0) } };
      }
    };
    return prepObj;
  };

  return {
    prepare(sql: string) {
      return makePrepared(sql);
    },
    async batch(statements: any[]) {
      db.exec("BEGIN IMMEDIATE");
      try {
        const results = statements.map((s) => s._executeSync());
        db.exec("COMMIT");
        return results;
      } catch (err) {
        try {
          db.exec("ROLLBACK");
        } catch {}
        throw err;
      }
    }
  } as unknown as D1Database;
}

function createSqliteR2(opts?: { failDelete?: boolean }) {
  const objects = new Map<string, { body: Uint8Array; metadata: any }>();
  const r2 = {
    failDelete: !!opts?.failDelete,
    objects,
    async put(key: string, val: any, options?: any) {
      let bytes: Uint8Array;
      if (typeof val === "string") bytes = new TextEncoder().encode(val);
      else if (val instanceof ArrayBuffer) bytes = new Uint8Array(val);
      else if (ArrayBuffer.isView(val))
        bytes = new Uint8Array(val.buffer, val.byteOffset, val.byteLength);
      else bytes = new Uint8Array(await new Response(val).arrayBuffer());
      objects.set(key, { body: bytes, metadata: options || {} });
      return { key };
    },
    async get(key: string) {
      const hit = objects.get(key);
      if (!hit) return null;
      return {
        async arrayBuffer() {
          return hit.body.slice().buffer;
        },
        async text() {
          return new TextDecoder().decode(hit.body);
        }
      };
    },
    async delete(keys: string | string[]) {
      if (r2.failDelete) {
        throw new Error("Simulated R2 outage");
      }
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) objects.delete(k);
    },
    async list(params?: { prefix?: string; cursor?: string; limit?: number }) {
      const prefix = params?.prefix || "";
      const matched = Array.from(objects.keys())
        .filter((k) => k.startsWith(prefix))
        .map((key) => ({ key }));
      return { objects: matched, truncated: false, cursor: undefined };
    }
  };
  return r2;
}

function buildSampleDag(overrides?: Partial<InstantiatedDAG>): InstantiatedDAG {
  return {
    topology_mode: "standard",
    template: {
      template_id: "tpl-direct-chat",
      name_zh: "文本直出",
      name_en: "Direct Chat",
      desc_zh: "",
      desc_en: "",
      head_modalities: ["text"],
      tail_modalities: ["text"],
      roles: [],
      priority: 1,
      status: "active"
    },
    candidate_templates: [],
    nodes: [
      {
        node_id: "role-direct-chat",
        role: {
          role_id: "role-direct-chat",
          name_zh: "直接对话",
          name_en: "Direct Chat",
          in_modalities: ["text"],
          out_modalities: ["text"],
          in_degree: 0,
          out_degree: 0,
          requisition_tags: ["#general"],
          compensation_prompts: {}
        },
        selected_model: {
          model_id: "cf_llama31_8b",
          display_name: "Llama 3.1 8B",
          provider: "Cloudflare",
          endpoint: "@cf/meta/llama-3.1-8b-instruct-fp8",
          modalities: ["text"],
          in_modalities: ["text"],
          out_modalities: ["text"],
          tags: ["#general"],
          context_window: 8192,
          max_concurrency: 10,
          active_connections: 0,
          precision: 0.9,
          user_rating: 4.5,
          usage_count: 1,
          cost_per_1k_tokens: 1,
          status: "active",
          is_generalist: 1,
          prior_score: 0.5,
          scenario_anchors: [],
          inference_target: "edge",
          auth_mode: "none",
          api_format: "workers_ai"
        },
        standby_models: [],
        score_details: {
          model: null as any,
          score: 1,
          sim: 1,
          concurrency_penalty: 0,
          specialist_score: 1
        },
        downgraded: false,
        claimed_assets: []
      }
    ],
    reasoning_trace: {
      intent_state: null,
      target_branch_id: "main",
      is_multi_round: false,
      subsistence_filtered_count: 1,
      selected_template_id: "tpl-direct-chat",
      downgrade_events: []
    },
    ...overrides
  };
}

function buildEnvelope(
  sessionId: string,
  userId: string,
  prompt: string,
  extra?: Partial<UnifiedProtocolEnvelope>
): UnifiedProtocolEnvelope {
  return {
    envelope_id: crypto.randomUUID(),
    session_id: sessionId,
    user_id: userId,
    round_index: 1,
    instruction_payload: prompt,
    assets_manifest: [],
    constraint_context: { target_language: "zh", output_style: "concise" },
    metadata: {
      client_timestamp: Date.now(),
      char_count_total: prompt.length,
      estimated_input_tokens: 50
    },
    ...extra
  };
}

async function runRealSqliteClosureSuite() {
  console.log("==================================================");
  console.log("   NanoMesh Real SQLite (0025) Closure Suite      ");
  console.log("==================================================");

  const db = new DatabaseSync(":memory:");
  const migrationsDir = path.resolve(process.cwd(), "migrations");
  const migrationFiles = fs
    .readdirSync(migrationsDir)
    .filter((f) => f.endsWith(".sql"))
    .sort();
  for (const mf of migrationFiles) {
    db.exec(fs.readFileSync(path.join(migrationsDir, mf), "utf8"));
  }
  assert.ok(migrationFiles.includes("0025_state_security_closure.sql"));
  console.log(`  ✓ Applied ${migrationFiles.length} real D1 SQLite migrations cleanly: PASSED`);

  const r2 = createSqliteR2();
  const env: Env = {
    DB: createRealSqliteD1(db),
    R2: r2 as any,
    AI: {
      async run() {
        return { response: "Real SQLite verified mock LLM response" };
      }
    } as any,
    JWT_SECRET: "real-sqlite-test-jwt-secret-99999",
    ADMIN_PASSWORD: "AdminPassword999!",
    FRONTEND_URL: "https://nanomesh.local",
    ENVIRONMENT: "development"
  } as unknown as Env;

  // Seed two tenants + models for chat/orchestration
  const userA = "usr_sql_a";
  const userB = "usr_sql_b";
  db.prepare(
    "INSERT INTO users (user_id, email, username, credits, token_version) VALUES (?, ?, ?, ?, 1)"
  ).run(userA, "sqla@nanomesh.local", "sqla", 100);
  db.prepare(
    "INSERT INTO users (user_id, email, username, credits, token_version) VALUES (?, ?, ?, ?, 1)"
  ).run(userB, "sqlb@nanomesh.local", "sqlb", 100);

  db.prepare(
    `INSERT OR IGNORE INTO models
     (model_id, display_name, provider, endpoint, modalities, in_modalities, out_modalities, tags, context_window, max_concurrency, precision, cost_per_1k_tokens, status, inference_target, auth_mode, api_format)
     VALUES (?, ?, 'Cloudflare', ?, '["text"]', '["text"]', '["text"]', '["#general"]', 8192, 10, 0.9, 1, 'active', 'edge', 'none', 'workers_ai')`
  ).run("cf_sql_text", "Llama SQL Text", "@cf/meta/llama-3.1-8b-instruct-fp8");

  db.prepare(
    `INSERT OR IGNORE INTO dag_roles
     (role_id, name_zh, name_en, in_modalities, out_modalities, requisition_tags)
     VALUES ('role-sql-chat', 'SQL对话岗', 'SQL Chat', '["text"]', '["text"]', '["#general"]')`
  ).run();

  db.prepare(
    `INSERT OR IGNORE INTO dag_templates
     (template_id, name_zh, name_en, desc_zh, desc_en, head_modalities, tail_modalities, roles, role_sequence, status, priority)
     VALUES ('tpl-sql-chat', 'SQL文本模板', 'SQL Text', 'desc', 'desc', '["text"]', '["text"]', '["role-sql-chat"]', '["role-sql-chat"]', 'active', 100)`
  ).run();

  const tokenA = await signJWT({ userId: userA, tokenVersion: 1 }, env.JWT_SECRET, 3600);
  const tokenB = await signJWT({ userId: userB, tokenVersion: 1 }, env.JWT_SECRET, 3600);

  // -----------------------------------------------------------------------
  // 1. PLAN-01 / NM-STATE-03 / NM-STATE-10: Multi-Tenant Same Session/Branch/Cache Isolation
  // -----------------------------------------------------------------------
  const sharedSessId = "shared_sess_collision_check";
  const dagA = buildSampleDag();
  const dagB = buildSampleDag();
  const envA = buildEnvelope(sharedSessId, userA, "User A prompt");
  const envB = buildEnvelope(sharedSessId, userB, "User B prompt");
  const planHash = await computePlanHash(dagA);

  await registerAndFreezeDagRunPlan(env, {
    runId: "run_ten_a",
    userId: userA,
    sessionId: sharedSessId,
    clientOpId: "op_ten_a",
    requestDigest: "dig_a",
    planHash,
    dag: dagA,
    originalEnvelope: envA,
    resolvedEnvelope: envA,
    isReRun: false,
    expectedParentCommitId: null,
    expectedBaseRevision: null
  });
  await registerAndFreezeDagRunPlan(env, {
    runId: "run_ten_b",
    userId: userB,
    sessionId: sharedSessId,
    clientOpId: "op_ten_b",
    requestDigest: "dig_b",
    planHash,
    dag: dagB,
    originalEnvelope: envB,
    resolvedEnvelope: envB,
    isReRun: false,
    expectedParentCommitId: null,
    expectedBaseRevision: null
  });

  const cResA = await commitAuthoritativeSessionTurn(env, {
    userId: userA,
    sessionId: sharedSessId,
    runId: "run_ten_a",
    envelope: envA,
    dag: dagA,
    finalOutput: "Output A",
    generatedMedia: [],
    perceptualCacheUpdates: [
      {
        source_digest: "same_img_digest",
        modality: "image",
        role_id: "vision",
        model_id: "m1",
        extracted_text: "A secret OCR",
        summary_snippet: "A OCR",
        updated_at: Date.now()
      }
    ],
    authMode: "cloud"
  });
  const cResB = await commitAuthoritativeSessionTurn(env, {
    userId: userB,
    sessionId: sharedSessId,
    runId: "run_ten_b",
    envelope: envB,
    dag: dagB,
    finalOutput: "Output B",
    generatedMedia: [],
    perceptualCacheUpdates: [
      {
        source_digest: "same_img_digest",
        modality: "image",
        role_id: "vision",
        model_id: "m1",
        extracted_text: "B secret OCR",
        summary_snippet: "B OCR",
        updated_at: Date.now()
      }
    ],
    authMode: "cloud"
  });
  assert.ok(cResA.ok && cResB.ok);

  const stateResA = await handleGetSessionState(
    new Request(`https://nanomesh.local/api/session/${sharedSessId}/state`, {
      headers: { Cookie: `session=${tokenA}` }
    }),
    env,
    sharedSessId
  );
  const stateResB = await handleGetSessionState(
    new Request(`https://nanomesh.local/api/session/${sharedSessId}/state`, {
      headers: { Cookie: `session=${tokenB}` }
    }),
    env,
    sharedSessId
  );
  const snapA = (await stateResA.json()) as any;
  const snapB = (await stateResB.json()) as any;
  assert.equal(snapA.branches.main.last_summary, "Output A");
  assert.equal(snapB.branches.main.last_summary, "Output B");
  assert.equal(snapA.perceptual_cache.same_img_digest.extracted_text, "A secret OCR");
  assert.equal(snapB.perceptual_cache.same_img_digest.extracted_text, "B secret OCR");

  // Execution cache must isolate strictly by (userId, sessionId)
  const sigA = await computeDeterministicSignature("r1", "m1", "in", "p", userA, sharedSessId);
  const sigB = await computeDeterministicSignature("r1", "m1", "in", "p", userB, sharedSessId);
  assert.notEqual(sigA, sigB);
  await storeDeterministicCache(env, sigA, "r1", "m1", "in", "p", "Cached A", userA, sharedSessId);
  assert.equal(await lookupDeterministicCache(env, sigA, userA, sharedSessId), "Cached A");
  assert.equal(await lookupDeterministicCache(env, sigA, userB, sharedSessId), null);
  console.log(
    "  ✓ PLAN-01 / NM-STATE-03 / NM-STATE-10 (Multi-tenant same session/branch/cache isolation): PASSED"
  );

  // -----------------------------------------------------------------------
  // 2. REV-01 Interleaving #1 & #2: Real SQLite Per-Attempt CAS & Zero Side Effects
  // -----------------------------------------------------------------------
  // 2a. Two concurrent commits for the SAME run_id & revision update
  const revRun1 = "run_rev_base";
  const revEnv1 = buildEnvelope("sess_rev_race", userA, "Base甲");
  const revDag = buildSampleDag();
  await registerAndFreezeDagRunPlan(env, {
    runId: revRun1,
    userId: userA,
    sessionId: "sess_rev_race",
    clientOpId: "op_rev_base",
    requestDigest: "dig_rev_base",
    planHash: await computePlanHash(revDag),
    dag: revDag,
    originalEnvelope: revEnv1,
    resolvedEnvelope: revEnv1,
    isReRun: false,
    expectedParentCommitId: null,
    expectedBaseRevision: null
  });
  const baseCommit = await commitAuthoritativeSessionTurn(env, {
    userId: userA,
    sessionId: "sess_rev_race",
    runId: revRun1,
    envelope: revEnv1,
    dag: revDag,
    finalOutput: "Result 甲",
    generatedMedia: [],
    perceptualCacheUpdates: [],
    authMode: "cloud"
  });
  assert.ok(baseCommit.ok);

  // Start micro-tuning run R targeting rev=1 -> rev=2
  const raceRunId = "run_rev_concurrent_R";
  const raceEnv = buildEnvelope("sess_rev_race", userA, "Base甲");
  await registerAndFreezeDagRunPlan(env, {
    runId: raceRunId,
    userId: userA,
    sessionId: "sess_rev_race",
    clientOpId: "op_rev_race",
    requestDigest: "dig_rev_race",
    planHash: await computePlanHash(revDag),
    dag: revDag,
    originalEnvelope: raceEnv,
    resolvedEnvelope: raceEnv,
    isReRun: true,
    baseCommitId: revRun1,
    expectedParentCommitId: null,
    expectedBaseRevision: 1
  });

  // Fire two parallel commits with different outputs for the SAME run_id R!
  const [raceA, raceB] = await Promise.all([
    commitAuthoritativeSessionTurn(env, {
      userId: userA,
      sessionId: "sess_rev_race",
      runId: raceRunId,
      envelope: raceEnv,
      dag: revDag,
      finalOutput: "Output Winner",
      generatedMedia: [],
      perceptualCacheUpdates: [],
      authMode: "cloud",
      isReRun: true,
      baseCommitId: revRun1,
      expectedBaseRevision: 1
    }),
    commitAuthoritativeSessionTurn(env, {
      userId: userA,
      sessionId: "sess_rev_race",
      runId: raceRunId,
      envelope: raceEnv,
      dag: revDag,
      finalOutput: "Output Stale Loser",
      generatedMedia: [],
      perceptualCacheUpdates: [
        {
          source_digest: "loser_should_not_exist",
          modality: "image",
          role_id: "vision",
          model_id: "m1",
          extracted_text: "LOSER",
          summary_snippet: "LOSER",
          updated_at: Date.now()
        }
      ],
      authMode: "cloud",
      isReRun: true,
      baseCommitId: revRun1,
      expectedBaseRevision: 1
    })
  ]);
  assert.equal([raceA.ok, raceB.ok].filter(Boolean).length, 1, "Exactly ONE writer wins");
  const loserPerceptCount = (
    db
      .prepare("SELECT COUNT(*) AS cnt FROM asset_perceptual_cache WHERE source_digest = ?")
      .get("loser_should_not_exist") as any
  ).cnt;
  assert.equal(
    loserPerceptCount,
    0,
    "Loser batch must produce ZERO side effects across all tables"
  );

  // 2b. Interleaving #2: Browser validated token, Cloud Failover steals ownership before browser commit
  const takeoverRunId = "run_browser_takeover";
  const takeoverEnv = buildEnvelope("sess_rev_race", userA, "Browser then cloud takeover");
  await registerAndFreezeDagRunPlan(env, {
    runId: takeoverRunId,
    userId: userA,
    sessionId: "sess_rev_race",
    clientOpId: "op_takeover",
    requestDigest: "dig_takeover",
    planHash: await computePlanHash(revDag),
    dag: revDag,
    originalEnvelope: takeoverEnv,
    resolvedEnvelope: takeoverEnv,
    isReRun: false,
    expectedParentCommitId: revRun1,
    expectedBaseRevision: null
  });
  const tailToken = await acquireBrowserTailCredential(env, userA, "sess_rev_race", takeoverRunId);
  const cloudTookOver = await claimCloudFailoverOwnership(
    env,
    userA,
    "sess_rev_race",
    takeoverRunId
  );
  assert.equal(cloudTookOver, true);

  const lateBrowserCommitRes = await handleCommitSessionTurn(
    new Request("https://nanomesh.local/api/session/sess_rev_race/commit", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenA}` },
      body: JSON.stringify({
        run_id: takeoverRunId,
        client_commit_token: tailToken,
        final_output: "Late Browser Output"
      })
    }),
    env,
    "sess_rev_race"
  );
  assert.equal(lateBrowserCommitRes.status, 409, "Late browser tail after takeover must get 409");
  const cloudAfterTakeover = await commitAuthoritativeSessionTurn(env, {
    userId: userA,
    sessionId: "sess_rev_race",
    runId: takeoverRunId,
    envelope: takeoverEnv,
    dag: revDag,
    finalOutput: "Cloud Failover Winner Output",
    generatedMedia: [],
    perceptualCacheUpdates: [],
    authMode: "cloud",
    expectedParentCommitId: revRun1
  });
  assert.ok(cloudAfterTakeover.ok, "Cloud failover must commit cleanly once");
  assert.equal(
    (
      db
        .prepare("SELECT output_summary FROM session_commits WHERE commit_id = ?")
        .get(takeoverRunId) as any
    ).output_summary,
    "Cloud Failover Winner Output"
  );
  console.log(
    "  ✓ REV-01 (Concurrent same-run CAS + Browser-vs-Cloud takeover zero side effects): PASSED"
  );

  // -----------------------------------------------------------------------
  // 3. REV-02: First-Submit Idempotency & Fail-Closed Freeze (dedicated users to respect L1 3-req burst limit)
  // -----------------------------------------------------------------------
  const userRev02 = "usr_sql_rev02";
  db.prepare(
    "INSERT INTO users (user_id, email, username, credits, token_version) VALUES (?, ?, ?, ?, 1)"
  ).run(userRev02, "rev02@nanomesh.local", "rev02", 100);
  const tokenRev02 = await signJWT({ userId: userRev02, tokenVersion: 1 }, env.JWT_SECRET, 3600);

  const userRev02Freeze = "usr_sql_rev02_freeze";
  db.prepare(
    "INSERT INTO users (user_id, email, username, credits, token_version) VALUES (?, ?, ?, ?, 1)"
  ).run(userRev02Freeze, "rev02f@nanomesh.local", "rev02f", 100);
  const tokenRev02Freeze = await signJWT(
    { userId: userRev02Freeze, tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  // 3a. Concurrent retry while run is still PENDING returns 409 run_already_in_progress
  const pendingSess = "sess_rev02_pending";
  await registerAndFreezeDagRunPlan(env, {
    runId: "run_pending_op",
    userId: userRev02Freeze,
    sessionId: pendingSess,
    clientOpId: "op_in_flight",
    requestDigest: await computeClientOpRequestDigest({
      instructionPayload: "In flight prompt",
      assets: [],
      isReRun: false,
      chosenTemplateId: "tpl-sql-chat"
    }),
    planHash,
    dag: buildSampleDag(),
    originalEnvelope: buildEnvelope(pendingSess, userRev02Freeze, "In flight prompt"),
    resolvedEnvelope: buildEnvelope(pendingSess, userRev02Freeze, "In flight prompt"),
    isReRun: false,
    expectedParentCommitId: null,
    expectedBaseRevision: null
  });
  const inProgressRes = await handleChat(
    new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenRev02Freeze}` },
      body: JSON.stringify({
        clientOpId: "op_in_flight",
        chosenTemplateId: "tpl-sql-chat",
        envelope: {
          envelope_id: "e0",
          session_id: pendingSess,
          round_index: 1,
          instruction_payload: "In flight prompt"
        }
      })
    }),
    env
  );
  assert.equal(inProgressRes.status, 409);
  assert.equal(((await inProgressRes.json()) as any).error, "run_already_in_progress");

  // 3b. Cloud completion + replay returns 200 JSON already_completed
  const idempSess = "sess_rev02_idemp";
  const clientOp = "op_unique_rev02";
  const chatReq1 = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: `session=${tokenRev02}` },
    body: JSON.stringify({
      clientOpId: clientOp,
      disableBrowserInference: true,
      chosenTemplateId: "tpl-sql-chat",
      envelope: {
        envelope_id: "e1",
        session_id: idempSess,
        round_index: 1,
        instruction_payload: "请总结这个结论"
      }
    })
  });
  const chatRes1 = await handleChat(chatReq1, env);
  assert.equal(chatRes1.status, 200);
  const sse1 = await chatRes1.text();
  assert.ok(sse1.includes("event: dag_complete"));

  // Identical clientOpId + identical payload after COMMITTED -> 200 JSON replay (0 extra credits spent!)
  const creditsAfterChat1 = (
    db.prepare("SELECT credits FROM users WHERE user_id = ?").get(userRev02) as any
  ).credits;
  const chatResReplay = await handleChat(
    new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenRev02}` },
      body: JSON.stringify({
        clientOpId: clientOp,
        disableBrowserInference: true,
        chosenTemplateId: "tpl-sql-chat",
        envelope: {
          envelope_id: "e2",
          session_id: idempSess,
          round_index: 1,
          instruction_payload: "请总结这个结论"
        }
      })
    }),
    env
  );
  const replayRaw = await chatResReplay.text();
  assert.equal(
    chatResReplay.status,
    200,
    `Replay status mismatch (${chatResReplay.status}): ${replayRaw} | sse1_tail=${sse1.slice(-400)}`
  );
  const replayJson = JSON.parse(replayRaw) as any;
  assert.equal(replayJson.already_completed, true);
  assert.equal(replayJson.authoritative_git_state.commit_order.length, 1);
  assert.equal(
    (db.prepare("SELECT credits FROM users WHERE user_id = ?").get(userRev02) as any).credits,
    creditsAfterChat1
  );

  // Same clientOpId + DIFFERENT payload -> 409 client_op_conflict
  const chatResConflict = await handleChat(
    new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenRev02}` },
      body: JSON.stringify({
        clientOpId: clientOp,
        disableBrowserInference: true,
        chosenTemplateId: "tpl-sql-chat",
        envelope: {
          envelope_id: "e3",
          session_id: idempSess,
          round_index: 1,
          instruction_payload: "完全不同的问题"
        }
      })
    }),
    env
  );
  assert.equal(chatResConflict.status, 409);
  assert.equal(((await chatResConflict.json()) as any).error, "client_op_conflict");

  // Fail-closed plan freeze on DB failure: NO credits deducted!
  const creditsBeforeDbErr = (
    db.prepare("SELECT credits FROM users WHERE user_id = ?").get(userRev02Freeze) as any
  ).credits;
  const brokenFreezeEnv = {
    ...env,
    DB: {
      prepare(q: string) {
        if (q.includes("INSERT INTO dag_run_plans")) {
          return {
            bind() {
              return {
                async run() {
                  throw new Error("Simulated D1 write failure");
                }
              };
            }
          };
        }
        return env.DB.prepare(q);
      },
      batch: env.DB.batch.bind(env.DB)
    } as any
  } as Env;
  const freezeErrRes = await handleChat(
    new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenRev02Freeze}` },
      body: JSON.stringify({
        clientOpId: "op_freeze_err",
        chosenTemplateId: "tpl-sql-chat",
        envelope: {
          envelope_id: "e4",
          session_id: idempSess,
          round_index: 2,
          instruction_payload: "DB failure abort check"
        }
      })
    }),
    brokenFreezeEnv
  );
  assert.equal(freezeErrRes.status, 503);
  assert.equal(
    (db.prepare("SELECT credits FROM users WHERE user_id = ?").get(userRev02Freeze) as any).credits,
    creditsBeforeDbErr
  );
  console.log(
    "  ✓ REV-02 (First-submit client_op_id replay/conflict & 503 fail-closed plan freeze): PASSED"
  );

  // -----------------------------------------------------------------------
  // 4. REV-03 (Idempotent Phase Billing) + REV-05 (Cloud Tail Retry Commit)
  // -----------------------------------------------------------------------
  const creditsBeforePhase = (
    db.prepare("SELECT credits FROM users WHERE user_id = ?").get(userA) as any
  ).credits;
  const phase = {
    userId: userA,
    runId: "run_billing_idemp",
    phase: "initial_stream",
    actualCost: 3,
    reservedCredits: 5,
    templateNameZh: "计费测试"
  };
  const count = (table: "credit_ledger" | "run_billing_settlements") =>
    Number(
      (db.prepare(`SELECT COUNT(*) AS count FROM ${table} WHERE user_id = ?`).get(userA) as any)
        .count
    );
  const ledgerBefore = count("credit_ledger");
  const markersBefore = count("run_billing_settlements");
  assert.deepEqual(
    await Promise.all([settleRunBillingPhase(env, phase), settleRunBillingPhase(env, phase)]),
    [true, true]
  );
  assert.equal(
    (db.prepare("SELECT credits FROM users WHERE user_id = ?").get(userA) as any).credits,
    creditsBeforePhase + 2
  );
  assert.equal(count("credit_ledger"), ledgerBefore + 1);
  assert.equal(count("run_billing_settlements"), markersBefore + 1);

  const retryPhase = {
    ...phase,
    phase: "resume_failed_settlement",
    actualCost: 5,
    reservedCredits: 3
  };
  const failBillingEnv = {
    ...env,
    DB: {
      prepare: env.DB.prepare.bind(env.DB),
      batch: async () => {
        throw new Error("Simulated billing batch failure");
      }
    } as unknown as D1Database
  };
  assert.equal(await settleOrQueueBillingPhase(failBillingEnv, retryPhase), "pending");
  assert.equal(count("credit_ledger"), ledgerBefore + 1);
  await Promise.all([retryPendingBillingSettlements(env), retryPendingBillingSettlements(env)]);
  assert.equal(count("credit_ledger"), ledgerBefore + 2);
  assert.equal(count("run_billing_settlements"), markersBefore + 2);
  assert.equal(
    (db.prepare("SELECT credits FROM users WHERE user_id = ?").get(userA) as any).credits,
    creditsBeforePhase
  );
  assert.equal(
    (db.prepare("SELECT COUNT(*) AS count FROM pending_billing_settlements").get() as any).count,
    0
  );

  // REV-05: Cloud tail save + transient failure + /commit-retry
  const retryRunId = "run_cloud_retry_rev05";
  const retrySessId = "sess_retry_rev05";
  const retryEnv = buildEnvelope(retrySessId, userA, "Cloud retry prompt");
  await registerAndFreezeDagRunPlan(env, {
    runId: retryRunId,
    userId: userA,
    sessionId: retrySessId,
    clientOpId: "op_cloud_retry",
    requestDigest: "dig_cloud_retry",
    planHash: await computePlanHash(revDag),
    dag: revDag,
    originalEnvelope: retryEnv,
    resolvedEnvelope: retryEnv,
    isReRun: false,
    expectedParentCommitId: null,
    expectedBaseRevision: null
  });
  const stagedCloud = await saveCloudTailResult(env, {
    userId: userA,
    sessionId: retrySessId,
    runId: retryRunId,
    finalOutput: "Precomputed Cloud Output For Retry",
    generatedMedia: [],
    perceptualCacheUpdates: []
  });
  assert.equal(stagedCloud.ok, true);

  const retryHttpRes = await handleCommitRetrySessionTurn(
    new Request(`https://nanomesh.local/api/session/${retrySessId}/commit-retry`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenA}` },
      body: JSON.stringify({ run_id: retryRunId })
    }),
    env,
    retrySessId
  );
  assert.equal(retryHttpRes.status, 200);
  const retrySnap = (await retryHttpRes.json()) as any;
  assert.equal(retrySnap.commits[retryRunId].output_summary, "Precomputed Cloud Output For Retry");
  console.log("  ✓ REV-03 & REV-05 (Idempotent phase billing & /commit-retry recovery): PASSED");

  // -----------------------------------------------------------------------
  // 5. NM-STATE-08 (>16KB Shift-Left Doc R2 Offload) + PLAN-03 (Pre-Cache Access)
  //    + REV-06 / PLAN-07 (Session & Account Deletion Tombstones + R2 Sweep)
  // -----------------------------------------------------------------------
  const largeDocSess = "sess_shift_left_purge";
  const largeDocText = "LARGE_DOC_START_" + "X".repeat(20 * 1024) + "_LARGE_DOC_END";
  const largeDocEnv = buildEnvelope(largeDocSess, userA, "Read large attached doc", {
    assets_manifest: [
      {
        asset_id: "doc_large_1",
        filename: "big.txt",
        modality: "text_doc",
        mime_type: "text/plain",
        file_size: largeDocText.length,
        in_memory_text: largeDocText,
        source_digest: "large_dig_1",
        consumed: false,
        is_new: true
      }
    ]
  });
  await registerAndFreezeDagRunPlan(env, {
    runId: "run_large_doc",
    userId: userA,
    sessionId: largeDocSess,
    clientOpId: "op_large_doc",
    requestDigest: "dig_large_doc",
    planHash: await computePlanHash(revDag),
    dag: revDag,
    originalEnvelope: largeDocEnv,
    resolvedEnvelope: largeDocEnv,
    isReRun: false,
    expectedParentCommitId: null,
    expectedBaseRevision: null
  });
  // Also stage a STAGING generated asset to verify REV-06 cleans un-committed R2 keys
  const stagingKey = `tmp/${userA}/${largeDocSess}/staging_orphan.png`;
  await registerStagingGeneratedAsset(env, {
    userId: userA,
    sessionId: largeDocSess,
    assetId: "staging_orphan_1",
    modality: "image",
    mimeType: "image/png",
    r2Key: stagingKey,
    fileSize: 8
  });
  await env.R2.put(stagingKey, new Uint8Array([1, 2, 3, 4]));

  const largeCommit = await commitAuthoritativeSessionTurn(env, {
    userId: userA,
    sessionId: largeDocSess,
    runId: "run_large_doc",
    envelope: largeDocEnv,
    dag: revDag,
    finalOutput: "Large doc analyzed",
    generatedMedia: [],
    perceptualCacheUpdates: [],
    authMode: "cloud"
  });
  assert.ok(largeCommit.ok);

  // Confirm DB stores text_r2_key with NULL inline in_memory_text for >16KB doc
  const storedAssetRow = db
    .prepare(
      "SELECT in_memory_text, text_r2_key FROM session_assets WHERE user_id = ? AND asset_id = ?"
    )
    .get(userA, "doc_large_1") as any;
  assert.equal(storedAssetRow.in_memory_text, null);
  assert.ok(storedAssetRow.text_r2_key);

  // Hydrate missing inline body from R2
  const docRecallList = [
    {
      asset_id: "doc_large_1",
      filename: "big.txt",
      modality: "text_doc" as const,
      mime_type: "text/plain",
      file_size: largeDocText.length,
      source_digest: "large_dig_1",
      consumed: false
    }
  ];
  await hydrateDocumentTextBodies(env, userA, largeDocSess, docRecallList);
  assert.equal((docRecallList[0] as any).in_memory_text, largeDocText);

  // Cron keeps old assets linked to a committed round or an active execution.
  const cronSessionId = "sess_cron_asset_retention";
  const cronImage = `tmp/${userA}/preflight/attached.png`;
  const cronStaging = `tmp/${userA}/preflight/staging.png`;
  const cronOrphan = `tmp/${userA}/preflight/orphan.png`;
  const cronFresh = `tmp/${userA}/preflight/fresh.png`;
  for (const key of [cronImage, cronStaging, cronOrphan, cronFresh]) {
    await env.R2.put(key, "fixture");
  }
  db.prepare(
    `INSERT INTO session_assets (user_id, session_id, asset_id, modality, r2_key, status)
     VALUES (?, ?, ?, 'image', ?, ?)`
  ).run(userA, cronSessionId, "cron-image", cronImage, "COMMITTED");
  await acquireSessionExecutionLock(env, {
    userId: userA,
    sessionId: cronSessionId,
    runId: "cron-active",
    clientOpId: "cron-active"
  });
  db.prepare(
    `INSERT INTO session_assets (user_id, session_id, asset_id, modality, r2_key, status)
     VALUES (?, ?, ?, 'image', ?, ?)`
  ).run(userA, cronSessionId, "cron-staging", cronStaging, "STAGING");
  const old = new Date(Date.now() - 25 * 3600 * 1000);
  const cronObjects = [cronImage, cronStaging, cronOrphan, storedAssetRow.text_r2_key].map(
    (key) => ({ key, uploaded: old })
  );
  cronObjects.push({ key: cronFresh, uploaded: new Date() });
  const cronEnv = {
    ...env,
    R2: {
      ...r2,
      list: async () => ({ objects: cronObjects, truncated: false })
    } as unknown as R2Bucket
  };
  const cronFaultEnv = {
    ...cronEnv,
    DB: {
      prepare(sql: string) {
        if (sql.includes("SELECT a.r2_key")) throw new Error("Simulated asset ledger outage");
        return env.DB.prepare(sql);
      }
    } as unknown as D1Database
  };
  await worker.scheduled({} as ScheduledEvent, cronFaultEnv, {} as ExecutionContext);
  assert.ok(await env.R2.get(cronOrphan), "Cron must leave objects intact if the ledger fails");
  await worker.scheduled({} as ScheduledEvent, cronEnv, {} as ExecutionContext);
  for (const key of [cronImage, cronStaging, cronFresh, storedAssetRow.text_r2_key]) {
    assert.ok(await env.R2.get(key), `Cron must retain ${key}`);
  }
  assert.equal(await env.R2.get(cronOrphan), null);
  const recalledAfterCleanup = [{ ...docRecallList[0], in_memory_text: undefined }];
  await hydrateDocumentTextBodies(env, userA, largeDocSess, recalledAfterCleanup);
  assert.equal(recalledAfterCleanup[0].in_memory_text, largeDocText);
  await finishRunWithoutCommit(env, {
    userId: userA,
    sessionId: cronSessionId,
    runId: "cron-active",
    outcome: "ABORTED"
  });

  // Pre-cache access denial check (PLAN-03): unowned R2 key must throw BEFORE lookupDeterministicCache!
  const unownedEnv = buildEnvelope("sess_victim_attacker", userA, "Read unowned R2");
  const preCachedKey = await computeDeterministicSignature(
    "role-direct-chat",
    "cf_llama31_8b",
    "::stolen-dig::",
    "prompt",
    userA,
    "sess_victim_attacker"
  );
  await storeDeterministicCache(
    env,
    preCachedKey,
    "role-direct-chat",
    "cf_llama31_8b",
    "::stolen-dig::",
    "prompt",
    "SHOULD_NOT_LEAK_CACHE",
    userA,
    "sess_victim_attacker"
  );
  const boladDag = buildSampleDag();
  boladDag.nodes[0].claimed_assets = [
    {
      asset_id: "forged_img",
      filename: "forged.png",
      modality: "image",
      mime_type: "image/png",
      file_size: 10,
      r2_key: `tmp/${userA}/${largeDocSess}/not_owned_by_attacker.png`,
      source_digest: "stolen-dig",
      consumed: false
    }
  ];
  const boladStream = await executeDAGStream(env, boladDag, unownedEnv, {
    userId: userA,
    sessionId: "sess_victim_attacker",
    verifyAssetAccess: (asset) =>
      verifySessionAssetR2Access(env, userA, "sess_victim_attacker", asset)
  });
  const boladSse = await new Response(boladStream).text();
  assert.ok(
    boladSse.includes("event: dag_error") && !boladSse.includes("SHOULD_NOT_LEAK_CACHE"),
    "PLAN-03: Asset ownership check must block before cache lookup!"
  );

  // Simulate R2 outage during session delete -> pending_r2_deletions preserves BOTH text_r2_key & stagingKey!
  r2.failDelete = true;
  await tombstoneAndPurgeSession(env, userA, largeDocSess);
  assert.ok(r2.objects.has(storedAssetRow.text_r2_key));
  assert.ok(r2.objects.has(stagingKey));
  assert.equal(
    (
      db
        .prepare(
          "SELECT COUNT(*) AS cnt FROM pending_r2_deletions WHERE user_id = ? AND session_id = ?"
        )
        .get(userA, largeDocSess) as any
    ).cnt,
    2
  );

  // Deleted session rejects subsequent state/history/chat requests with 410
  assert.equal(
    (
      await handleGetSessionState(
        new Request(`https://nanomesh.local/api/session/${largeDocSess}/state`, {
          headers: { Cookie: `session=${tokenA}` }
        }),
        env,
        largeDocSess
      )
    ).status,
    410
  );
  assert.equal(
    (
      await handleSaveHistory(
        new Request("https://nanomesh.local/api/history", {
          method: "POST",
          headers: {
            "X-History-Account": userA,
            "Content-Type": "application/json",
            Cookie: `session=${tokenA}`
          },
          body: JSON.stringify({ sessionId: largeDocSess, rounds: [{ runId: "x" }] })
        }),
        env
      )
    ).status,
    410
  );

  // Recover R2 and run sweep -> both text_r2_key & stagingKey deleted!
  r2.failDelete = false;
  await sweepPendingR2Cleanups(env, userA);
  assert.equal(r2.objects.has(storedAssetRow.text_r2_key), false);
  assert.equal(r2.objects.has(stagingKey), false);

  const staleAccountSave = await handleSaveHistory(
    new Request("https://nanomesh.local/api/history", {
      method: "POST",
      headers: { "X-History-Account": userA, Cookie: `session=${tokenB}` },
      body: JSON.stringify({
        sessionId: "stale-account-history",
        rounds: [{ userText: "A's history" }]
      })
    }),
    env
  );
  assert.equal(staleAccountSave.status, 409);
  assert.equal(
    db
      .prepare("SELECT 1 FROM user_chat_sessions WHERE user_id = ? AND session_id = ?")
      .get(userB, "stale-account-history"),
    undefined
  );

  // PLAN-06: History .slice(-100) retains newest 100 rounds
  const manyRounds = Array.from({ length: 120 }, (_, idx) => ({ round: idx + 1 }));
  const saveManyRes = await handleSaveHistory(
    new Request("https://nanomesh.local/api/history", {
      method: "POST",
      headers: {
        "X-History-Account": userA,
        "Content-Type": "application/json",
        Cookie: `session=${tokenA}`
      },
      body: JSON.stringify({ sessionId: "sess_many_rounds", rounds: manyRounds })
    }),
    env
  );
  assert.equal(saveManyRes.status, 200);
  const saveManyJson = (await saveManyRes.json()) as any;
  assert.equal(saveManyJson.truncated_older_count, 20);
  const savedRoundsRow = JSON.parse(
    (
      db
        .prepare("SELECT rounds_json FROM user_chat_sessions WHERE user_id = ? AND session_id = ?")
        .get(userA, "sess_many_rounds") as any
    ).rounds_json
  );
  assert.equal(savedRoundsRow.length, 100);
  const rejectedHistory = await handleSaveHistory(
    new Request("https://nanomesh.local/api/history", {
      method: "POST",
      headers: { "X-History-Account": userA, Cookie: `session=${tokenA}` },
      body: JSON.stringify({
        sessionId: "sess_many_rounds",
        rounds: Array.from({ length: 100 }, () => ({ output: "x".repeat(6000) }))
      })
    }),
    env
  );
  assert.equal(rejectedHistory.status, 413);
  const preservedHistory = db
    .prepare("SELECT rounds_json FROM user_chat_sessions WHERE user_id = ? AND session_id = ?")
    .get(userA, "sess_many_rounds") as { rounds_json: string };
  assert.deepEqual(JSON.parse(preservedHistory.rounds_json), savedRoundsRow);

  assert.equal(savedRoundsRow[0].round, 21);
  assert.equal(savedRoundsRow[99].round, 120);

  // Account deletion wipes EVERY 0024/0025 table + R2 prefix purges
  await handleDeleteAccount(
    new Request("https://nanomesh.local/api/user", {
      method: "POST",
      headers: { Cookie: `session=${tokenA}` }
    }),
    env
  );
  for (const tbl of [
    "user_chat_sessions",
    "chat_session_states",
    "session_branches",
    "session_commits",
    "session_assets",
    "dag_run_plans",
    "asset_perceptual_cache",
    "dag_execution_cache",
    "run_billing_settlements"
  ]) {
    const cnt = (
      db.prepare(`SELECT COUNT(*) AS cnt FROM ${tbl} WHERE user_id = ?`).get(userA) as any
    ).cnt;
    assert.equal(cnt, 0, `${tbl} must have 0 remaining rows for deleted userA`);
  }
  // User B data remains completely untouched!
  const bCommits = (
    db.prepare("SELECT COUNT(*) AS cnt FROM session_commits WHERE user_id = ?").get(userB) as any
  ).cnt;
  assert.equal(bCommits, 1, "Deleting User A must never touch User B data");

  // Orchestrator NM-STATE-13 (DETACH_RESET isolation) & NM-STATE-14 (isReRoute asset hydration)
  const detachEnv: Env = {
    ...env,
    AI: {
      async run(_model: string, input: any) {
        if (JSON.stringify(input).includes("Joint Git-DAG")) {
          return {
            response: JSON.stringify({
              intent_op: "DETACH_RESET",
              target_branch_id: "main",
              source_branch_ids: [],
              asset_bindings: [],
              delivery_confidence: "clear"
            })
          };
        }
        return { response: "Mock LLM response" };
      }
    } as any
  } as unknown as Env;
  const detachedDag = await runOrchestrationPipeline(
    detachEnv,
    buildEnvelope("sess_orch", userB, "无关新话题，全新开始分析另一件事"),
    {
      hasPreviousRound: true,
      previousRoundSummary: "之前的海报分析",
      activeBranchId: "main",
      activeBranchSummary: "之前的海报分析",
      branchCatalog: [
        {
          branch_id: "main",
          topic: "海报",
          is_media: true,
          last_summary: "之前的海报分析",
          head_commit_id: "cmt_1"
        }
      ]
    }
  );
  assert.equal(detachedDag.reasoning_trace.intent_state, "DETACH_RESET");
  assert.ok(
    detachedDag.reasoning_trace.target_branch_id &&
      detachedDag.reasoning_trace.target_branch_id !== "main",
    "DETACH_RESET must allocate an isolated branch ID when prior history exists"
  );

  const rerouteEnvelope = buildEnvelope("sess_orch", userB, "重新对比图B和文档C");
  const reroutedDag = await runOrchestrationPipeline(env, rerouteEnvelope, {
    reRouteMode: "switch_model",
    chosenRoleModels: { "role-sql-chat": "cf_sql_text" },
    sessionAssetLedger: [
      {
        asset_id: "hist_img_b",
        filename: "b.png",
        modality: "image",
        mime_type: "image/png",
        file_size: 24,
        introduced_round: 1,
        branch_id: "main",
        r2_key: `tmp/${userB}/sess_orch/b.png`,
        source_digest: "dig_b",
        origin: "upload",
        cached_perceptual_text: "Poster B objective extraction"
      },
      {
        asset_id: "hist_doc_c",
        filename: "c.txt",
        modality: "text_doc",
        mime_type: "text/plain",
        file_size: 12,
        introduced_round: 1,
        branch_id: "main",
        source_digest: "dig_c",
        origin: "upload",
        in_memory_text: "C DOCUMENT CONTENT"
      }
    ],
    frozenResolvedPlan: {
      intent_state: "CROSS_FUSION",
      target_branch_id: "main",
      mounted_asset_bindings: [
        { asset_id: "hist_img_b", bind_mode: "CACHED_TEXT" },
        { asset_id: "hist_doc_c", bind_mode: "RAW_MEDIA" }
      ]
    }
  });
  assert.ok(
    rerouteEnvelope.assets_manifest.some(
      (a) => a.asset_id === "hist_doc_c" && a.in_memory_text === "C DOCUMENT CONTENT"
    ),
    "isReRoute must preserve/rehydrate historical text_doc from mounted_asset_bindings"
  );
  assert.ok(
    reroutedDag.nodes.some((n) =>
      n.claimed_assets?.some(
        (a) =>
          a.asset_id === "hist_img_b" &&
          a.cached_perceptual_text === "Poster B objective extraction"
      )
    ),
    "isReRoute must preserve/rehydrate historical mounted image into prep node"
  );

  // Keep reference to handleDeleteHistoryItem & handleChatContinue to ensure clean compile coverage
  assert.equal(typeof handleDeleteHistoryItem, "function");
  assert.equal(typeof handleChatContinue, "function");

  console.log(
    "  ✓ NM-STATE-08 / PLAN-03 / PLAN-06 / PLAN-07 / REV-06 / NM-STATE-13 / NM-STATE-14: PASSED"
  );

  // -----------------------------------------------------------------------
  // 7. PHASE 4 CLOSURE (NM-STATE-R01 ~ R05) ON REAL SQLITE:
  //    User Acceptance Path A: Busy delete rejected (409) -> finishes -> deleted (200)
  //    User Acceptance Path B: "甲" -> micro-tune "乙" -> reload R05 recall -> fail/abandon -> follow-up inherits "乙"
  // -----------------------------------------------------------------------
  assert.ok(migrationFiles.includes("0026_session_occupancy_and_rerun.sql"));

  const userR = "usr_sql_phase4";
  db.prepare(
    "INSERT INTO users (user_id, email, username, credits, token_version) VALUES (?, ?, ?, ?, 1)"
  ).run(userR, "phase4@nanomesh.local", "phase4user", 50);
  const tokenR = await signJWT({ userId: userR, tokenVersion: 1 }, env.JWT_SECRET, 3600);

  // Seed a zero-credit user for R04 quota failure release & replay test
  const userZero = "usr_sql_zero_r04";
  db.prepare(
    "INSERT INTO users (user_id, email, username, credits, token_version) VALUES (?, ?, ?, ?, 1)"
  ).run(userZero, "zero_r04@nanomesh.local", "zeror04", 0);
  const tokenZero = await signJWT({ userId: userZero, tokenVersion: 1 }, env.JWT_SECRET, 3600);

  // R04: Pre-deduction 403 insufficient_quota immediately releases lock & records FAILED terminal state
  const r04Sess = "sess_r04_quota";
  const r04Op = "op_r04_quota_1";
  const quotaFailRes = await handleChat(
    new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenZero}` },
      body: JSON.stringify({
        clientOpId: r04Op,
        disableBrowserInference: true,
        chosenTemplateId: "tpl-sql-chat",
        envelope: {
          envelope_id: "e_r04_1",
          session_id: r04Sess,
          round_index: 1,
          instruction_payload: "Quota fail test"
        }
      })
    }),
    env
  );
  assert.equal(quotaFailRes.status, 403);
  assert.equal(((await quotaFailRes.json()) as any).error, "insufficient_quota");
  const r04StateRow = db
    .prepare(
      "SELECT occupancy_phase, active_run_id FROM chat_session_states WHERE user_id = ? AND session_id = ?"
    )
    .get(userZero, r04Sess) as any;
  assert.equal(r04StateRow?.occupancy_phase, null, "403 pre-deduction failure must release lock");
  assert.equal(r04StateRow?.active_run_id, null);

  // Same clientOpId replay after 403 must return original 403 insufficient_quota (NOT 409 run_already_in_progress!)
  const quotaReplayRes = await handleChat(
    new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenZero}` },
      body: JSON.stringify({
        clientOpId: r04Op,
        disableBrowserInference: true,
        chosenTemplateId: "tpl-sql-chat",
        envelope: {
          envelope_id: "e_r04_1",
          session_id: r04Sess,
          round_index: 1,
          instruction_payload: "Quota fail test"
        }
      })
    }),
    env
  );
  assert.equal(quotaReplayRes.status, 403);
  assert.equal(((await quotaReplayRes.json()) as any).error, "insufficient_quota");

  // Top up credits & send with new clientOpId -> immediately succeeds!
  db.prepare("UPDATE users SET credits = 20 WHERE user_id = ?").run(userZero);
  const afterTopupRes = await handleChat(
    new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenZero}` },
      body: JSON.stringify({
        clientOpId: "op_r04_topup_ok",
        disableBrowserInference: true,
        chosenTemplateId: "tpl-sql-chat",
        envelope: {
          envelope_id: "e_r04_2",
          session_id: r04Sess,
          round_index: 1,
          instruction_payload: "Quota recovered test"
        }
      })
    }),
    env
  );
  assert.equal(afterTopupRes.status, 200);
  await afterTopupRes.text();

  // Acceptance Path A (R01 + R02 + R03): Busy delete rejected (409) & concurrent tab blocked (409) -> finishes/abandons -> deleted (200)
  const pathASess = "sess_path_a_busy_delete";
  const pathARes1 = await handleChat(
    new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
      body: JSON.stringify({
        clientOpId: "op_pa_1",
        disableBrowserInference: true,
        chosenTemplateId: "tpl-sql-chat",
        envelope: {
          envelope_id: "e_pa_1",
          session_id: pathASess,
          round_index: 1,
          instruction_payload: "Initial committed round"
        }
      })
    }),
    env
  );
  assert.equal(pathARes1.status, 200);
  await pathARes1.text();

  // Simulate an active in-flight run holding EXECUTING lock on pathASess
  const execLockRes = await acquireSessionExecutionLock(env, {
    userId: userR,
    sessionId: pathASess,
    runId: "run_pa_inflight",
    clientOpId: "op_pa_inflight"
  });
  assert.equal(execLockRes.ok, true);

  // Concurrent second /api/chat (both normal send and canvas isReRun) must be rejected BEFORE orchestration with 409 session_busy
  const concurrentChatRes = await handleChat(
    new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
      body: JSON.stringify({
        clientOpId: "op_pa_tab2",
        isReRun: true,
        chosenTemplateId: "tpl-sql-chat",
        envelope: {
          envelope_id: "e_pa_tab2",
          session_id: pathASess,
          round_index: 1,
          instruction_payload: "Tab 2 concurrent rerun"
        }
      })
    }),
    env
  );
  assert.equal(concurrentChatRes.status, 409);
  assert.equal(((await concurrentChatRes.json()) as any).error, "session_busy");

  // Delete while EXECUTING -> 409 session_busy, zero rows purged!
  const delBusyExecRes = await handleDeleteHistoryItem(
    new Request(`https://nanomesh.local/api/history/${pathASess}`, {
      method: "DELETE",
      headers: { "X-History-Account": userR, Cookie: `session=${tokenR}` }
    }),
    env,
    pathASess
  );
  assert.equal(delBusyExecRes.status, 409);
  assert.equal(((await delBusyExecRes.json()) as any).error, "session_busy");
  assert.equal(
    (
      db
        .prepare("SELECT COUNT(*) AS cnt FROM session_commits WHERE user_id = ? AND session_id = ?")
        .get(userR, pathASess) as any
    ).cnt,
    1,
    "Busy delete must never purge committed commits"
  );

  // Transition into AWAITING_COMMIT -> concurrent delete AND concurrent send still rejected 409; GET /state exposes awaiting_commit!
  assert.equal(await markSessionAwaitingCommit(env, userR, pathASess, "run_pa_inflight"), false);
  await registerAndFreezeDagRunPlan(env, {
    userId: userR,
    sessionId: pathASess,
    runId: "run_pa_inflight",
    clientOpId: "op_pa_inflight",
    requestDigest: "pa_inflight",
    planHash: "ph_pa_inflight",
    dag: buildSampleDag(),
    originalEnvelope: buildEnvelope(pathASess, userR, "inflight"),
    resolvedEnvelope: buildEnvelope(pathASess, userR, "inflight"),
    isReRun: false,
    expectedParentCommitId: null,
    expectedBaseRevision: null
  });
  assert.equal(
    await markSessionAwaitingCommit(
      env,
      userR,
      pathASess,
      "run_pa_inflight",
      "wrong-browser-token"
    ),
    false
  );
  assert.equal(await markSessionAwaitingCommit(env, userR, pathASess, "run_pa_inflight"), true);
  const awaitingSnapRes = await handleGetSessionState(
    new Request(`https://nanomesh.local/api/session/${pathASess}/state`, {
      headers: { Cookie: `session=${tokenR}` }
    }),
    env,
    pathASess
  );
  assert.equal(awaitingSnapRes.status, 200);
  const awaitingSnapJson = (await awaitingSnapRes.json()) as any;
  assert.equal(awaitingSnapJson.occupancy_phase, "AWAITING_COMMIT");
  assert.equal(awaitingSnapJson.active_run_id, "run_pa_inflight");

  const delBusyAwaitingRes = await handleDeleteHistoryItem(
    new Request(`https://nanomesh.local/api/history/${pathASess}`, {
      method: "DELETE",
      headers: { "X-History-Account": userR, Cookie: `session=${tokenR}` }
    }),
    env,
    pathASess
  );
  assert.equal(delBusyAwaitingRes.status, 409);

  // Release / finish the active run -> now session is IDLE -> DELETE succeeds 200 & tombstones!
  await finishRunWithoutCommit(env, {
    userId: userR,
    sessionId: pathASess,
    runId: "run_pa_inflight",
    outcome: "ABORTED",
    failureStatus: 409,
    failureCode: "test_done"
  });
  const delIdleRes = await handleDeleteHistoryItem(
    new Request(`https://nanomesh.local/api/history/${pathASess}`, {
      method: "DELETE",
      headers: { "X-History-Account": userR, Cookie: `session=${tokenR}` }
    }),
    env,
    pathASess
  );
  assert.equal(delIdleRes.status, 200);
  const delStateCheck = db
    .prepare("SELECT deleted_at FROM chat_session_states WHERE user_id = ? AND session_id = ?")
    .get(userR, pathASess) as any;
  assert.ok(delStateCheck?.deleted_at, "Idle delete after run finishes must tombstone session");

  // Acceptance Path B (R03 + R05):
  // 第1轮上传图 -> 第2轮召回历史图生成 "甲" -> 画布微调生成 "乙" -> 刷新缺参数微调验证 R05 服务端还原 -> 下一次微调进待保存并点击放弃回滚 -> 续问仍继承 "乙"
  const origDateNow = Date.now;
  let clockOffsetMs = 0;
  Date.now = () => origDateNow() + clockOffsetMs;
  try {
    db.prepare(
      `INSERT OR IGNORE INTO models
       (model_id, display_name, provider, endpoint, modalities, in_modalities, out_modalities, tags, context_window, max_concurrency, precision, cost_per_1k_tokens, status, inference_target, auth_mode, api_format)
       VALUES ('cf_sql_vision', 'SQL Vision', 'Cloudflare', '@cf/meta/llama-3.2-11b-vision-instruct', '["image","text"]', '["image","text"]', '["text"]', '["#vision"]', 8192, 10, 0.9, 1, 'active', 'edge', 'none', 'workers_ai')`
    ).run();
    db.prepare(
      `INSERT OR IGNORE INTO dag_roles
       (role_id, name_zh, name_en, in_modalities, out_modalities, requisition_tags)
       VALUES ('role-sql-vision', 'SQL识图岗', 'SQL Vision', '["image","text"]', '["text"]', '["#vision"]')`
    ).run();
    db.prepare(
      `INSERT OR IGNORE INTO dag_templates
       (template_id, name_zh, name_en, desc_zh, desc_en, head_modalities, tail_modalities, roles, role_sequence, status, priority)
       VALUES ('tpl-sql-vision', 'SQL识图模板', 'SQL Vision', 'desc', 'desc', '["image","text"]', '["text"]', '["role-sql-vision"]', '["role-sql-vision"]', 'active', 200)`
    ).run();

    const pathBSess = "sess_path_b_r05";
    const recalledImgId = "ast_pb_img_01";
    const recalledImgKey = `tmp/${userR}/${pathBSess}/ref.png`;
    await r2.put(recalledImgKey, new Uint8Array([137, 80, 78, 71]), {
      httpMetadata: { contentType: "image/png" }
    });
    await registerPresignedAssetTicket(env, {
      assetId: recalledImgId,
      userId: userR,
      filename: "ref.png",
      modality: "image",
      mimeType: "image/png",
      fileSize: 4,
      r2Key: recalledImgKey
    });

    let mockAiMode = "round1";
    const observedPrompts: string[] = [];
    const observedImgInputs: number[] = [];
    const pathBEnv: Env = {
      ...env,
      AI: {
        async run(_model: string, input: any) {
          const serialized = JSON.stringify(input || {});
          if (serialized.includes("Joint Git-DAG")) {
            if (mockAiMode === "round2") {
              return {
                response: JSON.stringify({
                  intent_op: "REBIND_ROOT",
                  target_branch_id: "main",
                  source_branch_ids: ["main"],
                  asset_bindings: [{ asset_id: recalledImgId, bind_mode: "RAW_MEDIA" }],
                  delivery_confidence: "clear"
                })
              };
            }
            return {
              response: JSON.stringify({
                intent_op: "ANCHOR_TAIL",
                target_branch_id: "main",
                source_branch_ids: ["main"],
                asset_bindings: [],
                delivery_confidence: "clear"
              })
            };
          }
          observedPrompts.push(serialized);
          const msgArr = Array.isArray(input?.messages) ? input.messages : [];
          const hasImgContent =
            (typeof input?.image === "string" && input.image.length > 0) ||
            ((Array.isArray(input?.image) || ArrayBuffer.isView(input?.image)) &&
              input.image.byteLength !== 0 &&
              (input.image.length ?? input.image.byteLength) > 0) ||
            msgArr.some(
              (m: any) =>
                Array.isArray(m.content) && m.content.some((part: any) => part.type === "image_url")
            );
          observedImgInputs.push(hasImgContent ? 1 : 0);
          if (mockAiMode === "round1") return { response: "初稿总结完成：图像特征解析正常" };
          if (mockAiMode === "round2") return { response: "甲_权威首版摘要结果" };
          if (mockAiMode === "rerun_yi") return { response: "乙_画布微调新摘要结果" };
          if (mockAiMode === "rerun_r05") return { response: "乙_画布微调新摘要结果" };
          if (mockAiMode === "followup") return { response: "丙_基于乙继续扩展完成" };
          return { response: "默认响应结果已完整生成" };
        }
      } as any
    };

    // Round 1: Upload & commit image
    clockOffsetMs += 6000;
    mockAiMode = "round1";
    const r1Res = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({
          clientOpId: "op_pb_r1",
          disableBrowserInference: true,
          chosenTemplateId: "tpl-sql-vision",
          envelope: {
            envelope_id: "e_pb_r1",
            session_id: pathBSess,
            round_index: 1,
            instruction_payload: "解析上传参考图",
            assets_manifest: [
              {
                asset_id: recalledImgId,
                filename: "ref.png",
                modality: "image",
                mime_type: "image/png",
                file_size: 4,
                r2_key: recalledImgKey,
                source_digest: "dig_pb_img_01",
                is_new: true
              }
            ]
          }
        })
      }),
      pathBEnv
    );
    assert.equal(r1Res.status, 200);
    const r1Sse = await r1Res.text();
    assert.ok(r1Sse.includes('"state_committed":true'), `r1 failed to commit: ${r1Sse}`);

    // Round 2: Recall historical image & output "甲"
    clockOffsetMs += 6000;
    mockAiMode = "round2";
    const r2Res = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({
          clientOpId: "op_pb_r2",
          disableBrowserInference: true,
          chosenTemplateId: "tpl-sql-vision",
          envelope: {
            envelope_id: "e_pb_r2",
            session_id: pathBSess,
            round_index: 2,
            instruction_payload: "AUTHORITATIVE_ROUND2_IMAGE_PROMPT",
            assets_manifest: []
          }
        })
      }),
      pathBEnv
    );
    assert.equal(r2Res.status, 200);
    const r2Sse = await r2Res.text();
    assert.ok(r2Sse.includes('"state_committed":true'), `r2 failed to commit: ${r2Sse}`);

    const snapAfterR2 = (await (
      await handleGetSessionState(
        new Request(`https://nanomesh.local/api/session/${pathBSess}/state`, {
          headers: { Cookie: `session=${tokenR}` }
        }),
        env,
        pathBSess
      )
    ).json()) as any;
    assert.equal(snapAfterR2.commit_order.length, 2);
    const round2CommitId = snapAfterR2.branches.main.head_commit_id;
    assert.ok(snapAfterR2.branches.main.last_summary.includes("甲_权威首版摘要结果"));

    // Canvas micro-tuning 1 -> produces "乙_画布微调新摘要结果" (revision 2)
    clockOffsetMs += 6000;
    mockAiMode = "rerun_yi";
    const rerunYiRes = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({
          clientOpId: "op_pb_rerun_yi",
          isReRun: true,
          baseCommitId: round2CommitId,
          disableBrowserInference: true,
          reRouteMode: "switch_template",
          chosenTemplateId: "tpl-sql-vision",
          envelope: {
            envelope_id: "e_pb_rerun_yi",
            session_id: pathBSess,
            round_index: 2,
            instruction_payload: "AUTHORITATIVE_ROUND2_IMAGE_PROMPT"
          }
        })
      }),
      pathBEnv
    );
    assert.equal(rerunYiRes.status, 200);
    await rerunYiRes.text();

    // NM-STATE-R05a verification:
    // 1. Sending an uncommitted rogue upload with is_new: true during rerun must be blocked with 400 rerun_new_upload_forbidden
    clockOffsetMs += 6000;
    const rogueR2Key = `tmp/${userR}/r2_rogue_uncommitted_file.png`;
    await registerPresignedAssetTicket(env, {
      assetId: "ast_rogue",
      userId: userR,
      r2Key: rogueR2Key,
      filename: "rogue.png",
      modality: "image",
      mimeType: "image/png",
      fileSize: 1024
    });

    const rogueRerunRes = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({
          clientOpId: "op_pb_rerun_rogue",
          isReRun: true,
          baseCommitId: round2CommitId,
          disableBrowserInference: true,
          reRouteMode: "switch_model",
          chosenTemplateId: "tpl-sql-vision",
          assets_manifest: [
            {
              asset_id: "ast_rogue",
              modality: "image",
              mime_type: "image/png",
              file_size: 1024,
              r2_key: rogueR2Key,
              is_new: true
            }
          ],
          envelope: {
            envelope_id: "e_pb_rerun_rogue",
            session_id: pathBSess,
            round_index: 99,
            instruction_payload: "Rogue asset test",
            assets_manifest: [
              {
                asset_id: "ast_rogue",
                modality: "image",
                mime_type: "image/png",
                file_size: 1024,
                r2_key: rogueR2Key,
                is_new: true
              }
            ]
          }
        })
      }),
      pathBEnv
    );
    assert.equal(rogueRerunRes.status, 400);
    assert.equal(((await rogueRerunRes.json()) as any).error, "rerun_new_upload_forbidden");

    // 2. Client reloads/drops frozenResolvedPlan or sends unrefreshed frozenAssets (with is_new: true for committed image);
    // server recognises committed r2_key, allows it, and restores authoritative prompt & recalled image BEFORE orchestration!
    clockOffsetMs += 6000;
    mockAiMode = "rerun_r05";
    const imgCallCountBeforeR05 = observedPrompts.length;
    const imgInputCountBeforeR05 = observedImgInputs.length;
    const rerunR05Res = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({
          clientOpId: "op_pb_rerun_r05",
          isReRun: true,
          baseCommitId: round2CommitId,
          disableBrowserInference: true,
          reRouteMode: "switch_model",
          chosenTemplateId: "tpl-sql-vision",
          // Pass the already-committed round 1 image with is_new: true (NM-STATE-R05a unrefreshed page simulation)
          assets_manifest: [
            {
              asset_id: recalledImgId,
              modality: "image",
              mime_type: "image/png",
              file_size: 4,
              r2_key: recalledImgKey,
              is_new: true
            }
          ],
          envelope: {
            envelope_id: "e_pb_rerun_r05",
            session_id: pathBSess,
            round_index: 99,
            instruction_payload: "CLIENT_FORGED_PROMPT_MUST_BE_IGNORED",
            assets_manifest: [
              {
                asset_id: recalledImgId,
                modality: "image",
                mime_type: "image/png",
                file_size: 4,
                r2_key: recalledImgKey,
                is_new: true
              }
            ]
          }
        })
      }),
      pathBEnv
    );
    assert.equal(rerunR05Res.status, 200);
    const rerunR05Sse = await rerunR05Res.text();
    assert.ok(
      rerunR05Sse.includes("event: dag_complete") && rerunR05Sse.includes('"state_committed":true')
    );
    const promptSentDuringR05 = observedPrompts.slice(imgCallCountBeforeR05).join("\n");
    assert.ok(
      promptSentDuringR05.includes("AUTHORITATIVE_ROUND2_IMAGE_PROMPT") &&
        !promptSentDuringR05.includes("CLIENT_FORGED_PROMPT_MUST_BE_IGNORED"),
      "R05 must restore authoritative D1 instruction_payload before orchestration"
    );
    assert.ok(
      observedImgInputs.slice(imgInputCountBeforeR05).some((v) => v === 1),
      `R05 must restore recalled historical image into downstream vision node even when client omitted assets/frozenResolvedPlan. SSE=${rerunR05Sse}`
    );
    const snapAfterR05 = (await (
      await handleGetSessionState(
        new Request(`https://nanomesh.local/api/session/${pathBSess}/state`, {
          headers: { Cookie: `session=${tokenR}` }
        }),
        env,
        pathBSess
      )
    ).json()) as any;
    assert.equal(
      snapAfterR05.commit_order.length,
      2,
      "R05 micro-tuning must NOT create a new round"
    );
    assert.equal(snapAfterR05.commits[round2CommitId].revision, 3);
    assert.ok(snapAfterR05.branches.main.last_summary.includes("乙_画布微调新摘要结果"));

    // Next canvas micro-tuning hits AWAITING_COMMIT -> locked -> user abandons via POST /api/session/:id/abandon
    const badPendingRunId = "run_pb_pending_fail";
    await registerAndFreezeDagRunPlan(env, {
      runId: badPendingRunId,
      userId: userR,
      sessionId: pathBSess,
      clientOpId: "op_pb_pending_fail",
      requestDigest: "dig_pb_fail",
      planHash: "ph_pb_fail",
      dag: buildSampleDag(),
      originalEnvelope: buildEnvelope(pathBSess, userR, "AUTHORITATIVE_ROUND2_IMAGE_PROMPT"),
      resolvedEnvelope: buildEnvelope(pathBSess, userR, "AUTHORITATIVE_ROUND2_IMAGE_PROMPT"),
      isReRun: true,
      baseCommitId: round2CommitId,
      expectedParentCommitId: null,
      expectedBaseRevision: 3
    });
    await acquireSessionExecutionLock(env, {
      userId: userR,
      sessionId: pathBSess,
      runId: badPendingRunId,
      clientOpId: "op_pb_pending_fail"
    });

    // NM-STATE-R03b verification: Calling /abandon while occupancy_phase === "EXECUTING"
    // must be rejected with 409 cannot_abandon_active_run, and lock must NOT be wiped!
    const abandonExecutingRes = await handleAbandonSessionRun(
      new Request(`https://nanomesh.local/api/session/${pathBSess}/abandon`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({ run_id: badPendingRunId })
      }),
      env,
      pathBSess
    );
    assert.equal(abandonExecutingRes.status, 409);
    const abandonExecutingJson = (await abandonExecutingRes.json()) as any;
    assert.equal(abandonExecutingJson.error, "cannot_abandon_active_run");
    assert.equal(abandonExecutingJson.occupancy_phase, "EXECUTING");

    // Verify session lock remains active & EXECUTING in database
    const dbStateStillExecuting = await env.DB.prepare(
      "SELECT active_run_id, occupancy_phase FROM chat_session_states WHERE user_id = ? AND session_id = ?"
    )
      .bind(userR, pathBSess)
      .first<{ active_run_id: string; occupancy_phase: string }>();
    assert.equal(dbStateStillExecuting?.active_run_id, badPendingRunId);
    assert.equal(dbStateStillExecuting?.occupancy_phase, "EXECUTING");

    await markSessionAwaitingCommit(env, userR, pathBSess, badPendingRunId);

    // While AWAITING_COMMIT, follow-up input send is rejected with 409 session_busy
    clockOffsetMs += 6000;
    const blockedFollowup = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({
          clientOpId: "op_pb_blocked_fu",
          disableBrowserInference: true,
          chosenTemplateId: "tpl-sql-chat",
          envelope: {
            envelope_id: "e_pb_fu0",
            session_id: pathBSess,
            round_index: 3,
            instruction_payload: "Blocked while awaiting"
          }
        })
      }),
      pathBEnv
    );
    assert.equal(blockedFollowup.status, 409);
    assert.equal(((await blockedFollowup.json()) as any).awaiting_commit, true);

    // NM-STATE-R03b-1 verification: While in AWAITING_COMMIT, calling /abandon with a mismatch/stale run_id
    // must be rejected with 409 abandon_conflict, and NEITHER table may be modified!
    const staleRunId = "run_pb_stale_mismatch";
    await registerAndFreezeDagRunPlan(env, {
      runId: staleRunId,
      userId: userR,
      sessionId: pathBSess,
      clientOpId: "op_pb_stale_mismatch",
      requestDigest: "dig_pb_stale",
      planHash: "ph_pb_stale",
      dag: buildSampleDag(),
      originalEnvelope: buildEnvelope(pathBSess, userR, "STALE_PROMPT"),
      resolvedEnvelope: buildEnvelope(pathBSess, userR, "STALE_PROMPT"),
      isReRun: true,
      baseCommitId: round2CommitId,
      expectedParentCommitId: null,
      expectedBaseRevision: 3
    });

    const abandonMismatchRes = await handleAbandonSessionRun(
      new Request(`https://nanomesh.local/api/session/${pathBSess}/abandon`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({ run_id: staleRunId })
      }),
      env,
      pathBSess
    );
    assert.equal(abandonMismatchRes.status, 409);
    const mismatchJson = (await abandonMismatchRes.json()) as any;
    assert.equal(mismatchJson.error, "abandon_conflict");

    // Both tables must retain their original states (no unilateral modification)
    const stalePlanCheck = await env.DB.prepare(
      "SELECT commit_state FROM dag_run_plans WHERE user_id = ? AND session_id = ? AND run_id = ?"
    )
      .bind(userR, pathBSess, staleRunId)
      .first<{ commit_state: string }>();
    assert.equal(
      stalePlanCheck?.commit_state,
      "PENDING",
      "Stale plan must not be unilaterally marked ABORTED"
    );

    const sessionStateStillHeld = await env.DB.prepare(
      "SELECT active_run_id, occupancy_phase FROM chat_session_states WHERE user_id = ? AND session_id = ?"
    )
      .bind(userR, pathBSess)
      .first<{ active_run_id: string; occupancy_phase: string }>();
    assert.equal(sessionStateStillHeld?.active_run_id, badPendingRunId);
    assert.equal(sessionStateStillHeld?.occupancy_phase, "AWAITING_COMMIT");

    // Abandon the failed/pending micro-tuning with the correct matching run_id -> unlocks session & preserves "乙"
    // The run may have become terminal after the endpoint's initial read.
    const changePlan = db.prepare(
      "UPDATE dag_run_plans SET commit_state = ? WHERE user_id = ? AND run_id = ?"
    );
    changePlan.run("COMMITTED", userR, badPendingRunId);
    const blockedRelease = await finishRunWithoutCommit(env, {
      userId: userR,
      sessionId: pathBSess,
      runId: badPendingRunId,
      outcome: "ABORTED",
      expectedOccupancyPhase: "AWAITING_COMMIT"
    });
    assert.deepEqual(blockedRelease, { success: false, planChanges: 0, sessionChanges: 0 });
    changePlan.run("PENDING", userR, badPendingRunId);

    const abandonRes = await handleAbandonSessionRun(
      new Request(`https://nanomesh.local/api/session/${pathBSess}/abandon`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({ run_id: badPendingRunId })
      }),
      env,
      pathBSess
    );
    assert.equal(abandonRes.status, 200);
    const abandonJson = (await abandonRes.json()) as any;
    assert.equal(abandonJson.abandoned, true);
    assert.equal(abandonJson.authoritative_git_state.occupancy_phase, null);
    assert.ok(
      abandonJson.authoritative_git_state.branches.main.last_summary.includes(
        "乙_画布微调新摘要结果"
      )
    );

    // Follow-up input box query after abandon STILL inherits "乙" in real downstream prompt!
    clockOffsetMs += 6000;
    mockAiMode = "followup";
    const promptCountBeforeFollowup = observedPrompts.length;
    const followOkRes = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({
          clientOpId: "op_pb_followup_ok",
          disableBrowserInference: true,
          chosenTemplateId: "tpl-sql-chat",
          envelope: {
            envelope_id: "e_pb_fu1",
            session_id: pathBSess,
            round_index: 3,
            instruction_payload: "基于当前结果继续润色"
          }
        })
      }),
      pathBEnv
    );
    assert.equal(followOkRes.status, 200);
    await followOkRes.text();
    const promptSentFollowup = observedPrompts.slice(promptCountBeforeFollowup).join("\n");
    assert.ok(
      promptSentFollowup.includes("乙_画布微调新摘要结果"),
      `Follow-up downstream prompt after abandon must inherit "乙_画布微调新摘要结果". Got: ${promptSentFollowup}`
    );

    // Retry an uncommitted new turn using canvas route/model override (isReRun: false, no baseCommitId)
    // even when prior session history exists: must NOT hit base_commit_not_found and must append a new commit!
    clockOffsetMs += 6000;
    const retryNewTurnWithSwitchRes = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${tokenR}` },
        body: JSON.stringify({
          clientOpId: "op_pb_retry_new_turn_switch",
          isReRun: false,
          reRouteMode: "switch_model",
          chosenTemplateId: "tpl-sql-chat",
          chosenRoleModels: { "role-sql-chat": "cf_sql_text" },
          disableBrowserInference: true,
          envelope: {
            envelope_id: "e_pb_retry_new_turn",
            session_id: pathBSess,
            round_index: 4,
            instruction_payload: "基于当前乙方案继续改写第四轮"
          }
        })
      }),
      pathBEnv
    );
    assert.equal(retryNewTurnWithSwitchRes.status, 200);
    const retryNewTurnSse = await retryNewTurnWithSwitchRes.text();
    assert.ok(
      retryNewTurnSse.includes("event: dag_complete") &&
        retryNewTurnSse.includes('"state_committed":true'),
      `Canvas retry for uncommitted new turn must commit cleanly. SSE=${retryNewTurnSse}`
    );
    const snapAfterRetryNewTurn = (await (
      await handleGetSessionState(
        new Request(`https://nanomesh.local/api/session/${pathBSess}/state`, {
          headers: { Cookie: `session=${tokenR}` }
        }),
        env,
        pathBSess
      )
    ).json()) as any;
    assert.equal(
      snapAfterRetryNewTurn.commit_order.length,
      4,
      "Uncommitted new-turn canvas retry must append a new commit rather than overwriting prior commits"
    );
  } finally {
    Date.now = origDateNow;
  }

  console.log(
    "  ✓ NM-STATE-R01 ~ R05 (Occupancy Mutex, Busy Delete Reject, 403 Lock Release, Abandon & R05 Baseline Restore): PASSED"
  );
  console.log("\n==================================================");
  console.log("   🎉 REAL SQLITE STATE CLOSURE SUITE PASSED!     ");
  console.log("==================================================");
}

runRealSqliteClosureSuite().catch((err) => {
  console.error("❌ Real SQLite Closure Test Failed:", err);
  process.exit(1);
});

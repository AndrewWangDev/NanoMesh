// tests/integration_test.ts
import assert from "node:assert/strict";
import worker from "../src/index";
import { signJWT, verifyJWT } from "../src/auth/jwt";
import { handleGetAsset } from "../src/api/presign";
import { handleDeleteAccount } from "../src/api/user";
import { 
  handleAdminLogin, 
  handleAdminListNodes, 
  handleAdminCreateNode, 
  handleAdminUpdateNode,
  handleAdminListRoles,
  handleAdminCompetenceMatrix,
  handleAdminListTemplates,
  handleAdminCreateOrUpdateTemplate
} from "../src/api/admin";
import { runOrchestrationPipeline } from "../src/orchestration/orchestrator";
import { executeDAGStream } from "../src/orchestration/dispatcher";
import type { Env } from "../src/types";
import type { UnifiedProtocolEnvelope } from "../src/orchestration/types";

// =========================================================================
// In-Memory Mock Cloudflare Edge Runtime
// =========================================================================

interface TableStore {
  users: any[];
  credit_ledger: any[];
  models: any[];
  dag_roles: any[];
  dag_templates: any[];
  verification_codes: any[];
  redeem_attempts: any[];
  admin_login_attempts: any[];
  user_chat_sessions: any[];
  user_oauth_bindings: any[];
  account_tombstones: any[];
}

function createMockD1(store: TableStore) {
  return {
    prepare(sql: string) {
      let boundArgs: any[] = [];
      const stmt = {
        bind(...args: any[]) {
          boundArgs = args;
          return stmt;
        },
        async first<T = any>(): Promise<T | null> {
          const res = await stmt.all<T>();
          return res.results.length > 0 ? res.results[0] : null;
        },
        async all<T = any>(): Promise<{ results: T[] }> {
          const cleanSql = sql.trim();

          // 1. SELECT COUNT FROM admin_login_attempts
          if (cleanSql.includes("FROM admin_login_attempts")) {
            return { results: [{ count: store.admin_login_attempts.length }] as any };
          }

          // 2. SELECT * FROM models
          if (cleanSql.includes("FROM models")) {
            let res = [...store.models];
            if (cleanSql.includes("WHERE model_id = ?")) {
              res = res.filter(m => m.model_id === boundArgs[0]);
            } else if (cleanSql.includes("WHERE status = 'active'")) {
              res = res.filter(m => m.status === 'active');
            }
            return { results: res as any };
          }

          // 3. SELECT * FROM dag_roles
          if (cleanSql.includes("FROM dag_roles")) {
            let res = [...store.dag_roles];
            if (cleanSql.includes("WHERE role_id = ?")) {
              res = res.filter(r => r.role_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 4. SELECT * FROM dag_templates
          if (cleanSql.includes("FROM dag_templates")) {
            let res = [...store.dag_templates];
            if (cleanSql.includes("WHERE template_id = ?")) {
              res = res.filter(t => t.template_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 5. SELECT credits FROM users
          if (cleanSql.includes("FROM users")) {
            let res = [...store.users];
            if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter(u => u.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 6. SELECT credit_ledger
          if (cleanSql.includes("FROM credit_ledger")) {
            let res = [...store.credit_ledger];
            if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter(l => l.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 7. SELECT * FROM user_chat_sessions
          if (cleanSql.includes("FROM user_chat_sessions")) {
            let res = [...store.user_chat_sessions];
            if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter(s => s.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 8. SELECT * FROM user_oauth_bindings
          if (cleanSql.includes("FROM user_oauth_bindings")) {
            let res = [...store.user_oauth_bindings];
            if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter(b => b.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          return { results: [] };
        },
        async run(): Promise<{ meta: { changes: number } }> {
          const cleanSql = sql.trim();

          // DELETE FROM user_chat_sessions
          if (cleanSql.startsWith("DELETE FROM user_chat_sessions")) {
            const userId = boundArgs[0];
            store.user_chat_sessions = store.user_chat_sessions.filter(s => s.user_id !== userId);
            return { meta: { changes: 1 } };
          }

          // DELETE FROM user_oauth_bindings
          if (cleanSql.startsWith("DELETE FROM user_oauth_bindings")) {
            const userId = boundArgs[0];
            store.user_oauth_bindings = store.user_oauth_bindings.filter(b => b.user_id !== userId);
            return { meta: { changes: 1 } };
          }

          // DELETE FROM user_passkeys
          if (cleanSql.startsWith("DELETE FROM user_passkeys")) {
            return { meta: { changes: 1 } };
          }

          // INSERT INTO account_tombstones
          if (cleanSql.startsWith("INSERT INTO account_tombstones")) {
            store.account_tombstones.push({ hash_id: boundArgs[0] });
            return { meta: { changes: 1 } };
          }

          // UPDATE users (anonymization)
          if (cleanSql.startsWith("UPDATE users") && cleanSql.includes("SET email = 'deleted_'")) {
            const userId = boundArgs[0];
            const u = store.users.find(usr => usr.user_id === userId);
            if (u) {
              u.email = 'deleted_' + userId;
              u.username = 'del_' + userId.slice(0, 12);
              u.credits = 0;
              u.token_version = (u.token_version || 1) + 1;
            }
            return { meta: { changes: 1 } };
          }

          // DELETE FROM admin_login_attempts
          if (cleanSql.startsWith("DELETE FROM admin_login_attempts")) {
            store.admin_login_attempts = [];
            return { meta: { changes: 1 } };
          }

          // INSERT INTO users
          if (cleanSql.startsWith("INSERT INTO users")) {
            const [userId, username, email, password_hash, credits, referral_code, referred_by] = boundArgs;
            store.users.push({
              user_id: userId,
              username,
              email,
              password_hash,
              credits,
              referral_code,
              referred_by,
              token_version: 1
            });
            return { meta: { changes: 1 } };
          }

          // UPDATE users credits
          if (cleanSql.includes("UPDATE users SET credits")) {
            const userId = boundArgs[boundArgs.length - 1];
            const user = store.users.find(u => u.user_id === userId);
            if (user) {
              if (cleanSql.includes("credits = credits + 50")) {
                user.credits += 50;
              } else if (cleanSql.includes("credits = credits + 1")) {
                user.credits += 1;
              } else if (cleanSql.includes("credits = credits - 1")) {
                if (user.credits >= 1) {
                  user.credits -= 1;
                  return { meta: { changes: 1 } };
                }
                return { meta: { changes: 0 } };
              } else if (cleanSql.includes("credits = MAX(0, credits - ?)")) {
                user.credits = Math.max(0, user.credits - boundArgs[0]);
              }
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          // INSERT INTO credit_ledger
          if (cleanSql.startsWith("INSERT INTO credit_ledger")) {
            let ledger_id: string;
            let user_id: string;
            let category: string;
            let amount: number;
            let balance: number;
            let title: string;
            let detail: string;
            let related_id: any;

            if (cleanSql.includes("'compute_cost'")) {
              ledger_id = boundArgs[0];
              user_id = boundArgs[1];
              category = "compute_cost";
              amount = boundArgs.length === 4 ? -1 : (Number(boundArgs[2]) || -1);
              const u = store.users.find(usr => usr.user_id === user_id);
              balance = u?.credits ?? 0;
              title = "DAG智能编排调用";
              detail = boundArgs.length === 4 ? (boundArgs[3] || "") : (boundArgs[4] || "");
              related_id = null;
            } else if (cleanSql.includes("(SELECT credits FROM users")) {
              ledger_id = boundArgs[0];
              user_id = boundArgs[1];
              category = "referral_reward";
              amount = 50;
              const u = store.users.find(usr => usr.user_id === user_id);
              balance = u?.credits ?? 0;
              title = "Referral Reward";
              detail = boundArgs[3] || "";
              related_id = boundArgs[4] || null;
            } else if (cleanSql.includes("'signup_bonus'")) {
              ledger_id = boundArgs[0];
              user_id = boundArgs[1];
              category = "signup_bonus";
              amount = 100;
              balance = 100;
              title = "Signup Bonus";
              detail = "Welcome pack";
              related_id = null;
            } else {
              ledger_id = boundArgs[0];
              user_id = boundArgs[1];
              category = boundArgs[2] || "reward";
              amount = Number(boundArgs[3]) || 0;
              balance = Number(boundArgs[4]) || 0;
              title = boundArgs[5] || "Ledger Entry";
              detail = boundArgs[6] || "";
              related_id = boundArgs[7] || null;
            }

            store.credit_ledger.push({
              ledger_id,
              user_id,
              category,
              amount,
              balance,
              title,
              detail,
              related_id,
              created_at: new Date().toISOString()
            });
            return { meta: { changes: 1 } };
          }

          // INSERT / UPDATE models (ON CONFLICT)
          if (cleanSql.startsWith("INSERT INTO models")) {
            const modelId = boundArgs[0];
            const existingIdx = store.models.findIndex(m => m.model_id === modelId);
            const modelObj: any = {
              model_id: boundArgs[0],
              display_name: boundArgs[1],
              provider: boundArgs[2],
              endpoint: boundArgs[3],
              modalities: typeof boundArgs[4] === 'string' ? boundArgs[4] : JSON.stringify(boundArgs[4]),
              tags: typeof boundArgs[5] === 'string' ? boundArgs[5] : JSON.stringify(boundArgs[5]),
              context_window: boundArgs[6],
              max_concurrency: boundArgs[7],
              precision: boundArgs[8],
              cost_per_1k_tokens: boundArgs[9],
              status: boundArgs[10],
              auth_mode: boundArgs[11],
              auth_secret: boundArgs[12],
              api_format: boundArgs[13],
              inference_target: boundArgs[14]
            };
            if (existingIdx >= 0) {
              store.models[existingIdx] = modelObj;
            } else {
              store.models.push(modelObj);
            }
            return { meta: { changes: 1 } };
          }

          // UPDATE models
          if (cleanSql.startsWith("UPDATE models SET")) {
            const modelId = boundArgs[boundArgs.length - 1];
            const model = store.models.find(m => m.model_id === modelId);
            if (model) {
              model.display_name = boundArgs[0];
              model.provider = boundArgs[1];
              model.endpoint = boundArgs[2];
              model.modalities = boundArgs[3];
              model.tags = boundArgs[4];
              model.context_window = boundArgs[5];
              model.max_concurrency = boundArgs[6];
              model.precision = boundArgs[7];
              model.cost_per_1k_tokens = boundArgs[8];
              model.status = boundArgs[9];
              model.auth_mode = boundArgs[10];
              model.auth_secret = boundArgs[11];
              model.api_format = boundArgs[12];
              model.inference_target = boundArgs[13];
              return { meta: { changes: 1 } };
            }
          }

          // INSERT INTO dag_templates
          if (cleanSql.startsWith("INSERT INTO dag_templates")) {
            store.dag_templates.push({
              template_id: boundArgs[0],
              name_zh: boundArgs[1],
              name_en: boundArgs[2],
              desc_zh: boundArgs[3],
              desc_en: boundArgs[4],
              head_modalities: boundArgs[5],
              tail_modalities: boundArgs[6],
              roles: boundArgs[7],
              role_sequence: boundArgs[8],
              priority: boundArgs[9] || 1,
              status: boundArgs[10] || 'active'
            });
            return { meta: { changes: 1 } };
          }

          // DELETE FROM verification_codes
          if (cleanSql.startsWith("DELETE FROM verification_codes")) {
            return { meta: { changes: 1 } };
          }

          return { meta: { changes: 1 } };
        }
      };
      return stmt;
    },
    async batch(statements: any[]) {
      for (const s of statements) {
        await s.run();
      }
      return [];
    }
  };
}

function createMockR2() {
  const store = new Map<string, { body: Uint8Array; metadata: any }>();
  return {
    async put(key: string, body: any, options?: any) {
      const bytes = typeof body === "string" ? new TextEncoder().encode(body) : new Uint8Array(body);
      store.set(key, { body: bytes, metadata: options?.httpMetadata || {} });
      return { key, size: bytes.length };
    },
    async get(key: string) {
      const item = store.get(key);
      if (!item) return null;
      return {
        body: item.body,
        httpEtag: "mock-etag-12345",
        writeHttpMetadata(headers: Headers) {
          headers.set("content-type", item.metadata?.contentType || "application/octet-stream");
        }
      };
    },
    async list(options?: { prefix?: string }) {
      const prefix = options?.prefix || "";
      const objects = [];
      for (const [key, val] of store.entries()) {
        if (key.startsWith(prefix)) {
          objects.push({ key, size: val.body.length });
        }
      }
      return { objects };
    },
    async delete(keys: string | string[]) {
      const arr = Array.isArray(keys) ? keys : [keys];
      for (const k of arr) {
        store.delete(k);
      }
    }
  };
}

function createMockAI() {
  return {
    async run(model: string, input: any) {
      if (model === "@cf/baai/bge-m3") {
        return { data: [new Array(1024).fill(0.05)] };
      }
      if (model === "@cf/cloudflare/clef-flash") {
        const answers: Record<string, any> = {};
        for (const k of Object.keys(input.questions || {})) {
          answers[k] = { score: 2.0 };
        }
        return { answers };
      }
      if (model.includes("llama")) {
        // Realistic simulated generation latency (allows testing race conditions and client abort)
        await new Promise(r => setTimeout(r, 60));
      }
      return {
        response: "Mock Workers AI output response for role."
      };
    }
  };
}

function buildMockEnv(): { env: Env; store: TableStore } {
  const store: TableStore = {
    users: [
      {
        user_id: "usr_referrer_boss",
        username: "BossReferrer",
        email: "boss@nanomesh.local",
        password_hash: "hash",
        credits: 100,
        referral_code: "REF-BOSS-99",
        referred_by: null,
        token_version: 1
      }
    ],
    credit_ledger: [],
    models: [
      {
        model_id: "cf_llama32_text",
        display_name: "Llama 3.2 3B (Edge)",
        provider: "Cloudflare Workers AI",
        endpoint: "@cf/meta/llama-3.2-3b-instruct",
        modalities: '["text"]',
        tags: '["#chat", "#general"]',
        context_window: 8192,
        max_concurrency: 50,
        active_connections: 0,
        precision: 0.85,
        user_rating: 4.9,
        usage_count: 100,
        cost_per_1k_tokens: 0.0,
        status: "active",
        is_generalist: 1,
        prior_score: 0.25,
        scenario_anchors: '["chat", "text"]',
        inference_target: "edge",
        auth_mode: "none",
        api_format: "workers_ai"
      },
      {
        model_id: "cf_vision_model",
        display_name: "Llama 3.2 11B Vision (Edge)",
        provider: "Cloudflare Workers AI",
        endpoint: "@cf/meta/llama-3.2-11b-vision-instruct",
        modalities: '["image", "text"]',
        tags: '["#vision", "#analysis"]',
        context_window: 8192,
        max_concurrency: 20,
        active_connections: 0,
        precision: 0.9,
        user_rating: 4.95,
        usage_count: 50,
        cost_per_1k_tokens: 0.0,
        status: "active",
        is_generalist: 1,
        prior_score: 0.25,
        scenario_anchors: '["vision", "image"]',
        inference_target: "edge",
        auth_mode: "none",
        api_format: "workers_ai"
      }
    ],
    dag_roles: [
      {
        role_id: "role_text_reasoning",
        name_zh: "文本意图提炼与推理",
        name_en: "Text Reasoning",
        in_modalities: JSON.stringify(["text"]),
        out_modalities: JSON.stringify(["text"]),
        in_degree: 0,
        out_degree: 0,
        requisition_tags: JSON.stringify(["#chat"]),
        compensation_prompts: null
      },
      {
        role_id: "role_vision_perception",
        name_zh: "视觉多模态解析",
        name_en: "Vision Perception",
        in_modalities: JSON.stringify(["image"]),
        out_modalities: JSON.stringify(["text"]),
        in_degree: 0,
        out_degree: 1,
        requisition_tags: JSON.stringify(["#vision"]),
        compensation_prompts: null
      },
      {
        role_id: "role_audio_tts",
        name_zh: "语音高保真合成",
        name_en: "Voice Synthesis",
        in_modalities: JSON.stringify(["text"]),
        out_modalities: JSON.stringify(["audio"]),
        in_degree: 1,
        out_degree: 0,
        requisition_tags: JSON.stringify(["#audio_tts"]),
        compensation_prompts: null
      }
    ],
    dag_templates: [
      {
        template_id: "tpl_text_reasoning_pipeline",
        name_zh: "单工序智能对话与推理",
        name_en: "Single-stage Text Reasoning",
        desc_zh: "单工序文本大模型推理",
        desc_en: "Single stage text reasoning",
        scenario_category: "chat",
        scenario_anchor: "chat",
        roles: JSON.stringify(["role_text_reasoning"]),
        role_sequence: JSON.stringify(["role_text_reasoning"]),
        edges: JSON.stringify([]),
        head_modalities: JSON.stringify(["text"]),
        tail_modalities: JSON.stringify(["text"]),
        status: "active",
        priority: 1
      }
    ],
    verification_codes: [],
    redeem_attempts: [],
    admin_login_attempts: [],
    user_chat_sessions: [],
    user_oauth_bindings: [],
    account_tombstones: []
  };

  const env = {
    DB: createMockD1(store),
    R2: createMockR2(),
    AI: createMockAI(),
    JWT_SECRET: "test-jwt-secret-for-integration-tests-999",
    ADMIN_PASSWORD: "IntegrationAdminPass123!",
    FRONTEND_URL: "https://nanomesh.local"
  } as unknown as Env;

  return { env, store };
}

// =========================================================================
// Integration Test Runner
// =========================================================================

async function runIntegrationTests() {
  console.log("==================================================");
  console.log("       NanoMesh Local Integration Test Suite      ");
  console.log("==================================================");

  const { env, store } = buildMockEnv();

  // -----------------------------------------------------------------------
  // SCENARIO 1: User Registration, Referral & Atomic D1 Batch Ledger
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 1] User Registration, Referral & Atomic Batch Ledger");
  const newUserId = "usr_newbie_001";
  const referrerId = "usr_referrer_boss";
  const initialCredits = 150;

  // Execute registration statements batch
  const regBatch = [
    env.DB.prepare(`
      INSERT INTO users (user_id, username, email, password_hash, credits, referral_code, referred_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(newUserId, "NewbieUser", "newbie@nanomesh.local", "hash123", initialCredits, "REF-NEWBIE-1", referrerId),
    env.DB.prepare(`
      INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail)
      VALUES (?, ?, 'signup_bonus', 100, 100, 'Signup Bonus', 'Welcome pack')
    `).bind("ledg_1", newUserId),
    env.DB.prepare(`
      INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail, related_id)
      VALUES (?, ?, 'referral_reward', 50, 150, 'Referral Bonus', 'Invited by boss', ?)
    `).bind("ledg_2", newUserId, referrerId),
    env.DB.prepare("UPDATE users SET credits = credits + 50 WHERE user_id = ?").bind(referrerId),
    env.DB.prepare(`
      INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail, related_id)
      VALUES (?, ?, 'referral_reward', 50, (SELECT credits FROM users WHERE user_id = ?), 'Referral Reward', ?, ?)
    `).bind("ledg_3", referrerId, referrerId, "NewbieUser", newUserId)
  ];

  await env.DB.batch(regBatch);

  const newbieDb = store.users.find(u => u.user_id === newUserId);
  const bossDb = store.users.find(u => u.user_id === referrerId);
  assert.ok(newbieDb, "Newbie user must exist in DB");
  assert.equal(newbieDb.credits, 150, "Newbie must receive 100 base + 50 referral = 150 credits");
  assert.equal(bossDb.credits, 150, "Boss credits must be updated from 100 to 150");

  const newbieLedgers = store.credit_ledger.filter(l => l.user_id === newUserId);
  assert.equal(newbieLedgers.length, 2, "Newbie must have 2 ledger records (signup + referral)");

  const bossLedgers = store.credit_ledger.filter(l => l.user_id === referrerId);
  assert.equal(bossLedgers.length, 1, "Boss must have 1 referral reward ledger");
  assert.equal(bossLedgers[0].balance, 150, "Boss ledger balance snapshot must accurately equal 150");
  console.log("  ✓ Atomic registration batch & ledger balance consistency: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 2: R2 Asset Access Control & Public Light Node Route
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 2] R2 Asset Management & Access Control Isolation");
  
  // 2.1 Public Light Node weights in models/light/... (No session required!)
  const modelKey = "models/light/1700000000_qwen_webgpu.onnx";
  await env.R2.put(modelKey, "ONNX_MODEL_BINARY_WEIGHTS_DATA", { httpMetadata: { contentType: "application/octet-stream" } });

  const publicReq = new Request(`https://nanomesh.local/api/assets/${modelKey}`);
  const publicRes = await handleGetAsset(publicReq, env);
  assert.equal(publicRes.status, 200, "Public light model weights must be accessible without login");
  assert.equal(publicRes.headers.get("cache-control"), "public, max-age=31536000, immutable", "Must set 1-year immutable caching");
  assert.equal(publicRes.headers.get("access-control-allow-origin"), "*", "Must allow cross-origin fetching for browser WebGPU");

  // [ISSUE-01: Verify Gateway worker.fetch router dispatching to /api/assets/ without 404 nesting error]
  const gatewayReq = new Request(`https://nanomesh.local/api/assets/${modelKey}`);
  const gatewayRes = await worker.fetch(gatewayReq, env, {} as any);
  assert.equal(gatewayRes.status, 200, "Gateway must dispatch /api/assets/ to handleGetAsset without 404 route nesting error");

  // [ISSUE-02: Verify Avatar Static Storage security headers via worker.fetch]
  const avatarKey = `avatars/${newUserId}_1700000000.png`;
  await env.R2.put(avatarKey, "PNG_AVATAR_BYTES", { httpMetadata: { contentType: "image/png" } });
  const storageReq = new Request(`https://nanomesh.local/storage/${avatarKey}`);
  const storageRes = await worker.fetch(storageReq, env, {} as any);
  assert.equal(storageRes.status, 200, "Storage avatar endpoint must serve 200 OK");
  assert.equal(storageRes.headers.get("x-content-type-options"), "nosniff", "Storage must enforce nosniff");
  assert.equal(storageRes.headers.get("content-security-policy"), "default-src 'none'; sandbox", "Storage must enforce CSP sandbox");
  assert.equal(storageRes.headers.get("cross-origin-resource-policy"), "cross-origin");

  // 2.2 Private User Asset in tmp/${userId}/... (Strict user session required!)
  const userAssetKey = `tmp/${newUserId}/my_sketch.png`;
  await env.R2.put(userAssetKey, "PNG_IMAGE_BYTES", { httpMetadata: { contentType: "image/png" } });

  // Unauthenticated access
  const unauthReq = new Request(`https://nanomesh.local/api/asset?key=${userAssetKey}`);
  const unauthRes = await handleGetAsset(unauthReq, env);
  assert.equal(unauthRes.status, 401, "Unauthenticated access to private asset must return 401");

  // Authenticated Owner access
  const ownerToken = await signJWT({ userId: newUserId, tokenVersion: 1 }, env.JWT_SECRET, 3600);
  const ownerReq = new Request(`https://nanomesh.local/api/asset?key=${userAssetKey}`, {
    headers: { "Cookie": `session=${ownerToken}` }
  });
  const ownerRes = await handleGetAsset(ownerReq, env);
  assert.equal(ownerRes.status, 200, "Owner must be granted access to their private asset");

  // Authenticated Foreign User access
  store.users.push({
    user_id: "usr_attacker_666",
    username: "Attacker",
    email: "attacker@nanomesh.local",
    password_hash: "hash",
    credits: 10,
    referral_code: "REF-ATTACK",
    token_version: 1
  });
  const foreignToken = await signJWT({ userId: "usr_attacker_666", tokenVersion: 1 }, env.JWT_SECRET, 3600);
  const foreignReq = new Request(`https://nanomesh.local/api/asset?key=${userAssetKey}`, {
    headers: { "Cookie": `session=${foreignToken}` }
  });
  const foreignRes = await handleGetAsset(foreignReq, env);
  assert.equal(foreignRes.status, 403, "Foreign user accessing another user's asset must receive 403 Forbidden");
  console.log("  ✓ Light node public delivery & private tenant isolation: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 3: Admin Auth, SSRF Security Guard & Masked Updating
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 3] Admin Node Registry, SSRF Guard & Secret Masking");

  // 3.1 Admin Login
  const badLoginReq = new Request("https://nanomesh.local/api/admin/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: "wrong-password" })
  });
  const badLoginRes = await handleAdminLogin(badLoginReq, env);
  assert.equal(badLoginRes.status, 401, "Wrong password must return 401");

  const goodLoginReq = new Request("https://nanomesh.local/api/admin/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: "IntegrationAdminPass123!" })
  });
  const goodLoginRes = await handleAdminLogin(goodLoginReq, env);
  assert.equal(goodLoginRes.status, 200, "Correct password must return 200");
  const adminCookie = goodLoginRes.headers.get("Set-Cookie")!;
  assert.ok(adminCookie.includes("Max-Age=7200"), "Admin session TTL must be tightened to 2 hours (7200s)");

  // Extract admin session token
  const adminToken = adminCookie.match(/admin_session=([^;]+)/)![1];
  const adminReqHeaders = {
    "Cookie": `admin_session=${adminToken}`,
    "Content-Type": "application/json"
  };

  // 3.2 SSRF Block on Loopback & Private IPs
  const ssrfReq = new Request("https://nanomesh.local/api/admin/nodes", {
    method: "POST",
    headers: adminReqHeaders,
    body: JSON.stringify({
      model_id: "m_malicious_loopback",
      display_name: "Localhost Node",
      provider: "Hacker",
      endpoint: "http://127.0.0.1:8080/v1/chat",
      modalities: ["text"],
      tags: ["#chat"]
    })
  });
  const ssrfRes = await handleAdminCreateNode(ssrfReq, env);
  assert.equal(ssrfRes.status, 400, "SSRF attempt to loopback must be rejected with 400");
  const ssrfErr = await ssrfRes.json();
  assert.ok(ssrfErr.error.includes("非法算力终端地址"), "Must return SSRF security error");

  // 3.3 Register Valid Remote Node with Secret
  const validNodeReq = new Request("https://nanomesh.local/api/admin/nodes", {
    method: "POST",
    headers: adminReqHeaders,
    body: JSON.stringify({
      model_id: "cloud_vps_deepseek",
      display_name: "DeepSeek R1 (Custom VPS)",
      provider: "Private GPU Cluster",
      endpoint: "https://my-gpu.example.com/v1",
      modalities: ["text"],
      tags: ["#chat", "#reasoning"],
      context_window: 16384,
      max_concurrency: 10,
      precision: 0.95,
      cost_per_1k_tokens: 0.5,
      status: "active",
      auth_mode: "bearer_static",
      auth_secret: "sk-my-confidential-api-key-9988",
      api_format: "openai_compat",
      inference_target: "heavy"
    })
  });
  const validNodeRes = await handleAdminCreateNode(validNodeReq, env);
  assert.equal(validNodeRes.status, 200, "Legitimate public HTTPS node must register successfully");

  // 3.4 List Nodes and Verify Credential Masking
  const listNodesReq = new Request("https://nanomesh.local/api/admin/nodes", {
    headers: adminReqHeaders
  });
  const listNodesRes = await handleAdminListNodes(listNodesReq, env);
  const listNodesData = await listNodesRes.json();
  const deepseekListed = listNodesData.nodes.find((n: any) => n.model_id === "cloud_vps_deepseek");
  assert.ok(deepseekListed);
  assert.equal(deepseekListed.auth_secret, "••••••••", "Secret must be masked as •••••••• to prevent frontend exfiltration");

  // 3.5 Safe Update with Masked Secret Placeholder
  const updateReq = new Request("https://nanomesh.local/api/admin/nodes/cloud_vps_deepseek", {
    method: "PATCH",
    headers: adminReqHeaders,
    body: JSON.stringify({
      display_name: "DeepSeek R1 High Precision",
      auth_secret: "••••••••" // unchanged placeholder submitted from web form
    })
  });
  const updateRes = await handleAdminUpdateNode(updateReq, env, "cloud_vps_deepseek");
  assert.equal(updateRes.status, 200);

  const rawDeepseek = store.models.find(m => m.model_id === "cloud_vps_deepseek");
  assert.equal(rawDeepseek.display_name, "DeepSeek R1 High Precision");
  assert.equal(rawDeepseek.auth_secret, "sk-my-confidential-api-key-9988", "Real secret must be preserved when placeholder is submitted");

  // 3.6 [ISSUE-06 Admin Password Change Instant Revocation Verification]
  const validAdminReq = new Request("https://nanomesh.local/api/admin/nodes", { headers: adminReqHeaders });
  const validAdminRes = await handleAdminListNodes(validAdminReq, env);
  assert.equal(validAdminRes.status, 200, "Admin with valid token must have access");

  const originalPass = (env as any).ADMIN_PASSWORD;
  (env as any).ADMIN_PASSWORD = "NewlyRotatedPassword789!";
  
  const revokedAdminReq = new Request("https://nanomesh.local/api/admin/nodes", { headers: adminReqHeaders });
  const revokedAdminRes = await handleAdminListNodes(revokedAdminReq, env);
  assert.equal(revokedAdminRes.status, 401, "Changing ADMIN_PASSWORD must immediately revoke existing admin tokens (401)");

  // Restore password for remaining admin scenarios
  (env as any).ADMIN_PASSWORD = originalPass;
  console.log("  ✓ Admin login 2h TTL, SSRF filter & safe masked credential update: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 4: Admin Linear Pipeline Splicer & Gate Diagnostics
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 4] Linear Pipeline Splicer & 3 Validation Gates");

  // Gate 1: Modality Discontinuity (Audio output -> Vision input)
  const gate1Req = new Request("https://nanomesh.local/api/admin/templates", {
    method: "POST",
    headers: adminReqHeaders,
    body: JSON.stringify({
      name: "断裂流水线测试",
      role_sequence: ["role_audio_tts", "role_vision_perception"]
    })
  });
  const gate1Res = await handleAdminCreateOrUpdateTemplate(gate1Req, env);
  assert.equal(gate1Res.status, 400, "Modality discontinuity must fail with 400");
  const gate1Err = await gate1Res.json();
  assert.ok(gate1Err.error.includes("Modality Discontinuity"), "Must detect modality discontinuity between audio and image");

  // Gate 2: Subsistence Check (Role with 0 candidate models)
  const gate2Req = new Request("https://nanomesh.local/api/admin/templates", {
    method: "POST",
    headers: adminReqHeaders,
    body: JSON.stringify({
      name: "孤儿工序流水线测试",
      role_sequence: ["role_text_reasoning", "role_audio_tts"] // No audio model exists in store.models
    })
  });
  const gate2Res = await handleAdminCreateOrUpdateTemplate(gate2Req, env);
  assert.equal(gate2Res.status, 400, "Role with 0 candidate models must fail Gate 2");
  const gate2Err = await gate2Res.json();
  assert.ok(gate2Err.error.includes("Subsistence Check Failed"), "Must flag orphaned role without candidate models");

  // Gate 3: Valid Linear Pipeline Assembly & Persistence
  const gate3Req = new Request("https://nanomesh.local/api/admin/templates", {
    method: "POST",
    headers: adminReqHeaders,
    body: JSON.stringify({
      name: "视觉理解与深度推理流水线",
      description: "第一阶段图像理解，第二阶段语言推理",
      role_sequence: ["role_vision_perception", "role_text_reasoning"]
    })
  });
  const gate3Res = await handleAdminCreateOrUpdateTemplate(gate3Req, env);
  assert.equal(gate3Res.status, 200, "Valid linear pipeline must pass all 3 gates and save template");
  const gate3Data = await gate3Res.json();
  assert.ok(gate3Data.template_id);
  assert.ok(store.dag_templates.some(t => t.template_id === gate3Data.template_id));
  console.log("  ✓ Linear pipeline splicer Gate 1, Gate 2, Gate 3 verification: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 5: End-to-End Chat Orchestration & Atomic Billing Settlement
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 5] End-to-End Chat Orchestration & Atomic Billing Settlement");
  
  const envelope: UnifiedProtocolEnvelope = {
    envelope_id: "env_test_001",
    session_id: "sess_chat_001",
    user_id: newUserId,
    instruction_payload: "请分析多模态分布式调度器的架构优势",
    metadata: {
      estimated_input_tokens: 500
    },
    assets_manifest: []
  };

  // 5.1 Pre-deduct 1 credit base reservation
  const preDeductRes = await env.DB.prepare(
    "UPDATE users SET credits = credits - 1 WHERE user_id = ? AND credits >= 1"
  ).bind(newUserId).run();
  assert.equal(preDeductRes.meta.changes, 1, "Must atomically pre-deduct 1 base credit");
  assert.equal(store.users.find(u => u.user_id === newUserId).credits, 149);

  // 5.2 Gateway 3-Step Arbitration & DAG Instantiation
  const dag = await runOrchestrationPipeline(env, envelope, {
    chosenTemplateId: "tpl_text_reasoning_pipeline"
  });
  assert.ok(dag);
  assert.equal(dag.nodes.length, 1);
  assert.equal(dag.nodes[0].selected_model.model_id, "cf_llama32_text");

  // 5.3 Execute SSE Stream
  const sseStream = await executeDAGStream(env, dag, envelope, {
    userId: newUserId,
    hasPreDeducted: true
  });

  const reader = sseStream.getReader();
  const decoder = new TextDecoder();
  let receivedEvents = "";
  let done = false;
  while (!done) {
    const chunk = await reader.read();
    if (chunk.done) {
      done = true;
    } else {
      receivedEvents += decoder.decode(chunk.value, { stream: true });
    }
  }

  assert.ok(receivedEvents.includes("event: dag_plan"), "Stream must emit dag_plan");
  assert.ok(receivedEvents.includes("event: node_start"), "Stream must emit node_start");
  assert.ok(receivedEvents.includes("event: dag_complete"), "Stream must emit dag_complete");

  // 5.4 Verify Billing Settlement
  const postBillingUser = store.users.find(u => u.user_id === newUserId);
  assert.equal(postBillingUser.credits, 149, "Total cost 1 settled: balance remains 149");
  console.log("  ✓ End-to-end chat arbitration, SSE streaming & atomic billing: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 6: Premature Stream Cancelation & Credit Refund
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 6] Premature Stream Cancelation & Refund Handshake");

  // Pre-deduct 1 credit
  await env.DB.prepare(
    "UPDATE users SET credits = credits - 1 WHERE user_id = ? AND credits >= 1"
  ).bind(newUserId).run();
  assert.equal(store.users.find(u => u.user_id === newUserId).credits, 148);

  const abortStream = await executeDAGStream(env, dag, envelope, {
    userId: newUserId,
    hasPreDeducted: true
  });

  // Client abruptly cancels stream before tokens are emitted
  await abortStream.cancel("Client disconnected / Tab closed");

  // Wait a tick for async refund execution
  await new Promise(r => setTimeout(r, 50));

  const refundedUser = store.users.find(u => u.user_id === newUserId);
  assert.equal(refundedUser.credits, 149, "Pre-deducted credit must be safely refunded on cancel");
  console.log("  ✓ Premature client disconnect cleanly triggers credit refund: PASSED");

  // 6.2 [ISSUE-04: Premature Stream Cancelation AFTER Token Generation - Settle Ledger]
  await env.DB.prepare(
    "UPDATE users SET credits = credits - 1 WHERE user_id = ? AND credits >= 1"
  ).bind(newUserId).run();
  assert.equal(store.users.find(u => u.user_id === newUserId).credits, 148);

  const activeStream = await executeDAGStream(env, dag, envelope, {
    userId: newUserId,
    hasPreDeducted: true
  });
  const activeReader = activeStream.getReader();
  const textDecoder = new TextDecoder();
  let sawToken = false;
  while (!sawToken) {
    const chunk = await activeReader.read();
    if (chunk.done) break;
    const text = textDecoder.decode(chunk.value);
    if (text.includes("event: text_chunk")) {
      sawToken = true;
    }
  }
  assert.ok(sawToken, "Must receive at least one real text_chunk token before cancelling");

  // User aborts connection mid-stream after tokens generated
  await activeReader.cancel("Client disconnected mid-stream");
  await new Promise(r => setTimeout(r, 50));

  // Verify credit is retained (148)
  const abortedUser = store.users.find(u => u.user_id === newUserId);
  assert.equal(abortedUser.credits, 148, "Credit must be retained after tokens emitted");

  // Verify credit_ledger has an entry recording the retention!
  const abortLedger = store.credit_ledger.find(l => l.detail && l.detail.includes("中途断开连接算力保底扣费"));
  assert.ok(abortLedger, "Must record compute_cost ledger row for mid-stream abort");
  assert.equal(abortLedger.amount, -1, "Ledger amount must be -1");
  console.log("  ✓ Mid-stream abort records compute_cost ledger audit entry: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 7: Account Deletion Cascading Erasure of Private Sessions (ISSUE-05)
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 7] Account Deletion & GDPR Private Session Erasure");
  
  // Seed a chat session for newUserId
  store.user_chat_sessions.push({
    session_id: "sess_private_123",
    user_id: newUserId,
    title: "Secret Strategy Conversation",
    rounds_json: JSON.stringify([{ role: "user", text: "Classified Prompt" }])
  });
  assert.equal(store.user_chat_sessions.length, 1);

  // Authenticated user request to delete account
  const deleteReq = new Request("https://nanomesh.local/api/user/delete", {
    method: "POST",
    headers: { "Cookie": `session=${ownerToken}` }
  });
  const deleteRes = await handleDeleteAccount(deleteReq, env);
  assert.equal(deleteRes.status, 200, "handleDeleteAccount must succeed");

  // Verify user_chat_sessions is completely erased
  const remainingSessions = store.user_chat_sessions.filter(s => s.user_id === newUserId);
  assert.equal(remainingSessions.length, 0, "All private chat sessions must be physically erased upon deletion");
  
  const anonymizedUser = store.users.find(u => u.user_id === newUserId);
  assert.ok(anonymizedUser.email.startsWith("deleted_"), "User must be anonymized in-place");
  assert.equal(anonymizedUser.credits, 0, "Credits must be reset to 0");

  // Verify R2 user assets (tmp/ and avatars/) are completely erased
  const remainingTmp = await env.R2.list({ prefix: `tmp/${newUserId}/` });
  assert.equal(remainingTmp.objects.length, 0, "User tmp/ assets must be cascade deleted from R2 upon account deletion");
  const remainingAvatars = await env.R2.list({ prefix: `avatars/${newUserId}_` });
  assert.equal(remainingAvatars.objects.length, 0, "User avatars/ must be cascade deleted from R2 upon account deletion");

  console.log("  ✓ User account deletion cascades physical erasure of chat sessions & R2 assets: PASSED");

  console.log("\n==================================================");
  console.log("   🎉 ALL 7 INTEGRATION SCENARIOS PASSED (100%)!  ");
  console.log("==================================================");
}

runIntegrationTests().catch(err => {
  console.error("❌ Integration Test Failed:", err);
  process.exit(1);
});

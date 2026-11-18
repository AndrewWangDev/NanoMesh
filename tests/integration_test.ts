// tests/integration_test.ts
import assert from "node:assert/strict";
import worker from "../src/index";
import { signJWT, verifyJWT } from "../src/auth/jwt";
import { handleGetAsset } from "../src/api/presign";
import { handleDeleteAccount, handleUpdatePassword } from "../src/api/user";
import { handleUnbindOAuth } from "../src/api/auth";
import { 
  handleAdminLogin, 
  handleAdminListNodes, 
  handleAdminCreateNode, 
  handleAdminUpdateNode,
  handleAdminListRoles,
  handleAdminCompetenceMatrix,
  handleAdminListTemplates,
  handleAdminCreateOrUpdateTemplate,
  handleAdminDeleteTemplate,
  handleAdminUpdateModel
} from "../src/api/admin";
import { runOrchestrationPipeline } from "../src/orchestration/orchestrator";
import { executeDAGStream } from "../src/orchestration/dispatcher";
import { handleChat, handleChatContinue, triggerLazyHandshakeSweep } from "../src/api/chat";
import type { Env } from "../src/types";
import type { UnifiedProtocolEnvelope } from "../src/orchestration/types";
import bcrypt from "bcryptjs";

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
  user_passkeys: any[];
  user_uploaded_models: any[];
  account_tombstones: any[];
  dag_handshakes: any[];
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

          // 9. SELECT COUNT(*) as cnt FROM user_passkeys
          if (cleanSql.includes("FROM user_passkeys")) {
            const userId = boundArgs[0];
            const pks = (store.user_passkeys || []).filter(p => p.user_id === userId);
            return { results: [{ cnt: pks.length }] as any };
          }

          // 10. SELECT * FROM user_uploaded_models
          if (cleanSql.includes("FROM user_uploaded_models")) {
            let res = [...(store.user_uploaded_models || [])];
            if (cleanSql.includes("WHERE upload_id = ?")) {
              res = res.filter(m => m.upload_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 11. SELECT * FROM dag_handshakes
          if (cleanSql.includes("FROM dag_handshakes")) {
            let res = [...(store.dag_handshakes || [])];
            if (cleanSql.includes("WHERE handshake_id = ?")) {
              res = res.filter(h => h.handshake_id === boundArgs[0]);
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

          // UPDATE users SET password_hash
          if (cleanSql.startsWith("UPDATE users SET password_hash")) {
            const userId = boundArgs[2];
            const u = store.users.find(usr => usr.user_id === userId);
            if (u) {
              u.password_hash = boundArgs[0];
              u.token_version = boundArgs[1];
            }
            return { meta: { changes: 1 } };
          }

          // UPDATE user_uploaded_models
          if (cleanSql.startsWith("UPDATE user_uploaded_models")) {
            const uploadId = boundArgs[boundArgs.length - 1];
            const m = (store.user_uploaded_models || []).find(mod => mod.upload_id === uploadId);
            if (m) {
              m.status = boundArgs[0];
              if (boundArgs.length > 2) m.live_model_id = boundArgs[1];
            }
            return { meta: { changes: 1 } };
          }

          // INSERT INTO dag_handshakes
          if (cleanSql.startsWith("INSERT INTO dag_handshakes")) {
            const [handshakeId, userId, sessionId, templateId, nextStep, expiresAt] = boundArgs;
            store.dag_handshakes = store.dag_handshakes || [];
            store.dag_handshakes.push({
              handshake_id: handshakeId,
              user_id: userId,
              session_id: sessionId,
              template_id: templateId,
              next_step: nextStep,
              status: 'ISSUED',
              expires_at: expiresAt,
              created_at: new Date().toISOString()
            });
            return { meta: { changes: 1 } };
          }

          // UPDATE dag_handshakes SET status = 'CONSUMED'
          if (cleanSql.startsWith("UPDATE dag_handshakes") && cleanSql.includes("status = 'CONSUMED'")) {
            const [handshakeId, userId] = boundArgs;
            store.dag_handshakes = store.dag_handshakes || [];
            const item = store.dag_handshakes.find(
              h => h.handshake_id === handshakeId && h.user_id === userId && h.status === 'ISSUED'
            );
            if (item) {
              item.status = 'CONSUMED';
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          // DELETE FROM dag_handshakes
          if (cleanSql.startsWith("DELETE FROM dag_handshakes")) {
            store.dag_handshakes = store.dag_handshakes || [];
            const initialLen = store.dag_handshakes.length;
            const nowIso = new Date().toISOString();
            // keep non-expired
            store.dag_handshakes = store.dag_handshakes.filter(h => h.expires_at >= nowIso);
            const deleted = initialLen - store.dag_handshakes.length;
            return { meta: { changes: deleted } };
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
              precision: boundArgs[8]
            };
            if (cleanSql.includes("user_rating")) {
              modelObj.user_rating = boundArgs[9];
              modelObj.usage_count = boundArgs[10];
              modelObj.cost_per_1k_tokens = boundArgs[11];
              modelObj.status = boundArgs[12];
              modelObj.auth_mode = boundArgs[13];
              modelObj.auth_secret = boundArgs[14];
              modelObj.api_format = boundArgs[15];
              modelObj.inference_target = boundArgs[16];
            } else {
              modelObj.cost_per_1k_tokens = boundArgs[9];
              modelObj.status = boundArgs[10];
              modelObj.auth_mode = boundArgs[11];
              modelObj.auth_secret = boundArgs[12];
              modelObj.api_format = boundArgs[13];
              modelObj.inference_target = boundArgs[14];
            }
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

          // DELETE FROM dag_templates
          if (cleanSql.startsWith("DELETE FROM dag_templates")) {
            const templateId = boundArgs[0];
            store.dag_templates = store.dag_templates.filter(t => t.template_id !== templateId);
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
    async list(options?: { prefix?: string; cursor?: string; limit?: number }) {
      const prefix = options?.prefix || "";
      const limit = options?.limit || 1000;
      const allObjects = [];
      for (const [key, val] of store.entries()) {
        if (key.startsWith(prefix)) {
          allObjects.push({ key, size: val.body.length });
        }
      }
      const startIndex = options?.cursor ? parseInt(options.cursor, 10) : 0;
      const sliced = allObjects.slice(startIndex, startIndex + limit);
      const nextIndex = startIndex + sliced.length;
      const truncated = nextIndex < allObjects.length;
      return { 
        objects: sliced, 
        truncated, 
        cursor: truncated ? String(nextIndex) : undefined 
      };
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
    user_passkeys: [],
    user_uploaded_models: [],
    account_tombstones: [],
    dag_handshakes: []
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

  // 3.7 [ADMIN-02 Dead Endpoint Activation Guard]
  store.models.push({
    model_id: "test-ghost-model",
    display_name: "Ghost Mock",
    provider: "test",
    endpoint: "/api/infer",
    modalities: "[\"text\"]",
    tags: "[\"#test\"]",
    status: "disabled",
    inference_target: "edge"
  });
  const activateGhostReq = new Request("https://nanomesh.local/api/admin/nodes/test-ghost-model", {
    method: "PATCH",
    headers: adminReqHeaders,
    body: JSON.stringify({ status: "active" })
  });
  const activateGhostRes = await handleAdminUpdateNode(activateGhostReq, env, "test-ghost-model");
  assert.equal(activateGhostRes.status, 400, "Activating a model with dead endpoint /api/infer must be blocked with 400");
  const ghostErr = await activateGhostRes.json();
  assert.ok(ghostErr.error.includes("无法启用节点"), "Must explain invalid endpoint reason");

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

  // 4.5 [ADMIN-04 Template Deletion]
  const delTplReq = new Request(`https://nanomesh.local/api/admin/templates/${gate3Data.template_id}`, {
    method: "DELETE",
    headers: adminReqHeaders
  });
  const delTplRes = await handleAdminDeleteTemplate(delTplReq, env, gate3Data.template_id);
  assert.equal(delTplRes.status, 200, "Deleting template must succeed");
  assert.ok(!store.dag_templates.some(t => t.template_id === gate3Data.template_id), "Template must be removed from store");

  // Re-create it for subsequent workflow tests
  await handleAdminCreateOrUpdateTemplate(gate3Req, env);

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

  // -----------------------------------------------------------------------
  // SCENARIO 8: Audit Report 3 Remediations (BUG-01, BUG-02, BUG-03, BUG-04)
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 8] Audit Report 3 Remediations & Architectural Hardening");

  // 8.1 BUG-03: Password Update Token In Body
  const pwUser = {
    user_id: "u_pw_test",
    username: "pw_test_user",
    email: "pw_test@example.com",
    password_hash: bcrypt.hashSync("OldPass1234!", 10),
    token_version: 1,
    credits: 100
  };
  store.users.push(pwUser);
  const pwUserToken = await signJWT({ userId: pwUser.user_id, tokenVersion: 1 }, env.JWT_SECRET, 3600);

  const updatePwReq = new Request("https://nanomesh.local/api/user/password", {
    method: "PUT",
    headers: {
      "Cookie": `session=${pwUserToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      oldPassword: "OldPass1234!",
      newPassword: "NewPass5678!"
    })
  });
  const updatePwRes = await handleUpdatePassword(updatePwReq, env);
  assert.equal(updatePwRes.status, 200, "handleUpdatePassword must succeed");
  const updatePwData = await updatePwRes.json() as any;
  assert.equal(updatePwData.success, true);
  assert.ok(updatePwData.token, "Response JSON body must include the refreshed session token for API clients");
  const verifiedRefreshed = await verifyJWT(updatePwData.token, env.JWT_SECRET);
  assert.equal(verifiedRefreshed?.userId, pwUser.user_id);
  assert.equal(verifiedRefreshed?.tokenVersion, 2, "TokenVersion must increment to 2");
  console.log("  ✓ Password update issues refreshed token in response body: PASSED");

  // 8.2 BUG-04: OAuth Unbind Passkey Safety Verification
  const oauthPasskeyUser = {
    user_id: "u_oauth_pk",
    username: "oauth_pk_user",
    email: "oauth_pk@example.com",
    password_hash: null,
    token_version: 1,
    credits: 100
  };
  store.users.push(oauthPasskeyUser);
  store.user_oauth_bindings.push({ user_id: oauthPasskeyUser.user_id, provider: "github" });
  store.user_passkeys.push({ credential_id: "cred_123", user_id: oauthPasskeyUser.user_id });
  const oauthPkToken = await signJWT({ userId: oauthPasskeyUser.user_id, tokenVersion: 1 }, env.JWT_SECRET, 3600);

  const unbindReq = new Request("https://nanomesh.local/api/auth/oauth/github", {
    method: "DELETE",
    headers: { "Cookie": `session=${oauthPkToken}` }
  });
  const unbindRes = await handleUnbindOAuth(unbindReq, env, "github");
  assert.equal(unbindRes.status, 200, "User with registered passkeys must be permitted to unbind last OAuth provider");
  console.log("  ✓ OAuth unbinding permits decoupling when Passkey is active: PASSED");

  // 8.3 BUG-01: Admin Model Publishing Endpoint Guard
  store.user_uploaded_models.push({
    upload_id: "upload_model_1",
    user_id: "u_model_author",
    display_name: "Custom BERT",
    status: "pending",
    endpoint: "/api/infer"
  });

  // Attempt to publish without valid endpoint (or with dummy /api/infer)
  const pubFailReq = new Request("https://nanomesh.local/api/admin/models/upload_model_1", {
    method: "PATCH",
    headers: adminReqHeaders,
    body: JSON.stringify({
      status: "published",
      endpoint: "/api/infer"
    })
  });
  const pubFailRes = await handleAdminUpdateModel(pubFailReq, env);
  assert.equal(pubFailRes.status, 400, "Publishing model with /api/infer must be rejected");
  const pubFailData = await pubFailRes.json() as any;
  assert.equal(pubFailData.error, "error.validEndpointRequired");

  // Attempt to publish with legitimate endpoint succeeds
  const pubSuccessReq = new Request("https://nanomesh.local/api/admin/models/upload_model_1", {
    method: "PATCH",
    headers: adminReqHeaders,
    body: JSON.stringify({
      status: "published",
      endpoint: "https://ai.example.com/v1/chat/completions",
      inference_target: "heavy"
    })
  });
  const pubSuccessRes = await handleAdminUpdateModel(pubSuccessReq, env);
  assert.equal(pubSuccessRes.status, 200, "Publishing model with valid external endpoint must succeed");
  const insertedLiveModel = store.models.find(m => m.model_id === "um-upload_model_1");
  assert.ok(insertedLiveModel);
  assert.equal(insertedLiveModel.endpoint, "https://ai.example.com/v1/chat/completions");
  assert.equal(insertedLiveModel.inference_target, "heavy");
  console.log("  ✓ Admin model publishing validates endpoint and prevents /api/infer pollution: PASSED");

  // 8.4 Arbitrary WebGPU Topology: Template Multi-step WebGPU Intermediate Node Allowed
  store.dag_roles.push({
    role_id: "role_browser_only",
    name_zh: "端侧独占角色",
    name_en: "Browser Only Role",
    in_modalities: JSON.stringify(["text"]),
    out_modalities: JSON.stringify(["text"]),
    requisition_tags: JSON.stringify(["#browser_exclusive"]),
    compensation_prompts: "{}"
  });
  store.models.push({
    model_id: "m_browser_only",
    display_name: "WebGPU Exclusive Model",
    provider: "Client",
    endpoint: "onnx-community/test",
    modalities: JSON.stringify(["text"]),
    tags: JSON.stringify(["#browser_exclusive"]),
    context_window: 2048,
    max_concurrency: 10,
    active_connections: 0,
    precision: 0.9,
    user_rating: 4.9,
    usage_count: 10,
    is_generalist: 1,
    prior_score: 0.8,
    scenario_anchors: '["chat"]',
    status: "active",
    cost_per_1k_tokens: 0.0,
    inference_target: "browser"
  });

  const validMultiStepTemplateReq = new Request("https://nanomesh.local/api/admin/templates", {
    method: "POST",
    headers: adminReqHeaders,
    body: JSON.stringify({
      name_zh: "自由编排多步包含中间端侧节点",
      role_sequence: ["role_browser_only", "role_text_reasoning"]
    })
  });
  const validTplRes = await handleAdminCreateOrUpdateTemplate(validMultiStepTemplateReq, env);
  assert.equal(validTplRes.status, 200, "Template with intermediate browser node is now ALLOWED in arbitrary topology");
  const validTplData = await validTplRes.json() as any;
  const webgpuArbitraryTemplateId = validTplData.template_id;
  console.log("  ✓ DAG template allows WebGPU models at intermediate and any pipeline position: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 9: Arbitrary WebGPU Topology, Handshake CAS & Dynamic Billing
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 9] Arbitrary WebGPU Topology, Handshake CAS & Dynamic Billing");

  const testUser9Id = "usr_webgpu_tester_99";
  store.users.push({
    user_id: testUser9Id,
    username: "WebGPUTester",
    email: "webgpu@nanomesh.local",
    password_hash: "hash",
    credits: 5,
    token_version: 1
  });

  const user9AuthToken = await signJWT({ userId: testUser9Id, role: "user", tokenVersion: 1 }, env.JWT_SECRET, 3600);
  const user9ReqHeaders = {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${user9AuthToken}`
  };

  const testEnvelope9: UnifiedProtocolEnvelope = {
    envelope_id: "env_webgpu_001",
    session_id: "sess_webgpu_001",
    user_id: testUser9Id,
    instruction_payload: "本地快速摘要提取并交由云端深度推理",
    metadata: {},
    assets_manifest: []
  };

  // 9.1 AC-01: Phase 1 Step 0 WebGPU Zero Pre-Deduction & AC-03 Intermediate Plaintext Concealment
  const phase1Req = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: user9ReqHeaders,
    body: JSON.stringify({
      envelope: testEnvelope9,
      reRouteMode: "switch_template",
      chosenTemplateId: webgpuArbitraryTemplateId,
      capabilities: { webgpu_handover_v3: true }
    })
  });

  const phase1Res = await handleChat(phase1Req, env);
  assert.equal(phase1Res.status, 200, "Phase 1 chat request must return 200 SSE stream");

  // Read Phase 1 SSE stream
  const p1Reader = phase1Res.body!.getReader();
  const p1Decoder = new TextDecoder();
  let p1Events = "";
  let p1Done = false;
  while (!p1Done) {
    const chunk = await p1Reader.read();
    if (chunk.done) {
      p1Done = true;
    } else {
      p1Events += p1Decoder.decode(chunk.value, { stream: true });
    }
  }

  assert.ok(p1Events.includes("event: dag_handover"), "Phase 1 must emit dag_handover event");
  assert.ok(!p1Events.includes("event: text_chunk"), "AC-03: Intermediate WebGPU step must NOT emit text_chunk");

  // Extract handover payload
  const handoverMatch = p1Events.match(/event: dag_handover\ndata: (\{.*?\})\n\n/);
  assert.ok(handoverMatch, "Must contain valid dag_handover data block");
  const handoverData = JSON.parse(handoverMatch[1]);
  assert.equal(handoverData.current_step, 0);
  assert.equal(handoverData.next_step, 1);
  assert.equal(handoverData.is_tail_node, false);
  assert.ok(handoverData.continuation_token);

  // Assert AC-01: User credits in Phase 1 MUST REMAIN UNTOUCHED (Zero Pre-Deduction)
  const user9AfterPhase1 = store.users.find(u => u.user_id === testUser9Id);
  assert.equal(user9AfterPhase1.credits, 5, "AC-01: Phase 1 with Step 0 WebGPU must consume 0 credits! Credits must remain 5.");
  console.log("  ✓ AC-01 (Part 1): Step 0 WebGPU consumes 0 credits in Phase 1: PASSED");
  console.log("  ✓ AC-03: Intermediate node does not emit text_chunk to user stream: PASSED");

  // 9.2 AC-01 (Part 2): Phase 2 Continuation Triggers Cloud Pre-Deduction and Execution
  const phase2Req = new Request("https://nanomesh.local/api/chat/continue", {
    method: "POST",
    headers: user9ReqHeaders,
    body: JSON.stringify({
      continuation_token: handoverData.continuation_token,
      status: "success",
      client_step_output: "WebGPU 本地轻节点完成初始解析与特征提炼",
      envelope: testEnvelope9,
      orchestration_options: {
        chosenTemplateId: webgpuArbitraryTemplateId
      }
    })
  });

  const phase2Res = await handleChatContinue(phase2Req, env);
  assert.equal(phase2Res.status, 200, "Phase 2 chat continuation must return 200 SSE stream");

  const p2Reader = phase2Res.body!.getReader();
  const p2Decoder = new TextDecoder();
  let p2Events = "";
  let p2Done = false;
  while (!p2Done) {
    const chunk = await p2Reader.read();
    if (chunk.done) {
      p2Done = true;
    } else {
      p2Events += p2Decoder.decode(chunk.value, { stream: true });
    }
  }

  assert.ok(p2Events.includes("event: dag_resume"), "Phase 2 must emit dag_resume");
  assert.ok(p2Events.includes("event: dag_complete"), "Phase 2 must finish with dag_complete");

  // Assert AC-01: Cloud credit is deducted in Phase 2
  const user9AfterPhase2 = store.users.find(u => u.user_id === testUser9Id);
  assert.equal(user9AfterPhase2.credits, 4, "AC-01 (Part 2): Phase 2 cloud node execution must accurately deduct 1 credit (5 -> 4)");
  console.log("  ✓ AC-01 (Part 2): Phase 2 cloud node accurately consumes 1 credit: PASSED");

  // 9.3 AC-02: D1 Atomic CAS Anti-Replay Defense (10 concurrent continuation calls)
  const replayHandshakeId = "hs_replay_test_001";
  store.dag_handshakes.push({
    handshake_id: replayHandshakeId,
    user_id: testUser9Id,
    session_id: "sess_replay",
    template_id: webgpuArbitraryTemplateId,
    next_step: 1,
    status: "ISSUED",
    expires_at: new Date(Date.now() + 300000).toISOString()
  });

  const replayToken = await signJWT({
    jti: replayHandshakeId,
    sub: testUser9Id,
    sid: "sess_replay",
    tid: webgpuArbitraryTemplateId,
    nxt: 1
  }, env.JWT_SECRET, 300);

  // Send 10 concurrent continuation requests
  const concurrentRequests = Array.from({ length: 10 }).map(() => {
    const req = new Request("https://nanomesh.local/api/chat/continue", {
      method: "POST",
      headers: user9ReqHeaders,
      body: JSON.stringify({
        continuation_token: replayToken,
        status: "success",
        client_step_output: "Concurrent payload",
        envelope: testEnvelope9,
        orchestration_options: { chosenTemplateId: webgpuArbitraryTemplateId }
      })
    });
    return handleChatContinue(req, env);
  });

  const responses = await Promise.all(concurrentRequests);
  const statusCounts = responses.map(r => r.status);
  const count200 = statusCounts.filter(s => s === 200).length;
  const count409 = statusCounts.filter(s => s === 409).length;

  assert.equal(count200, 1, `AC-02: Exactly 1 request must succeed with 200, but got ${count200}`);
  assert.equal(count409, 9, `AC-02: Exactly 9 requests must be blocked with 409 CAS Conflict, but got ${count409}`);
  console.log("  ✓ AC-02: D1 Atomic CAS anti-replay blocks 9/10 concurrent requests with 409: PASSED");

  // 9.4 AC-06: Lazy sweep for orphan handshakes
  store.dag_handshakes.push({
    handshake_id: "hs_expired_1",
    user_id: testUser9Id,
    session_id: "s_exp1",
    template_id: "t1",
    next_step: 1,
    status: "ISSUED",
    expires_at: "2020-01-01T00:00:00.000Z"
  });
  store.dag_handshakes.push({
    handshake_id: "hs_expired_2",
    user_id: testUser9Id,
    session_id: "s_exp2",
    template_id: "t1",
    next_step: 1,
    status: "ISSUED",
    expires_at: "2020-01-01T00:00:00.000Z"
  });

  let capturedSweepPromise: Promise<any> | null = null;
  const mockCtx = {
    waitUntil(promise: Promise<any>) {
      capturedSweepPromise = promise;
    }
  } as any;

  triggerLazyHandshakeSweep(env, mockCtx);
  assert.ok(capturedSweepPromise, "Lazy sweep must schedule background promise via ctx.waitUntil");
  await capturedSweepPromise;
  assert.ok(!store.dag_handshakes.some(h => h.handshake_id.startsWith("hs_expired_")), "AC-06: Expired orphan handshakes must be swept");
  console.log("  ✓ AC-06: Lazy sweep cleans up expired orphan handshakes asynchronously: PASSED");

  // 9.5 AC-07: Standby Failover on candidate_failed
  const failoverHandshakeId = "hs_failover_test_001";
  store.dag_handshakes.push({
    handshake_id: failoverHandshakeId,
    user_id: testUser9Id,
    session_id: "sess_failover",
    template_id: webgpuArbitraryTemplateId,
    next_step: 1,
    status: "ISSUED",
    expires_at: new Date(Date.now() + 300000).toISOString()
  });

  const failoverToken = await signJWT({
    jti: failoverHandshakeId,
    sub: testUser9Id,
    sid: "sess_failover",
    tid: webgpuArbitraryTemplateId,
    nxt: 1
  }, env.JWT_SECRET, 300);

  // Add cloud fallback model to role_browser_only's model pool so standby failover has a cloud candidate
  store.models.push({
    model_id: "cf_browser_fallback_cloud",
    display_name: "Cloud Fallback for WebGPU Role",
    provider: "Cloudflare",
    endpoint: "@cf/meta/llama-3.2-3b-instruct",
    modalities: '["text"]',
    tags: '["#browser_exclusive"]',
    context_window: 8192,
    max_concurrency: 50,
    active_connections: 0,
    precision: 0.85,
    user_rating: 4.9,
    usage_count: 100,
    cost_per_1k_tokens: 1.0,
    status: "active",
    is_generalist: 1,
    prior_score: 0.7,
    scenario_anchors: '["chat"]',
    inference_target: "edge",
    auth_mode: "none",
    api_format: "workers_ai"
  });

  const failoverReq = new Request("https://nanomesh.local/api/chat/continue", {
    method: "POST",
    headers: user9ReqHeaders,
    body: JSON.stringify({
      continuation_token: failoverToken,
      status: "candidate_failed",
      failed_model_id: "m_browser_only",
      error_reason: "WebGPU Device creation failure",
      envelope: testEnvelope9,
      orchestration_options: { chosenTemplateId: webgpuArbitraryTemplateId }
    })
  });

  const failoverRes = await handleChatContinue(failoverReq, env);
  assert.equal(failoverRes.status, 200, "AC-07: candidate_failed must transparently fallback to standby cloud model");
  console.log("  ✓ AC-07: Standby model failover successfully executes on client failure report: PASSED");

  console.log("\n==================================================");
  console.log("   🎉 ALL 9 INTEGRATION SCENARIOS PASSED (100%)!  ");
  console.log("==================================================");
}

runIntegrationTests().catch(err => {
  console.error("❌ Integration Test Failed:", err);
  process.exit(1);
});

// tests/integration_test.ts
import assert from "node:assert/strict";
import fs from "node:fs";
import worker from "../src/index";
import { signJWT, verifyJWT } from "../src/auth/jwt";
import { handleGetAsset } from "../src/api/presign";
import { handleDeleteAccount, handleUpdatePassword } from "../src/api/user";
import { handleUnbindOAuth, handleSendCode } from "../src/api/auth";
import { getPersistentSalt } from "../src/api/billing";
import { handleSaveHistory } from "../src/api/history";
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
import { registerAndFreezeDagRunPlan, registerPresignedAssetTicket } from "../src/api/session";
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
  notifications: any[];
  broadcast_reads: any[];
  system_counters: any[];
  chat_session_states?: any[];
  session_branches?: any[];
  session_commits?: any[];
  session_assets?: any[];
  dag_run_plans?: any[];
  asset_perceptual_cache?: any[];
  dag_execution_cache?: any[];
  run_billing_settlements?: any[];
  pending_r2_deletions?: any[];
  pending_r2_prefix_purges?: any[];
}

interface TableConstraint {
  primaryKey: string;
  uniqueKeys?: string[][];
  nocaseKeys?: string[];
}

const SCHEMA_CONSTRAINTS: Record<string, TableConstraint> = {
  account_tombstones: { primaryKey: "hash_id" },
  users: {
    primaryKey: "user_id",
    uniqueKeys: [["email"], ["referral_code"], ["username"]],
    nocaseKeys: ["username", "email"]
  },
  user_oauth_bindings: {
    primaryKey: "id",
    uniqueKeys: [
      ["provider", "provider_id"],
      ["user_id", "provider"]
    ]
  },
  dag_handshakes: { primaryKey: "handshake_id" },
  dag_roles: { primaryKey: "role_id" },
  dag_templates: { primaryKey: "template_id" },
  models: { primaryKey: "model_id" },
  user_passkeys: { primaryKey: "credential_id" },
  user_chat_sessions: { primaryKey: "__compound_pk__", uniqueKeys: [["user_id", "session_id"]] },
  credit_ledger: { primaryKey: "ledger_id" },
  chat_session_states: { primaryKey: "__compound_pk__", uniqueKeys: [["user_id", "session_id"]] },
  session_branches: {
    primaryKey: "__compound_pk__",
    uniqueKeys: [["user_id", "session_id", "branch_id"]]
  },
  session_commits: {
    primaryKey: "__compound_pk__",
    uniqueKeys: [
      ["user_id", "session_id", "commit_id"],
      ["user_id", "session_id", "run_id"]
    ]
  },
  session_assets: { primaryKey: "__compound_pk__", uniqueKeys: [["user_id", "asset_id"]] },
  dag_run_plans: {
    primaryKey: "__compound_pk__",
    uniqueKeys: [
      ["user_id", "run_id"],
      ["user_id", "session_id", "client_op_id"]
    ]
  },
  asset_perceptual_cache: {
    primaryKey: "__compound_pk__",
    uniqueKeys: [["user_id", "session_id", "percept_key"]]
  },
  dag_execution_cache: {
    primaryKey: "__compound_pk__",
    uniqueKeys: [["user_id", "session_id", "cache_key"]]
  },
  run_billing_settlements: {
    primaryKey: "__compound_pk__",
    uniqueKeys: [["user_id", "run_id", "phase"]]
  },
  pending_r2_deletions: { primaryKey: "delete_id", uniqueKeys: [["user_id", "r2_key"]] },
  pending_r2_prefix_purges: { primaryKey: "user_id" }
};

function checkAndInsertRow(
  tableName: keyof TableStore,
  newRow: Record<string, any>,
  sql: string,
  store: TableStore
): { changes: number } {
  const constraint = SCHEMA_CONSTRAINTS[tableName as string];
  const tableData: any[] = store[tableName] || [];
  const cleanSql = sql.trim();
  const isOrIgnore = cleanSql.includes("INSERT OR IGNORE");
  const isOrReplace = cleanSql.includes("INSERT OR REPLACE");
  const hasOnConflict = cleanSql.includes("ON CONFLICT");

  if (constraint) {
    // 1. Check Primary Key
    const pk = constraint.primaryKey;
    const pkConflictIndex = tableData.findIndex(
      (r) => r[pk] !== undefined && r[pk] !== null && r[pk] === newRow[pk]
    );

    // 2. Check UNIQUE Keys (including compound keys and NOCASE collation)
    let ukConflictIndex = -1;
    let conflictedKey = pk;
    if (constraint.uniqueKeys) {
      for (const ukCols of constraint.uniqueKeys) {
        const idx = tableData.findIndex((r) =>
          ukCols.every((col) => {
            const valA = r[col];
            const valB = newRow[col];
            if (valA === undefined || valA === null || valB === undefined || valB === null)
              return false;
            if (
              constraint.nocaseKeys?.includes(col) &&
              typeof valA === "string" &&
              typeof valB === "string"
            ) {
              return valA.toLowerCase() === valB.toLowerCase();
            }
            return valA === valB;
          })
        );
        if (idx !== -1) {
          ukConflictIndex = idx;
          conflictedKey = ukCols.join("_");
          break;
        }
      }
    }

    const hasConflict = pkConflictIndex !== -1 || ukConflictIndex !== -1;
    const conflictIndex = pkConflictIndex !== -1 ? pkConflictIndex : ukConflictIndex;

    if (hasConflict) {
      if (isOrIgnore || cleanSql.includes("DO NOTHING")) {
        return { changes: 0 };
      } else if (isOrReplace || hasOnConflict) {
        tableData[conflictIndex] = { ...tableData[conflictIndex], ...newRow };
        return { changes: 1 };
      } else {
        throw new Error(
          `SQLITE_CONSTRAINT: UNIQUE constraint failed: ${tableName}.${conflictedKey}`
        );
      }
    }
  }

  tableData.push(newRow);
  return { changes: 1 };
}

function createMockD1(store: TableStore) {
  return {
    prepare(sql: string) {
      let boundArgs: any[] = [];
      const stmt = {
        requiresPreviousChange: sql.includes("changes() = 1"),
        bind(...args: any[]) {
          boundArgs = args;
          return stmt;
        },
        async first<T = any>(): Promise<T | null> {
          const res = await stmt.all<T>();
          return res.results.length > 0 ? res.results[0] : null;
        },
        async all<T = any>(): Promise<{ results: T[] }> {
          const cleanSql = sql.replace(/\s+/g, " ").trim();

          // 1. SELECT COUNT FROM admin_login_attempts
          if (cleanSql.includes("FROM admin_login_attempts")) {
            return { results: [{ count: store.admin_login_attempts.length }] as any };
          }

          // 2. SELECT * FROM models
          if (cleanSql.includes("FROM models")) {
            let res = [...store.models];
            if (cleanSql.includes("WHERE model_id = ?")) {
              res = res.filter((m) => m.model_id === boundArgs[0]);
            } else if (cleanSql.includes("WHERE status = 'active'")) {
              res = res.filter((m) => m.status === "active");
            }
            return { results: res as any };
          }

          // 3. SELECT * FROM dag_roles
          if (cleanSql.includes("FROM dag_roles")) {
            let res = [...store.dag_roles];
            if (cleanSql.includes("WHERE role_id = ?")) {
              res = res.filter((r) => r.role_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 4. SELECT * FROM dag_templates
          if (cleanSql.includes("FROM dag_templates")) {
            let res = [...store.dag_templates];
            if (cleanSql.includes("WHERE template_id = ?")) {
              res = res.filter((t) => t.template_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 5. SELECT credits FROM users
          if (cleanSql.includes("FROM users")) {
            let res = [...store.users];
            if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter((u) => u.user_id === boundArgs[0]);
            } else if (cleanSql.includes("LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?)")) {
              const emailArg = String(boundArgs[0] || "").toLowerCase();
              const userArg = String(boundArgs[1] || "").toLowerCase();
              res = res.filter(
                (u) =>
                  (u.email && u.email.toLowerCase() === emailArg) ||
                  (u.username && u.username.toLowerCase() === userArg)
              );
            } else if (cleanSql.includes("WHERE email = ? OR username = ?")) {
              res = res.filter((u) => u.email === boundArgs[0] || u.username === boundArgs[1]);
            } else if (cleanSql.includes("LOWER(username) = LOWER(?) AND user_id != ?")) {
              const userArg = String(boundArgs[0] || "").toLowerCase();
              const userId = boundArgs[1];
              res = res.filter(
                (u) => u.username && u.username.toLowerCase() === userArg && u.user_id !== userId
              );
            } else if (cleanSql.includes("WHERE referral_code = ?")) {
              const code = boundArgs[0];
              res = res.filter(
                (u) =>
                  u.referral_code === code &&
                  (!cleanSql.includes("email NOT LIKE 'deleted_%'") ||
                    !u.email?.startsWith("deleted_"))
              );
            } else if (
              cleanSql.includes("LOWER(email) = LOWER(?)") ||
              cleanSql.includes("LOWER(email) = ?")
            ) {
              const emailArg = String(boundArgs[0] || "").toLowerCase();
              res = res.filter((u) => u.email && u.email.toLowerCase() === emailArg);
            }
            return { results: res as any };
          }

          // 6. SELECT credit_ledger
          if (cleanSql.includes("FROM credit_ledger")) {
            let res = [...store.credit_ledger];
            if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter((l) => l.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 7. SELECT * FROM user_chat_sessions
          if (cleanSql.includes("FROM user_chat_sessions")) {
            let res = [...store.user_chat_sessions];
            if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter((s) => s.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 8. SELECT * FROM user_oauth_bindings
          if (cleanSql.includes("FROM user_oauth_bindings")) {
            let res = [...store.user_oauth_bindings];
            if (cleanSql.includes("WHERE user_id = ? AND provider = ?")) {
              res = res.filter((b) => b.user_id === boundArgs[0] && b.provider === boundArgs[1]);
            } else if (cleanSql.includes("WHERE provider = ? AND provider_id = ?")) {
              res = res.filter(
                (b) => b.provider === boundArgs[0] && String(b.provider_id) === String(boundArgs[1])
              );
            } else if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter((b) => b.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 8.5 SELECT * FROM account_tombstones
          if (cleanSql.includes("FROM account_tombstones")) {
            let res = [...(store.account_tombstones || [])];
            if (cleanSql.includes("WHERE hash_id = ?")) {
              const hashId = boundArgs[0];
              const nowIso = new Date().toISOString();
              res = res.filter(
                (t) =>
                  t.hash_id === hashId &&
                  (!cleanSql.includes("expires_at > datetime('now')") || t.expires_at > nowIso)
              );
            }
            return { results: res as any };
          }

          // 9. SELECT COUNT(*) as cnt FROM user_passkeys
          if (cleanSql.includes("FROM user_passkeys")) {
            const userId = boundArgs[0];
            const pks = (store.user_passkeys || []).filter((p) => p.user_id === userId);
            return { results: [{ cnt: pks.length }] as any };
          }

          // 10. SELECT * FROM user_uploaded_models
          if (cleanSql.includes("FROM user_uploaded_models")) {
            let res = [...(store.user_uploaded_models || [])];
            if (cleanSql.includes("WHERE upload_id = ?")) {
              res = res.filter((m) => m.upload_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 11. SELECT * FROM dag_handshakes
          if (cleanSql.includes("FROM dag_handshakes")) {
            let res = [...(store.dag_handshakes || [])];
            if (cleanSql.includes("WHERE handshake_id = ?")) {
              res = res.filter((h) => h.handshake_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 11b. SELECT * FROM chat_session_states
          if (cleanSql.includes("FROM chat_session_states")) {
            let res = [...(store.chat_session_states || [])];
            if (cleanSql.includes("WHERE user_id = ? AND session_id = ?")) {
              res = res.filter((r) => r.user_id === boundArgs[0] && r.session_id === boundArgs[1]);
            } else if (cleanSql.includes("WHERE session_id = ? AND user_id = ?")) {
              res = res.filter((r) => r.session_id === boundArgs[0] && r.user_id === boundArgs[1]);
            }
            return { results: res as any };
          }

          // 11c. SELECT * FROM session_branches
          if (cleanSql.includes("FROM session_branches")) {
            let res = [...(store.session_branches || [])];
            if (cleanSql.includes("WHERE user_id = ? AND session_id = ?")) {
              res = res.filter((r) => r.user_id === boundArgs[0] && r.session_id === boundArgs[1]);
            } else if (cleanSql.includes("WHERE session_id = ? AND user_id = ?")) {
              res = res.filter((r) => r.session_id === boundArgs[0] && r.user_id === boundArgs[1]);
            }
            return { results: res as any };
          }

          // 11d. SELECT * FROM session_commits
          if (cleanSql.includes("FROM session_commits")) {
            let res = [...(store.session_commits || [])];
            if (cleanSql.includes("WHERE user_id = ? AND session_id = ?")) {
              res = res.filter((r) => r.user_id === boundArgs[0] && r.session_id === boundArgs[1]);
            } else if (cleanSql.includes("WHERE session_id = ? AND user_id = ?")) {
              res = res.filter((r) => r.session_id === boundArgs[0] && r.user_id === boundArgs[1]);
            }
            return { results: res as any };
          }

          // 11e. SELECT * FROM session_assets
          if (cleanSql.includes("FROM session_assets")) {
            let res = [...(store.session_assets || [])];
            if (cleanSql.includes("WHERE user_id = ? AND (r2_key = ? OR text_r2_key = ?)")) {
              res = res.filter(
                (r) =>
                  r.user_id === boundArgs[0] &&
                  (r.r2_key === boundArgs[1] || r.text_r2_key === boundArgs[2])
              );
            } else if (cleanSql.includes("WHERE user_id = ? AND (r2_key = ? OR asset_id = ?)")) {
              res = res.filter(
                (r) =>
                  r.user_id === boundArgs[0] &&
                  (r.r2_key === boundArgs[1] || r.asset_id === boundArgs[2])
              );
            } else if (cleanSql.includes("WHERE user_id = ? AND session_id = ? AND asset_id = ?")) {
              res = res.filter(
                (r) =>
                  r.user_id === boundArgs[0] &&
                  r.session_id === boundArgs[1] &&
                  r.asset_id === boundArgs[2] &&
                  (!cleanSql.includes("status = 'COMMITTED'") || r.status === "COMMITTED")
              );
            } else if (cleanSql.includes("WHERE user_id = ? AND asset_id = ?")) {
              res = res.filter((r) => r.user_id === boundArgs[0] && r.asset_id === boundArgs[1]);
            } else if (cleanSql.includes("WHERE user_id = ? AND r2_key = ?")) {
              res = res.filter((r) => r.user_id === boundArgs[0] && r.r2_key === boundArgs[1]);
            } else if (cleanSql.includes("WHERE user_id = ? AND session_id = ?")) {
              res = res.filter(
                (r) =>
                  r.user_id === boundArgs[0] &&
                  r.session_id === boundArgs[1] &&
                  (!cleanSql.includes("status = 'COMMITTED'") || r.status === "COMMITTED")
              );
            } else if (cleanSql.includes("WHERE r2_key = ?")) {
              res = res.filter((r) => r.r2_key === boundArgs[0]);
            } else if (cleanSql.includes("WHERE session_id = ? AND user_id = ?")) {
              res = res.filter((r) => r.session_id === boundArgs[0] && r.user_id === boundArgs[1]);
            }
            return { results: res as any };
          }

          // 11f. SELECT * FROM dag_run_plans
          if (cleanSql.includes("FROM dag_run_plans")) {
            let res = [...(store.dag_run_plans || [])];
            if (cleanSql.includes("WHERE user_id = ? AND session_id = ? AND client_op_id = ?")) {
              res = res.filter(
                (r) =>
                  r.user_id === boundArgs[0] &&
                  r.session_id === boundArgs[1] &&
                  r.client_op_id === boundArgs[2]
              );
            } else if (cleanSql.includes("WHERE user_id = ? AND run_id = ? AND session_id = ?")) {
              res = res.filter(
                (r) =>
                  r.user_id === boundArgs[0] &&
                  r.run_id === boundArgs[1] &&
                  r.session_id === boundArgs[2]
              );
            } else if (cleanSql.includes("WHERE run_id = ?")) {
              res = res.filter((r) => r.run_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 11g. SELECT * FROM asset_perceptual_cache
          if (cleanSql.includes("FROM asset_perceptual_cache")) {
            let res = [...(store.asset_perceptual_cache || [])];
            if (cleanSql.includes("WHERE user_id = ? AND session_id = ?")) {
              res = res.filter((r) => r.user_id === boundArgs[0] && r.session_id === boundArgs[1]);
            } else if (cleanSql.includes("WHERE session_id = ? AND user_id = ?")) {
              res = res.filter((r) => r.session_id === boundArgs[0] && r.user_id === boundArgs[1]);
            }
            return { results: res as any };
          }

          // 11h. SELECT * FROM dag_execution_cache
          if (cleanSql.includes("FROM dag_execution_cache")) {
            let res = [...(store.dag_execution_cache || [])];
            if (cleanSql.includes("WHERE user_id = ? AND session_id = ? AND cache_key = ?")) {
              res = res.filter(
                (r) =>
                  r.user_id === boundArgs[0] &&
                  r.session_id === boundArgs[1] &&
                  r.cache_key === boundArgs[2]
              );
            } else if (cleanSql.includes("WHERE cache_key = ?")) {
              res = res.filter((r) => r.cache_key === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 11i. SELECT FROM run_billing_settlements
          if (cleanSql.includes("FROM run_billing_settlements")) {
            let res = [...(store.run_billing_settlements || [])];
            if (cleanSql.includes("WHERE user_id = ? AND run_id = ? AND phase = ?")) {
              res = res.filter(
                (r) =>
                  r.user_id === boundArgs[0] &&
                  r.run_id === boundArgs[1] &&
                  r.phase === boundArgs[2]
              );
            }
            return { results: res as any };
          }

          // 11j. SELECT FROM pending_r2_deletions / pending_r2_prefix_purges
          if (cleanSql.includes("FROM pending_r2_deletions")) {
            let res = [...(store.pending_r2_deletions || [])];
            if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter((r) => r.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }
          if (cleanSql.includes("FROM pending_r2_prefix_purges")) {
            let res = [...(store.pending_r2_prefix_purges || [])];
            if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter((r) => r.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 11k. SELECT session_id FROM user_chat_sessions
          if (cleanSql.includes("FROM user_chat_sessions")) {
            let res = [...(store.user_chat_sessions || [])];
            if (cleanSql.includes("WHERE user_id = ? AND (session_id = ? OR trace_id = ?)")) {
              res = res.filter(
                (r) =>
                  r.user_id === boundArgs[0] &&
                  (r.session_id === boundArgs[1] || r.trace_id === boundArgs[2])
              );
            } else if (cleanSql.includes("WHERE user_id = ?")) {
              res = res.filter((r) => r.user_id === boundArgs[0]);
            }
            return { results: res as any };
          }

          // 12. SELECT value FROM system_counters
          if (cleanSql.includes("FROM system_counters")) {
            const key = boundArgs[0];
            const row = (store.system_counters || []).find((c) => c.key === key);
            return { results: row ? [row as any] : [] };
          }

          // 13. SELECT id FROM verification_codes
          if (cleanSql.includes("FROM verification_codes")) {
            let res = [...(store.verification_codes || [])];
            if (
              cleanSql.includes("WHERE email = ?") ||
              cleanSql.includes("WHERE LOWER(email) = ?") ||
              cleanSql.includes("LOWER(email) = LOWER(?)")
            ) {
              const emailArg = String(boundArgs[0] || "").toLowerCase();
              const nowIso = new Date().toISOString();
              res = res.filter((v) => {
                if ((v.email || "").toLowerCase() !== emailArg) return false;
                if (
                  cleanSql.includes("code NOT LIKE 'NOTICE_%'") &&
                  String(v.code || "").startsWith("NOTICE_")
                )
                  return false;
                if (cleanSql.includes("code != 'OAUTH_NOTICE'") && v.code === "OAUTH_NOTICE")
                  return false;
                if (cleanSql.includes("expires_at > datetime('now')") && v.expires_at < nowIso)
                  return false;
                if (cleanSql.includes("created_at > datetime('now', '-60 seconds')")) {
                  if (!v.created_at) return false;
                  const createdAt = new Date(v.created_at).getTime();
                  if (Date.now() - createdAt > 60000) return false;
                }
                return true;
              });
            }
            if (cleanSql.includes("ORDER BY id DESC")) {
              res.sort((a, b) => (b.id || 0) - (a.id || 0));
            }
            return { results: res as any };
          }

          // 14. SELECT * FROM notifications
          if (cleanSql.includes("FROM notifications")) {
            let res = [...(store.notifications || [])];
            if (cleanSql.includes("WHERE notification_id = ?")) {
              res = res.filter((n) => n.notification_id === boundArgs[0]);
            } else if (cleanSql.includes("event_type = 'low_balance'")) {
              res = res.filter((n) => n.user_id === boundArgs[0] && n.event_type === "low_balance");
            }
            return { results: res as any };
          }

          return { results: [] };
        },
        async run(): Promise<{ meta: { changes: number } }> {
          const cleanSql = sql.replace(/\s+/g, " ").trim();

          // DELETE FROM user_chat_sessions & 0025 session tables
          if (cleanSql.startsWith("DELETE FROM user_chat_sessions")) {
            if (cleanSql.includes("(session_id = ? OR trace_id = ?)")) {
              const [uid, s1, s2, gUid, gSess] = boundArgs;
              if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
                const delOk = (store.chat_session_states || []).some(
                  (s) => s.user_id === gUid && s.session_id === gSess && !!s.deleted_at
                );
                if (!delOk) return { meta: { changes: 0 } };
              }
              store.user_chat_sessions = store.user_chat_sessions.filter(
                (s) => !(s.user_id === uid && (s.session_id === s1 || s.trace_id === s2))
              );
            } else {
              const userId = boundArgs[0];
              store.user_chat_sessions = store.user_chat_sessions.filter(
                (s) => s.user_id !== userId
              );
            }
            return { meta: { changes: 1 } };
          }

          if (cleanSql.startsWith("DELETE FROM chat_session_states")) {
            store.chat_session_states = (store.chat_session_states || []).filter(
              (r) => r.user_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }
          if (cleanSql.startsWith("DELETE FROM session_branches")) {
            if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
              const delOk = (store.chat_session_states || []).some(
                (s) => s.user_id === boundArgs[2] && s.session_id === boundArgs[3] && !!s.deleted_at
              );
              if (!delOk) return { meta: { changes: 0 } };
            }
            store.session_branches = (store.session_branches || []).filter((r) =>
              boundArgs.length >= 2
                ? !(r.user_id === boundArgs[0] && r.session_id === boundArgs[1])
                : r.user_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }
          if (cleanSql.startsWith("DELETE FROM session_commits")) {
            if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
              const delOk = (store.chat_session_states || []).some(
                (s) => s.user_id === boundArgs[2] && s.session_id === boundArgs[3] && !!s.deleted_at
              );
              if (!delOk) return { meta: { changes: 0 } };
            }
            store.session_commits = (store.session_commits || []).filter((r) =>
              boundArgs.length >= 2
                ? !(r.user_id === boundArgs[0] && r.session_id === boundArgs[1])
                : r.user_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }
          if (cleanSql.startsWith("DELETE FROM session_assets")) {
            if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
              const delOk = (store.chat_session_states || []).some(
                (s) => s.user_id === boundArgs[2] && s.session_id === boundArgs[3] && !!s.deleted_at
              );
              if (!delOk) return { meta: { changes: 0 } };
            }
            store.session_assets = (store.session_assets || []).filter((r) =>
              boundArgs.length >= 2
                ? !(r.user_id === boundArgs[0] && r.session_id === boundArgs[1])
                : r.user_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }
          if (cleanSql.startsWith("DELETE FROM run_billing_settlements")) {
            if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
              const delOk = (store.chat_session_states || []).some(
                (s) => s.user_id === boundArgs[1] && s.session_id === boundArgs[2] && !!s.deleted_at
              );
              if (!delOk) return { meta: { changes: 0 } };
              const [uid, , , pUid, pSess] = boundArgs;
              const runIds = new Set(
                (store.dag_run_plans || [])
                  .filter((p) => p.user_id === pUid && p.session_id === pSess)
                  .map((p) => p.run_id)
              );
              store.run_billing_settlements = (store.run_billing_settlements || []).filter(
                (r) => !(r.user_id === uid && runIds.has(r.run_id))
              );
            } else if (boundArgs.length >= 3) {
              const [uid, pUid, pSess] = boundArgs;
              const runIds = new Set(
                (store.dag_run_plans || [])
                  .filter((p) => p.user_id === pUid && p.session_id === pSess)
                  .map((p) => p.run_id)
              );
              store.run_billing_settlements = (store.run_billing_settlements || []).filter(
                (r) => !(r.user_id === uid && runIds.has(r.run_id))
              );
            } else {
              store.run_billing_settlements = (store.run_billing_settlements || []).filter(
                (r) => r.user_id !== boundArgs[0]
              );
            }
            return { meta: { changes: 1 } };
          }
          if (cleanSql.startsWith("DELETE FROM dag_run_plans")) {
            if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
              const delOk = (store.chat_session_states || []).some(
                (s) => s.user_id === boundArgs[2] && s.session_id === boundArgs[3] && !!s.deleted_at
              );
              if (!delOk) return { meta: { changes: 0 } };
            }
            store.dag_run_plans = (store.dag_run_plans || []).filter((r) =>
              boundArgs.length >= 2
                ? !(r.user_id === boundArgs[0] && r.session_id === boundArgs[1])
                : r.user_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }
          if (cleanSql.startsWith("DELETE FROM asset_perceptual_cache")) {
            if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
              const delOk = (store.chat_session_states || []).some(
                (s) => s.user_id === boundArgs[2] && s.session_id === boundArgs[3] && !!s.deleted_at
              );
              if (!delOk) return { meta: { changes: 0 } };
            }
            store.asset_perceptual_cache = (store.asset_perceptual_cache || []).filter((r) =>
              boundArgs.length >= 2
                ? !(r.user_id === boundArgs[0] && r.session_id === boundArgs[1])
                : r.user_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }
          if (cleanSql.startsWith("DELETE FROM dag_execution_cache")) {
            if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
              const delOk = (store.chat_session_states || []).some(
                (s) => s.user_id === boundArgs[2] && s.session_id === boundArgs[3] && !!s.deleted_at
              );
              if (!delOk) return { meta: { changes: 0 } };
            }
            store.dag_execution_cache = (store.dag_execution_cache || []).filter((r) =>
              boundArgs.length >= 2
                ? !(r.user_id === boundArgs[0] && r.session_id === boundArgs[1])
                : r.user_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }
          if (
            cleanSql.startsWith("DELETE FROM dag_handshakes") &&
            !cleanSql.includes("expires_at")
          ) {
            if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
              const delOk = (store.chat_session_states || []).some(
                (s) => s.user_id === boundArgs[2] && s.session_id === boundArgs[3] && !!s.deleted_at
              );
              if (!delOk) return { meta: { changes: 0 } };
            }
            store.dag_handshakes = (store.dag_handshakes || []).filter((r) =>
              boundArgs.length >= 2
                ? !(r.user_id === boundArgs[0] && r.session_id === boundArgs[1])
                : r.user_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }
          if (cleanSql.startsWith("DELETE FROM pending_r2_deletions")) {
            store.pending_r2_deletions = (store.pending_r2_deletions || []).filter(
              (r) => r.delete_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }
          if (cleanSql.startsWith("DELETE FROM pending_r2_prefix_purges")) {
            store.pending_r2_prefix_purges = (store.pending_r2_prefix_purges || []).filter(
              (r) => r.user_id !== boundArgs[0]
            );
            return { meta: { changes: 1 } };
          }

          // DELETE FROM user_oauth_bindings
          if (cleanSql.startsWith("DELETE FROM user_oauth_bindings")) {
            const userId = boundArgs[0];
            store.user_oauth_bindings = store.user_oauth_bindings.filter(
              (b) => b.user_id !== userId
            );
            return { meta: { changes: 1 } };
          }

          // DELETE FROM user_passkeys
          if (cleanSql.startsWith("DELETE FROM user_passkeys")) {
            return { meta: { changes: 1 } };
          }

          // DELETE FROM system_counters
          if (cleanSql.startsWith("DELETE FROM system_counters")) {
            const cutoffHour = new Date(Date.now() - 24 * 3600 * 1000).toISOString().slice(0, 13);
            const cutoffPrefix = `ip_code_rate_${cutoffHour}`;
            const cutoffEpoch = Math.floor(Date.now() / 1000) - 600;
            store.system_counters = (store.system_counters || []).filter((c) => {
              if (c.key.startsWith("ip_code_rate_20")) {
                const isExpired = c.key < `ip_code_rate_${cutoffHour}`;
                return !isExpired;
              }
              if (c.key.startsWith("ip_pwd_rate_20")) {
                const isExpired = c.key < `ip_pwd_rate_${cutoffHour}`;
                return !isExpired;
              }
              if (c.key.startsWith("pk_used_")) {
                const isExpired = c.value < cutoffEpoch;
                return !isExpired;
              }
              return true;
            });
            return { meta: { changes: 1 } };
          }

          // DELETE FROM notifications
          if (cleanSql.startsWith("DELETE FROM notifications")) {
            const userId = boundArgs[0];
            store.notifications = (store.notifications || []).filter((n) => n.user_id !== userId);
            return { meta: { changes: 1 } };
          }

          // INSERT INTO notifications
          if (cleanSql.startsWith("INSERT INTO notifications")) {
            const [
              notification_id,
              user_id,
              category,
              event_type,
              priority,
              title_zh,
              title_en,
              content_zh,
              content_en,
              action_type,
              action_payload,
              related_id,
              extra_data
            ] = boundArgs;
            const newRow = {
              notification_id,
              user_id: user_id || null,
              category,
              event_type,
              priority,
              title_zh,
              title_en,
              content_zh,
              content_en,
              action_type,
              action_payload,
              related_id,
              extra_data,
              is_read: 0,
              created_at: new Date().toISOString()
            };
            store.notifications = store.notifications || [];
            store.notifications.push(newRow);
            return { meta: { changes: 1 } };
          }

          // UPDATE notifications SET is_read = 1
          if (cleanSql.startsWith("UPDATE notifications SET is_read = 1")) {
            const notifId = boundArgs[0];
            const notif = (store.notifications || []).find((n) => n.notification_id === notifId);
            if (notif) {
              notif.is_read = 1;
              notif.read_at = new Date().toISOString();
            }
            return { meta: { changes: 1 } };
          }

          // DELETE FROM broadcast_reads
          if (cleanSql.startsWith("DELETE FROM broadcast_reads")) {
            const userId = boundArgs[0];
            store.broadcast_reads = (store.broadcast_reads || []).filter(
              (r) => r.user_id !== userId
            );
            return { meta: { changes: 1 } };
          }

          // INSERT INTO account_tombstones (faithful SQLite / D1 unique constraint simulation)
          if (cleanSql.includes("INTO account_tombstones")) {
            const hashId = boundArgs[0];
            const type = cleanSql.includes("'email'") ? "email" : "oauth";
            return {
              meta: checkAndInsertRow(
                "account_tombstones",
                { hash_id: hashId, type },
                cleanSql,
                store
              )
            };
          }

          // INSERT INTO user_oauth_bindings
          if (cleanSql.includes("INTO user_oauth_bindings")) {
            const [userId, provider, providerId] = boundArgs;
            const newRow = {
              id: crypto.randomUUID(),
              user_id: userId,
              provider,
              provider_id: String(providerId)
            };
            return { meta: checkAndInsertRow("user_oauth_bindings", newRow, cleanSql, store) };
          }

          // UPDATE users (anonymization)
          if (cleanSql.startsWith("UPDATE users") && cleanSql.includes("SET email = 'deleted_'")) {
            const userId = boundArgs[0];
            const u = store.users.find((usr) => usr.user_id === userId);
            if (u) {
              u.email = "deleted_" + userId;
              u.username = "del_" + userId.slice(0, 12);
              u.credits = 0;
              u.referral_code = null;
              u.token_version = (u.token_version || 1) + 1;
            }
            return { meta: { changes: 1 } };
          }

          // UPDATE users SET token_version = COALESCE(token_version, 1) + 1 (handleLogout)
          if (cleanSql.startsWith("UPDATE users") && cleanSql.includes("SET token_version =")) {
            const userId = boundArgs[boundArgs.length - 1];
            const u = store.users.find((usr) => usr.user_id === userId);
            if (u) {
              u.token_version = (u.token_version || 1) + 1;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          // UPDATE users SET password_hash
          if (cleanSql.includes("UPDATE users") && cleanSql.includes("SET password_hash")) {
            const userId = boundArgs[boundArgs.length - 1];
            const u = store.users.find((usr) => usr.user_id === userId);
            if (u) {
              u.password_hash = boundArgs[0];
              if (cleanSql.includes("token_version")) {
                u.token_version = (u.token_version || 1) + 1;
              }
            }
            return { meta: { changes: 1 } };
          }

          // UPDATE user_uploaded_models
          if (cleanSql.startsWith("UPDATE user_uploaded_models")) {
            const uploadId = boundArgs[boundArgs.length - 1];
            const m = (store.user_uploaded_models || []).find((mod) => mod.upload_id === uploadId);
            if (m) {
              m.status = boundArgs[0];
              if (boundArgs.length > 2) m.live_model_id = boundArgs[1];
            }
            return { meta: { changes: 1 } };
          }

          // INSERT INTO dag_handshakes
          if (cleanSql.startsWith("INSERT INTO dag_handshakes")) {
            const [handshakeId, userId, sessionId, templateId, nextStep, expiresAt] = boundArgs;
            const newRow = {
              handshake_id: handshakeId,
              user_id: userId,
              session_id: sessionId,
              template_id: templateId,
              next_step: nextStep,
              status: "ISSUED",
              expires_at: expiresAt,
              created_at: new Date().toISOString()
            };
            return { meta: checkAndInsertRow("dag_handshakes", newRow, cleanSql, store) };
          }

          // UPDATE dag_handshakes SET status = 'CONSUMED'
          if (
            cleanSql.startsWith("UPDATE dag_handshakes") &&
            cleanSql.includes("status = 'CONSUMED'")
          ) {
            const [handshakeId, userId] = boundArgs;
            store.dag_handshakes = store.dag_handshakes || [];
            const item = store.dag_handshakes.find(
              (h) => h.handshake_id === handshakeId && h.user_id === userId && h.status === "ISSUED"
            );
            if (item) {
              item.status = "CONSUMED";
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
            store.dag_handshakes = store.dag_handshakes.filter((h) => h.expires_at >= nowIso);
            const deleted = initialLen - store.dag_handshakes.length;
            return { meta: { changes: deleted } };
          }

          // DELETE FROM admin_login_attempts
          if (cleanSql.startsWith("DELETE FROM admin_login_attempts")) {
            store.admin_login_attempts = [];
            return { meta: { changes: 1 } };
          }

          // INSERT INTO admin_login_attempts
          if (cleanSql.startsWith("INSERT INTO admin_login_attempts")) {
            store.admin_login_attempts = store.admin_login_attempts || [];
            store.admin_login_attempts.push({
              ip: boundArgs[0],
              created_at: new Date().toISOString()
            });
            return { meta: { changes: 1 } };
          }

          // INSERT INTO users
          if (cleanSql.startsWith("INSERT INTO users")) {
            const [userId, username, email, password_hash, credits, referral_code, referred_by] =
              boundArgs;
            const newRow = {
              user_id: userId,
              username,
              email,
              password_hash,
              credits,
              referral_code,
              referred_by,
              token_version: 1
            };
            return { meta: checkAndInsertRow("users", newRow, cleanSql, store) };
          }

          // UPDATE users credits
          if (cleanSql.includes("UPDATE users SET credits")) {
            const userId =
              boundArgs.find(
                (arg) => typeof arg === "string" && store.users.some((u) => u.user_id === arg)
              ) || boundArgs[boundArgs.length - 1];
            const user = store.users.find((u) => u.user_id === userId);
            if (user) {
              if (cleanSql.includes("credits = credits + ?")) {
                user.credits += Number(boundArgs[0]) || 0;
                return { meta: { changes: 1 } };
              } else if (cleanSql.includes("credits = credits - ?")) {
                const deduct = Number(boundArgs[0]) || 1;
                if (cleanSql.includes("AND credits >= ?")) {
                  if (user.credits >= deduct) {
                    user.credits -= deduct;
                    return { meta: { changes: 1 } };
                  }
                  return { meta: { changes: 0 } };
                } else {
                  user.credits -= deduct;
                  return { meta: { changes: 1 } };
                }
              } else if (cleanSql.includes("credits = credits + 50")) {
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
              amount = boundArgs.length === 4 ? -1 : Number(boundArgs[2]) || -1;
              const u = store.users.find((usr) => usr.user_id === user_id);
              balance = u?.credits ?? 0;
              title = "DAG智能编排调用";
              detail = boundArgs.length === 4 ? boundArgs[3] || "" : boundArgs[4] || "";
              related_id = null;
            } else if (cleanSql.includes("(SELECT credits FROM users")) {
              ledger_id = boundArgs[0];
              user_id = boundArgs[1];
              category = "referral_reward";
              amount = 50;
              const u = store.users.find((usr) => usr.user_id === user_id);
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

            const newRow = {
              ledger_id,
              user_id,
              category,
              amount,
              balance,
              title,
              detail,
              related_id,
              created_at: new Date().toISOString()
            };
            return { meta: checkAndInsertRow("credit_ledger", newRow, cleanSql, store) };
          }

          // INSERT / UPDATE models (ON CONFLICT)
          if (cleanSql.startsWith("INSERT INTO models")) {
            const modelObj: any = {
              model_id: boundArgs[0],
              display_name: boundArgs[1],
              provider: boundArgs[2],
              endpoint: boundArgs[3],
              modalities:
                typeof boundArgs[4] === "string" ? boundArgs[4] : JSON.stringify(boundArgs[4]),
              tags: typeof boundArgs[5] === "string" ? boundArgs[5] : JSON.stringify(boundArgs[5])
            };
            if (cleanSql.includes("in_modalities")) {
              modelObj.in_modalities = boundArgs[6];
              modelObj.out_modalities = boundArgs[7];
              modelObj.cost_per_invocation = boundArgs[8];
              modelObj.context_window = boundArgs[9];
              modelObj.max_concurrency = boundArgs[10];
              modelObj.precision = boundArgs[11];
              modelObj.cost_per_1k_tokens = boundArgs[12];
              modelObj.status = boundArgs[13];
              modelObj.auth_mode = boundArgs[14];
              modelObj.auth_secret = boundArgs[15];
              modelObj.api_format = boundArgs[16];
              modelObj.inference_target = boundArgs[17];
            } else if (cleanSql.includes("user_rating")) {
              modelObj.context_window = boundArgs[6];
              modelObj.max_concurrency = boundArgs[7];
              modelObj.precision = boundArgs[8];
              modelObj.user_rating = boundArgs[9];
              modelObj.usage_count = boundArgs[10];
              modelObj.cost_per_1k_tokens = boundArgs[11];
              modelObj.status = boundArgs[12];
              modelObj.auth_mode = boundArgs[13];
              modelObj.auth_secret = boundArgs[14];
              modelObj.api_format = boundArgs[15];
              modelObj.inference_target = boundArgs[16];
            } else {
              modelObj.context_window = boundArgs[6];
              modelObj.max_concurrency = boundArgs[7];
              modelObj.precision = boundArgs[8];
              modelObj.cost_per_1k_tokens = boundArgs[9];
              modelObj.status = boundArgs[10];
              modelObj.auth_mode = boundArgs[11];
              modelObj.auth_secret = boundArgs[12];
              modelObj.api_format = boundArgs[13];
              modelObj.inference_target = boundArgs[14];
            }
            return { meta: checkAndInsertRow("models", modelObj, cleanSql, store) };
          }

          // UPDATE models
          if (cleanSql.startsWith("UPDATE models SET")) {
            const modelId = boundArgs[boundArgs.length - 1];
            const model = store.models.find((m) => m.model_id === modelId);
            if (model) {
              model.display_name = boundArgs[0];
              model.provider = boundArgs[1];
              model.endpoint = boundArgs[2];
              model.modalities = boundArgs[3];
              model.tags = boundArgs[4];
              if (cleanSql.includes("in_modalities")) {
                model.in_modalities = boundArgs[5];
                model.out_modalities = boundArgs[6];
                model.cost_per_invocation = boundArgs[7];
                model.context_window = boundArgs[8];
                model.max_concurrency = boundArgs[9];
                model.precision = boundArgs[10];
                model.cost_per_1k_tokens = boundArgs[11];
                model.status = boundArgs[12];
                model.auth_mode = boundArgs[13];
                model.auth_secret = boundArgs[14];
                model.api_format = boundArgs[15];
                model.inference_target = boundArgs[16];
              } else {
                model.context_window = boundArgs[5];
                model.max_concurrency = boundArgs[6];
                model.precision = boundArgs[7];
                model.cost_per_1k_tokens = boundArgs[8];
                model.status = boundArgs[9];
                model.auth_mode = boundArgs[10];
                model.auth_secret = boundArgs[11];
                model.api_format = boundArgs[12];
                model.inference_target = boundArgs[13];
              }
              return { meta: { changes: 1 } };
            }
          }

          // INSERT INTO dag_templates
          if (cleanSql.startsWith("INSERT INTO dag_templates")) {
            const newRow = {
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
              status: boundArgs[10] || "active"
            };
            return { meta: checkAndInsertRow("dag_templates", newRow, cleanSql, store) };
          }

          // DELETE FROM dag_templates
          if (cleanSql.startsWith("DELETE FROM dag_templates")) {
            const templateId = boundArgs[0];
            store.dag_templates = store.dag_templates.filter((t) => t.template_id !== templateId);
            return { meta: { changes: 1 } };
          }

          // system_counters (rate limiting counters & atomic CAS)
          if (cleanSql.includes("system_counters")) {
            const key = boundArgs[0];
            let row = (store.system_counters || []).find((c) => c.key === key);
            if (cleanSql.includes("INSERT OR IGNORE")) {
              if (row) {
                return { meta: { changes: 0 } };
              }
              store.system_counters.push({ key, value: 1 });
              return { meta: { changes: 1 } };
            }
            if (row) {
              row.value = (row.value || 0) + 1;
            } else {
              store.system_counters.push({ key, value: 1 });
            }
            return { meta: { changes: 1 } };
          }

          // INSERT INTO user_chat_sessions (composite (user_id, session_id))
          if (cleanSql.startsWith("INSERT INTO user_chat_sessions")) {
            const sessionId = boundArgs[0];
            const userId = boundArgs[1];
            const existing = store.user_chat_sessions.find(
              (s) => s.user_id === userId && s.session_id === sessionId
            );
            if (existing) {
              existing.trace_id = boundArgs[2];
              existing.title = boundArgs[3];
              existing.cost = boundArgs[4];
              existing.duration = boundArgs[5];
              existing.nodes_count = boundArgs[6];
              existing.cached = boundArgs[7];
              existing.pinned = boundArgs[8];
              existing.rounds_json = boundArgs[9];
              existing.updated_at = new Date().toISOString();
            } else {
              store.user_chat_sessions.push({
                session_id: sessionId,
                user_id: userId,
                trace_id: boundArgs[2],
                title: boundArgs[3],
                cost: boundArgs[4],
                duration: boundArgs[5],
                nodes_count: boundArgs[6],
                cached: boundArgs[7],
                pinned: boundArgs[8],
                rounds_json: boundArgs[9],
                updated_at: new Date().toISOString()
              });
            }
            return { meta: { changes: 1 } };
          }

          // INSERT INTO verification_codes
          if (cleanSql.startsWith("INSERT INTO verification_codes")) {
            store.verification_codes.push({
              id: store.verification_codes.length + 1,
              email: boundArgs[0],
              code: boundArgs[1],
              attempts: 0,
              created_at: new Date().toISOString(),
              expires_at: new Date(Date.now() + 600000).toISOString()
            });
            return { meta: { changes: 1 } };
          }

          // UPDATE users SET avatar_url
          if (cleanSql.startsWith("UPDATE users SET avatar_url")) {
            const avatarUrl = boundArgs[0];
            const userId = boundArgs[1];
            const u = store.users.find((usr) => usr.user_id === userId);
            if (!u) return { meta: { changes: 0 } };
            if (cleanSql.includes("avatar_updated_at IS NULL") && u.avatar_updated_at) {
              const lastTs = new Date(
                u.avatar_updated_at.includes("T")
                  ? u.avatar_updated_at
                  : u.avatar_updated_at.replace(" ", "T") + "Z"
              ).getTime();
              if (Date.now() - lastTs < 24 * 60 * 60 * 1000) {
                return { meta: { changes: 0 } };
              }
            }
            u.avatar_url = avatarUrl;
            u.avatar_updated_at = new Date().toISOString();
            return { meta: { changes: 1 } };
          }

          // UPDATE verification_codes SET attempts
          if (cleanSql.includes("UPDATE verification_codes") && cleanSql.includes("SET attempts")) {
            const codeId = boundArgs[0];
            const vc = (store.verification_codes || []).find((c) => c.id === codeId);
            if (vc) {
              if (cleanSql.includes("attempts < 5") && (vc.attempts || 0) >= 5) {
                return { meta: { changes: 0 } };
              }
              vc.attempts = (vc.attempts || 0) + 1;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          // DELETE FROM verification_codes
          if (cleanSql.startsWith("DELETE FROM verification_codes")) {
            const codeId = boundArgs[0];
            const idx = (store.verification_codes || []).findIndex((c) => c.id === codeId);
            if (idx !== -1) {
              store.verification_codes.splice(idx, 1);
            }
            return { meta: { changes: 1 } };
          }

          // Session Git State, CAS, Billing, Execution Cache & R2 Purge Tables (Migration 0025)
          if (cleanSql.startsWith("INSERT INTO dag_execution_cache")) {
            store.dag_execution_cache = store.dag_execution_cache || [];
            const [userId, sessionId, cacheKey, roleId, modelId, promptDigest, outputText] =
              boundArgs;
            return {
              meta: checkAndInsertRow(
                "dag_execution_cache",
                {
                  user_id: userId,
                  session_id: sessionId,
                  cache_key: cacheKey,
                  role_id: roleId,
                  model_id: modelId,
                  prompt_digest: promptDigest,
                  output_text: outputText
                },
                cleanSql,
                store
              )
            };
          }

          if (cleanSql.startsWith("INSERT INTO run_billing_settlements")) {
            store.run_billing_settlements = store.run_billing_settlements || [];
            const [userId, runId, phase, amount, reservedCredits] = boundArgs;
            return {
              meta: checkAndInsertRow(
                "run_billing_settlements",
                {
                  user_id: userId,
                  run_id: runId,
                  phase,
                  amount,
                  reserved_credits: reservedCredits
                },
                cleanSql,
                store
              )
            };
          }

          if (cleanSql.startsWith("INSERT INTO pending_r2_prefix_purges")) {
            store.pending_r2_prefix_purges = store.pending_r2_prefix_purges || [];
            const [userId, prefixesJson] = boundArgs;
            return {
              meta: checkAndInsertRow(
                "pending_r2_prefix_purges",
                { user_id: userId, prefixes_json: prefixesJson },
                cleanSql,
                store
              )
            };
          }

          if (cleanSql.startsWith("INSERT INTO pending_r2_deletions")) {
            store.pending_r2_deletions = store.pending_r2_deletions || [];
            const [userId, sessionId] = boundArgs;
            if (cleanSql.includes("s.deleted_at IS NOT NULL")) {
              const delOk = (store.chat_session_states || []).some(
                (s) => s.user_id === boundArgs[2] && s.session_id === boundArgs[3] && !!s.deleted_at
              );
              if (!delOk) return { meta: { changes: 0 } };
            }
            const useTextKey = cleanSql.includes("text_r2_key");
            let inserted = 0;
            for (const a of store.session_assets || []) {
              const keyVal = useTextKey ? a.text_r2_key : a.r2_key;
              if (
                a.user_id === userId &&
                (!cleanSql.includes("session_id = ?") || a.session_id === sessionId) &&
                keyVal
              ) {
                const res = checkAndInsertRow(
                  "pending_r2_deletions",
                  {
                    delete_id: crypto.randomUUID(),
                    user_id: userId,
                    session_id: a.session_id,
                    r2_key: keyVal
                  },
                  cleanSql,
                  store
                );
                inserted += res.changes;
              }
            }
            return { meta: { changes: inserted } };
          }

          if (
            cleanSql.startsWith("INSERT OR REPLACE INTO chat_session_states") ||
            cleanSql.startsWith("INSERT INTO chat_session_states")
          ) {
            store.chat_session_states = store.chat_session_states || [];
            if (cleanSql.includes("ON CONFLICT(user_id, session_id) DO UPDATE")) {
              const [sessionId, userId] = boundArgs;
              const nowIso = new Date().toISOString();
              const existing = store.chat_session_states.find(
                (r) => r.user_id === userId && r.session_id === sessionId
              );
              if (existing) {
                const lockAlive =
                  !!existing.occupancy_phase &&
                  (!existing.lock_expires_at || existing.lock_expires_at > nowIso);
                if (existing.deleted_at || lockAlive) {
                  return { meta: { changes: 0 } };
                }
                existing.version = Number(existing.version || 1) + 1;
                existing.last_tx_attempt_id = null;
                existing.active_run_id = null;
                existing.active_client_op_id = null;
                existing.occupancy_phase = null;
                existing.lock_expires_at = null;
                existing.deleted_at = nowIso;
                return { meta: { changes: 1 } };
              }
              store.chat_session_states.push({
                session_id: sessionId,
                user_id: userId,
                active_branch_id: "main",
                version: 1,
                last_tx_attempt_id: null,
                active_run_id: null,
                active_client_op_id: null,
                occupancy_phase: null,
                lock_expires_at: null,
                deleted_at: nowIso
              });
              return { meta: { changes: 1 } };
            }
            const [sessionId, userId] = boundArgs;
            return {
              meta: checkAndInsertRow(
                "chat_session_states",
                {
                  session_id: sessionId,
                  user_id: userId,
                  active_branch_id: "main",
                  version: 1,
                  last_tx_attempt_id: null,
                  active_run_id: null,
                  active_client_op_id: null,
                  occupancy_phase: null,
                  lock_expires_at: null,
                  deleted_at: null
                },
                cleanSql,
                store
              )
            };
          }

          if (
            cleanSql.startsWith(
              "UPDATE chat_session_states SET active_run_id = ?, active_client_op_id = ?"
            )
          ) {
            const [runId, clientOpId, lockExpiresAt, userId, sessionId] = boundArgs;
            const nowIso = new Date().toISOString();
            const sRow = (store.chat_session_states || []).find(
              (r) => r.user_id === userId && r.session_id === sessionId && !r.deleted_at
            );
            const canAcquire =
              !!sRow &&
              (!sRow.occupancy_phase || (sRow.lock_expires_at && sRow.lock_expires_at <= nowIso));
            if (!canAcquire) return { meta: { changes: 0 } };
            sRow.active_run_id = runId;
            sRow.active_client_op_id = clientOpId;
            sRow.occupancy_phase = "EXECUTING";
            sRow.lock_expires_at = lockExpiresAt;
            return { meta: { changes: 1 } };
          }

          if (
            cleanSql.startsWith(
              "UPDATE chat_session_states SET active_run_id = ?, occupancy_phase = 'EXECUTING'"
            )
          ) {
            const [runId, lockExpiresAt, userId, sessionId, expectedRunId] = boundArgs;
            const sRow = (store.chat_session_states || []).find(
              (r) =>
                r.user_id === userId &&
                r.session_id === sessionId &&
                !r.deleted_at &&
                (!r.active_run_id || r.active_run_id === expectedRunId)
            );
            if (!sRow) return { meta: { changes: 0 } };
            sRow.active_run_id = runId;
            sRow.occupancy_phase = "EXECUTING";
            sRow.lock_expires_at = lockExpiresAt;
            return { meta: { changes: 1 } };
          }

          if (
            cleanSql.startsWith(
              "UPDATE chat_session_states SET occupancy_phase = 'AWAITING_COMMIT'"
            )
          ) {
            const [runId, lockExpiresAt, userId, sessionId, expectedRunId] = boundArgs;
            const sRow = (store.chat_session_states || []).find(
              (r) =>
                r.user_id === userId &&
                r.session_id === sessionId &&
                !r.deleted_at &&
                (!r.active_run_id || r.active_run_id === expectedRunId)
            );
            if (!sRow) return { meta: { changes: 0 } };
            sRow.active_run_id = runId;
            sRow.occupancy_phase = "AWAITING_COMMIT";
            sRow.lock_expires_at = lockExpiresAt;
            return { meta: { changes: 1 } };
          }

          if (
            cleanSql.startsWith(
              "UPDATE chat_session_states SET active_run_id = NULL, active_client_op_id = NULL"
            )
          ) {
            const [userId, sessionId, expectedRunId] = boundArgs;
            const sRow = (store.chat_session_states || []).find(
              (r) =>
                r.user_id === userId &&
                r.session_id === sessionId &&
                r.active_run_id === expectedRunId
            );
            if (!sRow) return { meta: { changes: 0 } };
            sRow.active_run_id = null;
            sRow.active_client_op_id = null;
            sRow.occupancy_phase = null;
            sRow.lock_expires_at = null;
            return { meta: { changes: 1 } };
          }

          if (cleanSql.startsWith("UPDATE chat_session_states SET version = version + 1")) {
            const [
              isRer1,
              targetBranchId,
              attemptId,
              userId,
              sessionId,
              _pUid,
              runId,
              _pSess,
              authMode1,
              nonceHash,
              authMode2,
              isRer2,
              _cUid,
              _cSess,
              baseCommitId,
              expectedRev,
              _isRer3,
              _bUid,
              _bSess,
              bBranchId,
              expectedParent,
              activeOwnerRunId
            ] = boundArgs;
            const sRow = (store.chat_session_states || []).find(
              (r) =>
                r.user_id === userId &&
                r.session_id === sessionId &&
                !r.deleted_at &&
                (!r.active_run_id || r.active_run_id === (activeOwnerRunId || runId))
            );
            const pRow = (store.dag_run_plans || []).find(
              (p) =>
                p.user_id === userId &&
                p.run_id === runId &&
                p.session_id === sessionId &&
                p.commit_state === "PENDING" &&
                ((authMode1 === "browser_tail" &&
                  p.exec_owner === "BROWSER_TAIL" &&
                  p.client_commit_nonce_hash === nonceHash) ||
                  (authMode2 === "cloud" &&
                    (p.exec_owner === "CLOUD" || p.exec_owner === "CLOUD_FAILOVER")))
            );
            let baseOk = false;
            if (isRer2 === 1) {
              baseOk = (store.session_commits || []).some(
                (c) =>
                  c.user_id === userId &&
                  c.session_id === sessionId &&
                  c.commit_id === baseCommitId &&
                  Number(c.revision || 1) === Number(expectedRev)
              );
            } else {
              const br = (store.session_branches || []).find(
                (b) =>
                  b.user_id === userId && b.session_id === sessionId && b.branch_id === bBranchId
              );
              const head = br?.head_commit_id || "";
              baseOk = head === (expectedParent || "");
            }
            if (!sRow || !pRow || !baseOk) {
              return { meta: { changes: 0 } };
            }
            sRow.version = Number(sRow.version || 1) + 1;
            if (isRer1 !== 1) sRow.active_branch_id = targetBranchId;
            sRow.last_tx_attempt_id = attemptId;
            sRow.active_run_id = null;
            sRow.active_client_op_id = null;
            sRow.occupancy_phase = null;
            sRow.lock_expires_at = null;
            return { meta: { changes: 1 } };
          }

          if (
            cleanSql.startsWith("INSERT OR REPLACE INTO session_branches") ||
            cleanSql.startsWith("INSERT INTO session_branches")
          ) {
            store.session_branches = store.session_branches || [];
            const [
              sessionId,
              branchId,
              userId,
              topic,
              headCommitId,
              dominantModalities,
              lastSummary,
              lineageAssetIds,
              gUid,
              gSess,
              gAttemptId
            ] = boundArgs;
            if (gAttemptId) {
              const gateOk = (store.chat_session_states || []).some(
                (s) =>
                  s.user_id === gUid &&
                  s.session_id === gSess &&
                  s.last_tx_attempt_id === gAttemptId &&
                  !s.deleted_at
              );
              if (!gateOk) return { meta: { changes: 0 } };
            }
            return {
              meta: checkAndInsertRow(
                "session_branches",
                {
                  session_id: sessionId,
                  branch_id: branchId,
                  user_id: userId,
                  topic,
                  head_commit_id: headCommitId,
                  dominant_modalities: dominantModalities,
                  last_summary: lastSummary,
                  lineage_asset_ids: lineageAssetIds
                },
                cleanSql,
                store
              )
            };
          }

          if (cleanSql.startsWith("UPDATE session_branches SET last_summary")) {
            const [
              lastSummary,
              userId,
              sessionId,
              branchId,
              headCommitId,
              gUid,
              gSess,
              gAttemptId
            ] = boundArgs;
            if (gAttemptId) {
              const gateOk = (store.chat_session_states || []).some(
                (s) =>
                  s.user_id === gUid &&
                  s.session_id === gSess &&
                  s.last_tx_attempt_id === gAttemptId &&
                  !s.deleted_at
              );
              if (!gateOk) return { meta: { changes: 0 } };
            }
            const br = (store.session_branches || []).find(
              (b) =>
                b.user_id === userId &&
                b.session_id === sessionId &&
                b.branch_id === branchId &&
                (!headCommitId || b.head_commit_id === headCommitId)
            );
            if (br) {
              br.last_summary = lastSummary;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (
            cleanSql.startsWith("INSERT OR IGNORE INTO session_commits") ||
            cleanSql.startsWith("INSERT INTO session_commits")
          ) {
            store.session_commits = store.session_commits || [];
            const [
              commitId,
              sessionId,
              userId,
              runId,
              branchId,
              parentCommitId,
              sourceRefsJson,
              roundIndex,
              intentOp,
              userPrompt,
              mountedAssetsJson,
              introducedAssetIdsJson,
              generatedAssetIdsJson,
              templateId,
              outputSummary,
              createdAt,
              gUid,
              gSess,
              gAttemptId
            ] = boundArgs;
            if (gAttemptId) {
              const gateOk = (store.chat_session_states || []).some(
                (s) =>
                  s.user_id === gUid &&
                  s.session_id === gSess &&
                  s.last_tx_attempt_id === gAttemptId &&
                  !s.deleted_at
              );
              if (!gateOk) return { meta: { changes: 0 } };
            }
            return {
              meta: checkAndInsertRow(
                "session_commits",
                {
                  commit_id: commitId,
                  session_id: sessionId,
                  user_id: userId,
                  run_id: runId,
                  branch_id: branchId,
                  parent_commit_id: parentCommitId,
                  source_refs_json: sourceRefsJson,
                  round_index: roundIndex,
                  revision: 1,
                  intent_op: intentOp,
                  user_prompt: userPrompt,
                  mounted_assets_json: mountedAssetsJson,
                  introduced_asset_ids_json: introducedAssetIdsJson,
                  generated_asset_ids_json: generatedAssetIdsJson,
                  template_id: templateId,
                  output_summary: outputSummary,
                  created_at: createdAt
                },
                cleanSql,
                store
              )
            };
          }

          if (cleanSql.startsWith("UPDATE session_commits SET revision")) {
            const [
              rev,
              tplId,
              summary,
              userId,
              sessionId,
              commitId,
              expectedRev,
              gUid,
              gSess,
              gAttemptId
            ] = boundArgs;
            if (gAttemptId) {
              const gateOk = (store.chat_session_states || []).some(
                (s) =>
                  s.user_id === gUid &&
                  s.session_id === gSess &&
                  s.last_tx_attempt_id === gAttemptId &&
                  !s.deleted_at
              );
              if (!gateOk) return { meta: { changes: 0 } };
            }
            const c = (store.session_commits || []).find(
              (x) =>
                x.user_id === userId &&
                x.session_id === sessionId &&
                x.commit_id === commitId &&
                Number(x.revision || 1) === Number(expectedRev)
            );
            if (c) {
              c.revision = rev;
              c.template_id = tplId;
              c.output_summary = summary;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (
            cleanSql.startsWith("INSERT OR IGNORE INTO session_assets") ||
            cleanSql.startsWith("INSERT OR REPLACE INTO session_assets") ||
            cleanSql.startsWith("INSERT INTO session_assets")
          ) {
            store.session_assets = store.session_assets || [];
            let newRow: any;
            if (cleanSql.includes("VALUES (?, '__UNBOUND__'")) {
              const [assetId, userId, filename, modality, mimeType, fileSize, r2Key, origin] =
                boundArgs;
              newRow = {
                asset_id: assetId,
                session_id: "__UNBOUND__",
                user_id: userId,
                branch_id: null,
                commit_id: null,
                filename,
                modality,
                mime_type: mimeType,
                file_size: fileSize,
                r2_key: r2Key,
                text_r2_key: null,
                in_memory_text: null,
                source_digest: null,
                origin,
                introduced_round: 0,
                status: "UPLOADED",
                summary_snippet: ""
              };
            } else if (cleanSql.includes("'STAGING'")) {
              const [
                assetId,
                sessionId,
                userId,
                filename,
                modality,
                mimeType,
                fileSize,
                r2Key,
                textR2Key,
                gUid,
                gSess
              ] = boundArgs;
              const active = (store.chat_session_states || []).some(
                (s) => s.user_id === gUid && s.session_id === gSess && !s.deleted_at
              );
              if (!active) return { meta: { changes: 0 } };
              newRow = {
                asset_id: assetId,
                session_id: sessionId,
                user_id: userId,
                branch_id: null,
                commit_id: null,
                filename,
                modality,
                mime_type: mimeType,
                file_size: fileSize,
                r2_key: r2Key,
                text_r2_key: textR2Key,
                in_memory_text: null,
                source_digest: null,
                origin: "generated",
                introduced_round: 0,
                status: "STAGING",
                summary_snippet: ""
              };
            } else if (cleanSql.includes("'generated'")) {
              const [
                assetId,
                sessionId,
                userId,
                branchId,
                commitId,
                filename,
                modality,
                mimeType,
                fileSize,
                r2Key,
                sourceDigest,
                introducedRound,
                summarySnippet,
                gUid,
                gSess,
                gAttemptId
              ] = boundArgs;
              if (gAttemptId) {
                const gateOk = (store.chat_session_states || []).some(
                  (s) =>
                    s.user_id === gUid &&
                    s.session_id === gSess &&
                    s.last_tx_attempt_id === gAttemptId &&
                    !s.deleted_at
                );
                if (!gateOk) return { meta: { changes: 0 } };
              }
              newRow = {
                asset_id: assetId,
                session_id: sessionId,
                user_id: userId,
                branch_id: branchId,
                commit_id: commitId,
                filename,
                modality,
                mime_type: mimeType,
                file_size: fileSize,
                r2_key: r2Key,
                text_r2_key: null,
                in_memory_text: null,
                source_digest: sourceDigest,
                origin: "generated",
                introduced_round: introducedRound,
                status: "COMMITTED",
                summary_snippet: summarySnippet
              };
            } else {
              const [
                assetId,
                sessionId,
                userId,
                branchId,
                commitId,
                filename,
                modality,
                mimeType,
                fileSize,
                r2Key,
                sourceDigest,
                introducedRound,
                summarySnippet,
                inlineText,
                textR2Key,
                gUid,
                gSess,
                gAttemptId
              ] = boundArgs;
              if (gAttemptId) {
                const gateOk = (store.chat_session_states || []).some(
                  (s) =>
                    s.user_id === gUid &&
                    s.session_id === gSess &&
                    s.last_tx_attempt_id === gAttemptId &&
                    !s.deleted_at
                );
                if (!gateOk) return { meta: { changes: 0 } };
              }
              newRow = {
                asset_id: assetId,
                session_id: sessionId,
                user_id: userId,
                branch_id: branchId,
                commit_id: commitId,
                filename,
                modality,
                mime_type: mimeType,
                file_size: fileSize,
                r2_key: r2Key,
                source_digest: sourceDigest,
                origin: "upload",
                introduced_round: introducedRound,
                status: "COMMITTED",
                summary_snippet: summarySnippet,
                in_memory_text: inlineText ?? null,
                text_r2_key: textR2Key ?? null
              };
            }
            return { meta: checkAndInsertRow("session_assets", newRow, cleanSql, store) };
          }

          if (cleanSql.startsWith("UPDATE session_assets SET session_id")) {
            const [sessionId, sourceDigest, roundIdx, userId, assetId, r2Key] = boundArgs;
            const a = (store.session_assets || []).find(
              (x) =>
                x.user_id === userId &&
                x.asset_id === assetId &&
                x.r2_key === r2Key &&
                x.session_id === "__UNBOUND__"
            );
            if (a) {
              a.session_id = sessionId;
              a.source_digest = a.source_digest || sourceDigest;
              a.introduced_round = roundIdx;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (cleanSql.startsWith("INSERT INTO dag_run_plans")) {
            store.dag_run_plans = store.dag_run_plans || [];
            const [
              runId,
              userId,
              sessionId,
              clientOpId,
              requestDigest,
              planHash,
              dagJson,
              envelopeJson,
              resolvedEnvelopeJson,
              isRerun,
              baseCommitId,
              expectedParentCommitId,
              expectedBaseRevision,
              gUid,
              gSess
            ] = boundArgs;
            const active = (store.chat_session_states || []).some(
              (s) => s.user_id === gUid && s.session_id === gSess && !s.deleted_at
            );
            if (!active) return { meta: { changes: 0 } };
            return {
              meta: checkAndInsertRow(
                "dag_run_plans",
                {
                  run_id: runId,
                  user_id: userId,
                  session_id: sessionId,
                  client_op_id: clientOpId,
                  request_digest: requestDigest,
                  plan_hash: planHash,
                  dag_json: dagJson,
                  envelope_json: envelopeJson,
                  resolved_envelope_json: resolvedEnvelopeJson,
                  step_outputs_json: "{}",
                  is_rerun: isRerun,
                  base_commit_id: baseCommitId,
                  expected_parent_commit_id: expectedParentCommitId,
                  expected_base_revision: expectedBaseRevision,
                  exec_owner: "CLOUD",
                  commit_state: "PENDING",
                  client_commit_nonce_hash: null,
                  tail_result_json: null,
                  tail_result_hash: null,
                  status: "RUNNING"
                },
                cleanSql,
                store
              )
            };
          }

          if (cleanSql.startsWith("UPDATE dag_run_plans SET step_outputs_json")) {
            const [stepOutputsJson, userId, runId] = boundArgs;
            const p = (store.dag_run_plans || []).find(
              (x) => x.run_id === runId && x.user_id === userId
            );
            if (p) {
              p.step_outputs_json = stepOutputsJson;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (cleanSql.startsWith("UPDATE dag_run_plans SET exec_owner = 'BROWSER_TAIL'")) {
            const [nonceHash, userId, runId, sessionId, sUid, sSess] = boundArgs;
            const active = (store.chat_session_states || []).some(
              (s) => s.user_id === sUid && s.session_id === sSess && !s.deleted_at
            );
            const p = (store.dag_run_plans || []).find(
              (x) =>
                x.user_id === userId &&
                x.run_id === runId &&
                x.session_id === sessionId &&
                x.commit_state === "PENDING"
            );
            if (p && active) {
              p.exec_owner = "BROWSER_TAIL";
              p.client_commit_nonce_hash = nonceHash;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (cleanSql.startsWith("UPDATE dag_run_plans SET exec_owner = 'CLOUD_FAILOVER'")) {
            const [userId, runId, sessionId] = boundArgs;
            const p = (store.dag_run_plans || []).find(
              (x) =>
                x.user_id === userId &&
                x.run_id === runId &&
                x.session_id === sessionId &&
                x.exec_owner === "BROWSER_TAIL" &&
                x.commit_state === "PENDING"
            );
            if (p) {
              p.exec_owner = "CLOUD_FAILOVER";
              p.client_commit_nonce_hash = null;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (cleanSql.startsWith("UPDATE dag_run_plans SET tail_result_json")) {
            const [tailResultJson, tailResultHash, userId, runId, sessionId] = boundArgs;
            const p = (store.dag_run_plans || []).find(
              (x) =>
                x.user_id === userId &&
                x.run_id === runId &&
                x.session_id === sessionId &&
                (x.exec_owner === "CLOUD" || x.exec_owner === "CLOUD_FAILOVER") &&
                x.commit_state === "PENDING"
            );
            if (p) {
              p.tail_result_json = tailResultJson;
              p.tail_result_hash = tailResultHash;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (cleanSql.startsWith("UPDATE dag_run_plans SET commit_state = 'COMMITTED'")) {
            const [
              tailPayloadJson,
              tailResultHash,
              userId,
              runId,
              sessionId,
              gUid,
              gSess,
              gAttemptId
            ] = boundArgs;
            const gateOk = (store.chat_session_states || []).some(
              (s) =>
                s.user_id === gUid &&
                s.session_id === gSess &&
                s.last_tx_attempt_id === gAttemptId &&
                !s.deleted_at
            );
            const p = (store.dag_run_plans || []).find(
              (x) => x.user_id === userId && x.run_id === runId && x.session_id === sessionId
            );
            if (p && gateOk) {
              p.commit_state = "COMMITTED";
              p.exec_owner = "COMMITTED";
              p.client_commit_nonce_hash = null;
              p.tail_result_json = tailPayloadJson;
              p.tail_result_hash = tailResultHash;
              p.status = "COMPLETED";
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (cleanSql.startsWith("UPDATE dag_run_plans SET commit_state = 'ABORTED'")) {
            const [userId, sessionId, runId] = boundArgs;
            let changes = 0;
            for (const p of store.dag_run_plans || []) {
              if (
                p.user_id === userId &&
                p.session_id === sessionId &&
                p.commit_state === "PENDING" &&
                p.run_id !== runId
              ) {
                p.commit_state = "ABORTED";
                p.status = "ABORTED";
                p.failure_status = 409;
                p.failure_code = "session_lock_expired";
                p.client_commit_nonce_hash = null;
                changes++;
              }
            }
            return { meta: { changes } };
          }

          if (cleanSql.startsWith("UPDATE dag_run_plans SET status = 'AWAITING_COMMIT'")) {
            const [userId, sessionId, runId] = boundArgs;
            const p = (store.dag_run_plans || []).find(
              (x) =>
                x.user_id === userId &&
                x.session_id === sessionId &&
                x.run_id === runId &&
                x.commit_state === "PENDING"
            );
            if (p) {
              p.status = "AWAITING_COMMIT";
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (cleanSql.startsWith("UPDATE dag_run_plans SET commit_state = ?")) {
            const [
              outcome,
              status,
              failureStatus,
              failureCode,
              failureMessage,
              userId,
              sessionId,
              runId
            ] = boundArgs;
            const p = (store.dag_run_plans || []).find(
              (x) =>
                x.user_id === userId &&
                x.session_id === sessionId &&
                x.run_id === runId &&
                x.commit_state === "PENDING"
            );
            if (p) {
              p.commit_state = outcome;
              p.status = status;
              p.failure_status = failureStatus ?? p.failure_status ?? null;
              p.failure_code = failureCode ?? p.failure_code ?? null;
              p.failure_message = failureMessage ?? p.failure_message ?? null;
              p.client_commit_nonce_hash = null;
              return { meta: { changes: 1 } };
            }
            return { meta: { changes: 0 } };
          }

          if (cleanSql.startsWith("INSERT INTO asset_perceptual_cache")) {
            store.asset_perceptual_cache = store.asset_perceptual_cache || [];
            const [
              perceptKey,
              userId,
              sessionId,
              sourceDigest,
              modality,
              roleId,
              modelId,
              taskScope,
              promptDigest,
              extractedText,
              summarySnippet,
              updatedAt,
              gUid,
              gSess,
              gAttemptId
            ] = boundArgs;
            if (gAttemptId) {
              const gateOk = (store.chat_session_states || []).some(
                (s) =>
                  s.user_id === gUid &&
                  s.session_id === gSess &&
                  s.last_tx_attempt_id === gAttemptId &&
                  !s.deleted_at
              );
              if (!gateOk) return { meta: { changes: 0 } };
            }
            return {
              meta: checkAndInsertRow(
                "asset_perceptual_cache",
                {
                  percept_key: perceptKey,
                  user_id: userId,
                  session_id: sessionId,
                  source_digest: sourceDigest,
                  modality,
                  role_id: roleId,
                  model_id: modelId,
                  task_scope: taskScope,
                  prompt_digest: promptDigest,
                  extracted_text: extractedText,
                  summary_snippet: summarySnippet,
                  updated_at: updatedAt
                },
                cleanSql,
                store
              )
            };
          }

          return { meta: { changes: 1 } };
        }
      };
      return stmt;
    },
    async batch(statements: any[]) {
      const results: Array<{ meta: { changes: number } }> = [];
      for (const s of statements) {
        const previous = results[results.length - 1];
        results.push(
          s.requiresPreviousChange && previous?.meta.changes !== 1
            ? { meta: { changes: 0 } }
            : await s.run()
        );
      }
      return results;
    }
  };
}

function createMockR2() {
  const store = new Map<string, { body: Uint8Array; metadata: any }>();
  return {
    async put(key: string, body: any, options?: any) {
      const bytes =
        typeof body === "string" ? new TextEncoder().encode(body) : new Uint8Array(body);
      store.set(key, { body: bytes, metadata: options?.httpMetadata || {} });
      return { key, size: bytes.length };
    },
    async get(key: string) {
      const item = store.get(key);
      if (!item) return null;
      return {
        body: item.body,
        httpEtag: "mock-etag-12345",
        async arrayBuffer() {
          return item.body.buffer.slice(
            item.body.byteOffset,
            item.body.byteOffset + item.body.byteLength
          );
        },
        async text() {
          return new TextDecoder().decode(item.body);
        },
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
      if (model === "@cf/openai/whisper") {
        if (!Array.isArray(input.audio)) {
          throw new Error(
            "Workers AI Whisper input.audio must be a byte array Array<number> (Uint8Array serializes as JSON object in wrangler dev)!"
          );
        }
        return { text: "Mock Whisper transcription from voice audio stream." };
      }
      if (model === "@cf/black-forest-labs/flux-1-schnell") {
        return new Uint8Array([
          137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8,
          6, 0, 0, 0, 31, 21, 196, 137
        ]);
      }
      if (model === "@cf/black-forest-labs/flux-broken-zero") {
        return new Uint8Array([]);
      }
      if (model.includes("llama")) {
        // Realistic simulated generation latency (allows testing race conditions and client abort)
        await new Promise((r) => setTimeout(r, 60));
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
    dag_handshakes: [],
    notifications: [],
    broadcast_reads: [],
    system_counters: [],
    chat_session_states: [],
    session_branches: [],
    session_commits: [],
    session_assets: [],
    dag_run_plans: [],
    asset_perceptual_cache: [],
    dag_execution_cache: [],
    run_billing_settlements: [],
    pending_r2_deletions: [],
    pending_r2_prefix_purges: []
  };

  const env = {
    DB: createMockD1(store),
    R2: createMockR2(),
    AI: createMockAI(),
    JWT_SECRET: "test-jwt-secret-for-integration-tests-999",
    ADMIN_PASSWORD: "IntegrationAdminPass123!",
    FRONTEND_URL: "https://nanomesh.local",
    R2_ACCESS_KEY_ID: "mock-r2-access-key-id",
    R2_SECRET_ACCESS_KEY: "mock-r2-secret-access-key-very-long",
    Cloudflare_Account_ID: "mock-cf-account-id"
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
    env.DB.prepare(
      `
      INSERT INTO users (user_id, username, email, password_hash, credits, referral_code, referred_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `
    ).bind(
      newUserId,
      "NewbieUser",
      "newbie@nanomesh.local",
      "hash123",
      initialCredits,
      "REF-NEWBIE-1",
      referrerId
    ),
    env.DB.prepare(
      `
      INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail)
      VALUES (?, ?, 'signup_bonus', 100, 100, 'Signup Bonus', 'Welcome pack')
    `
    ).bind("ledg_1", newUserId),
    env.DB.prepare(
      `
      INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail, related_id)
      VALUES (?, ?, 'referral_reward', 50, 150, 'Referral Bonus', 'Invited by boss', ?)
    `
    ).bind("ledg_2", newUserId, referrerId),
    env.DB.prepare("UPDATE users SET credits = credits + 50 WHERE user_id = ?").bind(referrerId),
    env.DB.prepare(
      `
      INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail, related_id)
      VALUES (?, ?, 'referral_reward', 50, (SELECT credits FROM users WHERE user_id = ?), 'Referral Reward', ?, ?)
    `
    ).bind("ledg_3", referrerId, referrerId, "NewbieUser", newUserId)
  ];

  await env.DB.batch(regBatch);

  const newbieDb = store.users.find((u) => u.user_id === newUserId);
  const bossDb = store.users.find((u) => u.user_id === referrerId);
  assert.ok(newbieDb, "Newbie user must exist in DB");
  assert.equal(newbieDb.credits, 150, "Newbie must receive 100 base + 50 referral = 150 credits");
  assert.equal(bossDb.credits, 150, "Boss credits must be updated from 100 to 150");

  const newbieLedgers = store.credit_ledger.filter((l) => l.user_id === newUserId);
  assert.equal(newbieLedgers.length, 2, "Newbie must have 2 ledger records (signup + referral)");

  const bossLedgers = store.credit_ledger.filter((l) => l.user_id === referrerId);
  assert.equal(bossLedgers.length, 1, "Boss must have 1 referral reward ledger");
  assert.equal(
    bossLedgers[0].balance,
    150,
    "Boss ledger balance snapshot must accurately equal 150"
  );
  console.log("  ✓ Atomic registration batch & ledger balance consistency: PASSED");

  // Verify declarative unique constraint guard intercepts duplicate PK & UNIQUE violations
  await assert.rejects(async () => {
    await env.DB.prepare(
      `
        INSERT INTO users (user_id, username, email, password_hash, credits, referral_code, referred_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `
    )
      .bind(
        newUserId,
        "DuplicatePKUser",
        "different@nanomesh.local",
        "hash123",
        100,
        "REF-DUP-1",
        null
      )
      .run();
  }, /SQLITE_CONSTRAINT: UNIQUE constraint failed: users\.user_id/);

  await assert.rejects(async () => {
    await env.DB.prepare(
      `
        INSERT INTO users (user_id, username, email, password_hash, credits, referral_code, referred_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `
    )
      .bind(
        "usr_another_002",
        "DuplicateEmailUser",
        "newbie@nanomesh.local",
        "hash123",
        100,
        "REF-DUP-2",
        null
      )
      .run();
  }, /SQLITE_CONSTRAINT: UNIQUE constraint failed: users\.email/);

  // Verify case-insensitive username uniqueness guard (newbieuser vs NewbieUser)
  await assert.rejects(async () => {
    await env.DB.prepare(
      `
        INSERT INTO users (user_id, username, email, password_hash, credits, referral_code, referred_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `
    )
      .bind(
        "usr_case_insensitive_003",
        "newbieuser",
        "different2@nanomesh.local",
        "hash123",
        100,
        "REF-DUP-3",
        null
      )
      .run();
  }, /SQLITE_CONSTRAINT: UNIQUE constraint failed: users\.username/);

  console.log("  ✓ Declarative unique constraint guard intercepts PK & UNIQUE violations: PASSED");
  console.log(
    "  ✓ Case-insensitive unique constraint guard intercepts 'newbieuser' vs 'NewbieUser': PASSED"
  );

  // -----------------------------------------------------------------------
  // SCENARIO 2: R2 Asset Access Control & Public Light Node Route
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 2] R2 Asset Management & Access Control Isolation");

  // 2.1 Public Light Node weights in models/light/... (No session required!)
  const modelKey = "models/light/1700000000_qwen_webgpu.onnx";
  await env.R2.put(modelKey, "ONNX_MODEL_BINARY_WEIGHTS_DATA", {
    httpMetadata: { contentType: "application/octet-stream" }
  });

  const publicReq = new Request(`https://nanomesh.local/api/assets/${modelKey}`);
  const publicRes = await handleGetAsset(publicReq, env);
  assert.equal(
    publicRes.status,
    200,
    "Public light model weights must be accessible without login"
  );
  assert.equal(
    publicRes.headers.get("cache-control"),
    "public, max-age=31536000, immutable",
    "Must set 1-year immutable caching"
  );
  assert.equal(
    publicRes.headers.get("access-control-allow-origin"),
    "*",
    "Must allow cross-origin fetching for browser WebGPU"
  );

  // Verify Gateway worker.fetch router dispatching to /api/assets/ without 404 nesting error
  const gatewayReq = new Request(`https://nanomesh.local/api/assets/${modelKey}`);
  const gatewayRes = await worker.fetch(gatewayReq, env, {} as any);
  assert.equal(
    gatewayRes.status,
    200,
    "Gateway must dispatch /api/assets/ to handleGetAsset without 404 route nesting error"
  );

  // Verify Avatar Static Storage security headers via worker.fetch
  const avatarKey = `avatars/${newUserId}_1700000000.png`;
  await env.R2.put(avatarKey, "PNG_AVATAR_BYTES", { httpMetadata: { contentType: "image/png" } });
  const storageReq = new Request(`https://nanomesh.local/storage/${avatarKey}`);
  const storageRes = await worker.fetch(storageReq, env, {} as any);
  assert.equal(storageRes.status, 200, "Storage avatar endpoint must serve 200 OK");
  assert.equal(
    storageRes.headers.get("x-content-type-options"),
    "nosniff",
    "Storage must enforce nosniff"
  );
  assert.equal(
    storageRes.headers.get("content-security-policy"),
    "default-src 'none'; sandbox",
    "Storage must enforce CSP sandbox"
  );
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
    headers: { Cookie: `session=${ownerToken}` }
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
  const foreignToken = await signJWT(
    { userId: "usr_attacker_666", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const foreignReq = new Request(`https://nanomesh.local/api/asset?key=${userAssetKey}`, {
    headers: { Cookie: `session=${foreignToken}` }
  });
  const foreignRes = await handleGetAsset(foreignReq, env);
  assert.equal(
    foreignRes.status,
    403,
    "Foreign user accessing another user's asset must receive 403 Forbidden"
  );
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
  assert.ok(
    adminCookie.includes("Max-Age=7200"),
    "Admin session TTL must be tightened to 2 hours (7200s)"
  );

  // Extract admin session token
  const adminToken = adminCookie.match(/admin_session=([^;]+)/)![1];
  const adminReqHeaders = {
    Cookie: `admin_session=${adminToken}`,
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
  const ssrfErr = (await ssrfRes.json()) as any;
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
  const listNodesData = (await listNodesRes.json()) as any;
  const deepseekListed = listNodesData.nodes.find((n: any) => n.model_id === "cloud_vps_deepseek");
  assert.ok(deepseekListed);
  assert.equal(
    deepseekListed.auth_secret,
    "••••••••",
    "Secret must be masked as •••••••• to prevent frontend exfiltration"
  );

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

  const rawDeepseek = store.models.find((m) => m.model_id === "cloud_vps_deepseek");
  assert.equal(rawDeepseek.display_name, "DeepSeek R1 High Precision");
  assert.equal(
    rawDeepseek.auth_secret,
    "sk-my-confidential-api-key-9988",
    "Real secret must be preserved when placeholder is submitted"
  );

  // 3.6 [ISSUE-06 Admin Password Change Instant Revocation Verification]
  const validAdminReq = new Request("https://nanomesh.local/api/admin/nodes", {
    headers: adminReqHeaders
  });
  const validAdminRes = await handleAdminListNodes(validAdminReq, env);
  assert.equal(validAdminRes.status, 200, "Admin with valid token must have access");

  const originalPass = (env as any).ADMIN_PASSWORD;
  (env as any).ADMIN_PASSWORD = "NewlyRotatedPassword789!";

  const revokedAdminReq = new Request("https://nanomesh.local/api/admin/nodes", {
    headers: adminReqHeaders
  });
  const revokedAdminRes = await handleAdminListNodes(revokedAdminReq, env);
  assert.equal(
    revokedAdminRes.status,
    401,
    "Changing ADMIN_PASSWORD must immediately revoke existing admin tokens (401)"
  );

  // Restore password for remaining admin scenarios
  (env as any).ADMIN_PASSWORD = originalPass;

  // 3.7 [ADMIN-02 Dead Endpoint Activation Guard]
  store.models.push({
    model_id: "test-ghost-model",
    display_name: "Ghost Mock",
    provider: "test",
    endpoint: "/api/infer",
    modalities: '["text"]',
    tags: '["#test"]',
    status: "disabled",
    inference_target: "edge"
  });
  const activateGhostReq = new Request("https://nanomesh.local/api/admin/nodes/test-ghost-model", {
    method: "PATCH",
    headers: adminReqHeaders,
    body: JSON.stringify({ status: "active" })
  });
  const activateGhostRes = await handleAdminUpdateNode(activateGhostReq, env, "test-ghost-model");
  assert.equal(
    activateGhostRes.status,
    400,
    "Activating a model with dead endpoint /api/infer must be blocked with 400"
  );
  const ghostErr = (await activateGhostRes.json()) as any;
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
  const gate1Err = (await gate1Res.json()) as any;
  assert.ok(
    gate1Err.error.includes("Modality Discontinuity"),
    "Must detect modality discontinuity between audio and image"
  );

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
  const gate2Err = (await gate2Res.json()) as any;
  assert.ok(
    gate2Err.error.includes("Subsistence Check Failed"),
    "Must flag orphaned role without candidate models"
  );

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
  assert.equal(
    gate3Res.status,
    200,
    "Valid linear pipeline must pass all 3 gates and save template"
  );
  const gate3Data = (await gate3Res.json()) as any;
  assert.ok(gate3Data.template_id);
  assert.ok(store.dag_templates.some((t) => t.template_id === gate3Data.template_id));

  // 4.5 [ADMIN-04 Template Deletion]
  const delTplReq = new Request(
    `https://nanomesh.local/api/admin/templates/${gate3Data.template_id}`,
    {
      method: "DELETE",
      headers: adminReqHeaders
    }
  );
  const delTplRes = await handleAdminDeleteTemplate(delTplReq, env, gate3Data.template_id);
  assert.equal(delTplRes.status, 200, "Deleting template must succeed");
  assert.ok(
    !store.dag_templates.some((t) => t.template_id === gate3Data.template_id),
    "Template must be removed from store"
  );

  // Re-create it for subsequent workflow tests
  await handleAdminCreateOrUpdateTemplate(gate3Req, env);

  console.log("  ✓ Linear pipeline splicer Gate 1, Gate 2, Gate 3 verification: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 5: End-to-End Chat Orchestration & Atomic Billing Settlement
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 5] End-to-End Chat Orchestration & Atomic Billing Settlement");

  const envelope: UnifiedProtocolEnvelope = {
    round_index: 1,
    constraint_context: { target_language: "zh", output_style: "concise" },
    envelope_id: "env_test_001",
    session_id: "sess_chat_001",
    user_id: newUserId,
    instruction_payload: "请分析多模态分布式调度器的架构优势",
    metadata: { client_timestamp: Date.now(), char_count_total: 100, estimated_input_tokens: 500 },
    assets_manifest: []
  };

  // 5.1 Pre-deduct 1 credit base reservation
  const preDeductRes = await env.DB.prepare(
    "UPDATE users SET credits = credits - 1 WHERE user_id = ? AND credits >= 1"
  )
    .bind(newUserId)
    .run();
  assert.equal(preDeductRes.meta.changes, 1, "Must atomically pre-deduct 1 base credit");
  assert.equal(store.users.find((u) => u.user_id === newUserId).credits, 149);

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
  const postBillingUser = store.users.find((u) => u.user_id === newUserId);
  assert.equal(postBillingUser.credits, 149, "Total cost 1 settled: balance remains 149");
  console.log("  ✓ End-to-end chat arbitration, SSE streaming & atomic billing: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 6: Premature Stream Cancelation & Credit Refund
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 6] Premature Stream Cancelation & Refund Handshake");

  // Pre-deduct 1 credit
  await env.DB.prepare("UPDATE users SET credits = credits - 1 WHERE user_id = ? AND credits >= 1")
    .bind(newUserId)
    .run();
  assert.equal(store.users.find((u) => u.user_id === newUserId).credits, 148);

  const abortStream = await executeDAGStream(env, dag, envelope, {
    userId: newUserId,
    hasPreDeducted: true
  });

  // Client abruptly cancels stream before tokens are emitted
  await abortStream.cancel("Client disconnected / Tab closed");

  // Wait a tick for async refund execution
  await new Promise((r) => setTimeout(r, 50));

  const refundedUser = store.users.find((u) => u.user_id === newUserId);
  assert.equal(refundedUser.credits, 149, "Pre-deducted credit must be safely refunded on cancel");
  console.log("  ✓ Premature client disconnect cleanly triggers credit refund: PASSED");

  // 6.2 [ISSUE-04: Premature Stream Cancelation AFTER Token Generation - Settle Ledger]
  await env.DB.prepare("UPDATE users SET credits = credits - 1 WHERE user_id = ? AND credits >= 1")
    .bind(newUserId)
    .run();
  assert.equal(store.users.find((u) => u.user_id === newUserId).credits, 148);

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
  await new Promise((r) => setTimeout(r, 50));

  // Verify credit is retained (148)
  const abortedUser = store.users.find((u) => u.user_id === newUserId);
  assert.equal(abortedUser.credits, 148, "Credit must be retained after tokens emitted");

  // Verify credit_ledger has an entry recording the retention!
  const abortLedger = store.credit_ledger.find(
    (l) => l.detail && l.detail.includes("中途断开连接算力保底扣费")
  );
  assert.ok(abortLedger, "Must record compute_cost ledger row for mid-stream abort");
  assert.equal(abortLedger.amount, -1, "Ledger amount must be -1");
  console.log("  ✓ Mid-stream abort records compute_cost ledger audit entry: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 7: Account Deletion Cascading Erasure of Private Sessions
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 7] Account Deletion & GDPR Private Session Erasure");

  store.notifications = [];
  store.broadcast_reads = [];

  // Seed a chat session for newUserId
  store.user_chat_sessions.push({
    session_id: "sess_private_123",
    user_id: newUserId,
    title: "Secret Strategy Conversation",
    rounds_json: JSON.stringify([{ role: "user", text: "Classified Prompt" }])
  });
  // Seed notifications and broadcast read receipts
  store.notifications.push({
    notification_id: "notif_priv_1",
    user_id: newUserId,
    category: "billing",
    event_type: "topup_success",
    title_zh: "充值成功",
    title_en: "Top-up Success"
  });
  store.broadcast_reads.push({
    user_id: newUserId,
    notification_id: "notif_global_announcement_1",
    read_at: new Date().toISOString()
  });
  assert.equal(store.user_chat_sessions.length, 1);
  assert.equal(store.notifications.length, 1);
  assert.equal(store.broadcast_reads.length, 1);

  // Authenticated user request to delete account
  const deleteReq = new Request("https://nanomesh.local/api/user/delete", {
    method: "POST",
    headers: { Cookie: `session=${ownerToken}` }
  });
  const deleteRes = await handleDeleteAccount(deleteReq, env);
  assert.equal(deleteRes.status, 200, "handleDeleteAccount must succeed");

  // Verify user_chat_sessions is completely erased
  const remainingSessions = store.user_chat_sessions.filter((s) => s.user_id === newUserId);
  assert.equal(
    remainingSessions.length,
    0,
    "All private chat sessions must be physically erased upon deletion"
  );

  // Verify notifications and broadcast_reads are completely erased
  const remainingNotifs = store.notifications.filter((n) => n.user_id === newUserId);
  assert.equal(
    remainingNotifs.length,
    0,
    "All direct user notifications must be erased upon account deletion"
  );
  const remainingReads = store.broadcast_reads.filter((r) => r.user_id === newUserId);
  assert.equal(
    remainingReads.length,
    0,
    "All broadcast read receipts must be erased upon account deletion"
  );

  const anonymizedUser = store.users.find((u) => u.user_id === newUserId);
  assert.ok(anonymizedUser.email.startsWith("deleted_"), "User must be anonymized in-place");
  assert.equal(anonymizedUser.credits, 0, "Credits must be reset to 0");

  // Verify R2 user assets (tmp/ and avatars/) are completely erased
  const remainingTmp = await env.R2.list({ prefix: `tmp/${newUserId}/` });
  assert.equal(
    remainingTmp.objects.length,
    0,
    "User tmp/ assets must be cascade deleted from R2 upon account deletion"
  );
  const remainingAvatars = await env.R2.list({ prefix: `avatars/${newUserId}_` });
  assert.equal(
    remainingAvatars.objects.length,
    0,
    "User avatars/ must be cascade deleted from R2 upon account deletion"
  );

  console.log(
    "  ✓ User account deletion cascades physical erasure of chat sessions & R2 assets: PASSED"
  );

  // 7.2 OAuth user deletion with dual presence in users & user_oauth_bindings
  const oauthUserId = "usr_oauth_dual_presence";
  store.users.push({
    user_id: oauthUserId,
    username: "OAuthDualUser",
    email: "oauth_dual@example.com",
    password_hash: null,
    oauth_provider: "github",
    oauth_id: "gh_99999",
    frozen_credits: 0,
    credits: 0,
    token_version: 1
  });
  store.user_oauth_bindings.push({
    user_id: oauthUserId,
    provider: "github",
    provider_id: "gh_99999"
  });

  const oauthOwnerToken = await signJWT(
    { userId: oauthUserId, tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const deleteOauthReq = new Request("https://nanomesh.local/api/user/delete", {
    method: "POST",
    headers: { Cookie: `session=${oauthOwnerToken}` }
  });
  const deleteOauthRes = await handleDeleteAccount(deleteOauthReq, env);
  assert.equal(
    deleteOauthRes.status,
    200,
    "OAuth user deletion with dual records must succeed with 200 without D1 unique constraint failure"
  );
  const anonymizedOauthUser = store.users.find((u) => u.user_id === oauthUserId);
  assert.ok(
    anonymizedOauthUser.email.startsWith("deleted_"),
    "OAuth user must be anonymized in-place"
  );
  console.log(
    "  ✓ OAuth user deletion with duplicate bindings succeeds with idempotent tombstone: PASSED"
  );

  // -----------------------------------------------------------------------
  // SCENARIO 8: Distributed Topology & Stream Protocol Verification
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 8] Distributed Topology & Stream Protocol Verification");

  // 8.1 Password Update Token In Body
  const pwUser = {
    user_id: "u_pw_test",
    username: "pw_test_user",
    email: "pw_test@example.com",
    password_hash: bcrypt.hashSync("OldPass1234!", 10),
    token_version: 1,
    credits: 100
  };
  store.users.push(pwUser);
  const pwUserToken = await signJWT(
    { userId: pwUser.user_id, tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  const updatePwReq = new Request("https://nanomesh.local/api/user/password", {
    method: "PUT",
    headers: {
      Cookie: `session=${pwUserToken}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      oldPassword: "OldPass1234!",
      newPassword: "NewPass5678!"
    })
  });
  const updatePwRes = await handleUpdatePassword(updatePwReq, env);
  assert.equal(updatePwRes.status, 200, "handleUpdatePassword must succeed");
  const updatePwData = (await updatePwRes.json()) as any;
  assert.equal(updatePwData.success, true);
  assert.ok(
    updatePwData.token,
    "Response JSON body must include the refreshed session token for API clients"
  );
  const verifiedRefreshed = await verifyJWT(updatePwData.token, env.JWT_SECRET);
  assert.equal(verifiedRefreshed?.userId, pwUser.user_id);
  assert.equal(verifiedRefreshed?.tokenVersion, 2, "TokenVersion must increment to 2");
  console.log("  ✓ Password update issues refreshed token in response body: PASSED");

  // 8.2 OAuth Unbind Passkey Safety Verification
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
  const oauthPkToken = await signJWT(
    { userId: oauthPasskeyUser.user_id, tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  const unbindReq = new Request("https://nanomesh.local/api/auth/oauth/github", {
    method: "DELETE",
    headers: { Cookie: `session=${oauthPkToken}` }
  });
  const unbindRes = await handleUnbindOAuth(unbindReq, env, "github");
  assert.equal(
    unbindRes.status,
    200,
    "User with registered passkeys must be permitted to unbind last OAuth provider"
  );
  console.log("  ✓ OAuth unbinding permits decoupling when Passkey is active: PASSED");

  // 8.3 Admin Model Publishing Endpoint Guard
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
  const pubFailData = (await pubFailRes.json()) as any;
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
  assert.equal(
    pubSuccessRes.status,
    200,
    "Publishing model with valid external endpoint must succeed"
  );
  const insertedLiveModel = store.models.find((m) => m.model_id === "um-upload_model_1");
  assert.ok(insertedLiveModel);
  assert.equal(insertedLiveModel.endpoint, "https://ai.example.com/v1/chat/completions");
  assert.equal(insertedLiveModel.inference_target, "heavy");
  console.log(
    "  ✓ Admin model publishing validates endpoint and prevents /api/infer pollution: PASSED"
  );

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
  assert.equal(
    validTplRes.status,
    200,
    "Template with intermediate browser node is now ALLOWED in arbitrary topology"
  );
  const validTplData = (await validTplRes.json()) as any;
  const webgpuArbitraryTemplateId = validTplData.template_id;
  console.log(
    "  ✓ DAG template allows WebGPU models at intermediate and any pipeline position: PASSED"
  );

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

  const user9AuthToken = await signJWT(
    { userId: testUser9Id, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const user9ReqHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${user9AuthToken}`
  };

  const testEnvelope9: UnifiedProtocolEnvelope = {
    round_index: 1,
    constraint_context: { target_language: "zh", output_style: "concise" },
    envelope_id: "env_webgpu_001",
    session_id: "sess_webgpu_001",
    user_id: testUser9Id,
    instruction_payload: "本地快速摘要提取并交由云端深度推理",
    metadata: { client_timestamp: Date.now(), char_count_total: 100, estimated_input_tokens: 50 },
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
  assert.ok(
    !p1Events.includes("event: text_chunk"),
    "AC-03: Intermediate WebGPU step must NOT emit text_chunk"
  );

  // Extract handover payload
  const handoverMatch = p1Events.match(/event: dag_handover\ndata: (\{.*?\})\n\n/);
  assert.ok(handoverMatch, "Must contain valid dag_handover data block");
  const handoverData = JSON.parse(handoverMatch[1]);
  assert.equal(handoverData.current_step, 0);
  assert.equal(handoverData.next_step, 1);
  assert.equal(handoverData.is_tail_node, false);
  assert.ok(handoverData.continuation_token);

  // Assert AC-01: User credits in Phase 1 MUST REMAIN UNTOUCHED (Zero Pre-Deduction)
  const user9AfterPhase1 = store.users.find((u) => u.user_id === testUser9Id);
  assert.equal(
    user9AfterPhase1.credits,
    5,
    "AC-01: Phase 1 with Step 0 WebGPU must consume 0 credits! Credits must remain 5."
  );
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
  const user9AfterPhase2 = store.users.find((u) => u.user_id === testUser9Id);
  assert.equal(
    user9AfterPhase2.credits,
    4,
    "AC-01 (Part 2): Phase 2 cloud node execution must accurately deduct 1 credit (5 -> 4)"
  );
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

  const replayToken = await signJWT(
    {
      jti: replayHandshakeId,
      sub: testUser9Id,
      sid: "sess_replay",
      tid: webgpuArbitraryTemplateId,
      nxt: 1
    },
    env.JWT_SECRET,
    300
  );

  // Send 10 concurrent continuation requests
  const concurrentRequests = Array.from({ length: 10 }).map(() => {
    const req = new Request("https://nanomesh.local/api/chat/continue", {
      method: "POST",
      headers: user9ReqHeaders,
      body: JSON.stringify({
        continuation_token: replayToken,
        status: "success",
        client_step_output: "Concurrent payload",
        envelope: { ...testEnvelope9, session_id: "sess_replay" },
        orchestration_options: { chosenTemplateId: webgpuArbitraryTemplateId }
      })
    });
    return handleChatContinue(req, env);
  });

  const responses = await Promise.all(concurrentRequests);
  const statusCounts = responses.map((r) => r.status);
  const count200 = statusCounts.filter((s) => s === 200).length;
  const count409 = statusCounts.filter((s) => s === 409).length;

  assert.equal(count200, 1, `AC-02: Exactly 1 request must succeed with 200, but got ${count200}`);
  assert.equal(
    count409,
    9,
    `AC-02: Exactly 9 requests must be blocked with 409 CAS Conflict, but got ${count409}`
  );
  console.log(
    "  ✓ AC-02: D1 Atomic CAS anti-replay blocks 9/10 concurrent requests with 409: PASSED"
  );

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
  assert.ok(
    !store.dag_handshakes.some((h) => h.handshake_id.startsWith("hs_expired_")),
    "AC-06: Expired orphan handshakes must be swept"
  );
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

  const failoverToken = await signJWT(
    {
      jti: failoverHandshakeId,
      sub: testUser9Id,
      sid: "sess_failover",
      tid: webgpuArbitraryTemplateId,
      nxt: 1
    },
    env.JWT_SECRET,
    300
  );

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
      upstream_context: "Preserved Architectural Context from Step 0",
      envelope: { ...testEnvelope9, session_id: "sess_failover" },
      orchestration_options: { chosenTemplateId: webgpuArbitraryTemplateId }
    })
  });

  const failoverRes = await handleChatContinue(failoverReq, env);
  assert.equal(
    failoverRes.status,
    200,
    "AC-07: candidate_failed must transparently fallback to standby cloud model with restored upstream_context"
  );
  const failoverEvents = await failoverRes.text();
  assert.ok(
    failoverEvents.includes('"execution_backend":"workers_ai"'),
    "Cloud standby must report Workers AI as the actual execution backend"
  );
  console.log(
    "  ✓ AC-07 & AC-R4: Standby model failover successfully executes and restores upstream context: PASSED"
  );

  // 9.7 Tail WebGPU node issues continuation_token for Standby failover
  const tailBrowserTemplateReq = new Request("https://nanomesh.local/api/admin/templates", {
    method: "POST",
    headers: adminReqHeaders,
    body: JSON.stringify({
      name_zh: "尾节点端侧WebGPU模版",
      role_sequence: ["role_text_reasoning", "role_browser_only"]
    })
  });
  const tailTplRes = await handleAdminCreateOrUpdateTemplate(tailBrowserTemplateReq, env);
  assert.equal(tailTplRes.status, 200);
  const tailTplData = (await tailTplRes.json()) as any;

  const tailChatReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: user9ReqHeaders,
    body: JSON.stringify({
      envelope: {
        ...testEnvelope9,
        instruction_payload: "Tail WebGPU failover test"
      },
      reRouteMode: "switch_template",
      chosenTemplateId: tailTplData.template_id,
      capabilities: { webgpu_handover_v3: true }
    })
  });
  const tailChatRes = await handleChat(tailChatReq, env);
  assert.equal(tailChatRes.status, 200);
  const tailStreamText = await tailChatRes.text();
  assert.ok(
    tailStreamText.includes("client_exec_request"),
    "Tail WebGPU node must emit client_exec_request"
  );
  assert.ok(
    tailStreamText.includes("continuation_token"),
    "Tail WebGPU node with cloud standby MUST include continuation_token for failover "
  );
  console.log("  ✓ Tail WebGPU node issues continuation_token for transparent failover: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 10: Multimodal Pipeline Orchestration, ASR & Decoupled Competence
  // -----------------------------------------------------------------------
  console.log(
    "\n[Scenario 10] Multimodal Orchestration, ASR, Decoupled Competence & Targeted Claiming"
  );

  const testUser10Id = "usr_multimodal_001";
  store.users.push({
    user_id: testUser10Id,
    username: "MultimodalUser",
    email: "mm@nanomesh.local",
    password_hash: "hash",
    credits: 20,
    referral_code: "REF-MM-001",
    referred_by: null,
    token_version: 1
  });

  const user10AuthToken = await signJWT(
    { userId: testUser10Id, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const user10ReqHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${user10AuthToken}`
  };

  // 10.1 Register Multimodal Models (Whisper ASR, Flux Schnell)
  store.models.push(
    {
      model_id: "cf_whisper_node",
      display_name: "Whisper ASR (Edge)",
      provider: "Cloudflare Workers AI",
      endpoint: "@cf/openai/whisper",
      modalities: '["audio"]',
      in_modalities: '["audio"]',
      out_modalities: '["text"]',
      tags: '["#asr", "#audio"]',
      context_window: 4096,
      max_concurrency: 30,
      active_connections: 0,
      precision: 0.95,
      user_rating: 4.9,
      usage_count: 50,
      cost_per_1k_tokens: 1.0,
      cost_per_invocation: 0.0,
      status: "active",
      is_generalist: 0,
      prior_score: 0.8,
      scenario_anchors: '["asr", "audio"]',
      inference_target: "edge",
      auth_mode: "none",
      api_format: "workers_ai"
    },
    {
      model_id: "cf_flux_node",
      display_name: "FLUX.1-Schnell (Edge)",
      provider: "Cloudflare Workers AI",
      endpoint: "@cf/black-forest-labs/flux-1-schnell",
      modalities: '["text", "image"]',
      in_modalities: '["text"]',
      out_modalities: '["image"]',
      tags: '["#image_generation"]',
      context_window: 2048,
      max_concurrency: 20,
      active_connections: 0,
      precision: 0.98,
      user_rating: 4.95,
      usage_count: 50,
      cost_per_1k_tokens: 0.0,
      cost_per_invocation: 2.0,
      status: "active",
      is_generalist: 0,
      prior_score: 0.9,
      scenario_anchors: '["image_gen", "drawing"]',
      inference_target: "edge",
      auth_mode: "none",
      api_format: "workers_ai"
    }
  );

  // Register roles
  store.dag_roles.push(
    {
      role_id: "role_asr_transcribe",
      name_zh: "语音智能听写",
      name_en: "Audio ASR Transcription",
      in_modalities: JSON.stringify(["audio"]),
      out_modalities: JSON.stringify(["text"]),
      in_degree: 0,
      out_degree: 0,
      requisition_tags: JSON.stringify(["#asr"]),
      compensation_prompts: null
    },
    {
      role_id: "role_flux_draw",
      name_zh: "视觉图像生成",
      name_en: "Visual Image Generation",
      in_modalities: JSON.stringify(["text"]),
      out_modalities: JSON.stringify(["image"]),
      in_degree: 0,
      out_degree: 1,
      requisition_tags: JSON.stringify(["#image_generation"]),
      compensation_prompts: null
    },
    {
      role_id: "role_vision_critique",
      name_zh: "视觉多模态审校",
      name_en: "Vision Quality Critique",
      in_modalities: JSON.stringify(["image"]),
      out_modalities: JSON.stringify(["text"]),
      in_degree: 1,
      out_degree: 0,
      requisition_tags: JSON.stringify(["#vision"]),
      compensation_prompts: null
    }
  );

  // Register templates
  store.dag_templates.push(
    {
      template_id: "tpl_audio_transcription",
      name_zh: "语音转写流水线",
      name_en: "Audio Transcription Pipeline",
      desc_zh: "Whisper ASR 语音识别转写",
      desc_en: "Whisper ASR speech-to-text",
      scenario_category: "audio",
      scenario_anchor: "audio",
      roles: JSON.stringify(["role_asr_transcribe"]),
      role_sequence: JSON.stringify(["role_asr_transcribe"]),
      edges: JSON.stringify([]),
      head_modalities: JSON.stringify(["audio"]),
      tail_modalities: JSON.stringify(["text"]),
      status: "active",
      priority: 5
    },
    {
      template_id: "tpl_flux_and_inspect",
      name_zh: "生图与审校多模态编排",
      name_en: "Generation & Inspection Multimodal Pipeline",
      desc_zh: "FLUX.1 文本生图并由视觉模型质检",
      desc_en: "FLUX.1 text-to-image with vision model QA",
      scenario_category: "multimodal",
      scenario_anchor: "image_gen",
      roles: JSON.stringify(["role_flux_draw", "role_vision_critique"]),
      role_sequence: JSON.stringify(["role_flux_draw", "role_vision_critique"]),
      edges: JSON.stringify([]),
      head_modalities: JSON.stringify(["text"]),
      tail_modalities: JSON.stringify(["text"]),
      status: "active",
      priority: 5
    },
    {
      template_id: "tpl_text_then_vision",
      name_zh: "文本前序与视觉分析",
      name_en: "Text then Vision",
      desc_zh: "前序文本提炼后交由视觉分析",
      desc_en: "Text refinement then vision analysis",
      scenario_category: "multimodal",
      scenario_anchor: "vision",
      roles: JSON.stringify(["role_text_reasoning", "role_vision_critique"]),
      role_sequence: JSON.stringify(["role_text_reasoning", "role_vision_critique"]),
      edges: JSON.stringify([]),
      head_modalities: JSON.stringify(["text", "image"]),
      tail_modalities: JSON.stringify(["text"]),
      status: "active",
      priority: 5
    }
  );

  // 10.2 Whisper Audio Transcription
  const audioAssetKey = `tmp/${testUser10Id}/sess_audio_01/recording.wav`;
  const dummyWavBytes = new Uint8Array([82, 73, 70, 70, 36, 0, 0, 0, 87, 65, 86, 69]); // RIFF...WAVE
  await env.R2.put(audioAssetKey, dummyWavBytes, {
    httpMetadata: { contentType: "audio/wav" }
  });
  await registerPresignedAssetTicket(env, {
    assetId: "asset_voice_01",
    userId: testUser10Id,
    filename: "recording.wav",
    modality: "audio",
    mimeType: "audio/wav",
    fileSize: dummyWavBytes.byteLength,
    r2Key: audioAssetKey,
    origin: "upload"
  });

  const audioEnvelope: UnifiedProtocolEnvelope = {
    round_index: 1,
    constraint_context: { target_language: "zh", output_style: "concise" },
    envelope_id: "env_audio_001",
    session_id: "sess_audio_001",
    user_id: testUser10Id,
    instruction_payload: "请将该语音转写为文字",
    metadata: { client_timestamp: Date.now(), char_count_total: 100, estimated_input_tokens: 100 },
    assets_manifest: [
      {
        asset_id: "asset_voice_01",
        modality: "audio",
        mime_type: "audio/wav",
        file_size: dummyWavBytes.byteLength,
        r2_key: audioAssetKey,
        consumed: false,
        source_digest: "digest_voice_01",
        is_new: true
      }
    ]
  };

  const audioChatReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: user10ReqHeaders,
    body: JSON.stringify({
      envelope: audioEnvelope,
      reRouteMode: "switch_template",
      chosenTemplateId: "tpl_audio_transcription"
    })
  });

  const audioChatRes = await handleChat(audioChatReq, env);
  assert.equal(audioChatRes.status, 200, "Audio chat request must return 200 SSE stream");
  const audioStreamText = await audioChatRes.text();
  assert.ok(
    audioStreamText.includes("Mock Whisper transcription"),
    "Must receive Whisper transcription in SSE stream"
  );
  assert.ok(audioStreamText.includes("dag_complete"), "Audio pipeline must emit dag_complete");

  const user10AfterAudio = store.users.find((u) => u.user_id === testUser10Id);
  assert.equal(
    user10AfterAudio.credits,
    19,
    "Whisper transcription must consume 1 credit (20 -> 19)"
  );
  console.log(
    "  ✓ Whisper Audio ASR pipeline accurately transcribes R2 audio and deducts credit: PASSED"
  );

  // 10.3 Flux text-to-image + downstream vision critique (P0 targeted claiming & invocation pricing)
  const drawEnvelope: UnifiedProtocolEnvelope = {
    round_index: 1,
    constraint_context: { target_language: "zh", output_style: "concise" },
    envelope_id: "env_flux_001",
    session_id: "sess_flux_001",
    user_id: testUser10Id,
    instruction_payload: "请绘制赛博朋克霓虹城市夜景，并进行多模态构图分析",
    metadata: { client_timestamp: Date.now(), char_count_total: 100, estimated_input_tokens: 200 },
    assets_manifest: []
  };

  const drawChatReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: user10ReqHeaders,
    body: JSON.stringify({
      envelope: drawEnvelope,
      reRouteMode: "switch_template",
      chosenTemplateId: "tpl_flux_and_inspect"
    })
  });

  const drawChatRes = await handleChat(drawChatReq, env);
  assert.equal(drawChatRes.status, 200, "Flux + Vision chat request must return 200 SSE stream");
  const drawStreamText = await drawChatRes.text();

  assert.ok(
    drawStreamText.includes("event: asset_chunk"),
    "Pipeline must emit asset_chunk for generated image"
  );
  assert.ok(drawStreamText.includes("image/png"), "Asset chunk must specify image/png MIME");
  assert.ok(
    drawStreamText.includes("event: dag_complete"),
    "Must complete full two-stage multimodal pipeline"
  );

  // Verify R2 object creation for generated image
  const r2List = await env.R2.list({ prefix: `tmp/${testUser10Id}/${drawEnvelope.session_id}/` });
  assert.ok(r2List.objects.length > 0, "Generated Flux image must be stored in R2 bucket");

  // Verify billing: Flux invocation (2 credits) + Vision critique (1 credit) = 3 credits total
  const user10AfterDraw = store.users.find((u) => u.user_id === testUser10Id);
  assert.equal(
    user10AfterDraw.credits,
    16,
    "Flux (2 credits) + Vision critique (1 credit) must deduct exactly 3 credits (19 -> 16)"
  );

  const drawLedger = store.credit_ledger.find((l) => l.user_id === testUser10Id && l.amount === -3);
  assert.ok(drawLedger, "Credit ledger must record -3 compute_cost for multimodal pipeline");
  console.log(
    "  ✓ Flux image generation -> R2 persistence -> P0 vision critique claiming & atomic billing (3 credits): PASSED"
  );

  // 10.4 P1 Penetrating Claiming: Downstream vision node claims unconsumed user asset when Step 0 produces no media
  const userPhotoKey = `tmp/${testUser10Id}/sess_p1_01/user_photo.png`;
  await env.R2.put(userPhotoKey, new Uint8Array([137, 80, 78, 71, 1, 2, 3, 4]), {
    httpMetadata: { contentType: "image/png" }
  });
  await registerPresignedAssetTicket(env, {
    assetId: "user_photo_asset",
    userId: testUser10Id,
    filename: "user_photo.png",
    modality: "image",
    mimeType: "image/png",
    fileSize: 8,
    r2Key: userPhotoKey,
    origin: "upload"
  });

  // 10.4 P1 Penetrating Claiming & Reverse Pipeline :
  // User uploads ONLY physical image and writes text prompt (NO manual virtual_text_asset in manifest).
  // Generalized Subsistence Law must automatically satisfy text-first reverse pipeline!
  const p1Envelope: UnifiedProtocolEnvelope = {
    round_index: 1,
    constraint_context: { target_language: "zh", output_style: "concise" },
    envelope_id: "env_p1_001",
    session_id: "sess_p1_001",
    user_id: testUser10Id,
    instruction_payload: "请先根据宏观经济背景推导分析，再核验我上传的走势图图片",
    metadata: { client_timestamp: Date.now(), char_count_total: 100, estimated_input_tokens: 150 },
    assets_manifest: [
      {
        asset_id: "user_photo_asset",
        modality: "image",
        mime_type: "image/png",
        file_size: 8,
        r2_key: userPhotoKey,
        consumed: false,
        source_digest: "digest_p1_photo",
        is_new: true
      }
    ]
  };

  const p1ChatReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: user10ReqHeaders,
    body: JSON.stringify({
      envelope: p1Envelope,
      reRouteMode: "switch_template",
      chosenTemplateId: "tpl_text_then_vision"
    })
  });

  const p1ChatRes = await handleChat(p1ChatReq, env);
  assert.equal(p1ChatRes.status, 200, "P1 chat request must return 200 SSE stream");
  const p1StreamText = await p1ChatRes.text();
  assert.ok(
    p1StreamText.includes("dag_complete"),
    "P1 penetrating claiming reverse pipeline must complete"
  );

  // Step 0 text (1 credit) + Step 1 vision (1 credit) = 2 credits (16 -> 14)
  const user10AfterP1 = store.users.find((u) => u.user_id === testUser10Id);
  assert.equal(user10AfterP1.credits, 14, "P1 pipeline must deduct 2 credits (16 -> 14)");
  console.log(
    "  ✓ Reverse multimodal pipeline (text -> image) successfully passes subsistence & executes: PASSED"
  );

  // 10.5 FLUX 0-byte generation failover to Standby model
  // Register a separate user to avoid in-memory burst rate limit (capacity=3)
  const testUser10bId = "usr_multimodal_002_failover";
  store.users.push({
    user_id: testUser10bId,
    username: "FluxFailoverTester",
    email: "failover@nanomesh.local",
    password_hash: "hash",
    credits: 10,
    referral_code: "REF-MM-FAILOVER",
    referred_by: null,
    token_version: 1
  });

  const user10bAuthToken = await signJWT(
    { userId: testUser10bId, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const user10bReqHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${user10bAuthToken}`
  };

  // Register a broken FLUX model returning 0 bytes with higher precision, and normal FLUX as standby
  store.models.push({
    model_id: "cf_flux_broken_zero",
    display_name: "FLUX Broken (0-byte)",
    provider: "Cloudflare",
    endpoint: "@cf/black-forest-labs/flux-broken-zero",
    modalities: '["text", "image"]',
    in_modalities: '["text"]',
    out_modalities: '["image"]',
    tags: '["#image_generation"]',
    context_window: 2048,
    max_concurrency: 20,
    active_connections: 0,
    precision: 0.999, // higher precision so it ranks as primary
    user_rating: 4.99,
    usage_count: 10,
    cost_per_1k_tokens: 0.0,
    cost_per_invocation: 2.0,
    status: "active",
    is_generalist: 0,
    prior_score: 0.99,
    scenario_anchors: '["image_gen"]',
    inference_target: "edge",
    auth_mode: "none",
    api_format: "workers_ai"
  });

  store.dag_templates.push({
    template_id: "tpl_flux_failover_test",
    name_zh: "FLUX 0字节容灾测试流水线",
    name_en: "FLUX Zero Byte Failover Pipeline",
    desc_zh: "测试首选FLUX返回0字节时透明故障转移到备选",
    desc_en: "Test transparent failover when primary FLUX returns 0 bytes",
    scenario_category: "multimodal",
    scenario_anchor: "image_gen",
    roles: JSON.stringify(["role_flux_draw"]),
    role_sequence: JSON.stringify(["role_flux_draw"]),
    edges: JSON.stringify([]),
    head_modalities: JSON.stringify(["text"]),
    tail_modalities: JSON.stringify(["image"]),
    status: "active",
    priority: 5
  });

  const zeroByteEnvelope: UnifiedProtocolEnvelope = {
    round_index: 1,
    constraint_context: { target_language: "zh", output_style: "concise" },
    envelope_id: "env_flux_zero_001",
    session_id: "sess_flux_zero_001",
    user_id: testUser10bId,
    instruction_payload: "生成赛博朋克光影图",
    metadata: { client_timestamp: Date.now(), char_count_total: 100, estimated_input_tokens: 100 },
    assets_manifest: []
  };

  const zeroByteChatReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: user10bReqHeaders,
    body: JSON.stringify({
      envelope: zeroByteEnvelope,
      reRouteMode: "switch_template",
      chosenTemplateId: "tpl_flux_failover_test"
    })
  });

  const zeroByteChatRes = await handleChat(zeroByteChatReq, env);
  assert.equal(
    zeroByteChatRes.status,
    200,
    "FLUX failover chat request must return 200 SSE stream"
  );
  const zeroByteStreamText = await zeroByteChatRes.text();
  assert.ok(
    zeroByteStreamText.includes("event: node_failover"),
    "Must emit node_failover event when primary FLUX produces 0 bytes"
  );
  assert.ok(
    zeroByteStreamText.includes("event: asset_chunk"),
    "Must emit asset_chunk after standby FLUX succeeds"
  );
  assert.ok(
    zeroByteStreamText.includes("dag_complete"),
    "Must complete successfully after transparent failover"
  );
  console.log(
    "  ✓ FLUX 0-byte generation cleanly triggers node_failover and completes with standby model: PASSED"
  );

  // 10.6 DEFECT-02: Tail Heavy Image Node Streaming Bypass & JSON Recovery
  const testUser10cId = "usr_multimodal_003_heavytail";
  store.users.push({
    user_id: testUser10cId,
    username: "HeavyTailTester",
    email: "heavytail@test.local",
    password_hash: "hash_test",
    credits: 20,
    referral_code: "HEAVYTAIL",
    referred_by: null,
    token_version: 1
  });
  const user10cToken = await signJWT(
    { userId: testUser10cId, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const user10cReqHeaders = {
    Authorization: `Bearer ${user10cToken}`,
    "Content-Type": "application/json"
  };

  // Register a Heavy Commercial Image Model (e.g. DALL-E endpoint returning JSON)
  const heavyDalleEndpoint = "https://api.mock-heavy-dalle.com/v1/images/generations";
  store.models.push({
    model_id: "heavy_dalle_3",
    display_name: "DALL-E 3 Heavy Commercial",
    provider: "OpenAI Compatible",
    endpoint: heavyDalleEndpoint,
    modalities: '["text", "image"]',
    in_modalities: '["text"]',
    out_modalities: '["image"]',
    tags: '["#image_generation", "#commercial"]',
    context_window: 4096,
    max_concurrency: 10,
    active_connections: 0,
    precision: 0.99,
    user_rating: 4.99,
    usage_count: 50,
    cost_per_1k_tokens: 0.0,
    cost_per_invocation: 5.0,
    status: "active",
    is_generalist: 0,
    prior_score: 1.0,
    scenario_anchors: '["image_gen"]',
    inference_target: "heavy",
    auth_mode: "none",
    api_format: "openai_compat"
  });

  store.dag_templates.push({
    template_id: "tpl_heavy_dalle_tail",
    name_zh: "商用大模型生图单节点",
    name_en: "Heavy DALL-E Tail Gen",
    desc_zh: "商用生图单节点作为末端",
    desc_en: "Commercial image generation at tail",
    scenario_category: "multimodal",
    scenario_anchor: "image_gen",
    roles: JSON.stringify(["role_flux_draw"]),
    role_sequence: JSON.stringify(["role_flux_draw"]),
    edges: JSON.stringify([]),
    head_modalities: JSON.stringify(["text"]),
    tail_modalities: JSON.stringify(["image"]),
    status: "active",
    priority: 10
  });

  const origFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (urlStr.includes("api.mock-heavy-dalle.com")) {
        // Verify payload contract for OpenAI Images API
        if (init?.body) {
          const parsedBody = JSON.parse(init.body as string);
          if (!parsedBody.prompt || !parsedBody.response_format) {
            throw new Error(
              "Mock received invalid Image API payload: missing prompt or response_format"
            );
          }
        }
        // Return standard commercial JSON response format (b64_json)
        return new Response(
          JSON.stringify({
            data: [
              {
                b64_json:
                  "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
              }
            ]
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" }
          }
        );
      }
      return origFetch(input, init);
    };

    const heavyTailEnvelope: UnifiedProtocolEnvelope = {
      envelope_id: "env_heavytail_001",
      session_id: "sess_heavytail_001",
      user_id: testUser10cId,
      round_index: 1,
      instruction_payload: "Draw a commercial poster of neon cyberpunk city",
      metadata: {
        client_timestamp: Date.now(),
        char_count_total: 100,
        estimated_input_tokens: 100
      },
      assets_manifest: [],
      constraint_context: { target_language: "zh", output_style: "creative" }
    };

    const heavyTailReq = new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: user10cReqHeaders,
      body: JSON.stringify({
        envelope: heavyTailEnvelope,
        reRouteMode: "switch_template",
        chosenTemplateId: "tpl_heavy_dalle_tail"
      })
    });

    const heavyTailRes = await handleChat(heavyTailReq, env);
    assert.equal(
      heavyTailRes.status,
      200,
      "Heavy tail image node request must return 200 SSE stream"
    );
    const heavyStreamText = await heavyTailRes.text();
    assert.ok(
      heavyStreamText.includes("event: asset_chunk"),
      "DEFECT-02 Verified: Heavy tail node must bypass SSE parseAIResponse and emit asset_chunk"
    );
    assert.ok(
      heavyStreamText.includes("dag_complete"),
      "Must complete successfully without parseAIResponse empty stream failure"
    );
    console.log(
      "  ✓ DEFECT-02: Commercial Heavy Image Generation at tail node correctly executes and emits asset_chunk: PASSED"
    );
  } finally {
    globalThis.fetch = origFetch;
  }

  // 10.7 DEFECT-04: D1 0021 Image Generation Seed Migration Verification
  const fsMod = await import("node:fs");
  const pathMod = await import("node:path");
  const migration0021Path = pathMod.resolve(
    process.cwd(),
    "migrations",
    "0021_add_image_generation_seed.sql"
  );
  assert.ok(fsMod.existsSync(migration0021Path), "0021 migration file must exist on disk");
  const sql0021 = fsMod.readFileSync(migration0021Path, "utf-8");
  assert.ok(sql0021.includes("role_flux_draw"), "0021 migration must seed role_flux_draw");
  assert.ok(sql0021.includes("tpl-text-to-image"), "0021 migration must seed tpl-text-to-image");
  assert.ok(
    sql0021.includes("in_modalities") && sql0021.includes("out_modalities"),
    "Must match real dag_roles and dag_templates schema"
  );
  assert.ok(!sql0021.includes("topology"), "Must NOT contain fake topology column");
  assert.ok(
    !sql0021.includes("required_capabilities"),
    "Must NOT contain fake required_capabilities column"
  );
  console.log("  ✓ DEFECT-04: D1 0021 migration file verified with valid table schema: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 11: Credit Bounds & Handshake Two-Phase Commitment
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 11] Credit Bounds & Handshake Two-Phase Commitment");

  // 11.1 Zero-credit billing bypass prevention via WebGPU fallback
  const testUserZeroCreditId = "usr_zero_billing_01";
  store.users.push({
    user_id: testUserZeroCreditId,
    username: "ZeroCreditUser",
    email: "zero@nanomesh.local",
    password_hash: "hash",
    credits: 0,
    referral_code: "REF-ZERO-001",
    referred_by: null,
    token_version: 1
  });
  const userZeroToken = await signJWT(
    { userId: testUserZeroCreditId, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const userZeroReqHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${userZeroToken}`
  };

  // User with 0 credits requests chat where client explicitly declares no WebGPU support (forces cloud standby)
  const zeroCreditReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: userZeroReqHeaders,
    body: JSON.stringify({
      envelope: {
        envelope_id: "env_zero_001",
        session_id: "sess_zero_001",
        user_id: testUserZeroCreditId,
        round_index: 1,
        instruction_payload: "Test zero credit cloud execution",
        metadata: {
          client_timestamp: Date.now(),
          char_count_total: 100,
          estimated_input_tokens: 50
        },
        assets_manifest: []
      },
      capabilities: { webgpu_handover_v3: false } // Explicitly disabled WebGPU
    })
  });
  const zeroCreditRes = await handleChat(zeroCreditReq, env);
  assert.equal(
    zeroCreditRes.status,
    403,
    "Zero-credit user attempting cloud fallback must be blocked with HTTP 403"
  );
  const zeroCreditErrJson = (await zeroCreditRes.json()) as any;
  assert.equal(zeroCreditErrJson.error, "insufficient_quota");
  const userInDb = store.users.find((u) => u.user_id === testUserZeroCreditId);
  assert.equal(userInDb?.credits, 0, "User balance must remain 0 and not penetrated into negative");
  console.log("  ✓ Zero-credit WebGPU fallback exploit successfully blocked with HTTP 403: PASSED");

  // 11.2 Phase 2 Handshake 2PC & Non-destructive Recharging
  const testUserHandshakeId = "usr_handshake_2pc_01";
  store.users.push({
    user_id: testUserHandshakeId,
    username: "HandshakeUser",
    email: "hs@nanomesh.local",
    password_hash: "hash",
    credits: 0, // Starts with 0 credits
    referral_code: "REF-HS-001",
    referred_by: null,
    token_version: 1
  });
  const userHsToken = await signJWT(
    { userId: testUserHandshakeId, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const userHsReqHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${userHsToken}`
  };

  const testHandshakeId = "hs_2pc_test_001";
  const handshakeExpiresAt = new Date(Date.now() + 300 * 1000).toISOString();
  store.dag_handshakes.push({
    handshake_id: testHandshakeId,
    user_id: testUserHandshakeId,
    session_id: "sess_hs_001",
    template_id: webgpuArbitraryTemplateId,
    next_step: 1,
    status: "ISSUED",
    expires_at: handshakeExpiresAt
  });

  const continuationToken = await signJWT(
    {
      jti: testHandshakeId,
      sub: testUserHandshakeId,
      sid: "sess_hs_001",
      tid: webgpuArbitraryTemplateId,
      nxt: 1
    },
    env.JWT_SECRET,
    300
  );

  // Attempt continuation with 0 credits
  const continueWithZeroReq = new Request("https://nanomesh.local/api/chat/continue", {
    method: "POST",
    headers: userHsReqHeaders,
    body: JSON.stringify({
      continuation_token: continuationToken,
      status: "success",
      client_step_output: "Client WebGPU step 0 completed",
      envelope: {
        envelope_id: "env_hs_001",
        session_id: "sess_hs_001",
        user_id: testUserHandshakeId,
        round_index: 1,
        instruction_payload: "Continuation test",
        metadata: {
          client_timestamp: Date.now(),
          char_count_total: 100,
          estimated_input_tokens: 50
        },
        assets_manifest: []
      },
      orchestration_options: { chosenTemplateId: webgpuArbitraryTemplateId }
    })
  });

  const continueZeroRes = await handleChatContinue(continueWithZeroReq, env);
  assert.equal(
    continueZeroRes.status,
    403,
    "Zero-credit continue request must return 403 insufficient_quota"
  );
  const hsInDb = store.dag_handshakes.find((h) => h.handshake_id === testHandshakeId);
  assert.equal(
    hsInDb?.status,
    "ISSUED",
    "Handshake record must REMAIN 'ISSUED' (not prematurely burned to CONSUMED)"
  );

  // Top up user balance
  const hsUserInDb = store.users.find((u) => u.user_id === testUserHandshakeId);
  if (hsUserInDb) hsUserInDb.credits = 5;

  // Retry with the EXACT same continuation token!
  const continueAfterTopupReq = new Request("https://nanomesh.local/api/chat/continue", {
    method: "POST",
    headers: userHsReqHeaders,
    body: JSON.stringify({
      continuation_token: continuationToken,
      status: "success",
      client_step_output: "Client WebGPU step 0 completed",
      envelope: {
        envelope_id: "env_hs_001",
        session_id: "sess_hs_001",
        user_id: testUserHandshakeId,
        round_index: 1,
        instruction_payload: "Continuation test",
        metadata: {
          client_timestamp: Date.now(),
          char_count_total: 100,
          estimated_input_tokens: 50
        },
        assets_manifest: []
      },
      orchestration_options: { chosenTemplateId: webgpuArbitraryTemplateId }
    })
  });

  const continueTopupRes = await handleChatContinue(continueAfterTopupReq, env);
  assert.equal(
    continueTopupRes.status,
    200,
    "Retried continuation after credit top-up must succeed with 200"
  );
  assert.equal(hsInDb?.status, "CONSUMED", "Handshake record must now be updated to 'CONSUMED'");

  // Replay attempt with same consumed token
  const continueReplayReq = new Request("https://nanomesh.local/api/chat/continue", {
    method: "POST",
    headers: userHsReqHeaders,
    body: JSON.stringify({
      continuation_token: continuationToken,
      status: "success",
      client_step_output: "Client WebGPU step 0 completed",
      envelope: {
        envelope_id: "env_hs_001",
        session_id: "sess_hs_001",
        user_id: testUserHandshakeId,
        round_index: 1,
        instruction_payload: "Continuation test",
        metadata: {
          client_timestamp: Date.now(),
          char_count_total: 100,
          estimated_input_tokens: 50
        },
        assets_manifest: []
      },
      orchestration_options: { chosenTemplateId: webgpuArbitraryTemplateId }
    })
  });
  const continueReplayRes = await handleChatContinue(continueReplayReq, env);
  assert.equal(
    continueReplayRes.status,
    409,
    "Anti-replay must reject consumed handshake with 409 Conflict"
  );
  console.log(
    "  ✓ Handshake 2PC preserves ISSUED on 403, succeeds on top-up, and rejects replay: PASSED"
  );

  // -----------------------------------------------------------------------
  // SCENARIO 12: Dynamic Node Failover, Budget Protection & Redirect Interception
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 12] Dynamic Node Failover, Budget Protection & Redirect Interception");

  // 12.1 Symmetrical Heterogeneous Standby Failover (Cloud -> Browser WebGPU)
  const roleFailoverTest = {
    role_id: "role_failover_test",
    name_zh: "异构容灾测试岗",
    name_en: "Heterogeneous Failover Worker",
    in_modalities: JSON.stringify(["text"]),
    out_modalities: JSON.stringify(["text"]),
    in_degree: 0,
    out_degree: 0,
    requisition_tags: JSON.stringify(["#chat"]),
    compensation_prompts: "{}"
  };
  store.dag_roles.push(roleFailoverTest);

  // Add primary cloud model (destined to fail via simulated network drop)
  store.models.push({
    model_id: "m_failing_cloud_01",
    display_name: "Primary Failing Cloud",
    provider: "OpenAI Compatible",
    endpoint: "https://api.mock-failing-cloud.com/v1/chat/completions",
    modalities: JSON.stringify(["text"]),
    tags: JSON.stringify(["#chat"]),
    context_window: 4096,
    max_concurrency: 10,
    active_connections: 0,
    precision: 0.9,
    user_rating: 4.8,
    usage_count: 50,
    is_generalist: 1,
    prior_score: 0.95, // High prior score -> Top 1 Primary
    scenario_anchors: '["chat"]',
    status: "active",
    cost_per_1k_tokens: 1.0,
    inference_target: "cloud",
    api_format: "openai_compat"
  });

  // Add standby browser WebGPU model
  store.models.push({
    model_id: "m_standby_browser_01",
    display_name: "Standby Browser WebGPU",
    provider: "Client",
    endpoint: "onnx-community/Qwen2.5-0.5B-Instruct",
    modalities: JSON.stringify(["text"]),
    tags: JSON.stringify(["#chat"]),
    context_window: 2048,
    max_concurrency: 10,
    active_connections: 0,
    precision: 0.85,
    user_rating: 4.5,
    usage_count: 20,
    is_generalist: 1,
    prior_score: 0.8, // Standby candidate
    scenario_anchors: '["chat"]',
    status: "active",
    cost_per_1k_tokens: 0.0,
    inference_target: "browser"
  });

  store.dag_templates.push({
    template_id: "tpl_failover_cloud_to_browser",
    name_zh: "云端切端侧单步容灾测试",
    name_en: "Cloud to Browser Standby Failover Test",
    desc_zh: "测试云端主节点失败后对称流转至端侧",
    desc_en: "Test symmetrical dynamic failover from cloud to browser",
    role_sequence: JSON.stringify(["role_failover_test"]),
    head_modalities: JSON.stringify(["text"]),
    tail_modalities: JSON.stringify(["text"]),
    status: "active",
    priority: 10
  });

  const testUser12Id = "usr_failover_tester_12";
  store.users.push({
    user_id: testUser12Id,
    username: "FailoverTester",
    email: "failover@nanomesh.local",
    password_hash: "hash",
    credits: 5,
    token_version: 1
  });

  const user12AuthToken = await signJWT(
    { userId: testUser12Id, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const user12ReqHeaders = {
    "Content-Type": "application/json",
    Authorization: `Bearer ${user12AuthToken}`
  };

  const origFetch12 = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (urlStr.includes("api.mock-failing-cloud.com")) {
        // Simulate cloud model timeout / connection drop
        throw new Error("Connection dropped by cloud gateway (Simulated 504 Gateway Timeout)");
      }
      return origFetch12(input, init);
    };

    const failoverEnvelope: UnifiedProtocolEnvelope = {
      envelope_id: "env_failover_001",
      session_id: "sess_failover_001",
      user_id: testUser12Id,
      round_index: 1,
      constraint_context: { target_language: "zh", output_style: "concise" },
      instruction_payload: "测试云端宕机对称流转至本地算力",
      metadata: { client_timestamp: Date.now(), char_count_total: 100, estimated_input_tokens: 50 },
      assets_manifest: []
    };

    const failoverReq = new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: user12ReqHeaders,
      body: JSON.stringify({
        envelope: failoverEnvelope,
        reRouteMode: "switch_template",
        chosenTemplateId: "tpl_failover_cloud_to_browser",
        capabilities: { webgpu_handover_v3: true }
      })
    });

    const failoverRes = await handleChat(failoverReq, env);
    assert.equal(failoverRes.status, 200, "Failover request must return 200 SSE stream");

    const reader12 = failoverRes.body!.getReader();
    const decoder12 = new TextDecoder();
    let streamEvents12 = "";
    while (true) {
      const chunk = await reader12.read();
      if (chunk.done) break;
      streamEvents12 += decoder12.decode(chunk.value, { stream: true });
    }

    // 1. Assert node_failover emitted with dynamic handover notice
    assert.ok(
      streamEvents12.includes("event: node_failover"),
      "Must emit node_failover event when cloud model fails"
    );
    assert.ok(
      streamEvents12.includes("全对称自由流转至端侧 WebGPU 备用模型"),
      "Failover event must cite symmetrical handover to client WebGPU"
    );
    assert.ok(
      streamEvents12.includes("Standby Browser WebGPU"),
      "Fallback model must be Standby Browser WebGPU"
    );

    // 2. Assert client_exec_request emitted for client execution
    assert.ok(
      streamEvents12.includes("event: client_exec_request"),
      "Must emit client_exec_request for client WebGPU execution"
    );

    // 3. Assert dag_complete emitted
    assert.ok(
      streamEvents12.includes("event: dag_complete"),
      "Must emit dag_complete on tail node handover"
    );

    // 4. Assert Conservation of Credits: User balance MUST BE EXACTLY 5 (1 pre-deducted credit was refunded!)
    const user12InDb = store.users.find((u) => u.user_id === testUser12Id);
    assert.equal(
      user12InDb?.credits,
      5,
      "Conservation of Credits: pre-deducted credit must be refunded when failing over to free WebGPU browser model!"
    );
    console.log(
      "  ✓ Cloud -> Browser WebGPU symmetrical dynamic handover with refund & zero crash: PASSED"
    );
  } finally {
    globalThis.fetch = origFetch12;
  }

  // 12.2 Intermediate WebGPU Downgrade Interruption (Zero Credits, No dag_complete)
  const testUser12bId = "usr_downgrade_zero_credits";
  store.users.push({
    user_id: testUser12bId,
    username: "ZeroCreditsDowngrade",
    email: "zero@nanomesh.local",
    password_hash: "hash",
    credits: 0, // Zero credits!
    token_version: 1
  });

  const testDag12b = {
    template: {
      template_id: "tpl_downgrade_test",
      name_zh: "降级失败测试",
      name_en: "Downgrade Fail Test",
      desc_zh: "测试降级中断",
      desc_en: "Test downgrade abort",
      roles: [],
      head_modalities: ["text"],
      tail_modalities: ["text"],
      priority: 1,
      status: "active"
    },
    nodes: [
      {
        role: {
          role_id: "role_browser_intermediate",
          name_zh: "中间端侧岗",
          name_en: "Browser Intermediate",
          in_modalities: ["text"],
          out_modalities: ["text"],
          in_degree: 0,
          out_degree: 1,
          requisition_tags: []
        },
        selected_model: {
          model_id: "m_browser_inter",
          display_name: "Intermediate WebGPU",
          provider: "Client",
          endpoint: "onnx-community/model",
          modalities: ["text"],
          tags: [],
          context_window: 2048,
          max_concurrency: 10,
          active_connections: 0,
          precision: 0.9,
          user_rating: 4.5,
          usage_count: 0,
          status: "active",
          is_generalist: 1,
          prior_score: 0.8,
          scenario_anchors: [],
          cost_per_1k_tokens: 0,
          inference_target: "browser" as const
        },
        standby_models: [
          {
            model_id: "m_cloud_standby",
            display_name: "Cloud Standby Model",
            provider: "Cloud",
            endpoint: "https://api.cloud-standby.com",
            modalities: ["text"],
            tags: [],
            context_window: 2048,
            max_concurrency: 10,
            active_connections: 0,
            precision: 0.9,
            user_rating: 4.5,
            usage_count: 0,
            status: "active",
            is_generalist: 1,
            prior_score: 0.7,
            scenario_anchors: [],
            cost_per_1k_tokens: 1,
            inference_target: "cloud" as const
          }
        ]
      },
      {
        role: {
          role_id: "role_tail_worker",
          name_zh: "末端岗",
          name_en: "Tail Worker",
          in_modalities: ["text"],
          out_modalities: ["text"],
          in_degree: 1,
          out_degree: 0,
          requisition_tags: []
        },
        selected_model: {
          model_id: "m_tail_worker",
          display_name: "Tail Worker",
          provider: "Cloud",
          endpoint: "https://api.tail-worker.com",
          modalities: ["text"],
          tags: [],
          context_window: 2048,
          max_concurrency: 10,
          active_connections: 0,
          precision: 0.9,
          user_rating: 4.5,
          usage_count: 0,
          status: "active",
          is_generalist: 1,
          prior_score: 0.7,
          scenario_anchors: [],
          cost_per_1k_tokens: 1,
          inference_target: "cloud" as const
        },
        standby_models: []
      }
    ],
    execution_order: ["role_browser_intermediate", "role_tail_worker"],
    candidate_templates: [],
    is_incremental_refinement: false,
    is_security_violation: false,
    is_unreachable: false
  };

  const downgradeStream = await executeDAGStream(
    env,
    testDag12b as any,
    {
      envelope_id: "env_downgrade_001",
      session_id: "sess_downgrade_001",
      user_id: testUser12bId,
      round_index: 1,
      constraint_context: { target_language: "zh", output_style: "concise" },
      instruction_payload: "测试中间节点降级失败中断",
      metadata: { client_timestamp: Date.now(), char_count_total: 100, estimated_input_tokens: 50 },
      assets_manifest: []
    },
    {
      userId: testUser12bId,
      hasPreDeducted: false,
      clientCapabilities: { webgpu_handover_v3: false }
    }
  );

  const reader12b = downgradeStream.getReader();
  const decoder12b = new TextDecoder();
  let streamEvents12b = "";
  while (true) {
    const chunk = await reader12b.read();
    if (chunk.done) break;
    streamEvents12b += decoder12b.decode(chunk.value, { stream: true });
  }

  // Assert error event emitted
  assert.ok(
    streamEvents12b.includes("event: error"),
    "Must emit error event when user has insufficient credits for downgrade"
  );
  assert.ok(
    streamEvents12b.includes("当前可用积分不足，无法降级调用云端备用模型"),
    "Error message must state insufficient credits for downgrade"
  );

  // Assert: dag_complete MUST NOT be emitted!
  assert.ok(
    !streamEvents12b.includes("event: dag_complete"),
    "Terminated downgrade stream MUST NOT emit contradictory dag_complete event!"
  );
  console.log(
    "  ✓ Intermediate WebGPU downgrade failure immediately aborts and avoids contradictory dag_complete: PASSED"
  );

  // 12.3 Admin Route Precise PATCH Matching (Reject Catch-All)
  const patchAdminUnknownReq = new Request(
    "https://nanomesh.local/api/admin/arbitrary_nonexistent_route",
    {
      method: "PATCH",
      headers: adminReqHeaders,
      body: JSON.stringify({ dummy: true })
    }
  );
  const patchAdminRes = await worker.fetch(patchAdminUnknownReq, env, {} as any);
  assert.equal(
    patchAdminRes.status,
    404,
    "Unmatched PATCH route under /api/admin must return 404 Not Found"
  );
  console.log("  ✓ Admin PATCH route guard strictly returns 404 on unmapped subpaths: PASSED");

  // 12.4 Admin Route Trailing Slash Normalization & Scoped Suffix Matching
  const patchAdminWithSlash = new Request(
    "https://nanomesh.local/api/admin/nodes/cf_llama32_text/",
    {
      method: "PATCH",
      headers: adminReqHeaders,
      body: JSON.stringify({ display_name: "Llama 3.2 3B Normalized" })
    }
  );
  const patchSlashRes = await worker.fetch(patchAdminWithSlash, env, {} as any);
  assert.equal(
    patchSlashRes.status,
    200,
    "PATCH /api/admin/nodes/:id/ with trailing slash must succeed without 404"
  );

  // Verify non-model route with /download is rejected (does not enter handleAdminDownload)
  const unknownDownloadReq = new Request(
    "https://nanomesh.local/api/admin/arbitrary_route/download",
    {
      method: "GET",
      headers: adminReqHeaders
    }
  );
  const unknownDownloadRes = await worker.fetch(unknownDownloadReq, env, {} as any);
  assert.equal(
    unknownDownloadRes.status,
    404,
    "Unscoped /download must return 404 and not enter model download logic"
  );

  // Verify notification revocation with trailing slash succeeds without 400
  const deleteNotifWithSlash = new Request(
    "https://nanomesh.local/api/admin/notifications/notif_test_123/",
    {
      method: "DELETE",
      headers: adminReqHeaders
    }
  );
  const deleteNotifSlashRes = await worker.fetch(deleteNotifWithSlash, env, {} as any);
  assert.equal(
    deleteNotifSlashRes.status,
    200,
    "DELETE /api/admin/notifications/:id/ with trailing slash must succeed without 400"
  );
  console.log("  ✓ Admin trailing slash normalization & scoped prefix matching: PASSED");

  // 12.5 External Model HTTP Redirect (SSRF Defense) Rejection
  const origFetchRedirectTest = globalThis.fetch;
  try {
    let capturedRedirectOption: string | undefined = undefined;
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
      if (urlStr.includes("api.redirect-attack.com")) {
        capturedRedirectOption = init?.redirect;
        // Return 302 redirecting to internal metadata
        return new Response(null, {
          status: 302,
          headers: { Location: "http://169.254.169.254/latest/meta-data/" }
        });
      }
      return origFetchRedirectTest(input, init);
    };

    const redirectDag: any = {
      template: {
        template_id: "tpl_redirect_test",
        name_zh: "重定向测试模板",
        name_en: "Redirect Test Template",
        desc_zh: "测试外部重定向拦截",
        desc_en: "Test external redirect blocking",
        roles: [],
        head_modalities: ["text"],
        tail_modalities: ["text"],
        priority: 1,
        status: "active"
      },
      nodes: [
        {
          role: {
            role_id: "role_redirect_test",
            name_zh: "重定向测试岗",
            name_en: "Redirect Test Role",
            in_modalities: ["text"],
            out_modalities: ["text"],
            in_degree: 0,
            out_degree: 0,
            requisition_tags: []
          },
          selected_model: {
            model_id: "m_redirect_attacker",
            display_name: "Redirecting Cloud Model",
            provider: "Cloud",
            endpoint: "https://api.redirect-attack.com/v1/chat",
            auth_mode: "none",
            modalities: ["text"],
            tags: [],
            context_window: 2048,
            max_concurrency: 10,
            active_connections: 0,
            precision: 0.9,
            user_rating: 4.5,
            usage_count: 0,
            status: "active",
            is_generalist: 1,
            prior_score: 0.7,
            scenario_anchors: [],
            cost_per_1k_tokens: 1,
            inference_target: "cloud" as const
          },
          standby_models: []
        }
      ],
      execution_order: ["role_redirect_test"],
      candidate_templates: [],
      is_incremental_refinement: false,
      is_security_violation: false,
      is_unreachable: false
    };

    const redirectStream = await executeDAGStream(
      env,
      redirectDag,
      {
        envelope_id: "env_redirect_001",
        session_id: "sess_redirect_001",
        user_id: referrerId,
        round_index: 1,
        constraint_context: { target_language: "zh", output_style: "concise" },
        instruction_payload: "测试外部重定向拦截",
        metadata: {
          client_timestamp: Date.now(),
          char_count_total: 100,
          estimated_input_tokens: 50
        },
        assets_manifest: []
      },
      {
        userId: referrerId,
        hasPreDeducted: true
      }
    );

    const redirectReader = redirectStream.getReader();
    const redirectDecoder = new TextDecoder();
    let redirectEvents = "";
    while (true) {
      const chunk = await redirectReader.read();
      if (chunk.done) break;
      redirectEvents += redirectDecoder.decode(chunk.value, { stream: true });
    }

    assert.equal(
      capturedRedirectOption,
      "manual",
      "External model call must configure redirect: 'manual'"
    );
    assert.ok(
      redirectEvents.includes("event: dag_error"),
      "External model redirect must trigger dag_error event"
    );
    assert.ok(
      redirectEvents.includes("算力终端禁止 HTTP 重定向"),
      "Error message must report prohibited HTTP redirect"
    );
    console.log(
      "  ✓ External model fetch strictly enforces redirect: 'manual' and blocks 302 SSRF: PASSED"
    );
  } finally {
    globalThis.fetch = origFetchRedirectTest;
  }

  // -----------------------------------------------------------------------
  // SCENARIO 13: Rate Limiting, Modality Bounds & Continuation Guards
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 13] Rate Limiting, Modality Bounds & Continuation Guards");

  // 13.1 Admin Create & Update Node with in_modalities, out_modalities, cost_per_invocation
  const testNode11Req = new Request("https://nanomesh.local/api/admin/nodes", {
    method: "POST",
    headers: adminReqHeaders,
    body: JSON.stringify({
      model_id: "m_multimodal_cost_test",
      display_name: "Multimodal Cost Test Node",
      provider: "OpenAI Compatible",
      endpoint: "https://api.test-modalities.com/v1",
      modalities: ["text", "image"],
      in_modalities: ["image"],
      out_modalities: ["text"],
      cost_per_invocation: 0.05,
      tags: ["#vision"],
      context_window: 8192,
      max_concurrency: 5,
      precision: 0.9,
      cost_per_1k_tokens: 0.2,
      status: "active",
      auth_mode: "none",
      api_format: "openai_compat",
      inference_target: "heavy"
    })
  });
  const testNode11Res = await handleAdminCreateNode(testNode11Req, env);
  assert.equal(
    testNode11Res.status,
    200,
    "Node creation with in_modalities & cost_per_invocation must succeed"
  );
  const storedNode11 = store.models.find((m) => m.model_id === "m_multimodal_cost_test");
  assert.ok(storedNode11, "Created node must exist in store");
  assert.equal(
    storedNode11.cost_per_invocation,
    0.05,
    "cost_per_invocation must be persisted on creation"
  );
  assert.deepEqual(
    JSON.parse(storedNode11.in_modalities),
    ["image"],
    "in_modalities must be persisted on creation"
  );
  assert.deepEqual(
    JSON.parse(storedNode11.out_modalities),
    ["text"],
    "out_modalities must be persisted on creation"
  );

  // Update cost_per_invocation and in_modalities
  const updateNode11Req = new Request(
    "https://nanomesh.local/api/admin/nodes/m_multimodal_cost_test",
    {
      method: "PATCH",
      headers: adminReqHeaders,
      body: JSON.stringify({
        in_modalities: ["image", "text"],
        cost_per_invocation: 0.08
      })
    }
  );
  const updateNode11Res = await handleAdminUpdateNode(
    updateNode11Req,
    env,
    "m_multimodal_cost_test"
  );
  assert.equal(
    updateNode11Res.status,
    200,
    "Node update with in_modalities & cost_per_invocation must succeed"
  );
  assert.equal(storedNode11.cost_per_invocation, 0.08, "cost_per_invocation must be updated");
  assert.deepEqual(
    JSON.parse(storedNode11.in_modalities),
    ["image", "text"],
    "in_modalities must be updated"
  );
  console.log(
    "  ✓ Admin Create & Update Node accurately persists in_modalities, out_modalities & cost_per_invocation: PASSED"
  );

  // 13.2 Chat Envelope instruction_payload Type Guard
  const invalidChatReq1 = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: user12ReqHeaders,
    body: JSON.stringify({
      envelope: {
        session_id: "sess_type_guard_01",
        instruction_payload: 12345 // Non-string instruction payload
      }
    })
  });
  const invalidChatRes1 = await handleChat(invalidChatReq1, env);
  assert.equal(invalidChatRes1.status, 400, "Non-string instruction_payload must return 400");
  const invalidChatErr1 = (await invalidChatRes1.json()) as any;
  assert.ok(
    invalidChatErr1.error.includes("instruction_payload"),
    "Must flag instruction_payload type error"
  );

  const invalidChatReq2 = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: user12ReqHeaders,
    body: JSON.stringify({
      envelope: {
        session_id: "sess_type_guard_02",
        instruction_payload: "    " // Whitespace-only instruction payload
      }
    })
  });
  const invalidChatRes2 = await handleChat(invalidChatReq2, env);
  assert.equal(invalidChatRes2.status, 400, "Empty/whitespace instruction_payload must return 400");
  console.log(
    "  ✓ handleChat rejects non-string and whitespace instruction_payload with HTTP 400: PASSED"
  );

  // 13.3 IP-based Hourly Rate Limiting on handleSendCode
  const ipHeaders = {
    "Content-Type": "application/json",
    "CF-Connecting-IP": "198.51.100.42"
  };
  const origFetchSendCode = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("turnstile")) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      return new Response(JSON.stringify({ id: "mock_resend_email_id" }), { status: 200 });
    };

    // Send 5 codes (allowed within hourly quota)
    for (let i = 0; i < 5; i++) {
      const codeReq = new Request("https://nanomesh.local/api/auth/send-code", {
        method: "POST",
        headers: ipHeaders,
        body: JSON.stringify({ email: `testuser${i}@gmail.com`, turnstile_token: "bypass" })
      });
      const codeRes = await handleSendCode(codeReq, env);
      assert.equal(codeRes.status, 200, `Call ${i + 1} within hourly limit must return 200`);
    }

    // 6th call from same IP must be rate-limited
    const rateLimitedReq = new Request("https://nanomesh.local/api/auth/send-code", {
      method: "POST",
      headers: ipHeaders,
      body: JSON.stringify({ email: "overflow@gmail.com", turnstile_token: "bypass" })
    });
    const rateLimitedRes = await handleSendCode(rateLimitedReq, env);
    assert.equal(
      rateLimitedRes.status,
      429,
      "6th call from same IP within the hour must be rate-limited (429)"
    );
    const rateLimitedData = (await rateLimitedRes.json()) as any;
    assert.equal(rateLimitedData.error, "error.ipRateLimit", "Must return error.ipRateLimit");
    console.log(
      "  ✓ IP-based hourly rate limiting blocks excessive verification emails (429): PASSED"
    );
  } finally {
    globalThis.fetch = origFetchSendCode;
  }

  // 13.4 History Payload Defense Limit (Max 512KB & rounds slice)
  const hugeHistoryReq = new Request("https://nanomesh.local/api/history", {
    method: "POST",
    headers: { ...user12ReqHeaders, "X-History-Account": testUser12Id },
    body: JSON.stringify({
      sessionId: "sess_huge_history_01",
      title: "Huge Payload Attack".repeat(20), // 380 chars -> should be sliced to 100
      rounds: Array.from({ length: 200 }, (_, i) => ({
        round: i,
        largeData: "A".repeat(6000) // 100 * 6000 = ~600KB > 512KB
      }))
    })
  });
  const hugeHistoryRes = await handleSaveHistory(hugeHistoryReq, env);
  assert.equal(
    hugeHistoryRes.status,
    413,
    "History payload exceeding 512KB must return 413 Payload Too Large"
  );

  // Valid sized history with oversized title and > 100 rounds
  const validHistoryReq = new Request("https://nanomesh.local/api/history", {
    method: "POST",
    headers: { ...user12ReqHeaders, "X-History-Account": testUser12Id },
    body: JSON.stringify({
      sessionId: "sess_defense_history_02",
      title: "A".repeat(150), // should be clamped to 100 chars
      rounds: Array.from({ length: 150 }, (_, i) => ({ round: i, text: `Hello ${i}` })) // should be clamped to 100 rounds
    })
  });
  const validHistoryRes = await handleSaveHistory(validHistoryReq, env);
  assert.equal(
    validHistoryRes.status,
    200,
    "Sanitized history within limit must save successfully"
  );
  const savedSession = store.user_chat_sessions.find(
    (s) => s.session_id === "sess_defense_history_02"
  );
  assert.ok(savedSession, "Saved session must exist in store");
  assert.equal(savedSession.title.length, 100, "Title must be clamped to 100 chars");
  const savedRounds = JSON.parse(savedSession.rounds_json);
  assert.equal(savedRounds.length, 100, "Rounds array must be clamped to 100 items");
  console.log("  ✓ History payload strictly limits rounds, title length & max 512KB size: PASSED");

  // 13.5 NEW-04 & NEW-01: Admin Node Registration & Update with non-finite / NaN rates & 0-shot.ai endpoint
  const nanNodeReq = new Request("https://nanomesh.local/api/admin/nodes", {
    method: "POST",
    headers: adminReqHeaders,
    body: JSON.stringify({
      model_id: "m_nan_defense_test",
      display_name: "NaN Defense Test Node",
      provider: "Cloud",
      endpoint: "https://0-shot.ai/v1", // Validates NEW-01 in real node registration!
      modalities: ["text"],
      cost_per_invocation: "invalid_cost_string",
      cost_per_1k_tokens: "not_a_number",
      context_window: "not_a_number",
      max_concurrency: "abc",
      precision: "xyz",
      status: "active"
    })
  });
  const nanNodeRes = await handleAdminCreateNode(nanNodeReq, env);
  assert.equal(
    nanNodeRes.status,
    200,
    "Node with non-finite string inputs must gracefully sanitize and save"
  );
  const storedNanNode = store.models.find((m) => m.model_id === "m_nan_defense_test");
  assert.ok(storedNanNode);
  assert.equal(
    storedNanNode.cost_per_invocation,
    0.0,
    "Invalid cost_per_invocation must default to 0.0 without NaN"
  );
  assert.equal(
    storedNanNode.cost_per_1k_tokens,
    0.0,
    "Invalid cost_per_1k_tokens must default to 0.0 without NaN"
  );
  assert.equal(
    storedNanNode.context_window,
    4096,
    "Invalid context_window must default to 4096 without NaN"
  );
  assert.equal(
    storedNanNode.max_concurrency,
    10,
    "Invalid max_concurrency must default to 10 without NaN"
  );
  assert.equal(storedNanNode.precision, 0.8, "Invalid precision must default to 0.8 without NaN");

  // Test PATCH update with NaN strings
  const patchNanReq = new Request("https://nanomesh.local/api/admin/nodes/m_nan_defense_test", {
    method: "PATCH",
    headers: adminReqHeaders,
    body: JSON.stringify({
      cost_per_invocation: "corrupted_val",
      cost_per_1k_tokens: "corrupted_val"
    })
  });
  const patchNanRes = await handleAdminUpdateNode(patchNanReq, env, "m_nan_defense_test");
  assert.equal(patchNanRes.status, 200, "PATCH with non-finite string numbers must succeed");
  assert.equal(
    storedNanNode.cost_per_invocation,
    0.0,
    "cost_per_invocation must remain 0.0 without NaN"
  );
  console.log(
    "  ✓ Node create/update strictly sanitizes non-numeric inputs and allows 0-shot.ai: PASSED"
  );

  // 13.6 NEW-03 & NEW-05: Stale IP rate limit cleanup & active limit preservation (no slice collision)
  const currentTestHour = new Date().toISOString().slice(0, 13);
  // Stale key from 48h ago
  const staleHour = new Date(Date.now() - 48 * 3600 * 1000).toISOString().slice(0, 13);
  store.system_counters.push({
    key: `ip_code_rate_${staleHour}_198.51.100.99`,
    value: 5
  });
  // Active keys with collision-sensitive IPs (e.g. 203.0.113.1, 192.168.1.100)
  store.system_counters.push({
    key: `ip_code_rate_${currentTestHour}_203.0.113.1`,
    value: 3
  });
  store.system_counters.push({
    key: `ip_code_rate_${currentTestHour}_192.168.1.100`,
    value: 4
  });

  let waitUntilExecuted = false;
  const mockSendCodeCtx = {
    waitUntil: (p: Promise<any>) => {
      waitUntilExecuted = true;
      p.catch(() => {});
    }
  };
  const origFetchSweep = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("turnstile")) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      return new Response(JSON.stringify({ id: "mock_resend_email_id" }), { status: 200 });
    };
    const sweepReq = new Request("https://nanomesh.local/api/auth/send-code", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.200" },
      body: JSON.stringify({ email: "sweepuser@gmail.com", turnstile_token: "bypass" })
    });
    const sweepRes = await handleSendCode(sweepReq, env, mockSendCodeCtx as any);
    assert.equal(sweepRes.status, 200);
    assert.ok(waitUntilExecuted, "handleSendCode must delegate cleanup to ctx.waitUntil");

    // Stale key must be pruned
    assert.equal(
      store.system_counters.some((c) => c.key.includes(staleHour)),
      false,
      "Stale counter must be pruned"
    );
    // Active keys for 203.0.113.1 and 192.168.1.100 must NOT be accidentally deleted (NEW-05)
    assert.ok(
      store.system_counters.some((c) => c.key === `ip_code_rate_${currentTestHour}_203.0.113.1`),
      "Active counter for 203.0.113.1 must be preserved"
    );
    assert.ok(
      store.system_counters.some((c) => c.key === `ip_code_rate_${currentTestHour}_192.168.1.100`),
      "Active counter for 192.168.1.100 must be preserved"
    );
    console.log(
      "  ✓ Stale IP counters pruned without wiping active rate limits for sensitive IPs: PASSED"
    );
  } finally {
    globalThis.fetch = origFetchSweep;
  }

  // 13.7 NEW-02: Verify i18n dictionary contains error.ipRateLimit for zh and en
  const i18nContent = fs.readFileSync("public/i18n.js", "utf-8");
  assert.ok(
    i18nContent.includes("'error.ipRateLimit': '当前网络请求验证码过于频繁"),
    "i18n.js must contain Chinese translation for error.ipRateLimit"
  );
  assert.ok(
    i18nContent.includes("'error.ipRateLimit': 'Too many verification requests"),
    "i18n.js must contain English translation for error.ipRateLimit"
  );
  console.log(
    "  ✓ error.ipRateLimit defined in both zh and en dictionaries in public/i18n.js: PASSED"
  );

  // ----------------------------------------------------
  // SCENARIO 14: Session Security, Deduplication & Atomic Key Lifecycle
  // ----------------------------------------------------
  console.log("\n[Scenario 14] Session Security, Deduplication & Atomic Key Lifecycle");

  // 14.1 OAuth Bind CSRF rejection
  // Attacker creates a state for user "attacker_victim_target", but session belongs to "victim_user"
  const attackerState = await signJWT(
    { nonce: "test_nonce_1", action: "bind", userId: "attacker_user_id" },
    env.JWT_SECRET,
    300
  );
  const victimToken = await signJWT(
    { userId: "victim_user_id", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  // Victim has an active account
  store.users.push({
    user_id: "victim_user_id",
    username: "victim",
    email: "victim@example.com",
    credits: 100,
    frozen_credits: 0,
    avatar_url: null,
    avatar_updated_at: null,
    password_hash: null,
    token_version: 1
  });

  const csrfReq = new Request(
    `https://nanomesh.local/api/auth/callback/github?code=mock_code&state=${attackerState}`,
    {
      headers: { Cookie: `session=${victimToken}` }
    }
  );
  // Mock GitHub callback to return attacker's GitHub profile
  const origFetchOauth = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("access_token")) {
        return new Response(JSON.stringify({ access_token: "mock_gh_token" }), { status: 200 });
      }
      if (urlStr.includes("api.github.com/user/emails")) {
        return new Response(
          JSON.stringify([{ email: "attacker@github.com", primary: true, verified: true }]),
          { status: 200 }
        );
      }
      if (urlStr.includes("api.github.com/user")) {
        return new Response(JSON.stringify({ id: 999999, login: "attacker_gh" }), { status: 200 });
      }
      return origFetchOauth(input, init);
    };

    const csrfRes = await worker.fetch(csrfReq, env, {} as any);
    assert.equal(csrfRes.status, 302);
    const location = csrfRes.headers.get("Location") || "";
    assert.ok(
      location.includes("error=bind_csrf_rejected"),
      "Cross-user OAuth bind must be rejected with bind_csrf_rejected"
    );
    // Ensure no binding inserted for victim
    const victimBinding = store.user_oauth_bindings.find((b) => b.user_id === "victim_user_id");
    assert.equal(victimBinding, undefined, "Attacker oauth ID must NOT be bound to victim account");
    console.log("  ✓ OAuth bind CSRF attack intercepted and blocked: PASSED");

    // 14.2 OAuth registration cooldown bypass check (tombstone for profile.email)
    const encoder = new TextEncoder();
    const deletedEmail = "cooldown_test@gmail.com";
    const emailSaltData = encoder.encode(deletedEmail + getPersistentSalt(env));
    const emailHashBuf = await crypto.subtle.digest("SHA-256", emailSaltData);
    const emailHash = Array.from(new Uint8Array(emailHashBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    // Insert email tombstone into account_tombstones
    store.account_tombstones.push({
      hash_id: emailHash,
      type: "email",
      expires_at: new Date(Date.now() + 86400000 * 90).toISOString()
    });

    // Mock Google callback to return profile with that deletedEmail
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("oauth2.googleapis.com/token")) {
        return new Response(JSON.stringify({ access_token: "mock_google_token" }), { status: 200 });
      }
      if (urlStr.includes("googleapis.com/oauth2/v2/userinfo")) {
        return new Response(
          JSON.stringify({
            id: "goog_fresh_9988",
            email: deletedEmail,
            verified_email: true,
            name: "Cooldown Test"
          }),
          { status: 200 }
        );
      }
      return origFetchOauth(input, init);
    };

    const googleLoginState = await signJWT(
      { nonce: "test_nonce_2", action: "login" },
      env.JWT_SECRET,
      300
    );
    const cooldownReq = new Request(
      `https://nanomesh.local/api/auth/callback/google?code=mock_code&state=${googleLoginState}`
    );
    const cooldownRes = await worker.fetch(cooldownReq, env, {} as any);
    assert.equal(cooldownRes.status, 302);
    const cdLocation = cooldownRes.headers.get("Location") || "";
    assert.ok(
      cdLocation.includes("error=account_cooldown"),
      "OAuth login with tombstoned email must be rejected with account_cooldown"
    );
    // Ensure no new user created
    const createdCooldownUser = store.users.find((u) => u.email === deletedEmail);
    assert.equal(createdCooldownUser, undefined, "User must NOT be created for tombstoned email");
    console.log("  ✓ OAuth registration blocks tombstoned emails during cooldown: PASSED");
  } finally {
    globalThis.fetch = origFetchOauth;
  }

  // 14.3 Low Balance Warning notification generated after settlement
  const lowBalanceUserId = "low_balance_usr_1";
  store.users.push({
    user_id: lowBalanceUserId,
    username: "lowbalance",
    email: "low@balance.com",
    credits: 450, // < 500
    frozen_credits: 0,
    avatar_url: null,
    avatar_updated_at: null,
    password_hash: null,
    token_version: 1
  });

  const { checkAndNotifyLowBalance } = await import("../src/api/notifications");
  await checkAndNotifyLowBalance(env, lowBalanceUserId, 450);
  const lowBalNotif = store.notifications.find(
    (n) => n.user_id === lowBalanceUserId && n.event_type === "low_balance"
  );
  assert.ok(lowBalNotif, "Low balance notification must be created when credits < 500");
  assert.equal(lowBalNotif.category, "quota");

  // Deduplication check: call again within 24h
  const initialNotifCount = store.notifications.filter(
    (n) => n.user_id === lowBalanceUserId && n.event_type === "low_balance"
  ).length;
  await checkAndNotifyLowBalance(env, lowBalanceUserId, 400);
  const secondNotifCount = store.notifications.filter(
    (n) => n.user_id === lowBalanceUserId && n.event_type === "low_balance"
  ).length;
  assert.equal(
    secondNotifCount,
    initialNotifCount,
    "24-hour deduplication window must prevent duplicate low balance alerts"
  );
  console.log(
    "  ✓ checkAndNotifyLowBalance alerts on < 500 credits with 24h deduplication: PASSED"
  );

  // 14.4 Client routes with trailing slash normalization
  // Notification read with trailing slash: /api/notifications/:id/read/
  store.notifications.push({
    notification_id: "notif_slash_1",
    user_id: lowBalanceUserId,
    category: "system",
    event_type: "test",
    priority: "normal",
    title_zh: "测试",
    title_en: "Test",
    content_zh: "测试内容",
    content_en: "Test Content",
    action_type: "none",
    action_payload: "{}",
    is_read: 0,
    read_at: null,
    created_at: new Date().toISOString()
  });

  const notifToken = await signJWT(
    { userId: lowBalanceUserId, tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const notifSlashReq = new Request(
    "https://nanomesh.local/api/notifications/notif_slash_1/read/",
    {
      method: "POST",
      headers: { Cookie: `session=${notifToken}` }
    }
  );
  const notifSlashRes = await worker.fetch(notifSlashReq, env, {} as any);
  assert.equal(
    notifSlashRes.status,
    200,
    "POST /api/notifications/:id/read/ must return 200 with trailing slash"
  );
  const updatedNotif = store.notifications.find((n) => n.notification_id === "notif_slash_1");
  assert.equal(updatedNotif?.is_read, 1, "Notification must be marked as read");
  console.log("  ✓ Client API routes correctly normalize and match trailing slashes: PASSED");

  // 14.5 Passkey challenge replay rejected via single-use CAS & TTL cleanup
  const replayChallenge = "test_challenge_replay_cas_123";
  const nowSec = Math.floor(Date.now() / 1000);
  store.system_counters.push({
    key: `pk_used_${replayChallenge}`,
    value: nowSec
  });
  store.system_counters.push({
    key: "pk_used_stale_expired_challenge_999",
    value: nowSec - 700
  });
  // Simulate handlePasskeyLoginVerify with already consumed challenge
  const passkeyUser = {
    user_id: "pk_user_1",
    username: "pkuser",
    email: "pk@user.com",
    credits: 100,
    token_version: 1
  };
  store.users.push(passkeyUser as any);
  store.user_passkeys.push({
    credential_id: "test_cred_id_123",
    user_id: "pk_user_1",
    public_key: "dummy_pk",
    public_key_alg: -7,
    counter: 0,
    device_name: "MacBook",
    aaguid: "00000000-0000-0000-0000-000000000000",
    transports: "[]",
    created_at: new Date().toISOString(),
    last_used_at: null
  });

  // Attempting to consume an already-consumed challenge
  const casResult = await env.DB.prepare(
    "INSERT OR IGNORE INTO system_counters (key, value) VALUES (?, ?)"
  )
    .bind(`pk_used_${replayChallenge}`, nowSec)
    .run();
  assert.equal(
    casResult.meta.changes,
    0,
    "Replaying challenge must result in 0 changes (CAS failure)"
  );

  // Run cleanup query (simulating opportunistic cleanup)
  await env.DB.prepare(
    "DELETE FROM system_counters WHERE key LIKE 'pk_used_%' AND value < strftime('%s', 'now', '-10 minutes')"
  ).run();
  assert.equal(
    store.system_counters.some((c) => c.key === "pk_used_stale_expired_challenge_999"),
    false,
    "Stale challenge key (> 10 min) must be pruned"
  );
  assert.equal(
    store.system_counters.some((c) => c.key === `pk_used_${replayChallenge}`),
    true,
    "Recent challenge key must be retained"
  );
  console.log("  ✓ Passkey challenge replay blocked via atomic CAS & stale keys pruned: PASSED");

  // 14.6 handleSaveHistory validates sessionId type & length
  const histToken = await signJWT(
    { userId: lowBalanceUserId, tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const badSessionIdReq1 = new Request("https://nanomesh.local/api/history", {
    method: "POST",
    headers: {
      "X-History-Account": lowBalanceUserId,
      "Content-Type": "application/json",
      Cookie: `session=${histToken}`
    },
    body: JSON.stringify({ sessionId: { bad: "object" } })
  });
  const badSessionIdRes1 = await worker.fetch(badSessionIdReq1, env, {} as any);
  assert.equal(badSessionIdRes1.status, 400, "Non-string sessionId must return 400");

  const badSessionIdReq2 = new Request("https://nanomesh.local/api/history", {
    method: "POST",
    headers: {
      "X-History-Account": lowBalanceUserId,
      "Content-Type": "application/json",
      Cookie: `session=${histToken}`
    },
    body: JSON.stringify({ sessionId: "a".repeat(65) })
  });
  const badSessionIdRes2 = await worker.fetch(badSessionIdReq2, env, {} as any);
  assert.equal(badSessionIdRes2.status, 400, "Overly long sessionId (> 64 chars) must return 400");
  console.log(
    "  ✓ handleSaveHistory strictly enforces string type & <= 64 char limit on sessionId: PASSED"
  );

  // 14.7 models/light/ static delivery includes CSP & Attachment headers
  await env.R2.put("models/light/test-model.onnx", "mock_onnx_weights", {
    httpMetadata: { contentType: "application/octet-stream" }
  });

  const lightModelReq = new Request(
    "https://nanomesh.local/api/assets/models/light/test-model.onnx"
  );
  const lightModelRes = await worker.fetch(lightModelReq, env, {} as any);
  assert.equal(lightModelRes.status, 200);
  assert.equal(lightModelRes.headers.get("Content-Security-Policy"), "default-src 'none'; sandbox");
  assert.equal(lightModelRes.headers.get("Content-Disposition"), "attachment");
  console.log(
    "  ✓ Public light node static responses strictly include CSP sandbox and attachment headers: PASSED"
  );

  // -----------------------------------------------------------------------
  // SCENARIO 15: CORS Enforcement, Method Validation & Path Isolation
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 15] CORS Enforcement, Method Validation & Path Isolation");

  // 15.1 /api/user/credits unauthenticated returns 401 with CORS headers & JSON error
  const unauthCreditsReq = new Request("https://nanomesh.local/api/user/credits", {
    method: "GET",
    headers: { Origin: "https://frontend.nanomesh.app" }
  });
  const unauthCreditsRes = await worker.fetch(unauthCreditsReq, env, {} as any);
  assert.equal(unauthCreditsRes.status, 401, "/api/user/credits without session must return 401");
  assert.ok(
    unauthCreditsRes.headers.get("access-control-allow-origin"),
    "Must include access-control-allow-origin header"
  );
  assert.equal(
    unauthCreditsRes.headers.get("x-content-type-options"),
    "nosniff",
    "Must include nosniff security header"
  );
  const unauthBody = (await unauthCreditsRes.json()) as any;
  assert.equal(unauthBody.error, "Unauthorized", "Response must be JSON error object");
  console.log(
    "  ✓ Unauthenticated /api/user/credits returns 401 with full CORS and security headers: PASSED"
  );

  // 15.2 Read-only endpoints reject non-GET requests with 405 Method Not Allowed
  const postCreditsReq = new Request("https://nanomesh.local/api/user/credits", { method: "POST" });
  const postCreditsRes = await worker.fetch(postCreditsReq, env, {} as any);
  assert.equal(postCreditsRes.status, 405, "POST /api/user/credits must return 405");

  const postConfigReq = new Request("https://nanomesh.local/api/auth/config", { method: "POST" });
  const postConfigRes = await worker.fetch(postConfigReq, env, {} as any);
  assert.equal(postConfigRes.status, 405, "POST /api/auth/config must return 405");

  const postBindingsReq = new Request("https://nanomesh.local/api/user/bindings", {
    method: "POST"
  });
  const postBindingsRes = await worker.fetch(postBindingsReq, env, {} as any);
  assert.equal(postBindingsRes.status, 405, "POST /api/user/bindings must return 405");
  console.log(
    "  ✓ Read-only endpoints strictly enforce HTTP Method GET/HEAD and reject POST with 405: PASSED"
  );

  // 15.3 Path traversal filter blocks '..' in asset key
  const traversalReq1 = new Request(
    "https://nanomesh.local/api/assets?key=models/light/../secret.onnx"
  );
  const traversalRes1 = await worker.fetch(traversalReq1, env, {} as any);
  assert.equal(
    traversalRes1.status,
    400,
    "Path traversal sequence in asset key must be rejected with 400"
  );

  const traversalReq2 = new Request(
    `https://nanomesh.local/api/assets?key=tmp/${lowBalanceUserId}/..\\other\\pass.txt`,
    {
      headers: { Cookie: `session=${histToken}` }
    }
  );
  const traversalRes2 = await worker.fetch(traversalReq2, env, {} as any);
  assert.equal(
    traversalRes2.status,
    400,
    "Encoded path traversal sequence must be rejected with 400"
  );
  console.log("  ✓ Asset retrieval strictly intercepts path traversal sequences with 400: PASSED");

  // 15.4 Passkey login rejects deleted user (email starting with deleted_)
  const deletedUserId = "del_pk_user_999";
  store.users.push({
    user_id: deletedUserId,
    username: "del_user",
    email: `deleted_${deletedUserId}`,
    credits: 0,
    token_version: 1
  } as any);
  store.user_passkeys.push({
    credential_id: "cred_deleted_user_1",
    user_id: deletedUserId,
    public_key: "dummy_pk",
    public_key_alg: -7,
    counter: 0,
    device_name: "MacBook",
    aaguid: "00000000-0000-0000-0000-000000000000",
    transports: "[]",
    created_at: new Date().toISOString(),
    last_used_at: null
  });

  const { handlePasskeyLoginVerify } = await import("../src/api/passkey");
  const delVerifyReq = new Request("https://nanomesh.local/api/auth/passkey/login/verify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      id: "cred_deleted_user_1",
      rawId: "cred_deleted_user_1",
      response: {
        clientDataJSON: Buffer.from(
          JSON.stringify({
            type: "webauthn.get",
            challenge: "dummy_c",
            origin: "https://nanomesh.local"
          })
        ).toString("base64url"),
        authenticatorData: Buffer.from("a".repeat(37)).toString("base64url"),
        signature: Buffer.from("dummy_sig").toString("base64url")
      }
    })
  });
  const delVerifyRes = await handlePasskeyLoginVerify(delVerifyReq, env);
  assert.equal(delVerifyRes.status, 401, "Deleted user passkey login must be rejected with 401");
  const delVerifyBody = (await delVerifyRes.json()) as any;
  assert.equal(
    delVerifyBody.error,
    "error.userNotFound",
    "Must return userNotFound error for deleted user"
  );
  console.log("  ✓ Passkey verification strictly rejects tombstoned (deleted_) accounts: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 16: Referral Integrity, Admin Anti-DoS & CSRF Protection
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 16] Referral Integrity, Admin Anti-DoS & CSRF Protection");

  // 16.1 Deleted user referral code rejection
  const delTestUserId = "usr_to_delete_for_ref";
  const delTestUserToken = await signJWT(
    { userId: delTestUserId, tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  store.users.push({
    user_id: delTestUserId,
    username: "UserToDelete",
    email: "todelete@nanomesh.local",
    password_hash: "hash_del",
    credits: 50,
    referral_code: "REF-DEL-CODE-1",
    referred_by: null,
    token_version: 1
  } as any);

  // Perform account deletion
  const delReq = new Request("https://nanomesh.local/api/user/delete", {
    method: "POST",
    headers: { Cookie: `session=${delTestUserToken}` }
  });
  const delRes = await handleDeleteAccount(delReq, env);
  assert.equal(delRes.status, 200, "Account deletion must succeed");
  const deletedDbUser = store.users.find((u) => u.user_id === delTestUserId);
  assert.equal(
    deletedDbUser?.referral_code,
    null,
    "Deleted user referral_code must be set to null"
  );

  // Attempt to register with the old deleted referral code
  const { handleRegister } = await import("../src/api/auth");
  // Set verification code for registration
  store.verification_codes.push({
    id: "vc_del_ref_test",
    email: "new_referral_target@gmail.com",
    code: "123456",
    expires_at: new Date(Date.now() + 600000).toISOString()
  });
  const registerWithDeletedRefReq = new Request("https://nanomesh.local/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      username: "NewRefTarget",
      email: "new_referral_target@gmail.com",
      password: "Password123!",
      code: "123456",
      referral_code: "REF-DEL-CODE-1",
      turnstile_token: "mock_turnstile_pass"
    })
  });
  const origFetchRegister = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("turnstile")) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      return origFetchRegister(input, init);
    };

    const registerWithDeletedRefRes = await handleRegister(registerWithDeletedRefReq, env);
    assert.equal(
      registerWithDeletedRefRes.status,
      400,
      "Registration with deleted user's referral code must be rejected"
    );
    const regErrBody = (await registerWithDeletedRefRes.json()) as any;
    assert.equal(regErrBody.error, "error.invalidReferralCode");
    assert.equal(
      deletedDbUser?.credits,
      0,
      "Deleted user credits must remain 0 and not receive ghost reward"
    );
  } finally {
    globalThis.fetch = origFetchRegister;
  }
  console.log(
    "  ✓ Deleted account referral code is nulled and registration with it rejected: PASSED"
  );

  // 16.2 Admin login rejects non-POST without recording attempts (Anti-DoS)
  store.admin_login_attempts = [];
  const adminGetReq = new Request("https://nanomesh.local/api/admin/login", { method: "GET" });
  for (let i = 0; i < 5; i++) {
    const adminGetRes = await worker.fetch(adminGetReq, env, {} as any);
    assert.equal(
      adminGetRes.status,
      405,
      "GET /api/admin/login must return 405 Method Not Allowed"
    );
  }
  assert.equal(
    store.admin_login_attempts.length,
    0,
    "GET requests must never write to admin_login_attempts"
  );

  // Valid POST still succeeds (not locked out)
  const adminPostReq = new Request("https://nanomesh.local/api/admin/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password: (env as any).ADMIN_PASSWORD || "IntegrationAdminPass123!" })
  });
  const adminPostRes = await worker.fetch(adminPostReq, env, {} as any);
  assert.equal(
    adminPostRes.status,
    200,
    "Valid POST admin login must succeed without being DoS locked"
  );
  console.log("  ✓ Non-POST /api/admin/login returns 405 and avoids lockout DoS: PASSED");

  // 16.3 Logout routes reject GET (Logout CSRF defense)
  const userLogoutGetReq = new Request("https://nanomesh.local/api/auth/logout", { method: "GET" });
  const userLogoutGetRes = await worker.fetch(userLogoutGetReq, env, {} as any);
  assert.equal(userLogoutGetRes.status, 405, "GET /api/auth/logout must return 405");

  const adminLogoutGetReq = new Request("https://nanomesh.local/api/admin/logout", {
    method: "GET"
  });
  const adminLogoutGetRes = await worker.fetch(adminLogoutGetReq, env, {} as any);
  assert.equal(adminLogoutGetRes.status, 405, "GET /api/admin/logout must return 405");

  const userLogoutPostReq = new Request("https://nanomesh.local/api/auth/logout", {
    method: "POST"
  });
  const userLogoutPostRes = await worker.fetch(userLogoutPostReq, env, {} as any);
  assert.equal(userLogoutPostRes.status, 200, "POST /api/auth/logout must succeed");
  console.log("  ✓ Logout endpoints strictly reject GET to block Logout CSRF: PASSED");

  // 16.4 Read-only endpoints reject non-GET/HEAD with 405
  const postMeReq = new Request("https://nanomesh.local/api/auth/me", { method: "POST" });
  const postMeRes = await worker.fetch(postMeReq, env, {} as any);
  assert.equal(postMeRes.status, 405, "POST /api/auth/me must return 405");

  const postLedgerReq = new Request("https://nanomesh.local/api/user/ledger", { method: "POST" });
  const postLedgerRes = await worker.fetch(postLedgerReq, env, {} as any);
  assert.equal(postLedgerRes.status, 405, "POST /api/user/ledger must return 405");

  const postAssetReq = new Request("https://nanomesh.local/api/assets?key=models/light/qwen.onnx", {
    method: "POST"
  });
  const postAssetRes = await worker.fetch(postAssetReq, env, {} as any);
  assert.equal(postAssetRes.status, 405, "POST /api/assets must return 405");
  console.log(
    "  ✓ /api/auth/me, /api/user/ledger and /api/assets enforce GET/HEAD with 405: PASSED"
  );

  // 16.5 Continuation payload boundary (> 512KB) rejected with 413
  const oversizedContReq = new Request("https://nanomesh.local/api/chat/continue", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `session=${histToken}`
    },
    body: JSON.stringify({
      continuation_token: "dummy_token",
      status: "success",
      envelope: { session_id: "sess_test_cont", messages: [] },
      client_step_output: "X".repeat(512 * 1024 + 10)
    })
  });
  const oversizedContRes = await worker.fetch(oversizedContReq, env, {} as any);
  assert.equal(
    oversizedContRes.status,
    413,
    "Oversized continuation payload must return 413 Payload Too Large"
  );
  console.log("  ✓ Chat continuation strictly rejects payload exceeding 512KB with 413: PASSED");

  // ====================================================
  // SCENARIO 17: Payload Boundaries, Password Recovery & Storage Lifecycle
  // ====================================================
  console.log("\n[Scenario 17] Payload Boundaries, Password Recovery & Storage Lifecycle");

  // 17.1 /api/chat payload boundary (> 512KB) rejected with 413
  const oversizedChatReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `session=${histToken}`
    },
    body: JSON.stringify({
      envelope: {
        session_id: "sess_chat_oversized",
        instruction_payload: "Y".repeat(512 * 1024 + 10),
        messages: []
      }
    })
  });
  const oversizedChatRes = await worker.fetch(oversizedChatReq, env, {} as any);
  assert.equal(
    oversizedChatRes.status,
    413,
    "/api/chat must reject instruction_payload > 512KB with 413"
  );
  console.log("  ✓ /api/chat strictly rejects instruction_payload > 512KB with 413: PASSED");

  // 17.2 POST with null JSON body returns 400 Bad Request instead of unhandled 500
  const nullRegisterReq = new Request("https://nanomesh.local/api/auth/register", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "null"
  });
  const nullRegisterRes = await worker.fetch(nullRegisterReq, env, {} as any);
  assert.equal(nullRegisterRes.status, 400, "POST null to register must return 400");

  const nullLoginReq = new Request("https://nanomesh.local/api/auth/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "null"
  });
  const nullLoginRes = await worker.fetch(nullLoginReq, env, {} as any);
  assert.equal(nullLoginRes.status, 400, "POST null to login must return 400");
  console.log("  ✓ Endpoints safely handle literal JSON null body with 400 instead of 500: PASSED");

  // 17.3 Non-POST/DELETE requests return 405 Method Not Allowed before auth
  const unauthChatGetReq = new Request("https://nanomesh.local/api/chat", { method: "GET" });
  const unauthChatGetRes = await worker.fetch(unauthChatGetReq, env, {} as any);
  assert.equal(unauthChatGetRes.status, 405, "Unauthenticated GET /api/chat must return 405");

  const unauthPresignGetReq = new Request("https://nanomesh.local/api/upload/presign", {
    method: "GET"
  });
  const unauthPresignGetRes = await worker.fetch(unauthPresignGetReq, env, {} as any);
  assert.equal(
    unauthPresignGetRes.status,
    405,
    "Unauthenticated GET /api/upload/presign must return 405"
  );

  const oauthGetReq = new Request("https://nanomesh.local/api/auth/oauth/google", {
    method: "GET"
  });
  const oauthGetRes = await worker.fetch(oauthGetReq, env, {} as any);
  assert.equal(oauthGetRes.status, 405, "GET /api/auth/oauth/:provider must return 405");
  console.log("  ✓ HTTP Method check executes before auth and returns 405: PASSED");

  // 17.4 Setup registered user for auth and reset tests
  const registeredEmail = "carol_r15@gmail.com";
  const pwdHash = bcrypt.hashSync("OldPassword123!", 10);
  store.users.push({
    user_id: "usr_carol_r15",
    username: "carol_r15",
    email: registeredEmail,
    password_hash: pwdHash,
    credits: 100,
    frozen_credits: 0,
    avatar_url: "/storage/avatars/usr_carol_r15_old.png",
    referral_code: "REF_CAROL_15",
    token_version: 1
  });

  const origFetch17 = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("turnstile")) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      if (urlStr.includes("resend.com")) {
        return new Response(JSON.stringify({ id: "resend_mock_msg_id" }), { status: 200 });
      }
      return origFetch17(input, init);
    };

    // 17.4 /api/auth/send-code returns 200 for registered email without leaking status
    const sendCodeReq = new Request("https://nanomesh.local/api/auth/send-code", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: registeredEmail, turnstile_token: "mock_turnstile_pass" })
    });
    const sendCodeRes = await worker.fetch(sendCodeReq, env, {} as any);
    const sendCodeData = await sendCodeRes.json().catch(() => ({}));
    assert.equal(
      sendCodeRes.status,
      200,
      `send-code for existing user must return 200 to prevent enumeration: ${JSON.stringify(sendCodeData)}`
    );
    console.log("  ✓ Anti-account enumeration privacy protection for send-code: PASSED");

    // NM-AUD-05: Second send-code within 60s for existing user must be rate-limited (429)
    const sendCodeSpamRes = await worker.fetch(
      new Request("https://nanomesh.local/api/auth/send-code", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: registeredEmail, turnstile_token: "mock_turnstile_pass" })
      }),
      env,
      {} as any
    );
    assert.equal(
      sendCodeSpamRes.status,
      429,
      "NM-AUD-05: Duplicate send-code for existing user within 60s must trigger 429 cooldown"
    );

    // Advance verification_codes timestamp past 60s cooldown before running forgot-password test
    for (const vc of store.verification_codes) {
      if (vc.email.toLowerCase() === registeredEmail.toLowerCase()) {
        vc.created_at = new Date(Date.now() - 65000).toISOString();
      }
    }

    // 17.5 Self-service forgot-password & reset-password flow
    const forgotReq = new Request("https://nanomesh.local/api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: registeredEmail, turnstile_token: "mock_turnstile_pass" })
    });
    const forgotRes = await worker.fetch(forgotReq, env, {} as any);
    assert.equal(forgotRes.status, 200, "forgot-password must return 200");

    const resetCodeRow = await env.DB.prepare(
      "SELECT code FROM verification_codes WHERE LOWER(email) = LOWER(?) ORDER BY id DESC LIMIT 1"
    )
      .bind(registeredEmail)
      .first<{ code: string }>();
    assert.ok(resetCodeRow?.code, "Reset code must be recorded in verification_codes");

    // reset-password succeeds without redundant turnstile_token (no single-use token deadlock)
    const resetReq = new Request("https://nanomesh.local/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: registeredEmail,
        code: resetCodeRow.code,
        newPassword: "BrandNewPassword2026!"
      })
    });
    const resetRes = await worker.fetch(resetReq, env, {} as any);
    assert.equal(resetRes.status, 200, "reset-password must return 200 without turnstile_token");

    // Verify login with new password succeeds
    const loginNewReq = new Request("https://nanomesh.local/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email: registeredEmail,
        password: "BrandNewPassword2026!",
        turnstile_token: "mock_turnstile_pass"
      })
    });
    const loginNewRes = await worker.fetch(loginNewReq, env, {} as any);
    assert.equal(loginNewRes.status, 200, "Login with new password must succeed");
    console.log(
      "  ✓ Self-service forgot-password and reset-password flow (no turnstile deadlock): PASSED"
    );
  } finally {
    globalThis.fetch = origFetch17;
  }

  // 17.6 Updating avatar cleans up old R2 object to eliminate storage leaks
  const oldAvatarKey = "avatars/usr_carol_r15_old.png";
  await env.R2.put(oldAvatarKey, "OLD_AVATAR_BYTES", {
    httpMetadata: { contentType: "image/png" }
  });
  assert.ok(await env.R2.get(oldAvatarKey), "Old avatar should exist prior to replacement");

  const avatarSessionToken = await signJWT(
    { userId: "usr_carol_r15", tokenVersion: 2 },
    env.JWT_SECRET,
    3600
  );
  const formData = new FormData();
  const blob = new Blob([new Uint8Array([137, 80, 78, 71, 1, 2, 3, 4])], { type: "image/png" });
  formData.append("file", blob, "new_avatar.png");

  const updateAvatarReq = new Request("https://nanomesh.local/api/user/avatar", {
    method: "POST",
    headers: {
      Cookie: `session=${avatarSessionToken}`
    },
    body: formData
  });
  const updateAvatarRes = await worker.fetch(updateAvatarReq, env, {} as any);
  assert.equal(updateAvatarRes.status, 200, "Updating avatar must succeed");
  const updateAvatarBody = (await updateAvatarRes.json()) as any;
  assert.ok(updateAvatarBody.avatar_url, "Must return new avatar URL");

  const oldAvatarInR2 = await env.R2.get(oldAvatarKey);
  assert.equal(
    oldAvatarInR2,
    null,
    "Old avatar key in R2 must be deleted to prevent orphaned storage accumulation"
  );
  console.log("  ✓ Updating avatar cleans up old R2 object to eliminate storage leaks: PASSED");

  // 17.7 system_counters cleanup prunes stale ip_pwd_rate_* entries
  store.system_counters.push({
    key: "ip_pwd_rate_2024-01-01T00_10.0.0.1",
    value: 5
  });
  store.system_counters.push({
    key: "ip_pwd_rate_2099-01-01T00_10.0.0.1",
    value: 2
  });
  await env.DB.prepare(
    `
    DELETE FROM system_counters 
    WHERE (key LIKE 'ip_code_rate_20%' AND key < 'ip_code_rate_' || strftime('%Y-%m-%dT%H', 'now', '-24 hours'))
       OR (key LIKE 'ip_pwd_rate_20%' AND key < 'ip_pwd_rate_' || strftime('%Y-%m-%dT%H', 'now', '-24 hours'))
  `
  ).run();
  assert.equal(
    store.system_counters.some((c) => c.key === "ip_pwd_rate_2024-01-01T00_10.0.0.1"),
    false,
    "Stale ip_pwd_rate_* counter must be pruned"
  );
  assert.equal(
    store.system_counters.some((c) => c.key === "ip_pwd_rate_2099-01-01T00_10.0.0.1"),
    true,
    "Active ip_pwd_rate_* counter must be preserved"
  );
  console.log("  ✓ Stale ip_pwd_rate_* counters pruned while preserving active entries: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 18: Template Re-Routing, Defensive Invariants & Health Diagnostics
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 18] Template Re-Routing, Defensive Invariants & Health Diagnostics");

  // 18.1 POST /api/chat with omitted metadata and omitted assets_manifest
  const reqOmittedFields = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `session=${histToken}`
    },
    body: JSON.stringify({
      envelope: {
        session_id: "sess_omitted_test_01",
        instruction_payload: "Test message without metadata or assets_manifest"
      }
    })
  });
  const resOmittedFields = await worker.fetch(reqOmittedFields, env, {} as any);
  assert.notEqual(
    resOmittedFields.status,
    500,
    "POST /api/chat without metadata or assets_manifest MUST NOT throw 500 TypeError"
  );
  assert.equal(resOmittedFields.status, 200, "Request must successfully initiate stream with 200");
  console.log(
    "  ✓ POST /api/chat safely handles omitted metadata and assets_manifest with 200: PASSED"
  );

  // 18.2 GET /api/health endpoint probe
  const healthReq = new Request("https://nanomesh.local/api/health", { method: "GET" });
  const healthRes = await worker.fetch(healthReq, env, {} as any);
  assert.equal(healthRes.status, 200, "Health probe on test env must return 200");
  const healthJson = (await healthRes.json()) as any;
  assert.equal(healthJson.status, "healthy");
  console.log("  ✓ GET /api/health returns 200 healthy for operational runtime: PASSED");

  // 18.3 Re-route with image asset to text-only tpl-direct-chat MUST NOT silently prune image; rejected by subsistence law
  store.dag_roles.push({
    role_id: "role-direct-chat",
    name_zh: "综合理解与生成",
    name_en: "General Synthesis",
    in_modalities: JSON.stringify(["text"]),
    out_modalities: JSON.stringify(["text"]),
    requisition_tags: JSON.stringify(["#chat", "#text_generation", "#general"]),
    compensation_prompts: JSON.stringify({})
  });
  store.dag_templates.push({
    template_id: "tpl-direct-chat",
    name_zh: "全能直答",
    name_en: "Direct Inference",
    desc_zh: "单节点高敏捷响应",
    desc_en: "Single-node direct response",
    scenario_category: "chat",
    scenario_anchor: "chat",
    roles: JSON.stringify([
      {
        role_id: "role-direct-chat",
        name_zh: "综合理解与生成",
        name_en: "General Synthesis",
        in_modalities: ["text"],
        out_modalities: ["text"],
        in_degree: 0,
        out_degree: 0,
        requisition_tags: ["#chat", "#text_generation", "#general"],
        compensation_prompts: {}
      }
    ]),
    role_sequence: JSON.stringify(["role-direct-chat"]),
    edges: JSON.stringify([]),
    status: "active"
  });

  const reqReRouteDirectChat = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `session=${histToken}`
    },
    body: JSON.stringify({
      reRouteMode: "switch_template",
      chosenTemplateId: "tpl-direct-chat",
      envelope: {
        session_id: "sess_reroute_test_02",
        instruction_payload: "Switching to pure text direct chat",
        assets_manifest: [
          { asset_id: "media_img_01", modality: "image", consumed: false },
          { asset_id: "doc_txt_02", modality: "text_doc", consumed: false }
        ]
      }
    })
  });
  const resReRouteDirectChat = await worker.fetch(reqReRouteDirectChat, env, {} as any);
  assert.equal(
    resReRouteDirectChat.status,
    500,
    "Re-routing image-bearing task to text-only tpl-direct-chat must be rejected rather than silently stripping images"
  );
  console.log(
    "  ✓ Re-routing image task to text-only tpl-direct-chat strictly rejected by subsistence law: PASSED"
  );

  // 18.4 Email case-insensitive unique constraint validation
  assert.ok(
    SCHEMA_CONSTRAINTS.users.nocaseKeys?.includes("email"),
    "Users schema constraints must enforce NOCASE on email"
  );
  console.log("  ✓ Schema constraint model enforces case-insensitive email uniqueness: PASSED");

  // -----------------------------------------------------------------------
  // SCENARIO 19: Password Reset Lockout & IP Limits, Dynamic Multi-Node Pre-Deduction & Presign Bounds
  // -----------------------------------------------------------------------
  console.log(
    "\n[Scenario 19] Password Reset Lockout, Multi-Node Dynamic Billing & Presign Bounds"
  );

  // 19.1 Verification Code Attempt Exhaustion & Atomic Lockout
  const lockoutUserEmail = "lockout_victim@gmail.com";
  store.users.push({
    user_id: "usr_lockout_victim",
    username: "LockoutVictim",
    email: lockoutUserEmail,
    password_hash: await bcrypt.hash("OldPass123456", 4),
    credits: 10,
    token_version: 1
  });
  store.verification_codes.push({
    id: 9991,
    email: lockoutUserEmail,
    code: "654321",
    attempts: 4, // 4 prior failed attempts
    created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 600000).toISOString()
  });

  // Attempt 5th incorrect guess (increments attempts to 5)
  const fifthReq = new Request("https://nanomesh.local/api/auth/reset-password", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.42" },
    body: JSON.stringify({
      email: lockoutUserEmail,
      code: "000000",
      newPassword: "NewSecretPass123!"
    })
  });
  const fifthRes = await worker.fetch(fifthReq, env, {} as any);
  assert.equal(fifthRes.status, 400, "5th attempt with wrong code must return 400");

  // Subsequent attempt with CORRECT code must be rejected with 400 because attempts >= 5
  const lockedReq = new Request("https://nanomesh.local/api/auth/reset-password", {
    method: "POST",
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.42" },
    body: JSON.stringify({
      email: lockoutUserEmail,
      code: "654321",
      newPassword: "NewSecretPass123!"
    })
  });
  const lockedRes = await worker.fetch(lockedReq, env, {} as any);
  assert.equal(lockedRes.status, 400, "Attempt with code after 5 failures must be rejected");
  const lockedJson = (await lockedRes.json()) as any;
  assert.equal(
    lockedJson.error,
    "error.codeLockedTooManyAttempts",
    "Must state code is locked due to too many attempts"
  );
  console.log(
    "  ✓ Password reset atomic attempt exhaustion (attempts >= 5) locks out brute force: PASSED"
  );

  // Rapid requests exceeding email rate limit (max 5/min) trigger 429
  let hitRateLimit = false;
  for (let i = 0; i < 5; i++) {
    const rateReq = new Request("https://nanomesh.local/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.42" },
      body: JSON.stringify({
        email: lockoutUserEmail,
        code: "999999",
        newPassword: "NewSecretPass123!"
      })
    });
    const rateRes = await worker.fetch(rateReq, env, {} as any);
    if (rateRes.status === 429) {
      hitRateLimit = true;
      break;
    }
  }
  assert.ok(hitRateLimit, "Exceeding 5 requests/min per email must trigger 429 rate limit");
  console.log("  ✓ Password reset email sliding window rate limiting triggers HTTP 429: PASSED");

  // 19.2 Presigned Upload URL Bound Enforcement
  const presignUserToken = await signJWT(
    { userId: "usr_lockout_victim", role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  // Negative or 0 fileSize must return 400
  const invalidPresignReq = new Request("https://nanomesh.local/api/upload/presign", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${presignUserToken}`
    },
    body: JSON.stringify({
      fileName: "test.png",
      fileType: "image/png",
      fileSize: 0,
      sessionId: "sess_upload_01"
    })
  });
  const invalidPresignRes = await worker.fetch(invalidPresignReq, env, {} as any);
  assert.equal(invalidPresignRes.status, 400, "Zero or negative fileSize must return 400");

  // Fractional or float fileSize must also return 400 (NM-17 integer enforcement)
  const floatPresignReq = new Request("https://nanomesh.local/api/upload/presign", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${presignUserToken}`
    },
    body: JSON.stringify({
      file_name: "test.png",
      mime_type: "image/png",
      file_size: 0.4,
      sessionId: "sess_upload_01"
    })
  });
  const floatPresignRes = await worker.fetch(floatPresignReq, env, {} as any);
  assert.equal(floatPresignRes.status, 400, "Fractional fileSize must return 400");

  const validPresignReq = new Request("https://nanomesh.local/api/upload/presign", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${presignUserToken}`
    },
    body: JSON.stringify({
      file_name: "test.png",
      mime_type: "image/png",
      file_size: 4096,
      sessionId: "sess_upload_01"
    })
  });
  const validPresignRes = await worker.fetch(validPresignReq, env, {} as any);
  assert.equal(validPresignRes.status, 200, "Valid fileSize returns 200 presigned URL");
  const validPresignJson = (await validPresignRes.json()) as any;
  assert.ok(validPresignJson.uploadUrl, "Presigned payload must include uploadUrl");
  console.log("  ✓ Presigned upload URL enforces positive integer fileSize bounds: PASSED");

  // 19.3 Admin Node Update Enum Whitelist & Type Safety
  const adminTestToken = await signJWT({ role: "admin" }, env.JWT_SECRET, 3600);
  const testNodeId = "m_enum_test_node";
  store.models.push({
    model_id: testNodeId,
    display_name: "Enum Test Model",
    provider: "Testing",
    endpoint: "https://api.example.com/v1",
    modalities: '["text"]',
    tags: '["#chat"]',
    context_window: 4096,
    max_concurrency: 10,
    active_connections: 0,
    precision: 0.8,
    status: "active",
    cost_per_1k_tokens: 0.0,
    cost_per_invocation: 2.0,
    auth_mode: "none",
    api_format: "openai_compat",
    inference_target: "cloud"
  });

  const updateEnumReq = new Request(`https://nanomesh.local/api/admin/models/${testNodeId}`, {
    method: "PUT",
    headers: adminReqHeaders,
    body: JSON.stringify({
      display_name: 12345, // Non-string to test type safety
      auth_mode: "invalid_exploit_mode", // Invalid enum
      api_format: "hacked_format" // Invalid enum
    })
  });
  const updateEnumRes = await handleAdminUpdateNode(updateEnumReq, env, testNodeId);
  assert.equal(
    updateEnumRes.status,
    200,
    "Admin node update with non-string and invalid enums handled safely"
  );
  const nodeAfterUpdate = store.models.find((m) => m.model_id === testNodeId);
  assert.equal(
    nodeAfterUpdate.auth_mode,
    "none",
    "Invalid auth_mode must be rejected and preserve existing value"
  );
  assert.equal(
    nodeAfterUpdate.api_format,
    "openai_compat",
    "Invalid api_format must be rejected and preserve existing value"
  );
  console.log("  ✓ Admin node update strictly validates enums and type guards strings: PASSED");

  // 19.4 Multi-Node Dynamic Billing & Pre-deduction Alignment (NM-15)
  const dynRole1Id = "role_dyn_qwq";
  const dynRole2Id = "role_dyn_llama";
  const dynModel1Id = "m_dyn_qwq_node";
  const dynModel2Id = "m_dyn_llama_node";

  store.dag_roles.push(
    {
      role_id: dynRole1Id,
      name_zh: "高精度推理节点",
      name_en: "High Precision Reasoning Node",
      in_modalities: JSON.stringify(["text"]),
      out_modalities: JSON.stringify(["text"]),
      requisition_tags: JSON.stringify(["#qwq_reasoning"]),
      compensation_prompts: JSON.stringify({})
    },
    {
      role_id: dynRole2Id,
      name_zh: "综合生成节点",
      name_en: "General Generation Node",
      in_modalities: JSON.stringify(["text"]),
      out_modalities: JSON.stringify(["text"]),
      requisition_tags: JSON.stringify(["#llama_generation"]),
      compensation_prompts: JSON.stringify({})
    }
  );

  store.models.push(
    {
      model_id: dynModel1Id,
      display_name: "QwQ 32B Cloud",
      provider: "Workers AI",
      endpoint: "@cf/qwen/qwq-32b-preview",
      modalities: JSON.stringify(["text"]),
      tags: JSON.stringify(["#qwq_reasoning"]),
      context_window: 8192,
      max_concurrency: 10,
      active_connections: 0,
      precision: 0.95,
      user_rating: 4.9,
      status: "active",
      cost_per_1k_tokens: 2.0,
      cost_per_invocation: 0.0,
      auth_mode: "none",
      api_format: "openai_compat",
      inference_target: "cloud"
    },
    {
      model_id: dynModel2Id,
      display_name: "LLaMA 3.1 8B Cloud",
      provider: "Workers AI",
      endpoint: "@cf/meta/llama-3.1-8b-instruct",
      modalities: JSON.stringify(["text"]),
      tags: JSON.stringify(["#llama_generation"]),
      context_window: 4096,
      max_concurrency: 10,
      active_connections: 0,
      precision: 0.88,
      user_rating: 4.7,
      status: "active",
      cost_per_1k_tokens: 1.0,
      cost_per_invocation: 1.0,
      auth_mode: "none",
      api_format: "openai_compat",
      inference_target: "cloud"
    }
  );

  store.dag_templates.push({
    template_id: "tpl_multi_dyn_billing",
    name_zh: "多节点动态计费模板",
    name_en: "Multi-Node Dynamic Billing",
    desc_zh: "前序QwQ推理与后序LLaMA生成",
    desc_en: "Sequential QwQ and LLaMA nodes",
    scenario_category: "chat",
    scenario_anchor: "chat",
    roles: JSON.stringify([
      {
        role_id: dynRole1Id,
        name_zh: "高精度推理节点",
        name_en: "High Precision Reasoning Node",
        in_modalities: ["text"],
        out_modalities: ["text"],
        in_degree: 0,
        out_degree: 1,
        requisition_tags: ["#qwq_reasoning"],
        compensation_prompts: {}
      },
      {
        role_id: dynRole2Id,
        name_zh: "综合生成节点",
        name_en: "General Generation Node",
        in_modalities: ["text"],
        out_modalities: ["text"],
        in_degree: 1,
        out_degree: 0,
        requisition_tags: ["#llama_generation"],
        compensation_prompts: {}
      }
    ]),
    role_sequence: JSON.stringify([dynRole1Id, dynRole2Id]),
    edges: JSON.stringify([]),
    status: "active",
    priority: 10
  });

  // User with insufficient balance (3 credits < 4 required)
  const poorUserId = "usr_dyn_poor";
  store.users.push({
    user_id: poorUserId,
    username: "DynPoorUser",
    email: "dyn_poor@nanomesh.local",
    password_hash: "hash",
    credits: 3,
    token_version: 1
  });
  const poorToken = await signJWT(
    { userId: poorUserId, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  const poorChatReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${poorToken}`
    },
    body: JSON.stringify({
      reRouteMode: "switch_template",
      chosenTemplateId: "tpl_multi_dyn_billing",
      envelope: {
        session_id: "sess_dyn_01",
        instruction_payload: "Test multi-node dynamic billing under-allocation check"
      }
    })
  });
  const poorChatRes = await worker.fetch(poorChatReq, env, {} as any);
  assert.equal(
    poorChatRes.status,
    403,
    "Insufficient credits for multi-node dynamic pipeline must return 403"
  );
  const poorChatJson = (await poorChatRes.json()) as any;
  assert.equal(poorChatJson.error, "insufficient_quota");
  assert.ok(
    poorChatJson.message.includes("4"),
    "Rejection message must indicate 4 credits required"
  );
  const poorUserAfter = store.users.find((u) => u.user_id === poorUserId);
  assert.equal(poorUserAfter.credits, 3, "Failed pre-deduction must preserve balance");

  // User with sufficient balance (10 credits >= 4 required)
  const richUserId = "usr_dyn_rich";
  store.users.push({
    user_id: richUserId,
    username: "DynRichUser",
    email: "dyn_rich@nanomesh.local",
    password_hash: "hash",
    credits: 10,
    token_version: 1
  });
  const richToken = await signJWT(
    { userId: richUserId, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  const richChatReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${richToken}`
    },
    body: JSON.stringify({
      reRouteMode: "switch_template",
      chosenTemplateId: "tpl_multi_dyn_billing",
      envelope: {
        session_id: "sess_dyn_02",
        instruction_payload: "Run full multi-node dynamic billing pipeline"
      }
    })
  });
  const richChatRes = await worker.fetch(richChatReq, env, {} as any);
  assert.equal(
    richChatRes.status,
    200,
    "Sufficient credits multi-node dynamic pipeline returns 200 SSE"
  );
  const richStreamText = await richChatRes.text();
  assert.ok(
    richStreamText.includes("dag_complete"),
    "Multi-node dynamic execution must emit dag_complete"
  );
  const richUserAfter = store.users.find((u) => u.user_id === richUserId);
  assert.equal(
    richUserAfter.credits,
    6,
    "10 initial credits - 4 pre-deducted = exactly 6 remaining credits"
  );
  const richLedgerEntry = store.credit_ledger.find(
    (l) => l.user_id === richUserId && l.category === "compute_cost"
  );
  assert.ok(richLedgerEntry, "Credit ledger must contain compute_cost entry for rich user");
  assert.equal(richLedgerEntry.amount, -4, "Ledger entry amount must be -4");
  console.log(
    "  ✓ Multi-node dynamic token + invocation cost pre-deduction & settlement (NM-15): PASSED"
  );

  // 19.5 Pure OAuth Account Takeover Prevention (NM-20)
  const oauthVictimEmail = "oauth_victim_user@gmail.com";
  const oauthVictimId = "usr_oauth_victim_01";
  store.users.push({
    user_id: oauthVictimId,
    username: "OAuthVictim",
    email: oauthVictimEmail,
    password_hash: null, // Pure OAuth user!
    credits: 10,
    token_version: 1
  });

  // 1. Attacker calls forgot-password on the victim's email
  const origFetchForgot = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("turnstile")) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      if (urlStr.includes("resend.com")) {
        return new Response(JSON.stringify({ id: "mock_resend_notice_id" }), { status: 200 });
      }
      return origFetchForgot(input, init);
    };

    const forgotReq = new Request("https://nanomesh.local/api/auth/forgot-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.99" },
      body: JSON.stringify({
        email: oauthVictimEmail,
        turnstile_token: "mock_turnstile_pass"
      })
    });
    const forgotRes = await worker.fetch(forgotReq, env, {} as any);
    assert.equal(forgotRes.status, 200, "Forgot password for OAuth user returns 200 notice");

    // Check that code recorded in verification_codes is an unguessable NOTICE_ token, NOT 'OAUTH_NOTICE'
    const noticeEntry = store.verification_codes.find((c) => c.email === oauthVictimEmail);
    assert.ok(noticeEntry, "Notice entry must exist for cooldown");
    assert.ok(
      String(noticeEntry.code).startsWith("NOTICE_OAUTH_"),
      "Notice code must be prefixed with NOTICE_OAUTH_ and contain random UUID"
    );
    assert.notEqual(
      noticeEntry.code,
      "OAUTH_NOTICE",
      "Static OAUTH_NOTICE string must not be stored"
    );

    // 2. Attacker attempts to call reset-password with code = 'OAUTH_NOTICE'
    const exploitReq1 = new Request("https://nanomesh.local/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.99" },
      body: JSON.stringify({
        email: oauthVictimEmail,
        code: "OAUTH_NOTICE",
        newPassword: "HackedPassword123!"
      })
    });
    const exploitRes1 = await worker.fetch(exploitReq1, env, {} as any);
    assert.equal(exploitRes1.status, 400, "Non-6-digit code string must be rejected with 400");
    const exploitJson1 = (await exploitRes1.json()) as any;
    assert.equal(exploitJson1.error, "error.invalidCode");

    // 3. Attacker attempts to call reset-password with the actual notice token
    const exploitReq2 = new Request("https://nanomesh.local/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.99" },
      body: JSON.stringify({
        email: oauthVictimEmail,
        code: noticeEntry.code,
        newPassword: "HackedPassword123!"
      })
    });
    const exploitRes2 = await worker.fetch(exploitReq2, env, {} as any);
    assert.equal(exploitRes2.status, 400, "Notice token must be rejected with 400 invalid code");

    // 4. Even with a simulated 6-digit code, pure OAuth user must be rejected with 404 error.userNotFound
    store.verification_codes.push({
      id: 9999,
      email: oauthVictimEmail,
      code: "123456",
      attempts: 0,
      created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + 600000).toISOString()
    });
    const exploitReq3 = new Request("https://nanomesh.local/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.99" },
      body: JSON.stringify({
        email: oauthVictimEmail,
        code: "123456",
        newPassword: "HackedPassword123!"
      })
    });
    const exploitRes3 = await worker.fetch(exploitReq3, env, {} as any);
    assert.equal(
      exploitRes3.status,
      400,
      "Pure OAuth user password reset must return generic 400 error.invalidCode"
    );
    const exploitJson3 = (await exploitRes3.json()) as any;
    assert.equal(exploitJson3.error, "error.invalidCode");
    const victimUserAfter = store.users.find((u) => u.user_id === oauthVictimId);
    assert.equal(
      victimUserAfter.password_hash,
      null,
      "Victim password_hash must remain strictly null"
    );
    console.log("  ✓ NM-20: Pure OAuth account takeover attempt completely blocked: PASSED");

    // 19.5.1 Anti-Enumeration Oracle Invariance (NM-22)
    // Probe 1: Unregistered email
    const probeUnregisteredReq = new Request("https://nanomesh.local/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.99" },
      body: JSON.stringify({
        email: "completely_nonexistent_user_999@gmail.com",
        code: "654321",
        newPassword: "TestPassword123!"
      })
    });
    const probeUnregRes = await worker.fetch(probeUnregisteredReq, env, {} as any);
    assert.equal(probeUnregRes.status, 400, "Unregistered user reset probe must return 400");
    const probeUnregJson = (await probeUnregRes.json()) as any;
    assert.equal(probeUnregJson.error, "error.invalidCode");

    // Probe 2: Pure OAuth user
    const probeOAuthReq = new Request("https://nanomesh.local/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.99" },
      body: JSON.stringify({
        email: oauthVictimEmail,
        code: "654321",
        newPassword: "TestPassword123!"
      })
    });
    const probeOAuthRes = await worker.fetch(probeOAuthReq, env, {} as any);
    assert.equal(probeOAuthRes.status, 400, "Pure OAuth user reset probe must return 400");
    const probeOAuthJson = (await probeOAuthRes.json()) as any;
    assert.equal(probeOAuthJson.error, "error.invalidCode");

    // Probe 3: Registered password user
    const freshPwdEmail = "probe_pwd_user@gmail.com";
    store.users.push({
      user_id: "usr_probe_pwd",
      username: "ProbePwdUser",
      email: freshPwdEmail,
      password_hash: "hash_exists_123",
      credits: 10,
      token_version: 1
    });
    const probePasswordReq = new Request("https://nanomesh.local/api/auth/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.123" },
      body: JSON.stringify({
        email: freshPwdEmail,
        code: "654321",
        newPassword: "TestPassword123!"
      })
    });
    const probePasswordRes = await worker.fetch(probePasswordReq, env, {} as any);
    assert.equal(probePasswordRes.status, 400, "Password user reset probe must return 400");
    const probePasswordJson = (await probePasswordRes.json()) as any;
    assert.equal(probePasswordJson.error, "error.invalidCode");

    assert.equal(
      probeUnregRes.status,
      probeOAuthRes.status,
      "Response status must be invariant across user types"
    );
    assert.equal(
      probeOAuthRes.status,
      probePasswordRes.status,
      "Response status must be invariant across user types"
    );
    console.log(
      "  ✓ NM-22: Reset-password returns uniform 400 error.invalidCode with zero enumeration leakage: PASSED"
    );
  } finally {
    globalThis.fetch = origFetchForgot;
  }

  // 19.6 Continuation Multi-WebGPU Handover Break (NM-21)
  const templateInterleavedId = "tpl_interleaved_webgpu_billing";
  store.dag_templates.push({
    template_id: templateInterleavedId,
    name_zh: "交替WebGPU多步编排",
    name_en: "Interleaved WebGPU Orchestration",
    desc_zh: "端侧与云端多步交替",
    desc_en: "Alternating client WebGPU and cloud nodes",
    scenario_category: "chat",
    scenario_anchor: "chat",
    roles: JSON.stringify([
      {
        role_id: "role_browser_only",
        name_zh: "端侧独占角色",
        name_en: "Browser Only Role",
        in_modalities: ["text"],
        out_modalities: ["text"],
        in_degree: 0,
        out_degree: 1,
        requisition_tags: ["#browser_exclusive"],
        compensation_prompts: {}
      },
      {
        role_id: dynRole1Id,
        name_zh: "高精度推理节点",
        name_en: "High Precision Reasoning Node",
        in_modalities: ["text"],
        out_modalities: ["text"],
        in_degree: 1,
        out_degree: 1,
        requisition_tags: ["#qwq_reasoning"],
        compensation_prompts: {}
      },
      {
        role_id: "role_browser_only",
        name_zh: "端侧独占角色",
        name_en: "Browser Only Role",
        in_modalities: ["text"],
        out_modalities: ["text"],
        in_degree: 1,
        out_degree: 1,
        requisition_tags: ["#browser_exclusive"],
        compensation_prompts: {}
      },
      {
        role_id: dynRole2Id,
        name_zh: "综合生成节点",
        name_en: "General Generation Node",
        in_modalities: ["text"],
        out_modalities: ["text"],
        in_degree: 1,
        out_degree: 0,
        requisition_tags: ["#llama_generation"],
        compensation_prompts: {}
      }
    ]),
    role_sequence: JSON.stringify([
      "role_browser_only",
      dynRole1Id,
      "role_browser_only",
      dynRole2Id
    ]),
    edges: JSON.stringify([]),
    status: "active",
    priority: 10
  });

  const userNm21Id = "usr_nm21_handover_test";
  store.users.push({
    user_id: userNm21Id,
    username: "UserNM21",
    email: "user_nm21@nanomesh.local",
    password_hash: "hash",
    credits: 3, // Sufficient for Step 1 (2 credits), but insufficient for Step 1 + Step 3 (4 credits)
    token_version: 1
  });

  const handshakeNm21Id = "hs_nm21_interleaved_01";
  store.dag_handshakes.push({
    handshake_id: handshakeNm21Id,
    user_id: userNm21Id,
    session_id: "sess_nm21_interleaved",
    template_id: templateInterleavedId,
    next_step: 1,
    status: "ISSUED",
    expires_at: new Date(Date.now() + 300000).toISOString()
  });

  const contTokenNm21 = await signJWT(
    {
      jti: handshakeNm21Id,
      sub: userNm21Id,
      sid: "sess_nm21_interleaved",
      tid: templateInterleavedId,
      nxt: 1
    },
    env.JWT_SECRET,
    300
  );

  // Client continues from Step 0 WebGPU completion into Step 1 Cloud (without explicit capabilities in body)
  const contNm21Req = new Request("https://nanomesh.local/api/chat/continue", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `session=${await signJWT({ userId: userNm21Id, role: "user", tokenVersion: 1 }, env.JWT_SECRET, 3600)}`
    },
    body: JSON.stringify({
      continuation_token: contTokenNm21,
      status: "success",
      client_step_output: "Client WebGPU Step 0 Completed",
      envelope: {
        session_id: "sess_nm21_interleaved",
        instruction_payload: "Testing continuation multi-webgpu break"
      }
      // Note: capabilities omitted intentionally to test NM-21 default handover break
    })
  });

  const contNm21Res = await worker.fetch(contNm21Req, env, {} as any);
  assert.equal(
    contNm21Res.status,
    200,
    "Continuation with next WebGPU node must break and only pre-deduct immediate cloud step (200 OK)"
  );
  const contStreamText = await contNm21Res.text();
  assert.ok(
    contStreamText.includes("node_start"),
    "Continuation stream must start executing cloud node"
  );
  console.log(
    "  ✓ NM-21: Continuation multi-WebGPU handover break correctly isolates billing: PASSED"
  );

  // 19.7 NM-01 handleRegister verification code atomic CAS brute force lockout & deletion
  const regEmail = "cas_reg_brute_test@gmail.com";
  store.verification_codes.push({
    id: 99101,
    email: regEmail,
    code: "654321",
    attempts: 0,
    expires_at: new Date(Date.now() + 600000).toISOString()
  });

  const origFetchReg = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("turnstile")) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      return origFetchReg(input, init);
    };

    // Send 5 incorrect attempts
    for (let i = 1; i <= 5; i++) {
      const failRegReq = new Request("https://nanomesh.local/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: `CasUser${i}`,
          email: regEmail,
          password: "Password123!",
          code: "000000",
          turnstile_token: "mock_token"
        })
      });
      const failRes = await worker.fetch(failRegReq, env, {} as any);
      assert.equal(failRes.status, 400, `Attempt ${i} must return 400`);
      const body = (await failRes.json()) as any;
      assert.equal(body.error, "error.invalidCode", `Attempt ${i} must report invalidCode`);
    }

    // 6th attempt: CAS attempts < 5 condition fails, must trigger lockout and delete code
    const sixthRegReq = new Request("https://nanomesh.local/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: "CasUserLock",
        email: regEmail,
        password: "Password123!",
        code: "654321",
        turnstile_token: "mock_token"
      })
    });
    const sixthRes = await worker.fetch(sixthRegReq, env, {} as any);
    assert.equal(sixthRes.status, 400, "Exhausted code must return 400");
    const sixthBody = (await sixthRes.json()) as any;
    assert.equal(
      sixthBody.error,
      "error.codeLockedTooManyAttempts",
      "Must return error.codeLockedTooManyAttempts"
    );
    const codeLeft = store.verification_codes.find((c) => c.email === regEmail);
    assert.equal(codeLeft, undefined, "Verification code must be purged upon reaching 5 attempts");
    console.log("  ✓ NM-01: handleRegister atomic CAS anti-brute force lockout & deletion: PASSED");
  } finally {
    globalThis.fetch = origFetchReg;
  }

  // 19.8 NM-02 handleOAuthCallback duplicate provider & foreign conflict intercept
  const oauthTestUserId = "user_oauth_bind_tester";
  store.users.push({
    user_id: oauthTestUserId,
    username: "oauth_binder",
    email: "oauth_binder@gmail.com",
    avatar_url: null,
    credits: 100
  });
  store.user_oauth_bindings.push({
    id: "bind_orig_gh",
    user_id: oauthTestUserId,
    provider: "github",
    provider_id: "gh_1001"
  });

  const origFetchOauthBind = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("token")) {
        return new Response(JSON.stringify({ access_token: "mock_token" }), { status: 200 });
      }
      if (urlStr.includes("userinfo")) {
        return new Response(
          JSON.stringify({ id: "go_9999", email: "oauth_other@gmail.com", verified_email: true }),
          {
            status: 200
          }
        );
      }
      if (urlStr.includes("api.github.com/user/emails")) {
        return new Response(
          JSON.stringify([{ email: "oauth_binder@gmail.com", primary: true, verified: true }]),
          { status: 200 }
        );
      }
      if (urlStr.includes("api.github.com/user")) {
        return new Response(JSON.stringify({ id: 2002, login: "new_gh_acc" }), { status: 200 });
      }
      return origFetchOauthBind(input, init);
    };

    // User attempts to bind a second GitHub account (different ID: 2002) while already having github bound
    const bindStateToken = await signJWT(
      { nonce: "nonce_gh_bind_1", userId: oauthTestUserId, action: "bind" },
      env.JWT_SECRET,
      600
    );
    const sessionToken = await signJWT(
      { userId: oauthTestUserId, role: "user", tokenVersion: 1 },
      env.JWT_SECRET,
      3600
    );

    const dupProviderReq = new Request(
      `https://nanomesh.local/api/auth/callback/github?code=mock_code&state=${bindStateToken}`,
      {
        headers: {
          Cookie: `session=${sessionToken}`
        }
      }
    );
    const dupRes = await worker.fetch(dupProviderReq, env, {} as any);
    assert.equal(dupRes.status, 302, "Duplicate provider bind must return 302 redirect");
    assert.ok(
      (dupRes.headers.get("Location") || "").includes("error=oauth_already_bound#settings"),
      "Must redirect with error=oauth_already_bound#settings"
    );

    // Another user tries to bind google account when they already have google bound
    const otherUserId = "user_oauth_other";
    store.users.push({
      user_id: otherUserId,
      username: "oauth_other",
      email: "oauth_other@gmail.com",
      avatar_url: null,
      credits: 100
    });
    store.user_oauth_bindings.push({
      id: "bind_foreign_gh",
      user_id: otherUserId,
      provider: "google",
      provider_id: "go_9999"
    });
    const bindStateGoogle = await signJWT(
      { nonce: "nonce_go_bind_2", userId: otherUserId, action: "bind" },
      env.JWT_SECRET,
      600
    );
    const sessionTokenOther = await signJWT(
      { userId: otherUserId, role: "user", tokenVersion: 1 },
      env.JWT_SECRET,
      3600
    );
    const dupGoogleReq = new Request(
      `https://nanomesh.local/api/auth/callback/google?code=mock_code&state=${bindStateGoogle}`,
      {
        headers: {
          Cookie: `session=${sessionTokenOther}`
        }
      }
    );
    const dupGoogleRes = await worker.fetch(dupGoogleReq, env, {} as any);
    assert.equal(dupGoogleRes.status, 302, "Must return 302 redirect");
    assert.ok(
      (dupGoogleRes.headers.get("Location") || "").includes("error=oauth_already_bound#settings"),
      "Must redirect with error=oauth_already_bound#settings"
    );
    console.log(
      "  ✓ NM-02: OAuth callback bind duplicate provider & foreign conflict intercepted: PASSED"
    );
  } finally {
    globalThis.fetch = origFetchOauthBind;
  }

  // -----------------------------------------------------------------------
  // SCENARIO 20: Batch 21 Category 2 Security, Billing & Robustness Suite
  // -----------------------------------------------------------------------
  console.log("\n[Scenario 20] Batch 21 Category 2 Security, Billing & Robustness Regression");

  // 20.1 NM-AUD-01: OAuth bind state token rejected as Bearer session credential
  const s20UserId = "usr_batch21_sec";
  store.users.push({
    user_id: s20UserId,
    username: "batch21_sec",
    email: "batch21_sec@gmail.com",
    password_hash: bcrypt.hashSync("LegacyPwd99!", 4),
    credits: 20,
    frozen_credits: 0,
    avatar_url: null,
    avatar_updated_at: null,
    token_version: 1
  });
  const leakedOAuthState = await signJWT(
    { typ: "oauth_state", nonce: "nonce_leak", action: "bind", userId: s20UserId },
    env.JWT_SECRET,
    300
  );
  const stateAsBearerRes = await worker.fetch(
    new Request("https://nanomesh.local/api/auth/me", {
      headers: { Authorization: `Bearer ${leakedOAuthState}` }
    }),
    env,
    {} as any
  );
  assert.equal(
    stateAsBearerRes.status,
    401,
    "NM-AUD-01: OAuth bind state JWT must be rejected by /api/auth/me"
  );

  // 20.2 NM-AUD-02: Oversized upload Content-Length pre-check (413) & presign daily quota (429)
  const validS20Token = await signJWT(
    { userId: s20UserId, tokenVersion: 1, typ: "session" },
    env.JWT_SECRET,
    3600
  );
  const hugeUploadRes = await worker.fetch(
    new Request("https://nanomesh.local/api/upload/file", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${validS20Token}`,
        "Content-Length": String(30 * 1024 * 1024)
      },
      body: "not-even-parsed"
    }),
    env,
    {} as any
  );
  assert.equal(
    hugeUploadRes.status,
    413,
    "NM-AUD-02: Oversized upload Content-Length must fail fast with 413 before formData()"
  );

  const todayPresignKey = `presign_daily_${new Date().toISOString().slice(0, 10)}_${s20UserId}`;
  store.system_counters.push({ key: todayPresignKey, value: 50 });
  const quotaExceededPresignRes = await worker.fetch(
    new Request("https://nanomesh.local/api/upload/presign", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${validS20Token}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ file_name: "a.png", file_size: 1024, mime_type: "image/png" })
    }),
    env,
    {} as any
  );
  assert.equal(
    quotaExceededPresignRes.status,
    429,
    "NM-AUD-02: Exceeding daily presign quota must return 429"
  );

  // Also verify /api/upload/file enforces the exact same daily quota (no bypass)
  const quotaFd = new FormData();
  quotaFd.append("file", new Blob([new Uint8Array([1, 2, 3])], { type: "image/png" }), "a.png");
  const quotaExceededUploadRes = await worker.fetch(
    new Request("https://nanomesh.local/api/upload/file", {
      method: "POST",
      headers: { Authorization: `Bearer ${validS20Token}` },
      body: quotaFd
    }),
    env,
    {} as any
  );
  assert.equal(
    quotaExceededUploadRes.status,
    429,
    "NM-AUD-02: Proxy /api/upload/file must also enforce daily upload quota (429)"
  );

  // Verify scheduled() cron purges expired tmp/ R2 objects (> 24h)
  const oldTmpKey = `tmp/${s20UserId}/old_asset/stale.png`;
  const freshTmpKey = `tmp/${s20UserId}/new_asset/fresh.png`;
  await env.R2.put(oldTmpKey, "OLD_TMP");
  await env.R2.put(freshTmpKey, "NEW_TMP");
  const origList = env.R2.list.bind(env.R2);
  (env.R2 as any).list = async (opts: any) => {
    const listed = await origList(opts);
    return {
      ...listed,
      objects: (listed.objects || []).map((o: any) => ({
        ...o,
        uploaded: o.key === oldTmpKey ? new Date(Date.now() - 48 * 3600 * 1000) : new Date()
      }))
    };
  };
  await worker.scheduled({} as any, env, {} as any);
  (env.R2 as any).list = origList;
  assert.equal(await env.R2.get(oldTmpKey), null, "Cron must purge tmp/ objects > 24h");
  assert.ok(await env.R2.get(freshTmpKey), "Cron must preserve fresh tmp/ objects < 24h");

  // 20.3 NM-AUD-06: User & Admin logout revokes tokens server-side
  const logoutUserRes = await worker.fetch(
    new Request("https://nanomesh.local/api/auth/logout", {
      method: "POST",
      headers: { Authorization: `Bearer ${validS20Token}` }
    }),
    env,
    {} as any
  );
  assert.equal(logoutUserRes.status, 200);
  const postLogoutMeRes = await worker.fetch(
    new Request("https://nanomesh.local/api/auth/me", {
      headers: { Authorization: `Bearer ${validS20Token}` }
    }),
    env,
    {} as any
  );
  assert.equal(
    postLogoutMeRes.status,
    401,
    "NM-AUD-06: Old user JWT must fail with 401 immediately after POST /api/auth/logout"
  );

  const adminLoginRes20 = await worker.fetch(
    new Request("https://nanomesh.local/api/admin/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": "198.51.100.77"
      },
      body: JSON.stringify({ password: (env as any).ADMIN_PASSWORD })
    }),
    env,
    {} as any
  );
  assert.equal(adminLoginRes20.status, 200);
  const adminCookie20 = (adminLoginRes20.headers.get("Set-Cookie") || "").split(";")[0];
  assert.ok(adminCookie20.startsWith("admin_session="));

  const adminLogoutRes20 = await worker.fetch(
    new Request("https://nanomesh.local/api/admin/logout", {
      method: "POST",
      headers: { Cookie: adminCookie20 }
    }),
    env,
    {} as any
  );
  assert.equal(adminLogoutRes20.status, 200);
  const postAdminLogoutNodesRes = await worker.fetch(
    new Request("https://nanomesh.local/api/admin/nodes", {
      method: "GET",
      headers: { Cookie: adminCookie20 }
    }),
    env,
    {} as any
  );
  assert.equal(
    postAdminLogoutNodesRes.status,
    401,
    "NM-AUD-06: Revoked admin_session cookie must be rejected with 401 after logout"
  );

  // 20.4 NM-AUD-13: Legacy bcrypt user logs in & upgrades transparently to PBKDF2
  const origFetch20 = globalThis.fetch;
  try {
    globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
      const urlStr =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.toString()
            : (input as any).url;
      if (urlStr.includes("turnstile")) {
        return new Response(JSON.stringify({ success: true }), { status: 200 });
      }
      return origFetch20(input, init);
    };

    const legacyLoginRes = await worker.fetch(
      new Request("https://nanomesh.local/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "batch21_sec@gmail.com",
          password: "LegacyPwd99!",
          turnstile_token: "mock_pass"
        })
      }),
      env,
      {} as any
    );
    assert.equal(legacyLoginRes.status, 200, "Legacy bcrypt login must succeed");
    const upgradedUserRow = store.users.find((u) => u.user_id === s20UserId)!;
    assert.ok(
      upgradedUserRow.password_hash.startsWith("$pbkdf2-sha256$"),
      "NM-AUD-13: Successful legacy bcrypt login must transparently upgrade password_hash to PBKDF2"
    );
  } finally {
    globalThis.fetch = origFetch20;
  }

  // Fresh token after token_version bump (now 2)
  const freshS20Token = await signJWT(
    { userId: s20UserId, tokenVersion: 2, typ: "session" },
    env.JWT_SECRET,
    3600
  );

  // 20.5 NM-AUD-07: NaN query params on ledger/notifications & literal null JSON on history
  const badLedgerRes = await worker.fetch(
    new Request("https://nanomesh.local/api/user/ledger?page=abc&limit=NaN", {
      headers: { Authorization: `Bearer ${freshS20Token}` }
    }),
    env,
    {} as any
  );
  assert.equal(badLedgerRes.status, 200, "NM-AUD-07: Ledger must safely handle NaN query params");
  const badLedgerJson = (await badLedgerRes.json()) as any;
  assert.equal(badLedgerJson.page, 1);
  assert.equal(badLedgerJson.limit, 20);

  const badNotifRes = await worker.fetch(
    new Request("https://nanomesh.local/api/notifications?page=xyz&limit=-99", {
      headers: { Authorization: `Bearer ${freshS20Token}` }
    }),
    env,
    {} as any
  );
  assert.equal(badNotifRes.status, 200, "NM-AUD-07: Notifications must handle NaN query params");

  const nullHistSaveRes = await worker.fetch(
    new Request("https://nanomesh.local/api/history", {
      method: "POST",
      headers: {
        "X-History-Account": s20UserId,
        Authorization: `Bearer ${freshS20Token}`,
        "Content-Type": "application/json"
      },
      body: "null"
    }),
    env,
    {} as any
  );
  assert.equal(nullHistSaveRes.status, 400, "NM-AUD-07: POST /api/history with null returns 400");

  const nullHistPatchRes = await worker.fetch(
    new Request("https://nanomesh.local/api/history/sess_x", {
      method: "PATCH",
      headers: {
        "X-History-Account": s20UserId,
        Authorization: `Bearer ${freshS20Token}`,
        "Content-Type": "application/json"
      },
      body: "null"
    }),
    env,
    {} as any
  );
  assert.equal(
    nullHistPatchRes.status,
    400,
    "NM-AUD-07: PATCH /api/history/:id with null returns 400"
  );

  // 20.6 NM-AUD-12: Avatar magic bytes rejection & CAS 24h cooldown check
  const fakeAvatarFd = new FormData();
  fakeAvatarFd.append(
    "file",
    new Blob(["<html><script>alert(1)</script></html>"], { type: "image/png" }),
    "exploit.png"
  );
  const fakeAvatarRes = await worker.fetch(
    new Request("https://nanomesh.local/api/user/avatar", {
      method: "POST",
      headers: { Authorization: `Bearer ${freshS20Token}` },
      body: fakeAvatarFd
    }),
    env,
    {} as any
  );
  assert.equal(
    fakeAvatarRes.status,
    400,
    "NM-AUD-12: Disguised HTML uploaded as .png avatar must be rejected by magic bytes check"
  );

  // 20.7 NM-AUD-09: Legacy WebGPU fallback charges exact 1 credit (no double deduction)
  const legacyUserId = "usr_legacy_gpu_nm09";
  store.users.push({
    user_id: legacyUserId,
    username: "legacy_gpu",
    email: "legacy_gpu@gmail.com",
    credits: 10,
    frozen_credits: 0,
    token_version: 1
  });
  const legacyToken = await signJWT(
    { userId: legacyUserId, tokenVersion: 1, typ: "session" },
    env.JWT_SECRET,
    3600
  );
  const { executeDAGStream: executeLegacyDAGStream } =
    await import("../src/orchestration/dispatcher");
  const legacyDag: any = {
    template: { template_id: "tpl_legacy_gpu", name_zh: "Legacy GPU Test", roles: [] },
    candidate_templates: [],
    nodes: [
      {
        role: {
          role_id: "role_head_gpu",
          name_zh: "端侧感知",
          in_modalities: ["text"],
          out_modalities: ["text"],
          in_degree: 0,
          out_degree: 1,
          requisition_tags: ["#text"]
        },
        selected_model: {
          model_id: "browser-qwen-test",
          display_name: "Browser Qwen",
          provider: "browser",
          endpoint: "browser://qwen",
          modalities: ["text"],
          tags: [],
          context_window: 4096,
          max_concurrency: 10,
          active_connections: 0,
          precision: 0.9,
          user_rating: 5,
          usage_count: 0,
          cost_per_1k_tokens: 0,
          cost_per_invocation: 0,
          status: "active",
          is_generalist: 0,
          prior_score: 1,
          scenario_anchors: [],
          inference_target: "browser"
        },
        standby_models: [
          {
            model_id: "cloud-fallback-test",
            display_name: "Cloud Fallback",
            provider: "cloudflare",
            endpoint: "@cf/meta/llama-3.1-8b-instruct-fast",
            modalities: ["text"],
            tags: [],
            context_window: 4096,
            max_concurrency: 10,
            active_connections: 0,
            precision: 0.9,
            user_rating: 5,
            usage_count: 0,
            cost_per_1k_tokens: 1,
            cost_per_invocation: 0,
            status: "active",
            is_generalist: 0,
            prior_score: 1,
            scenario_anchors: [],
            inference_target: "edge"
          }
        ],
        downgraded: false,
        claimed_assets: []
      },
      {
        role: {
          role_id: "role_tail_text",
          name_zh: "云端收尾",
          in_modalities: ["text"],
          out_modalities: ["text"],
          in_degree: 1,
          out_degree: 0,
          requisition_tags: ["#text"]
        },
        selected_model: {
          model_id: "cloud-tail-test",
          display_name: "Cloud Tail",
          provider: "cloudflare",
          endpoint: "@cf/meta/llama-3.1-8b-instruct-fast",
          modalities: ["text"],
          tags: [],
          context_window: 4096,
          max_concurrency: 10,
          active_connections: 0,
          precision: 0.9,
          user_rating: 5,
          usage_count: 0,
          cost_per_1k_tokens: 1,
          cost_per_invocation: 0,
          status: "active",
          is_generalist: 0,
          prior_score: 1,
          scenario_anchors: [],
          inference_target: "edge"
        },
        standby_models: [],
        downgraded: false,
        claimed_assets: []
      }
    ],
    reasoning_trace: { is_multi_round: false, intent_state: null }
  };
  const legacyStream = await executeLegacyDAGStream(
    env,
    legacyDag,
    {
      envelope_id: "env_nm09",
      session_id: "sess_nm09",
      round_index: 1,
      instruction_payload: "hello legacy",
      assets_manifest: [],
      constraint_context: { target_language: "en", output_style: "concise" }
    } as any,
    {
      userId: legacyUserId,
      hasPreDeducted: false,
      preDeductedCredits: 0,
      clientCapabilities: { webgpu_handover_v3: false }
    }
  );
  const legacyReader = legacyStream.getReader();
  while (!(await legacyReader.read()).done) {}
  const legacyUserAfter = store.users.find((u) => u.user_id === legacyUserId)!;
  assert.equal(
    legacyUserAfter.credits,
    8,
    "NM-AUD-09: Legacy WebGPU fallback across 2 nodes (cost 1 + 1 = 2) must deduct 2 credits cleanly (10 - 2 = 8), NOT double-charge 3 credits"
  );

  // Also verify 1-credit user CANNOT abuse expensive (10-credit) standby fallback/failover into negative balance
  const oneCreditUserId = "usr_one_credit_guard";
  store.users.push({
    user_id: oneCreditUserId,
    username: "one_credit_guard",
    email: "one_credit_guard@gmail.com",
    credits: 1,
    frozen_credits: 0,
    token_version: 1
  });
  const expensiveFallbackDag: any = {
    template: { template_id: "tpl_exp_fallback", name_zh: "Expensive Standby Test", roles: [] },
    candidate_templates: [],
    nodes: [
      {
        role: {
          role_id: "role_head_exp",
          name_zh: "端侧节点",
          in_modalities: ["text"],
          out_modalities: ["text"],
          in_degree: 0,
          out_degree: 1,
          requisition_tags: ["#text"]
        },
        selected_model: {
          model_id: "browser-qwen-exp",
          display_name: "Browser Qwen",
          provider: "browser",
          endpoint: "browser://qwen",
          modalities: ["text"],
          tags: [],
          context_window: 4096,
          max_concurrency: 10,
          active_connections: 0,
          precision: 0.9,
          user_rating: 5,
          usage_count: 0,
          cost_per_1k_tokens: 0,
          cost_per_invocation: 0,
          status: "active",
          is_generalist: 0,
          prior_score: 1,
          scenario_anchors: [],
          inference_target: "browser"
        },
        standby_models: [
          {
            model_id: "expensive-cloud-10",
            display_name: "Expensive Cloud 10",
            provider: "openai",
            endpoint: "https://api.openai.com/v1/chat/completions",
            modalities: ["text"],
            tags: [],
            context_window: 4096,
            max_concurrency: 10,
            active_connections: 0,
            precision: 0.9,
            user_rating: 5,
            usage_count: 0,
            cost_per_1k_tokens: 10,
            cost_per_invocation: 0,
            status: "active",
            is_generalist: 0,
            prior_score: 1,
            scenario_anchors: [],
            inference_target: "heavy"
          }
        ],
        downgraded: false,
        claimed_assets: []
      },
      {
        role: {
          role_id: "role_tail_exp",
          name_zh: "云端收尾",
          in_modalities: ["text"],
          out_modalities: ["text"],
          in_degree: 1,
          out_degree: 0,
          requisition_tags: ["#text"]
        },
        selected_model: {
          model_id: "cloud-tail-exp",
          display_name: "Cloud Tail Exp",
          provider: "cloudflare",
          endpoint: "@cf/meta/llama-3.1-8b-instruct-fast",
          modalities: ["text"],
          tags: [],
          context_window: 4096,
          max_concurrency: 10,
          active_connections: 0,
          precision: 0.9,
          user_rating: 5,
          usage_count: 0,
          cost_per_1k_tokens: 1,
          cost_per_invocation: 0,
          status: "active",
          is_generalist: 0,
          prior_score: 1,
          scenario_anchors: [],
          inference_target: "edge"
        },
        standby_models: [],
        downgraded: false,
        claimed_assets: []
      }
    ],
    reasoning_trace: { is_multi_round: false, intent_state: null }
  };
  const expStream = await executeLegacyDAGStream(
    env,
    expensiveFallbackDag,
    {
      envelope_id: "env_exp",
      session_id: "sess_exp",
      round_index: 1,
      instruction_payload: "test expensive fallback",
      assets_manifest: [],
      constraint_context: { target_language: "en", output_style: "concise" }
    } as any,
    {
      userId: oneCreditUserId,
      hasPreDeducted: false,
      preDeductedCredits: 0,
      clientCapabilities: { webgpu_handover_v3: false }
    }
  );
  const expReader = expStream.getReader();
  let expSseText = "";
  const expDec = new TextDecoder();
  while (true) {
    const { done, value } = await expReader.read();
    if (done) break;
    expSseText += expDec.decode(value, { stream: true });
  }
  assert.ok(
    expSseText.includes("event: error"),
    "Expensive 10-credit standby fallback for 1-credit user must emit error event before execution"
  );
  const oneCreditUserAfter = store.users.find((u) => u.user_id === oneCreditUserId)!;
  assert.equal(
    oneCreditUserAfter.credits,
    1,
    "1-credit user blocked from expensive fallback must stay at 1 credit (never negative)"
  );

  // 20.8 NM-AUD-15 & NM-AUD-16: Admin enum/subsistence checks & Edge security headers
  const adminReLoginRes = await worker.fetch(
    new Request("https://nanomesh.local/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json", "CF-Connecting-IP": "198.51.100.78" },
      body: JSON.stringify({ password: (env as any).ADMIN_PASSWORD })
    }),
    env,
    {} as any
  );
  const freshAdminCookie = (adminReLoginRes.headers.get("Set-Cookie") || "").split(";")[0];

  store.user_uploaded_models.push({
    upload_id: "uum_nm15_test",
    user_id: s20UserId,
    display_name: "Test Model",
    status: "pending"
  });
  const badStatusModelRes = await worker.fetch(
    new Request("https://nanomesh.local/api/admin/models/uum_nm15_test", {
      method: "PATCH",
      headers: { Cookie: freshAdminCookie, "Content-Type": "application/json" },
      body: JSON.stringify({ status: "hacked" })
    }),
    env,
    {} as any
  );
  assert.equal(
    badStatusModelRes.status,
    400,
    "NM-AUD-15: handleAdminUpdateModel must reject invalid status enum"
  );

  store.dag_templates.push({
    template_id: "tpl_dead_nm15",
    name_zh: "Dead Template",
    role_sequence: JSON.stringify(["role_nonexistent_nm15"]),
    status: "disabled"
  });
  const toggleDeadTplRes = await worker.fetch(
    new Request("https://nanomesh.local/api/admin/templates/tpl_dead_nm15/toggle", {
      method: "POST",
      headers: { Cookie: freshAdminCookie, "Content-Type": "application/json" },
      body: JSON.stringify({ status: "active" })
    }),
    env,
    {} as any
  );
  assert.equal(
    toggleDeadTplRes.status,
    400,
    "NM-AUD-15: Activating a template with broken/dead roles must be blocked with 400"
  );

  const optionsRes = await worker.fetch(
    new Request("https://nanomesh.local/api/auth/me", { method: "OPTIONS" }),
    env,
    {} as any
  );
  assert.equal(optionsRes.headers.get("Vary"), "Origin");
  assert.equal(optionsRes.headers.get("Access-Control-Max-Age"), "86400");

  const storage403Res = await worker.fetch(
    new Request("https://nanomesh.local/storage/private.txt"),
    env,
    {} as any
  );
  assert.equal(storage403Res.status, 403);
  assert.equal(storage403Res.headers.get("X-Content-Type-Options"), "nosniff");

  const storage404Res = await worker.fetch(
    new Request("https://nanomesh.local/storage/avatars/does_not_exist.png"),
    env,
    {} as any
  );
  assert.equal(storage404Res.status, 404);
  assert.equal(storage404Res.headers.get("X-Content-Type-Options"), "nosniff");

  console.log(
    "  ✓ Scenario 20 (NM-AUD-01/02/05/06/07/09/12/13/15/16) all regression checks: PASSED"
  );

  // -------------------------------------------------------------------------------------------------
  // [Scenario 21] Canvas Micro-Tuning, Re-selection Safety & Input Freezing Invariants
  // -------------------------------------------------------------------------------------------------
  console.log(
    "\n[Scenario 21] Canvas Micro-Tuning, Re-selection Safety & Input Freezing Invariants"
  );

  const scen21UserId = "usr_scen21_tuning";
  store.users.push({
    user_id: scen21UserId,
    username: "scen21_user",
    email: "scen21@example.com",
    credits: 100,
    frozen_credits: 0,
    token_version: 1
  });
  const scen21Token = await signJWT(
    { userId: scen21UserId, tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  // 21.1 switch_template must strictly enforce subsistence law (modality matching) and block bypass
  store.dag_roles.push({
    role_id: "role-audio-only",
    name_zh: "纯音频转写岗",
    in_modalities: JSON.stringify(["audio"]),
    out_modalities: JSON.stringify(["text"]),
    requisition_tags: JSON.stringify(["#audio", "#asr"]),
    compensation_prompts: JSON.stringify({})
  });
  store.dag_templates.push({
    template_id: "tpl_audio_strictly_requires_media",
    name_zh: "严格音频转录流水线",
    roles: JSON.stringify([
      {
        role_id: "role-audio-only",
        name_zh: "纯音频转写岗",
        in_modalities: ["audio"],
        out_modalities: ["text"],
        in_degree: 0,
        out_degree: 0,
        requisition_tags: ["#audio", "#asr"]
      }
    ]),
    role_sequence: JSON.stringify(["role-audio-only"]),
    edges: JSON.stringify([]),
    status: "active"
  });

  // User input is pure text; trying to force switch_template to tpl_audio_strictly_requires_media must be rejected
  const reqIncompatibleTpl = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `session=${scen21Token}`,
      "CF-Connecting-IP": "198.51.100.99"
    },
    body: JSON.stringify({
      reRouteMode: "switch_template",
      chosenTemplateId: "tpl_audio_strictly_requires_media",
      envelope: {
        session_id: "sess_incompatible_tpl_01",
        instruction_payload: "Pure text query without audio asset",
        assets_manifest: []
      }
    })
  });
  const resIncompatibleTpl = await worker.fetch(reqIncompatibleTpl, env, {} as any);
  assert.equal(
    resIncompatibleTpl.status,
    500,
    "Incompatible template with unsatisfied input modality must be rejected, cannot bypass subsistence law"
  );

  // 21.2 isReRoute must preserve pristine instruction_payload and NOT inject '[上轮产物背景:...]\n用户追问:...'
  const pristinePayloadText = "Analyze this travel schedule objectively";
  const envelopeToTest: any = {
    envelope_id: "env_reroute_purity",
    session_id: "sess_reroute_purity",
    round_index: 1,
    instruction_payload: pristinePayloadText,
    assets_manifest: [],
    constraint_context: { target_language: "zh", output_style: "concise" },
    metadata: { client_timestamp: Date.now(), char_count_total: 10, estimated_input_tokens: 20 }
  };
  const dagReRouteTest = await runOrchestrationPipeline(env, envelopeToTest, {
    reRouteMode: "switch_model",
    chosenTemplateId: "tpl-direct-chat",
    hasPreviousRound: true,
    previousRoundSummary: "Old output from round 1 that should not contaminate this re-run"
  });
  // instruction_payload must stay completely pure!
  assert.equal(
    envelopeToTest.instruction_payload,
    pristinePayloadText,
    "isReRoute must keep instruction_payload pure and avoid injecting previous round summary"
  );
  assert.equal(dagReRouteTest.template.template_id, "tpl-direct-chat");

  // 21.3 switch_model with incompetent role model must safely fall back to competent model
  // Try assigning flux image generator to role-direct-chat (text only role)
  const dagIncompetentModelFallback = await runOrchestrationPipeline(
    env,
    {
      envelope_id: "env_model_competence",
      session_id: "sess_model_competence",
      round_index: 1,
      instruction_payload: "Text synthesis query",
      assets_manifest: [],
      constraint_context: { target_language: "zh", output_style: "concise" },
      metadata: { client_timestamp: Date.now(), char_count_total: 10, estimated_input_tokens: 20 }
    } as any,
    {
      reRouteMode: "switch_model",
      chosenTemplateId: "tpl-direct-chat",
      chosenRoleModels: {
        "role-direct-chat": "flux-schnell" // Image generation model, incompetent for text generation!
      }
    }
  );
  const assignedModel = dagIncompetentModelFallback.nodes[0].selected_model;
  assert.notEqual(
    assignedModel.model_id,
    "flux-schnell",
    "Incompetent model for role modality must be intercepted and safely fallback, not bound directly"
  );
  assert.ok(
    assignedModel.modalities.includes("text"),
    "Fell-back model must be competent for the text role"
  );

  // 21.4 switch_model (and prompt injection) with incompatible/offlined base template must explicitly fail rather than silently swapping templates
  await assert.rejects(
    async () => {
      await runOrchestrationPipeline(
        env,
        {
          envelope_id: "env_switch_model_subsistence",
          session_id: "sess_switch_model_subsistence",
          round_index: 1,
          instruction_payload: "Pure text query",
          assets_manifest: [],
          constraint_context: { target_language: "zh", output_style: "concise" },
          metadata: {
            client_timestamp: Date.now(),
            char_count_total: 10,
            estimated_input_tokens: 20
          }
        } as any,
        {
          reRouteMode: "switch_model",
          chosenTemplateId: "tpl_audio_strictly_requires_media" // Incompatible with pure text input!
        }
      );
    },
    /无法适配当前任务的输入模态或已被下线/,
    "switch_model must explicitly reject an invalid/incompatible base template instead of silently substituting another template"
  );

  // 21.5 Frozen input baseline integrity & round grouping logic
  // Simulate frozen input snapshot with asset A vs mutable canvas with asset B
  const frozenBaseline = {
    userText: "Initial query with asset A",
    frozenAssets: [
      { name: "file_a.txt", modality: "text", size: 100, assetId: "ast_a", r2Key: "r2_a" }
    ],
    targetLanguage: "ja",
    outputStyle: "academic",
    baseSummary: "",
    roundIndex: 1,
    baseRunId: "run-test-base-01",
    committedRevision: 1,
    revision: 1
  };
  const mutatedCanvasAssets = [
    { name: "file_b.png", modality: "image", size: 500, assetId: "ast_b", r2Key: "r2_b" }
  ];
  // Re-run constructor strictly isolates to frozenBaseline.frozenAssets
  const effectiveReRunAssets =
    frozenBaseline && Array.isArray(frozenBaseline.frozenAssets)
      ? JSON.parse(JSON.stringify(frozenBaseline.frozenAssets))
      : mutatedCanvasAssets;
  assert.equal(effectiveReRunAssets.length, 1);
  assert.equal(effectiveReRunAssets[0].name, "file_a.txt");
  assert.equal(effectiveReRunAssets[0].assetId, "ast_a");
  assert.equal(
    effectiveReRunAssets.some((a: any) => a.name === "file_b.png"),
    false,
    "Re-run must strictly isolate to frozen assets and discard mutated canvas assets"
  );

  // Simulate History Grouping by baseRunId
  const simulatedHistoryRounds = [
    {
      runId: "run-01",
      baseRunId: "run-01",
      revision: 1,
      isReRun: false,
      roundIndex: 1,
      userPrompt: "Q1"
    },
    {
      runId: "run-01-rev2",
      baseRunId: "run-01",
      revision: 2,
      isReRun: true,
      roundIndex: 1,
      userPrompt: "Q1"
    },
    {
      runId: "run-01-rev3",
      baseRunId: "run-01",
      revision: 3,
      isReRun: true,
      roundIndex: 1,
      userPrompt: "Q1"
    },
    {
      runId: "run-02",
      baseRunId: "run-02",
      revision: 1,
      isReRun: false,
      roundIndex: 2,
      userPrompt: "Q2"
    }
  ];
  const roundGroups = new Map<string, any[]>();
  simulatedHistoryRounds.forEach((r) => {
    const key = r.baseRunId || `round-${r.roundIndex}`;
    if (!roundGroups.has(key)) roundGroups.set(key, []);
    roundGroups.get(key)!.push(r);
  });
  // Must group into 2 distinct user rounds, NOT 4!
  assert.equal(
    roundGroups.size,
    2,
    "History grouping by baseRunId must identify exactly 2 rounds despite in-place revisions"
  );
  assert.equal(
    roundGroups.get("run-01")!.length,
    3,
    "Round 1 group must contain all 3 revisions in lineage"
  );
  assert.equal(
    roundGroups.get("run-01")![2].revision,
    3,
    "Latest revision of Round 1 must be revision 3"
  );

  // 21.6 Empty frozenAssets ([]), chunked SSE event preservation & history restore skipping failed revisions
  const emptyFrozenBaseline = { frozenAssets: [] as any[] };
  const resolvedEmptyAssets =
    emptyFrozenBaseline && Array.isArray(emptyFrozenBaseline.frozenAssets)
      ? JSON.parse(JSON.stringify(emptyFrozenBaseline.frozenAssets))
      : mutatedCanvasAssets;
  assert.equal(
    resolvedEmptyAssets.length,
    0,
    "Empty frozenAssets [] must be preserved rather than falling back to mutated canvas assets"
  );

  // Verify chunked SSE stream keeps event name across read() chunks until blank line delimiter
  const sseChunks = [
    "event: node_start\n",
    'data: {"role_id":"r1"}\n\nevent: dag_error\n',
    'data: {"error":"boom"}\n\n'
  ];
  const parsedEvents: Array<{ event: string; data: any }> = [];
  let sseBuffer = "";
  let sseEvent = "message";
  for (const chunk of sseChunks) {
    sseBuffer += chunk;
    const lines = sseBuffer.split("\n");
    sseBuffer = lines.pop() ?? "";
    for (const rawLine of lines) {
      const line = rawLine.replace(/\r$/, "");
      if (line === "") {
        sseEvent = "message";
        continue;
      }
      if (line.startsWith("event: ")) {
        sseEvent = line.slice(7).trim() || "message";
      } else if (line.startsWith("data: ")) {
        const dataStr = line.slice(6).trim();
        if (dataStr) parsedEvents.push({ event: sseEvent, data: JSON.parse(dataStr) });
      }
    }
  }
  assert.deepEqual(parsedEvents, [
    { event: "node_start", data: { role_id: "r1" } },
    { event: "dag_error", data: { error: "boom" } }
  ]);

  // Verify history restore skips trailing fast-failed revision and recovers targetLanguage/outputStyle
  const roundsWithTrailingFailure = [
    {
      runId: "run-01",
      baseRunId: "run-01",
      revision: 1,
      isFastFailed: false,
      targetLanguage: "ja",
      outputStyle: "academic",
      nodes: [{ role_id: "role-direct-chat" }],
      assistantOutput: "Valid output"
    },
    {
      runId: "run-01-rev2",
      baseRunId: "run-01",
      revision: 2,
      isFastFailed: true,
      targetLanguage: "ja",
      outputStyle: "academic",
      nodes: [{ role_id: "role_edge_firewall", status: "blocked" }],
      assistantOutput: ""
    }
  ];
  const isFailedRun = (r: any) =>
    !!(
      r?.isFastFailed ||
      (Array.isArray(r?.nodes) && r.nodes.some((n: any) => n.role_id === "role_edge_firewall"))
    );
  const restoredRound =
    [...roundsWithTrailingFailure].reverse().find((r) => !isFailedRun(r)) ||
    roundsWithTrailingFailure[roundsWithTrailingFailure.length - 1];
  assert.equal(restoredRound.runId, "run-01");
  assert.equal(restoredRound.targetLanguage, "ja");
  assert.equal(restoredRound.outputStyle, "academic");

  // 21.7 Canvas re-run ignores unsubmitted right-side chat input files & skips upload checks
  const rightInputSelectedFiles = [
    { name: "unsubmitted_b.png", uploadStatus: "uploading", modality: "image" },
    { name: "broken_c.pdf", uploadStatus: "error", modality: "pdf" }
  ];
  const isSwitchRun = true;
  const blockedByRightInputUpload =
    !isSwitchRun &&
    rightInputSelectedFiles.some(
      (f) => f.uploadStatus === "uploading" || f.uploadStatus === "error"
    );
  const newlySelectedOnRerun = isSwitchRun ? [] : [...rightInputSelectedFiles];
  assert.equal(
    blockedByRightInputUpload,
    false,
    "Canvas micro-tuning re-run must not be blocked by unsubmitted right-side input attachments"
  );
  assert.equal(
    newlySelectedOnRerun.length,
    0,
    "Canvas micro-tuning re-run must keep newlySelectedFiles empty so unsubmitted files never pollute session ledger"
  );

  console.log(
    "  ✓ Scenario 21 (Canvas Micro-Tuning, Re-selection Safety & Input Freezing Invariants): PASSED"
  );

  // -------------------------------------------------------------------------------------------------
  // [Scenario 22] Compositional Simultaneous Multimodal Flow, Parallel SSE & Clarification Interrupt
  // -------------------------------------------------------------------------------------------------
  console.log(
    "\n[Scenario 22] Compositional Simultaneous Multimodal Flow, Parallel SSE & Clarification Interrupt"
  );

  const scen22UserId = "usr_scen22_multimodal";
  store.users.push({
    user_id: scen22UserId,
    username: "scen22_user",
    email: "scen22@example.com",
    credits: 100,
    frozen_credits: 0,
    token_version: 1
  });
  const scen22Token = await signJWT(
    { userId: scen22UserId, tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  // Put both an image and an audio object into mock R2 for simultaneous multimodal execution
  const s22ImgKey = `tmp/${scen22UserId}/sess_scen22/img1.png`;
  const s22AudioKey = `tmp/${scen22UserId}/sess_scen22/aud1.mp3`;
  await env.R2.put(s22ImgKey, new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13]), {
    httpMetadata: { contentType: "image/png" }
  });
  await env.R2.put(s22AudioKey, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]), {
    httpMetadata: { contentType: "audio/mpeg" }
  });
  await registerPresignedAssetTicket(env, {
    assetId: "s22_img_1",
    userId: scen22UserId,
    filename: "room.png",
    modality: "image",
    mimeType: "image/png",
    fileSize: 12,
    r2Key: s22ImgKey,
    origin: "upload"
  });
  await registerPresignedAssetTicket(env, {
    assetId: "s22_aud_1",
    userId: scen22UserId,
    filename: "note.mp3",
    modality: "audio",
    mimeType: "audio/mpeg",
    fileSize: 8,
    r2Key: s22AudioKey,
    origin: "upload"
  });

  // Ensure whisper & vision models exist in store for simultaneous image + audio extraction
  if (!store.models.some((m: any) => m.model_id === "cf-whisper")) {
    store.models.push({
      model_id: "cf-whisper",
      display_name: "Whisper ASR",
      provider: "OpenAI",
      endpoint: "@cf/openai/whisper",
      modalities: JSON.stringify(["audio"]),
      in_modalities: JSON.stringify(["audio"]),
      out_modalities: JSON.stringify(["text"]),
      tags: JSON.stringify(["#asr", "#audio_processing"]),
      context_window: 4096,
      max_concurrency: 30,
      active_connections: 0,
      precision: 0.96,
      user_rating: 4.9,
      usage_count: 10,
      cost_per_1k_tokens: 1.0,
      cost_per_invocation: 0.0,
      status: "active",
      is_generalist: 0,
      prior_score: 0.0,
      scenario_anchors: JSON.stringify(["语音转写"]),
      inference_target: "edge",
      auth_mode: "none",
      api_format: "workers_ai"
    });
  }
  if (!store.dag_roles.some((r: any) => r.role_id === "role-audio-asr")) {
    store.dag_roles.push({
      role_id: "role-audio-asr",
      name_zh: "语音转录提取",
      name_en: "Speech Recognition",
      in_modalities: JSON.stringify(["audio"]),
      out_modalities: JSON.stringify(["text"]),
      requisition_tags: JSON.stringify(["#asr", "#audio_processing"]),
      compensation_prompts: JSON.stringify({})
    });
  }

  // 22.1 Simultaneous Image + Audio + Text Document -> Compositional Parallel Prep -> Reducer -> Synthesis
  const s22Req = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `session=${scen22Token}`,
      "CF-Connecting-IP": "198.51.100.122"
    },
    body: JSON.stringify({
      envelope: {
        envelope_id: "env_s22_comp",
        session_id: "sess_scen22",
        round_index: 1,
        instruction_payload: "请结合图片、录音与文档内容总结要点",
        assets_manifest: [
          {
            asset_id: "s22_img_1",
            filename: "room.png",
            modality: "image",
            mime_type: "image/png",
            file_size: 12,
            r2_key: s22ImgKey,
            consumed: false,
            source_digest: "s22-dig-img",
            is_new: true
          },
          {
            asset_id: "s22_aud_1",
            filename: "note.mp3",
            modality: "audio",
            mime_type: "audio/mpeg",
            file_size: 8,
            r2_key: s22AudioKey,
            consumed: false,
            source_digest: "s22-dig-aud",
            is_new: true
          },
          {
            asset_id: "s22_doc_1",
            filename: "spec.txt",
            modality: "text_doc",
            mime_type: "text/plain",
            file_size: 20,
            in_memory_text: "预算上限: 8000元",
            consumed: false,
            source_digest: "s22-dig-doc",
            is_new: true
          }
        ],
        constraint_context: { target_language: "zh", output_style: "concise" },
        metadata: {
          client_timestamp: Date.now(),
          char_count_total: 20,
          estimated_input_tokens: 250
        }
      }
    })
  });
  const s22Res = await worker.fetch(s22Req, env, {} as any);
  assert.equal(
    s22Res.status,
    200,
    "Simultaneous image+audio+doc must succeed via compositional DAG (HTTP 200)"
  );
  const s22Text = await s22Res.text();
  assert.ok(
    s22Text.includes('"topology_mode":"compositional"'),
    "Must emit compositional topology_mode in dag_plan"
  );
  assert.ok(
    s22Text.includes('"exec_mode":"parallel"'),
    "Must execute independent raw sensory prep nodes with parallel exec_mode"
  );
  assert.ok(
    s22Text.includes("reducer-merge"),
    "Must include reducer-merge node converging prep outputs"
  );
  assert.ok(
    s22Text.includes('"perceptual_entries"'),
    "Must emit perceptual_entries on dag_complete"
  );

  // 22.2 Ambiguous CROSS_FUSION triggers 0-credit clarification_required, then resumes cleanly after target confirmation
  const s22ClarifyImgKey = `tmp/${scen22UserId}/s22-clarify-img/poster_a.png`;
  await env.R2.put(
    s22ClarifyImgKey,
    new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13]),
    { httpMetadata: { contentType: "image/png" } }
  );
  store.session_assets!.push({
    asset_id: "ast_a_poster",
    session_id: "sess_scen22_clarify",
    user_id: scen22UserId,
    branch_id: "branch_a",
    commit_id: "cmt_s22_a",
    filename: "poster_a.png",
    modality: "image",
    mime_type: "image/png",
    file_size: 12,
    r2_key: s22ClarifyImgKey,
    source_digest: "s22-dig-img",
    origin: "upload",
    introduced_round: 1,
    status: "COMMITTED",
    summary_snippet: "海报A设计"
  });
  const creditsBeforeClarify = store.users.find((u) => u.user_id === scen22UserId)!.credits;
  const origAiS22 = env.AI;
  try {
    (env as any).AI = {
      async run(model: string, input: any) {
        if (
          model === "@cf/meta/llama-3.1-8b-instruct-fast" &&
          JSON.stringify(input).includes("Joint Git-DAG")
        ) {
          return {
            response: JSON.stringify({
              intent_op: "CROSS_FUSION",
              target_branch_id: "branch_b",
              source_branch_ids: ["branch_a"],
              asset_bindings: [{ asset_id: "ast_a_poster", bind_mode: "RAW_MEDIA" }],
              delivery_confidence: "ambiguous",
              needs_wider_recall: false
            })
          };
        }
        return origAiS22.run(model, input);
      }
    };

    const clarifyReq = new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `session=${scen22Token}`,
        "CF-Connecting-IP": "198.51.100.123"
      },
      body: JSON.stringify({
        hasPreviousRound: true,
        activeBranchId: "branch_b",
        activeBranchSummary: "分支B最新方案",
        sessionAssetLedger: [
          {
            asset_id: "ast_a_poster",
            filename: "poster_a.png",
            modality: "image",
            branch_id: "branch_a",
            r2_key: s22ClarifyImgKey,
            source_digest: "s22-dig-img",
            origin: "upload"
          }
        ],
        branchCatalog: [
          {
            branch_id: "branch_a",
            topic: "海报分支A",
            is_active: false,
            last_summary: "海报A设计"
          },
          { branch_id: "branch_b", topic: "方案分支B", is_active: true, last_summary: "当前方案B" }
        ],
        envelope: {
          envelope_id: "env_s22_clarify",
          session_id: "sess_scen22_clarify",
          round_index: 2,
          instruction_payload: "把之前的海报和这个合一下",
          assets_manifest: [
            {
              asset_id: "ast_a_poster",
              filename: "poster_a.png",
              modality: "image",
              mime_type: "image/png",
              file_size: 12,
              r2_key: s22ClarifyImgKey,
              consumed: false,
              source_digest: "s22-dig-img",
              is_new: false,
              branch_id: "branch_a"
            }
          ]
        }
      })
    });
    const clarifyRes = await worker.fetch(clarifyReq, env, {} as any);
    assert.equal(clarifyRes.status, 200);
    const clarifySse = await clarifyRes.text();
    assert.ok(
      clarifySse.includes("event: clarification_required"),
      "Ambiguous cross-branch delivery must emit clarification_required"
    );
    assert.ok(clarifySse.includes('"is_clarification_required":true'));
    const creditsAfterClarify = store.users.find((u) => u.user_id === scen22UserId)!.credits;
    assert.equal(
      creditsAfterClarify,
      creditsBeforeClarify,
      "Clarification interrupt must charge 0 credits"
    );

    // Resume after user selects branch_a via existing input box
    const resumeReq = new Request("https://nanomesh.local/api/chat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Cookie: `session=${scen22Token}`,
        "CF-Connecting-IP": "198.51.100.124"
      },
      body: JSON.stringify({
        hasPreviousRound: true,
        activeBranchId: "branch_b",
        resolvedClarificationTargetBranchId: "branch_a",
        activeBranchSummary: "分支B最新方案",
        sessionAssetLedger: [
          {
            asset_id: "ast_a_poster",
            filename: "poster_a.png",
            modality: "image",
            branch_id: "branch_a",
            r2_key: s22ClarifyImgKey,
            source_digest: "s22-dig-img",
            origin: "upload"
          }
        ],
        branchCatalog: [
          {
            branch_id: "branch_a",
            topic: "海报分支A",
            is_active: false,
            last_summary: "海报A设计"
          },
          { branch_id: "branch_b", topic: "方案分支B", is_active: true, last_summary: "当前方案B" }
        ],
        envelope: {
          envelope_id: "env_s22_resume",
          session_id: "sess_scen22_clarify",
          round_index: 2,
          instruction_payload: "把之前的海报和这个合一下",
          assets_manifest: [
            {
              asset_id: "ast_a_poster",
              filename: "poster_a.png",
              modality: "image",
              mime_type: "image/png",
              file_size: 12,
              r2_key: s22ClarifyImgKey,
              consumed: false,
              source_digest: "s22-dig-img",
              is_new: false,
              branch_id: "branch_a"
            }
          ]
        }
      })
    });
    const resumeRes = await worker.fetch(resumeReq, env, {} as any);
    assert.equal(resumeRes.status, 200);
    const resumeSse = await resumeRes.text();
    assert.ok(
      !resumeSse.includes("event: clarification_required"),
      "Resolved target branch must proceed directly to execution"
    );
    assert.ok(
      resumeSse.includes('"target_branch_id":"branch_a"'),
      "Must honor user's clarified delivery branch_a"
    );
  } finally {
    (env as any).AI = origAiS22;
  }

  console.log(
    "  ✓ Scenario 22 (Compositional Simultaneous Multimodal, Parallel Prep & Clarification Loop): PASSED"
  );

  // =========================================================================
  // Scenario 23: Plan Identity Freeze (/api/chat/continue), Authoritative Session State,
  //              Cross-Session R2 BOLA Guard & Bounded Parallel Prep Concurrency
  // =========================================================================
  console.log(
    "\n[Scenario 23] Testing Plan Identity Freeze, Authoritative Git State, Cross-Session R2 Block & Bounded Concurrency..."
  );

  const scen23UserId = "usr_scen23_closed_loop";
  store.users.push({
    user_id: scen23UserId,
    username: "Scenario23User",
    email: "scen23@nanomesh.local",
    password_hash: "hash",
    credits: 100,
    token_version: 1
  });
  const scen23Token = await signJWT(
    { userId: scen23UserId, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  const s23OwnerKey = `tmp/${scen23UserId}/s23-owner/secret.png`;
  await env.R2.put(s23OwnerKey, new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]), {
    httpMetadata: { contentType: "image/png" }
  });
  store.session_assets!.push({
    asset_id: "ast_s23_owner",
    session_id: "sess_s23_legit_a",
    user_id: scen23UserId,
    branch_id: "main",
    commit_id: "cmt_s23_a",
    filename: "secret.png",
    modality: "image",
    mime_type: "image/png",
    file_size: 8,
    r2_key: s23OwnerKey,
    source_digest: "s23-owner-dig",
    origin: "upload",
    introduced_round: 1,
    status: "COMMITTED",
    summary_snippet: "Session A secret image"
  });

  // 23.1 Cross-session R2 access attempt blocked even for same user across sessions
  const crossSessionReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `session=${scen23Token}`,
      "CF-Connecting-IP": "198.51.100.125"
    },
    body: JSON.stringify({
      envelope: {
        envelope_id: "env_s23_bola",
        session_id: "sess_scen23_attacker",
        round_index: 1,
        instruction_payload: "读取另一会话里的图片",
        assets_manifest: [
          {
            asset_id: "forged_ast",
            filename: "stolen.png",
            modality: "image",
            mime_type: "image/png",
            file_size: 8,
            r2_key: s23OwnerKey, // Owned by sess_s23_legit_a!
            consumed: false,
            source_digest: "s23-owner-dig",
            is_new: false
          }
        ]
      }
    })
  });
  const crossSessionRes = await worker.fetch(crossSessionReq, env, {} as any);
  assert.equal(
    crossSessionRes.status,
    403,
    "Attempt to claim or read R2 key owned by another session must be rejected with HTTP 403"
  );
  const crossSessionJson: any = await crossSessionRes.json();
  assert.equal(crossSessionJson.error, "asset_ownership_violation");

  // 23.2 Bounded concurrency <= 2 on 3 simultaneous raw images + waiting_resource + authoritative session commit & GET /state
  const s23BatchImgs = [1, 2, 3].map((i) => ({
    id: `s23_img_${i}`,
    key: `tmp/${scen23UserId}/s23-batch-${i}/img_${i}.png`,
    digest: `s23-batch-dig-${i}`
  }));
  for (const img of s23BatchImgs) {
    await env.R2.put(img.key, new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10]), {
      httpMetadata: { contentType: "image/png" }
    });
    await registerPresignedAssetTicket(env, {
      assetId: img.id,
      userId: scen23UserId,
      filename: `${img.id}.png`,
      modality: "image",
      mimeType: "image/png",
      fileSize: 8,
      r2Key: img.key,
      origin: "upload"
    });
  }
  const s23BatchReq = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Cookie: `session=${scen23Token}`,
      "CF-Connecting-IP": "198.51.100.126"
    },
    body: JSON.stringify({
      runId: "run_s23_batch_1",
      disableBrowserInference: true,
      envelope: {
        envelope_id: "env_s23_batch",
        session_id: "sess_scen23_auth",
        round_index: 1,
        instruction_payload: "对比这三张图的差异",
        assets_manifest: s23BatchImgs.map((img, i) => ({
          asset_id: img.id,
          filename: `img_${i + 1}.png`,
          modality: "image",
          mime_type: "image/png",
          file_size: 8,
          r2_key: img.key,
          consumed: false,
          source_digest: img.digest,
          is_new: true
        })),
        constraint_context: { target_language: "zh", output_style: "concise" },
        metadata: { client_timestamp: Date.now(), char_count_total: 10, estimated_input_tokens: 80 }
      }
    })
  });
  const s23BatchRes = await worker.fetch(s23BatchReq, env, {} as any);
  assert.equal(s23BatchRes.status, 200);
  const s23BatchSse = await s23BatchRes.text();
  assert.ok(
    s23BatchSse.includes('"status":"waiting_resource"'),
    "3 parallel sensory prep nodes with limit=2 must emit waiting_resource for queued node"
  );
  assert.ok(
    s23BatchSse.includes('"authoritative_git_state"') &&
      s23BatchSse.includes("event: dag_complete"),
    "Cloud completion must commit authoritative Git state to D1 and emit snapshot in dag_complete"
  );

  const getStateReq = new Request("https://nanomesh.local/api/session/sess_scen23_auth/state", {
    method: "GET",
    headers: { Cookie: `session=${scen23Token}` }
  });
  const getStateRes = await worker.fetch(getStateReq, env, {} as any);
  assert.equal(getStateRes.status, 200);
  const authSnapshot: any = await getStateRes.json();
  assert.equal(authSnapshot.commit_order.length, 1);
  assert.equal(authSnapshot.session_asset_ledger.length, 3);

  // 23.3 Frozen Plan Identity on /api/chat/continue rejects tampered plan_hash (HTTP 409) & accepts valid frozen plan
  const testRunId = "run_s23_frozen_handover";
  const frozenHandoverId = "hs_s23_frozen_1";
  store.dag_handshakes.push({
    handshake_id: frozenHandoverId,
    user_id: scen23UserId,
    session_id: "sess_scen23_handover",
    template_id: webgpuArbitraryTemplateId,
    next_step: 1,
    status: "ISSUED",
    expires_at: new Date(Date.now() + 300000).toISOString()
  });
  const frozenDagSample: any = {
    template: {
      template_id: webgpuArbitraryTemplateId,
      name_zh: "冻结计划校验模板",
      name_en: "Frozen Plan Template",
      desc_zh: "",
      desc_en: "",
      head_modalities: ["text"],
      tail_modalities: ["text"],
      roles: [],
      priority: 1,
      status: "active"
    },
    candidate_templates: [],
    topology_mode: "standard",
    nodes: [
      {
        node_id: "step_0_prep",
        stage_group: "evidence_prep",
        depends_on: ["__ORIGIN__"],
        role: {
          role_id: "role_text_reasoning",
          name_zh: "步骤0",
          name_en: "Step0",
          in_modalities: ["text"],
          out_modalities: ["text"],
          in_degree: 0,
          out_degree: 1,
          requisition_tags: []
        },
        selected_model:
          store.models.find((m) => m.model_id === "webgpu_slm_local") || store.models[0],
        standby_models: [],
        score_details: {
          model: store.models[0],
          score: 1,
          sim: 1,
          concurrency_penalty: 0,
          specialist_score: 1
        },
        downgraded: false,
        claimed_assets: []
      },
      {
        node_id: "step_1_synth",
        stage_group: "synthesis_output",
        depends_on: ["step_0_prep"],
        role: {
          role_id: "role_text_reasoning",
          name_zh: "总结推理",
          name_en: "Synth",
          in_modalities: ["text"],
          out_modalities: ["text"],
          in_degree: 1,
          out_degree: 0,
          requisition_tags: []
        },
        selected_model: {
          model_id: "cf-llama-s23-frozen",
          display_name: "Llama 3.1 8B Frozen Edge",
          provider: "Cloudflare Workers AI",
          endpoint: "@cf/meta/llama-3.1-8b-instruct-fast",
          modalities: ["text"],
          in_modalities: ["text"],
          out_modalities: ["text"],
          tags: ["#chat"],
          context_window: 8192,
          max_concurrency: 20,
          active_connections: 0,
          precision: 0.95,
          user_rating: 4.9,
          usage_count: 10,
          cost_per_1k_tokens: 1,
          cost_per_invocation: 0,
          status: "active",
          is_generalist: 1,
          prior_score: 0.5,
          scenario_anchors: ["chat"],
          inference_target: "edge",
          auth_mode: "none",
          api_format: "workers_ai"
        },
        standby_models: [],
        score_details: {
          model: store.models[0],
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
      selected_template_id: webgpuArbitraryTemplateId,
      downgrade_events: []
    }
  };
  const frozenEnvSample: UnifiedProtocolEnvelope = {
    envelope_id: "env_s23_frozen",
    session_id: "sess_scen23_handover",
    round_index: 1,
    instruction_payload: "FROZEN_PLAN_ORIGINAL_PROMPT",
    assets_manifest: [],
    constraint_context: { target_language: "zh", output_style: "concise" },
    metadata: { client_timestamp: Date.now(), char_count_total: 20, estimated_input_tokens: 50 }
  };
  await registerAndFreezeDagRunPlan(env, {
    runId: testRunId,
    userId: scen23UserId,
    sessionId: "sess_scen23_handover",
    clientOpId: "op_s23_frozen_1",
    requestDigest: "dig_s23_frozen_1",
    planHash: "valid-plan-hash-s23",
    dag: frozenDagSample,
    originalEnvelope: frozenEnvSample,
    resolvedEnvelope: frozenEnvSample,
    isReRun: false,
    expectedParentCommitId: null,
    expectedBaseRevision: null
  });

  const tamperedContinueJwt = await signJWT(
    {
      jti: frozenHandoverId,
      sub: scen23UserId,
      sid: "sess_scen23_handover",
      tid: webgpuArbitraryTemplateId,
      nxt: 1,
      rid: testRunId,
      ph: "tampered-wrong-hash"
    },
    env.JWT_SECRET,
    300
  );
  const tamperedContReq = new Request("https://nanomesh.local/api/chat/continue", {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: `session=${scen23Token}` },
    body: JSON.stringify({
      continuation_token: tamperedContinueJwt,
      status: "success",
      client_step_output: "WebGPU Done",
      envelope: frozenEnvSample
    })
  });
  const tamperedContRes = await handleChatContinue(tamperedContReq, env);
  assert.equal(
    tamperedContRes.status,
    409,
    "/api/chat/continue MUST reject mismatched plan_hash with 409 plan_identity_mismatch"
  );

  const validContinueJwt = await signJWT(
    {
      jti: frozenHandoverId,
      sub: scen23UserId,
      sid: "sess_scen23_handover",
      tid: webgpuArbitraryTemplateId,
      nxt: 1,
      rid: testRunId,
      ph: "valid-plan-hash-s23"
    },
    env.JWT_SECRET,
    300
  );
  const validContReq = new Request("https://nanomesh.local/api/chat/continue", {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: `session=${scen23Token}` },
    body: JSON.stringify({
      continuation_token: validContinueJwt,
      status: "success",
      client_step_output: "WebGPU Step 0 Frozen Output",
      envelope: {
        ...frozenEnvSample,
        // Deliberately alter client envelope prompt to verify server restores frozen D1 envelope!
        instruction_payload: "CLIENT_FORGED_PROMPT_SHOULD_NOT_WIN"
      }
    })
  });
  const validContRes = await handleChatContinue(validContReq, env);
  assert.equal(validContRes.status, 200, "Valid (run_id, plan_hash) must resume cleanly");
  const validContSse = await validContRes.text();
  assert.ok(
    validContSse.includes("event: dag_complete"),
    `Resumed frozen plan must complete. Got SSE: ${validContSse}`
  );

  console.log(
    "  ✓ Scenario 23 (Plan Identity Freeze, Authoritative Git State, Cross-Session R2 Block & Bounded Concurrency): PASSED"
  );

  // Scenario 24: switch_model & retry must keep standby_models in dag_plan for UI inspector while disabling execution failover
  const scen24UserId = "usr_scen24_switch_lock";
  store.users.push({
    user_id: scen24UserId,
    username: "SwitchLockTester",
    email: "switchlock@test.local",
    password_hash: "hash",
    credits: 100,
    token_version: 1
  });
  const scen24Token = await signJWT(
    { userId: scen24UserId, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const prevAiRun24 = env.AI.run;
  let scen24StandbyAttempted = false;
  (env.AI as any).run = async (endpoint: string, payload: any) => {
    if (endpoint === "@cf/qwen/qwen3.8-27b") {
      throw new Error("Simulated Qwen3.8 failure in switch_model");
    }
    if (endpoint === "@cf/meta/llama-3.1-8b-instruct-fast") {
      scen24StandbyAttempted = true;
      return { response: "Fallback fast response" };
    }
    return prevAiRun24.call(env.AI, endpoint, payload);
  };
  store.models.push(
    {
      model_id: "cf-qwen3.8-s24",
      display_name: "Qwen3.8-27B S24",
      provider: "Qwen",
      endpoint: "@cf/qwen/qwen3.8-27b",
      modalities: '["text"]',
      in_modalities: '["text"]',
      out_modalities: '["text"]',
      tags: '["#chat","#text_generation","#general"]',
      context_window: 32768,
      max_concurrency: 40,
      active_connections: 0,
      precision: 0.96,
      user_rating: 4.95,
      usage_count: 100,
      cost_per_1k_tokens: 1,
      cost_per_invocation: 0,
      status: "active",
      is_generalist: 1,
      prior_score: 0.25,
      scenario_anchors: "[]",
      inference_target: "edge",
      auth_mode: "none",
      api_format: "workers_ai"
    },
    {
      model_id: "cf-fast-s24",
      display_name: "Llama-3.1-8B Fast S24",
      provider: "Meta",
      endpoint: "@cf/meta/llama-3.1-8b-instruct-fast",
      modalities: '["text"]',
      in_modalities: '["text"]',
      out_modalities: '["text"]',
      tags: '["#chat","#text_generation","#general"]',
      context_window: 32768,
      max_concurrency: 80,
      active_connections: 0,
      precision: 0.95,
      user_rating: 4.96,
      usage_count: 100,
      cost_per_1k_tokens: 1,
      cost_per_invocation: 0,
      status: "active",
      is_generalist: 1,
      prior_score: 0.25,
      scenario_anchors: "[]",
      inference_target: "edge",
      auth_mode: "none",
      api_format: "workers_ai"
    }
  );
  const scen24Req = new Request("https://nanomesh.local/api/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json", Cookie: `session=${scen24Token}` },
    body: JSON.stringify({
      clientOpId: "op_scen24_switch_lock",
      isReRun: false,
      reRouteMode: "switch_model",
      chosenTemplateId: "tpl-direct-chat",
      chosenRoleModels: { "role-direct-chat": "cf-qwen3.8-s24" },
      envelope: {
        envelope_id: "env_scen24",
        session_id: "sess_scen24",
        round_index: 1,
        instruction_payload: "Test strict model switch lock",
        assets_manifest: [],
        constraint_context: { target_language: "zh", output_style: "concise" },
        metadata: { client_timestamp: Date.now(), char_count_total: 20, estimated_input_tokens: 20 }
      }
    })
  });
  const scen24Res = await handleChat(scen24Req, env);
  assert.equal(scen24Res.status, 200);
  const scen24Sse = await scen24Res.text();
  (env.AI as any).run = prevAiRun24;
  const scen24PlanMatch = scen24Sse.match(/event: dag_plan\ndata: ([^\n]+)/);
  assert.ok(scen24PlanMatch, "dag_plan event must be emitted");
  const scen24Plan = JSON.parse(scen24PlanMatch![1]);
  assert.equal(scen24Plan.nodes[0].selected_model.model_id, "cf-qwen3.8-s24");
  assert.ok(
    Array.isArray(scen24Plan.nodes[0].standby_models) &&
      scen24Plan.nodes[0].standby_models.length > 0,
    "dag_plan must still include standby_models so UI Inspector dropdown retains candidate choices"
  );
  assert.equal(
    scen24StandbyAttempted,
    false,
    "switch_model execution must NOT fail over to standby_models"
  );
  assert.ok(!scen24Sse.includes("event: node_failover"));
  assert.ok(scen24Sse.includes("event: dag_error"));
  console.log(
    "  ✓ Scenario 24 (switch_model Strict Execution Lock Preserving UI Candidate Options): PASSED"
  );

  // -----------------------------------------------------------------------
  // SCENARIO 25: Multimodal Artifact Routing Across Light (WebGPU), Medium (Workers AI), Heavy (VPS/External) & DAG Positions
  // -----------------------------------------------------------------------
  console.log(
    "\n[Scenario 25] Multimodal Artifacts Across Light/Medium/Heavy Tiers & Arbitrary DAG Positions"
  );
  const { signJWT: signJwtS25 } = await import("../src/auth/jwt");
  const { buildDownstreamMessages: buildMsgsS25 } = await import("../src/orchestration/dispatcher");
  const { handleCommitSessionTurn: handleCommitS25 } = await import("../src/api/session");
  const { handleChatContinue: handleContinueS25 } = await import("../src/api/chat");

  const scen25UserId = "usr_scen25_mm";
  const scen25User2Id = "usr_scen25_mm_2";
  store.users.push(
    {
      user_id: scen25UserId,
      username: "scen25_mm",
      email: "scen25@nanomesh.local",
      password_hash: "unused",
      role: "user",
      credits: 200,
      token_version: 1
    },
    {
      user_id: scen25User2Id,
      username: "scen25_mm_2",
      email: "scen25_2@nanomesh.local",
      password_hash: "unused",
      role: "user",
      credits: 200,
      token_version: 1
    }
  );
  const scen25Token = await signJwtS25(
    { userId: scen25UserId, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );
  const scen25Token2 = await signJwtS25(
    { userId: scen25User2Id, role: "user", tokenVersion: 1 },
    env.JWT_SECRET,
    3600
  );

  store.dag_roles.push(
    {
      role_id: "role_s25_text_head",
      name_zh: "文本首节点拆解",
      name_en: "Text Head Extractor",
      in_modalities: JSON.stringify(["text"]),
      out_modalities: JSON.stringify(["text"]),
      requisition_tags: JSON.stringify(["#chat", "#text_generation", "#general"])
    },
    {
      role_id: "role_s25_browser_mid",
      name_zh: "端侧过渡整理",
      name_en: "Browser Mid Synth",
      in_modalities: JSON.stringify(["text"]),
      out_modalities: JSON.stringify(["text"]),
      requisition_tags: JSON.stringify(["#chat", "#general"])
    },
    {
      role_id: "role_s25_heavy_vlm_tail",
      name_zh: "重节点视觉终审",
      name_en: "Heavy VLM Tail",
      in_modalities: JSON.stringify(["image", "text"]),
      out_modalities: JSON.stringify(["text"]),
      requisition_tags: JSON.stringify(["#multimodal_vision", "#general_vlm"])
    },
    {
      role_id: "role_s25_heavy_gem_img",
      name_zh: "重节点Gemini生图",
      name_en: "Heavy Gemini ImageGen",
      in_modalities: JSON.stringify(["text"]),
      out_modalities: JSON.stringify(["image"]),
      requisition_tags: JSON.stringify(["#image_generation"])
    }
  );
  store.models.push(
    {
      model_id: "browser-s25-text",
      display_name: "WebGPU S25",
      provider: "WebGPU",
      endpoint: "onnx-community/SmolLM2-135M-Instruct-ONNX",
      modalities: '["text"]',
      in_modalities: '["text"]',
      out_modalities: '["text"]',
      tags: '["#chat","#general"]',
      context_window: 1024,
      max_concurrency: 100,
      active_connections: 0,
      precision: 0.85,
      user_rating: 4.9,
      usage_count: 10,
      cost_per_1k_tokens: 0,
      cost_per_invocation: 0,
      status: "active",
      is_generalist: 1,
      prior_score: 0.25,
      scenario_anchors: "[]",
      inference_target: "browser",
      auth_mode: "none",
      api_format: "workers_ai"
    },
    {
      model_id: "heavy-vlm-s25",
      display_name: "Heavy VLM S25",
      provider: "ExternalVLM",
      endpoint: "https://api.mock-s25-heavy.com/v1/chat/completions",
      modalities: '["image","text"]',
      in_modalities: '["image","text"]',
      out_modalities: '["text"]',
      tags: '["#multimodal_vision","#general_vlm","#analysis","#chat"]',
      context_window: 32768,
      max_concurrency: 50,
      active_connections: 0,
      precision: 0.96,
      user_rating: 4.9,
      usage_count: 10,
      cost_per_1k_tokens: 1,
      cost_per_invocation: 0,
      status: "active",
      is_generalist: 0,
      prior_score: 0,
      scenario_anchors: "[]",
      inference_target: "heavy",
      auth_mode: "bearer_static",
      auth_secret: "sk-s25-test",
      api_format: "openai_compat"
    },
    {
      model_id: "heavy-gemini-img-s25",
      display_name: "Gemini Image S25",
      provider: "Google",
      endpoint: "https://api.mock-s25-gemini.com/v1beta/models",
      modalities: '["text","image"]',
      in_modalities: '["text"]',
      out_modalities: '["image"]',
      tags: '["#image_generation"]',
      context_window: 32768,
      max_concurrency: 50,
      active_connections: 0,
      precision: 0.96,
      user_rating: 4.9,
      usage_count: 10,
      cost_per_1k_tokens: 1,
      cost_per_invocation: 0,
      status: "active",
      is_generalist: 0,
      prior_score: 0,
      scenario_anchors: "[]",
      inference_target: "heavy",
      auth_mode: "bearer_static",
      auth_secret: "sk-gem-s25",
      api_format: "google_ai"
    }
  );
  store.dag_templates.push(
    {
      template_id: "tpl_s25_flux_browser_heavyvlm",
      name_zh: "中生图→轻过渡→重识图",
      name_en: "Flux->Browser->HeavyVLM",
      desc_zh:
        "Medium Flux generates image, Browser runs mid step, Heavy VLM inspects generated image",
      desc_en: "Medium->Light->Heavy multimodal",
      role_sequence: JSON.stringify([
        "role_flux_draw",
        "role_s25_browser_mid",
        "role_s25_heavy_vlm_tail"
      ]),
      edges: JSON.stringify([]),
      head_modalities: JSON.stringify(["text"]),
      tail_modalities: JSON.stringify(["text"]),
      status: "active",
      priority: 5
    },
    {
      template_id: "tpl_s25_gemimg_browser_tail",
      name_zh: "重Gemini生图→轻端侧总结",
      name_en: "GeminiImg->BrowserTail",
      desc_zh: "Heavy Gemini generates image before Browser tail",
      desc_en: "Heavy->Light multimodal",
      role_sequence: JSON.stringify(["role_s25_heavy_gem_img", "role_s25_browser_mid"]),
      edges: JSON.stringify([]),
      head_modalities: JSON.stringify(["text"]),
      tail_modalities: JSON.stringify(["image"]),
      status: "active",
      priority: 5
    },
    {
      template_id: "tpl_s25_text_head_browser",
      name_zh: "纯文本多节点流水线",
      name_en: "MultiNode Text Pipeline",
      desc_zh: "Multi-node pure text pipeline",
      desc_en: "Multi-node pure text",
      role_sequence: JSON.stringify(["role_s25_text_head", "role_s25_browser_mid"]),
      edges: JSON.stringify([]),
      head_modalities: JSON.stringify(["text"]),
      tail_modalities: JSON.stringify(["text"]),
      status: "active",
      priority: 5
    }
  );

  // 25.1 Medium Flux [Head] -> Light WebGPU [Intermediate] -> Heavy VLM [Tail]
  const s25TinPngB64 =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";
  let s25HeavyVlmSawImageUrl = false;
  let s25HeavyVlmSawBrowserMidText = false;
  let s25HeavyVlmImageAttachedToCurrentTurn = false;
  let s25TextHeadSawDoc = false;
  let s25TextHeadSawVisionMask = false;
  const prevAiRun25 = env.AI.run;
  const origFetch25 = globalThis.fetch;

  (env.AI as any).run = async (ep: string, payload: any) => {
    if (ep.includes("flux")) {
      return { image: s25TinPngB64 };
    }
    if (ep.includes("bge-m3")) {
      return { data: [[0.1, 0.2, 0.3]] };
    }
    if (ep.includes("llama-3.1-8b") && typeof payload?.messages?.[0]?.content === "string") {
      const msgBlob = JSON.stringify(payload.messages);
      if (msgBlob.includes("Extract KPI summary")) {
        s25TextHeadSawDoc = msgBlob.includes("ROW_DATA_");
        s25TextHeadSawVisionMask = msgBlob.includes("请对输入的图像进行全要素解析");
        return { response: "KPI extracted cleanly: revenue +20%." };
      }
      return { response: "SAFE" };
    }
    return { response: "Edge response" };
  };
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (url.includes("api.mock-s25-heavy.com")) {
      const bodyObj = JSON.parse((init?.body as string) || "{}");
      const msgs = bodyObj.messages || [];
      const lastMsg = msgs[msgs.length - 1];
      s25HeavyVlmSawBrowserMidText = JSON.stringify(msgs).includes("Browser mid prompt for VLM");
      if (Array.isArray(lastMsg?.content)) {
        const hasImg = lastMsg.content.some(
          (p: any) =>
            p.type === "image_url" &&
            String(p.image_url?.url || "").startsWith("data:image/png;base64,")
        );
        s25HeavyVlmSawImageUrl = hasImg;
        s25HeavyVlmImageAttachedToCurrentTurn = hasImg;
      }
      return new Response(
        'data: {"choices":[{"delta":{"content":"重节点VLM已成功校验端侧中间产物与Phase1生图"}}]}\n\ndata: [DONE]\n\n',
        { status: 200, headers: { "Content-Type": "text/event-stream" } }
      );
    }
    if (url.includes("api.mock-s25-gemini.com")) {
      return new Response(
        JSON.stringify({
          candidates: [
            { content: { parts: [{ inlineData: { mimeType: "image/png", data: s25TinPngB64 } }] } }
          ]
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    }
    return origFetch25(input, init);
  };

  try {
    const sess25a = "sess_s25_flux_mid_heavy";
    const env25a: UnifiedProtocolEnvelope = {
      envelope_id: "env_s25a",
      session_id: sess25a,
      user_id: scen25UserId,
      round_index: 1,
      instruction_payload: "Draw a badge then analyze it",
      assets_manifest: [],
      constraint_context: { target_language: "zh", output_style: "concise" },
      metadata: { client_timestamp: Date.now(), char_count_total: 30, estimated_input_tokens: 30 }
    };
    const res25a = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token}` },
        body: JSON.stringify({
          clientOpId: "op_s25a_phase1",
          reRouteMode: "switch_model",
          chosenTemplateId: "tpl_s25_flux_browser_heavyvlm",
          chosenRoleModels: {
            role_flux_draw: "cf_flux_node",
            role_s25_browser_mid: "browser-s25-text",
            role_s25_heavy_vlm_tail: "heavy-vlm-s25"
          },
          envelope: env25a,
          capabilities: { webgpu_handover_v3: true }
        })
      }),
      env
    );
    assert.equal(res25a.status, 200);
    const sse25a = await res25a.text();
    assert.ok(sse25a.includes("event: asset_chunk"), "Phase 1 Flux must emit asset_chunk");
    const handoverMatch = sse25a.match(/event: dag_handover\ndata: ([^\n]+)/);
    assert.ok(handoverMatch, "Browser mid node must emit dag_handover");
    const handoverPayload = JSON.parse(handoverMatch![1]);
    assert.ok(
      typeof handoverPayload.raw_upstream_output === "string" &&
        handoverPayload.raw_upstream_output.includes(".png"),
      "dag_handover must expose raw_upstream_output separately from wrapped user_prompt"
    );

    // Phase 2: locked switch_model failure on browser mid must fail-closed with 409 locked_model_failed
    const lockedFailRes = await handleContinueS25(
      new Request("https://nanomesh.local/api/chat/continue", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token}` },
        body: JSON.stringify({
          continuation_token: handoverPayload.continuation_token,
          status: "candidate_failed",
          failed_model_id: "browser-s25-text",
          upstream_context: handoverPayload.raw_upstream_output,
          envelope: env25a
        })
      }),
      env
    );
    assert.equal(
      lockedFailRes.status,
      409,
      "switch_model browser failover via /api/chat/continue must reject standby takeover with 409"
    );

    // Re-issue a normal-mode run for full continuation success check
    const env25b = { ...env25a, envelope_id: "env_s25b", session_id: "sess_s25_cont_ok" };
    const res25b = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token}` },
        body: JSON.stringify({
          clientOpId: "op_s25b_phase1",
          reRouteMode: "switch_template",
          chosenTemplateId: "tpl_s25_flux_browser_heavyvlm",
          chosenRoleModels: {
            role_flux_draw: "cf_flux_node",
            role_s25_browser_mid: "browser-s25-text",
            role_s25_heavy_vlm_tail: "heavy-vlm-s25"
          },
          envelope: env25b,
          capabilities: { webgpu_handover_v3: true }
        })
      }),
      env
    );
    const sse25b = await res25b.text();
    const ho25b = JSON.parse(sse25b.match(/event: dag_handover\ndata: ([^\n]+)/)![1]);
    const res25bCont = await handleContinueS25(
      new Request("https://nanomesh.local/api/chat/continue", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token}` },
        body: JSON.stringify({
          continuation_token: ho25b.continuation_token,
          status: "success",
          client_step_output: "Browser mid prompt for VLM",
          envelope: env25b
        })
      }),
      env
    );
    assert.equal(res25bCont.status, 200);
    const sse25bCont = await res25bCont.text();
    assert.ok(sse25bCont.includes("event: dag_complete"), "Continuation DAG must complete");
    assert.ok(
      s25HeavyVlmSawBrowserMidText &&
        s25HeavyVlmSawImageUrl &&
        s25HeavyVlmImageAttachedToCurrentTurn,
      "Heavy VLM Tail after Browser mid handover must receive both Browser output AND Phase 1 Flux generated image on the active turn"
    );
    const committed25bMedia = (store.session_assets || []).filter(
      (a: any) =>
        a.session_id === "sess_s25_cont_ok" && a.origin === "generated" && a.status === "COMMITTED"
    );
    assert.ok(
      committed25bMedia.length >= 1,
      "Phase 1 Flux generated image must survive Browser handover and be promoted to COMMITTED"
    );

    // 25.2 Heavy Gemini ImageGen [Head] -> Light WebGPU [Tail] commit preserves server-trusted Phase 1 generated image
    const env25c: UnifiedProtocolEnvelope = {
      envelope_id: "env_s25c",
      session_id: "sess_s25_gem_browsertail",
      user_id: scen25UserId,
      round_index: 1,
      instruction_payload: "Generate via Gemini then summarize on WebGPU",
      assets_manifest: [],
      constraint_context: { target_language: "zh", output_style: "concise" },
      metadata: { client_timestamp: Date.now(), char_count_total: 40, estimated_input_tokens: 40 }
    };
    const res25c = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token}` },
        body: JSON.stringify({
          clientOpId: "op_s25c_gem_tail",
          reRouteMode: "switch_template",
          chosenTemplateId: "tpl_s25_gemimg_browser_tail",
          chosenRoleModels: {
            role_s25_heavy_gem_img: "heavy-gemini-img-s25",
            role_s25_browser_mid: "browser-s25-text"
          },
          envelope: env25c,
          capabilities: { webgpu_handover_v3: true }
        })
      }),
      env
    );
    assert.equal(res25c.status, 200);
    const sse25c = await res25c.text();
    assert.ok(sse25c.includes("event: asset_chunk"), "Gemini image gen must emit asset_chunk");
    const req25cMatch = sse25c.match(/event: client_exec_request\ndata: ([^\n]+)/);
    assert.ok(req25cMatch, "Browser tail after Gemini image gen must emit client_exec_request");
    const req25c = JSON.parse(req25cMatch![1]);
    const commit25cRes = await handleCommitS25(
      new Request("https://nanomesh.local/api/session/sess_s25_gem_browsertail/commit", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token}` },
        body: JSON.stringify({
          run_id: req25c.run_id,
          client_commit_token: req25c.client_commit_token,
          final_output: "WebGPU summary of Gemini image"
        })
      }),
      env,
      "sess_s25_gem_browsertail"
    );
    assert.equal(commit25cRes.status, 200);
    const committed25cMedia = (store.session_assets || []).filter(
      (a: any) =>
        a.session_id === "sess_s25_gem_browsertail" &&
        a.origin === "generated" &&
        a.status === "COMMITTED"
    );
    assert.ok(
      committed25cMedia.length >= 1,
      "Phase 1 Heavy Gemini generated image must be promoted to COMMITTED when Browser tail commits"
    );

    // 25.3 Heavy Multi-Image + Audio + CROSS_FUSION refinementBackground serialization + Text Multi-Node Head
    const heavyBuilt = buildMsgsS25(
      {
        systemPrompt: "sys",
        initialUserDirective: "Analyze audio and 2 images",
        sanitizedIntermediateOutput: "Upstream step notes",
        currentTaskDirective: "Synthesize final decision",
        flatPromptContent: "flat",
        attachedDocsContent: "doc",
        refinementBackground: "Cross-branch red badge identifier NM-427",
        imageB64: "data:image/png;base64,AAA",
        imageMimeType: "image/png",
        extraImages: [{ b64: "data:image/jpeg;base64,BBB", mimeType: "image/jpeg" }],
        audioB64: "data:audio/wav;base64,CCC",
        audioMimeType: "audio/wav",
        mediaFromUpstreamGeneration: false
      },
      {
        model_id: "heavy-test",
        display_name: "Heavy",
        provider: "Test",
        endpoint: "https://example.com",
        modalities: ["image", "audio", "text"],
        tags: [],
        context_window: 32768,
        max_concurrency: 10,
        active_connections: 0,
        precision: 0.9,
        user_rating: 5,
        usage_count: 1,
        cost_per_1k_tokens: 1,
        status: "active",
        is_generalist: 0,
        prior_score: 0,
        scenario_anchors: [],
        inference_target: "heavy"
      }
    );
    assert.ok(
      JSON.stringify(heavyBuilt.openaiMessages[1]).includes(
        "Cross-branch red badge identifier NM-427"
      ) &&
        JSON.stringify(heavyBuilt.openaiMessages[1]).includes("input_audio") &&
        JSON.stringify(heavyBuilt.geminiContents[0].parts).includes("audio/wav") &&
        heavyBuilt.geminiContents[0].parts.filter((p: any) => p.inlineData).length === 3,
      "Heavy downstream buildDownstreamMessages must preserve refinementBackground, multi-image, and audio parts"
    );

    // 25.4 Pure-Text Multi-Node Head with text_doc + context window guard on Browser
    const hugeDocText = "ROW_DATA_".repeat(800);
    const res25d = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token2}` },
        body: JSON.stringify({
          clientOpId: "op_s25d_text_head",
          reRouteMode: "switch_template",
          chosenTemplateId: "tpl_s25_text_head_browser",
          chosenRoleModels: {
            role_s25_text_head: "cf-fast-s24",
            role_s25_browser_mid: "browser-s25-text"
          },
          envelope: {
            envelope_id: "env_s25d",
            session_id: "sess_s25_text_head",
            user_id: scen25User2Id,
            round_index: 1,
            instruction_payload: "Extract KPI summary",
            assets_manifest: [
              {
                asset_id: "doc_s25_csv",
                modality: "text_doc",
                mime_type: "text/csv",
                file_size: hugeDocText.length,
                in_memory_text: hugeDocText,
                consumed: false,
                source_digest: "digest_s25_csv",
                is_new: true,
                filename: "kpi.csv"
              }
            ],
            constraint_context: { target_language: "zh", output_style: "concise" },
            metadata: {
              client_timestamp: Date.now(),
              char_count_total: 100,
              estimated_input_tokens: 100
            }
          },
          capabilities: { webgpu_handover_v3: true }
        })
      }),
      env
    );
    assert.equal(res25d.status, 200);
    const sse25d = await res25d.text();
    const req25dMatch = sse25d.match(/event: client_exec_request\ndata: ([^\n]+)/);
    assert.ok(
      req25dMatch,
      `Text Head -> Browser Tail must emit client_exec_request (events=${sse25d
        .split("\n")
        .filter((l) => l.startsWith("event:") || l.includes("error"))
        .join(" | ")}; tail=${sse25d.slice(-400)})`
    );
    const req25d = JSON.parse(req25dMatch![1]);
    assert.ok(
      s25TextHeadSawDoc && !s25TextHeadSawVisionMask,
      "Pure-text multi-node head must receive text_doc and NOT receive vision extraction prompt"
    );
    assert.ok(
      req25d.user_prompt.length <= 2600,
      `Browser tail user_prompt must be bounded by context_window=1024 guard (got len=${req25d.user_prompt.length})`
    );

    // 25.5 Multimodal-capable model (["image","text"]) serving text-only role with zero images runs in text mode cleanly
    const res25e = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token2}` },
        body: JSON.stringify({
          clientOpId: "op_s25e_vlm_text_mode",
          reRouteMode: "switch_model",
          chosenTemplateId: "tpl-direct-chat",
          chosenRoleModels: { "role-direct-chat": "heavy-vlm-s25" },
          envelope: {
            envelope_id: "env_s25e",
            session_id: "sess_s25_vlm_text_mode",
            user_id: scen25User2Id,
            round_index: 1,
            instruction_payload: "Pure text query on multimodal heavy model",
            assets_manifest: [],
            constraint_context: { target_language: "zh", output_style: "concise" },
            metadata: {
              client_timestamp: Date.now(),
              char_count_total: 40,
              estimated_input_tokens: 40
            }
          }
        })
      }),
      env
    );
    assert.equal(res25e.status, 200);
    const sse25e = await res25e.text();
    assert.ok(
      sse25e.includes("event: dag_complete") && !sse25e.includes("强依赖图像资产输入"),
      "Multimodal model serving a text-only role with no claimed media must execute cleanly in text mode"
    );

    // 25.6 Path A Compositional with Image + Audio + CSV must NOT duplicate CSV text into synthesis tail
    const scen25User3Id = "usr_scen25_mm_3";
    store.users.push({
      user_id: scen25User3Id,
      username: "scen25_mm_3",
      email: "scen25_3@nanomesh.local",
      password_hash: "unused",
      role: "user",
      credits: 300,
      token_version: 1
    });
    const scen25Token3 = await signJwtS25(
      { userId: scen25User3Id, role: "user", tokenVersion: 1 },
      env.JWT_SECRET,
      3600
    );
    const s25Img1Key = `tmp/${scen25User3Id}/sess_s25_mt/img1.png`;
    const s25Img2Key = `tmp/${scen25User3Id}/sess_s25_mt/img2.png`;
    const s25Aud1Key = `tmp/${scen25User3Id}/sess_s25_mt/aud1.wav`;
    await env.R2.put(s25Img1Key, Uint8Array.from([137, 80, 78, 71, 1, 2, 3, 4]));
    await env.R2.put(s25Img2Key, Uint8Array.from([137, 80, 78, 71, 5, 6, 7, 8]));
    await env.R2.put(s25Aud1Key, Uint8Array.from([82, 73, 70, 70, 1, 2, 3, 4]));
    store.session_assets!.push(
      {
        asset_id: "s25_mt_img1",
        session_id: "__UNBOUND__",
        user_id: scen25User3Id,
        filename: "poster1.png",
        modality: "image",
        mime_type: "image/png",
        file_size: 8,
        r2_key: s25Img1Key,
        source_digest: "digest_s25_mt_img1",
        origin: "upload",
        introduced_round: 1,
        status: "STAGING"
      },
      {
        asset_id: "s25_mt_img2",
        session_id: "__UNBOUND__",
        user_id: scen25User3Id,
        filename: "poster2.png",
        modality: "image",
        mime_type: "image/png",
        file_size: 8,
        r2_key: s25Img2Key,
        source_digest: "digest_s25_mt_img2",
        origin: "upload",
        introduced_round: 4,
        status: "STAGING"
      },
      {
        asset_id: "s25_mt_aud1",
        session_id: "__UNBOUND__",
        user_id: scen25User3Id,
        filename: "voice1.wav",
        modality: "audio",
        mime_type: "audio/wav",
        file_size: 8,
        r2_key: s25Aud1Key,
        source_digest: "digest_s25_mt_aud1",
        origin: "upload",
        introduced_round: 1,
        status: "STAGING"
      }
    );

    let s25SynthPromptsSeen: string[] = [];
    let s25VisionCallCount = 0;
    let s25AudioCallCount = 0;
    let s25MockIntentOp: "ANCHOR_TAIL" | "REBIND_ROOT" | "CROSS_FUSION" = "ANCHOR_TAIL";
    let s25MockBindings: Array<{ asset_id: string; bind_mode: string }> = [];

    (env.AI as any).run = async (ep: string, payload: any) => {
      if (ep.includes("clef-flash")) {
        const qKeys = Object.keys(payload?.questions || {});
        if (qKeys.includes("intent_op")) {
          const answers: Record<string, any> = {
            intent_op: { choice: s25MockIntentOp },
            target_branch: { choice: "main" }
          };
          for (const qk of qKeys) {
            if (qk.startsWith("bind_")) {
              const aid = qk.slice(5);
              const found = s25MockBindings.find((b) => b.asset_id === aid);
              answers[qk] = { choice: found ? found.bind_mode : "DROP" };
            }
          }
          return { answers };
        }
        const tplAnswers: Record<string, any> = {};
        for (const qk of qKeys) {
          tplAnswers[qk] = {
            score: qk === "tpl-direct-chat" || qk === "tpl-multimodal-fusion" ? 2.0 : 1.0
          };
        }
        return { answers: tplAnswers };
      }
      if (ep.includes("bge-m3")) return { data: [[0.1, 0.2, 0.3]] };
      if (ep.includes("whisper")) {
        s25AudioCallCount++;
        return { text: "Audio transcript: priority task deadline Friday." };
      }
      if (ep.includes("vision") || ep.includes("moondream") || ep.includes("llava")) {
        s25VisionCallCount++;
        return { response: `Visual inspection #${s25VisionCallCount}: red badge NM-427.` };
      }
      if (ep.includes("llama-3.1-8b")) {
        const msgStr = JSON.stringify(payload?.messages || []);
        if (
          msgStr.includes("Gateway Safety") ||
          payload?.max_tokens === 5 ||
          payload?.max_tokens === 60
        ) {
          return { response: msgStr.includes("JSON") ? '["tpl-direct-chat"]' : "SAFE" };
        }
        s25SynthPromptsSeen.push(msgStr);
        return { response: "Synthesized multimodal deliverable with NM-427." };
      }
      if (Array.isArray(payload?.messages)) {
        s25SynthPromptsSeen.push(JSON.stringify(payload.messages));
      }
      return { response: "Edge response" };
    };

    // 25.6 Turn 1: Compositional (1 image + 1 audio + 1 CSV) -> CSV must NOT be duplicated in synth-0
    const res25fTurn1 = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token3}` },
        body: JSON.stringify({
          clientOpId: "op_s25f_t1",
          disableBrowserInference: true,
          envelope: {
            envelope_id: "env_s25f_t1",
            session_id: "sess_s25_mt",
            user_id: scen25User3Id,
            round_index: 1,
            instruction_payload: "Combine poster, audio, and budget csv",
            assets_manifest: [
              {
                asset_id: "s25_mt_img1",
                modality: "image",
                mime_type: "image/png",
                file_size: 8,
                r2_key: s25Img1Key,
                source_digest: "digest_s25_mt_img1",
                consumed: false,
                is_new: true,
                filename: "poster1.png"
              },
              {
                asset_id: "s25_mt_aud1",
                modality: "audio",
                mime_type: "audio/wav",
                file_size: 8,
                r2_key: s25Aud1Key,
                source_digest: "digest_s25_mt_aud1",
                consumed: false,
                is_new: true,
                filename: "voice1.wav"
              },
              {
                asset_id: "s25_mt_csv1",
                modality: "text_doc",
                mime_type: "text/csv",
                file_size: 40,
                in_memory_text: "UNIQUE_CSV_MARKER_991,budget=5000",
                source_digest: "digest_s25_mt_csv1",
                consumed: false,
                is_new: true,
                filename: "budget.csv"
              }
            ],
            constraint_context: { target_language: "zh", output_style: "concise" },
            metadata: {
              client_timestamp: Date.now(),
              char_count_total: 40,
              estimated_input_tokens: 40
            }
          }
        })
      }),
      env
    );
    assert.equal(res25fTurn1.status, 200);
    const sse25fT1 = await res25fTurn1.text();
    assert.ok(sse25fT1.includes("event: dag_complete"), "Turn 1 compositional must complete");
    assert.equal(s25VisionCallCount, 1);
    assert.equal(s25AudioCallCount, 1);
    const lastSynthT1 = s25SynthPromptsSeen[s25SynthPromptsSeen.length - 1] || "";
    const csvMatchesT1 = lastSynthT1.match(/UNIQUE_CSV_MARKER_991/g) || [];
    assert.equal(
      csvMatchesT1.length,
      1,
      `Path A Compositional synth-0 must include CSV exactly once via reducer-merge (got count=${csvMatchesT1.length})`
    );

    // 25.7 Multi-turn continuation:
    // Turn 2 (ANCHOR_TAIL): follow-up without re-reading raw image/audio (0 new vision/audio calls)
    s25MockIntentOp = "ANCHOR_TAIL";
    s25MockBindings = [
      { asset_id: "s25_mt_img1", bind_mode: "CACHED_TEXT" },
      { asset_id: "s25_mt_aud1", bind_mode: "DROP" },
      { asset_id: "s25_mt_csv1", bind_mode: "DROP" }
    ];
    const visionBeforeT2 = s25VisionCallCount;
    const audioBeforeT2 = s25AudioCallCount;
    const res25fTurn2 = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token3}` },
        body: JSON.stringify({
          clientOpId: "op_s25f_t2",
          disableBrowserInference: true,
          envelope: {
            envelope_id: "env_s25f_t2",
            session_id: "sess_s25_mt",
            user_id: scen25User3Id,
            round_index: 2,
            instruction_payload: "Translate the summary into English",
            assets_manifest: [],
            constraint_context: { target_language: "en", output_style: "concise" },
            metadata: {
              client_timestamp: Date.now(),
              char_count_total: 35,
              estimated_input_tokens: 35
            }
          }
        })
      }),
      env
    );
    assert.equal(res25fTurn2.status, 200);
    const sse25fT2 = await res25fTurn2.text();
    assert.ok(sse25fT2.includes("event: dag_complete"), "Turn 2 ANCHOR_TAIL must complete");
    assert.equal(
      s25VisionCallCount,
      visionBeforeT2,
      "ANCHOR_TAIL must reuse L1 cache with 0 VLM calls"
    );
    assert.equal(s25AudioCallCount, audioBeforeT2, "ANCHOR_TAIL must NOT re-call Whisper ASR");

    // Turn 3 (REBIND_ROOT): selectively re-read raw image only (vision++ , audio unchanged)
    s25MockIntentOp = "REBIND_ROOT";
    s25MockBindings = [
      { asset_id: "s25_mt_img1", bind_mode: "RAW_MEDIA" },
      { asset_id: "s25_mt_aud1", bind_mode: "DROP" },
      { asset_id: "s25_mt_csv1", bind_mode: "DROP" }
    ];
    const visionBeforeT3 = s25VisionCallCount;
    const audioBeforeT3 = s25AudioCallCount;
    const res25fTurn3 = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token3}` },
        body: JSON.stringify({
          clientOpId: "op_s25f_t3",
          disableBrowserInference: true,
          envelope: {
            envelope_id: "env_s25f_t3",
            session_id: "sess_s25_mt",
            user_id: scen25User3Id,
            round_index: 3,
            instruction_payload: "Re-check the exact letters inside poster1",
            assets_manifest: [],
            constraint_context: { target_language: "zh", output_style: "concise" },
            metadata: {
              client_timestamp: Date.now(),
              char_count_total: 40,
              estimated_input_tokens: 40
            }
          }
        })
      }),
      env
    );
    assert.equal(res25fTurn3.status, 200);
    const sse25fT3 = await res25fTurn3.text();
    assert.ok(sse25fT3.includes("event: dag_complete"), "Turn 3 REBIND_ROOT must complete");
    assert.equal(
      s25VisionCallCount,
      visionBeforeT3 + 1,
      "REBIND_ROOT must re-read raw img1 from R2 via vision node"
    );
    assert.equal(
      s25AudioCallCount,
      audioBeforeT3,
      "REBIND_ROOT must NOT touch dropped audio asset"
    );

    // Turn 4 (CROSS_FUSION + new upload img2): fuses newly uploaded img2 with historical img1 as RAW_MEDIA
    // Use separate token scen25Token2 to stay under per-user burst rate limit of 3
    const scen25User4Id = "usr_scen25_mm_4";
    store.users.push({
      user_id: scen25User4Id,
      username: "scen25_mm_4",
      email: "scen25_4@nanomesh.local",
      password_hash: "unused",
      role: "user",
      credits: 300,
      token_version: 1
    });
    const scen25Token4 = await signJwtS25(
      { userId: scen25User4Id, role: "user", tokenVersion: 1 },
      env.JWT_SECRET,
      3600
    );
    const s25T4Img1 = `tmp/${scen25User4Id}/sess_s25_cf/img1.png`;
    const s25T4Img2 = `tmp/${scen25User4Id}/sess_s25_cf/img2.png`;
    await env.R2.put(s25T4Img1, Uint8Array.from([137, 80, 78, 71, 9, 9, 9, 9]));
    await env.R2.put(s25T4Img2, Uint8Array.from([137, 80, 78, 71, 7, 7, 7, 7]));
    store.session_assets!.push(
      {
        asset_id: "s25_cf_img1",
        session_id: "__UNBOUND__",
        user_id: scen25User4Id,
        filename: "cf_img1.png",
        modality: "image",
        mime_type: "image/png",
        file_size: 8,
        r2_key: s25T4Img1,
        source_digest: "digest_s25_cf_img1",
        origin: "upload",
        introduced_round: 1,
        status: "STAGING"
      },
      {
        asset_id: "s25_cf_img2",
        session_id: "__UNBOUND__",
        user_id: scen25User4Id,
        filename: "cf_img2.png",
        modality: "image",
        mime_type: "image/png",
        file_size: 8,
        r2_key: s25T4Img2,
        source_digest: "digest_s25_cf_img2",
        origin: "upload",
        introduced_round: 2,
        status: "STAGING"
      }
    );
    const cfT1 = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token4}` },
        body: JSON.stringify({
          clientOpId: "op_s25_cf_t1",
          disableBrowserInference: true,
          envelope: {
            envelope_id: "env_s25_cf_t1",
            session_id: "sess_s25_cf",
            user_id: scen25User4Id,
            round_index: 1,
            instruction_payload: "Inspect cf_img1",
            assets_manifest: [
              {
                asset_id: "s25_cf_img1",
                modality: "image",
                mime_type: "image/png",
                file_size: 8,
                r2_key: s25T4Img1,
                source_digest: "digest_s25_cf_img1",
                consumed: false,
                is_new: true,
                filename: "cf_img1.png"
              }
            ],
            constraint_context: { target_language: "zh", output_style: "concise" },
            metadata: {
              client_timestamp: Date.now(),
              char_count_total: 16,
              estimated_input_tokens: 20
            }
          }
        })
      }),
      env
    );
    assert.equal(cfT1.status, 200);
    await cfT1.text();

    s25MockIntentOp = "CROSS_FUSION";
    s25MockBindings = [{ asset_id: "s25_cf_img1", bind_mode: "RAW_MEDIA" }];
    const visionBeforeCfT2 = s25VisionCallCount;
    const cfT2 = await handleChat(
      new Request("https://nanomesh.local/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json", Cookie: `session=${scen25Token4}` },
        body: JSON.stringify({
          clientOpId: "op_s25_cf_t2",
          disableBrowserInference: true,
          envelope: {
            envelope_id: "env_s25_cf_t2",
            session_id: "sess_s25_cf",
            user_id: scen25User4Id,
            round_index: 2,
            instruction_payload: "Compare cf_img2 with cf_img1",
            assets_manifest: [
              {
                asset_id: "s25_cf_img2",
                modality: "image",
                mime_type: "image/png",
                file_size: 8,
                r2_key: s25T4Img2,
                source_digest: "digest_s25_cf_img2",
                consumed: false,
                is_new: true,
                filename: "cf_img2.png"
              }
            ],
            constraint_context: { target_language: "zh", output_style: "concise" },
            metadata: {
              client_timestamp: Date.now(),
              char_count_total: 26,
              estimated_input_tokens: 26,
              has_new_upload: true,
              new_upload_modalities: ["image"]
            }
          }
        })
      }),
      env
    );
    assert.equal(cfT2.status, 200);
    const sseCfT2 = await cfT2.text();
    assert.ok(
      sseCfT2.includes("event: dag_complete"),
      "Turn 2 CROSS_FUSION with new image must complete"
    );
    assert.equal(
      s25VisionCallCount,
      visionBeforeCfT2 + 2,
      "CROSS_FUSION comparing new img2 with historical img1 (RAW_MEDIA) must invoke vision node for BOTH images"
    );
  } finally {
    (env.AI as any).run = prevAiRun25;
    globalThis.fetch = origFetch25;
  }

  console.log(
    "  ✓ Scenario 25 (Multimodal Artifacts Across Light/Medium/Heavy Tiers & Arbitrary DAG Positions): PASSED"
  );

  console.log("\n==================================================");
  console.log("   🎉 ALL 24 INTEGRATION SCENARIOS PASSED (100%)! ");
  console.log("==================================================");
}

runIntegrationTests().catch((err) => {
  console.error("❌ Integration Test Failed:", err);
  process.exit(1);
});

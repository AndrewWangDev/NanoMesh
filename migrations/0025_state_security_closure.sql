-- Migration 0025: Multi-tenant composite PKs across session/history tables,
-- per-attempt CAS gate tracking, client_op_id idempotency, per-stage billing ledger,
-- scoped caches, Shift-Left document persistence, and durable R2 deletion queues.

-- 1. Rebuild user_chat_sessions with composite PK (user_id, session_id)
CREATE TABLE IF NOT EXISTS user_chat_sessions_v2 (
  session_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  trace_id TEXT,
  title TEXT NOT NULL,
  cost TEXT DEFAULT '0',
  duration TEXT DEFAULT '0s',
  nodes_count INTEGER DEFAULT 1,
  cached INTEGER DEFAULT 0,
  pinned INTEGER DEFAULT 0,
  rounds_json TEXT NOT NULL DEFAULT '[]',
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, session_id)
);

INSERT OR IGNORE INTO user_chat_sessions_v2
  (session_id, user_id, trace_id, title, cost, duration, nodes_count, cached, pinned, rounds_json, created_at, updated_at)
SELECT session_id, user_id, trace_id, title, cost, duration, nodes_count, cached, pinned, rounds_json, created_at, updated_at
FROM user_chat_sessions;

DROP TABLE IF EXISTS user_chat_sessions;
ALTER TABLE user_chat_sessions_v2 RENAME TO user_chat_sessions;
CREATE INDEX IF NOT EXISTS idx_chat_user_updated ON user_chat_sessions(user_id, updated_at DESC);

-- 2. Rebuild chat_session_states with composite PK (user_id, session_id), per-attempt fence & deleted_at tombstone
CREATE TABLE IF NOT EXISTS chat_session_states_v2 (
  session_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  active_branch_id TEXT NOT NULL DEFAULT 'main',
  version INTEGER NOT NULL DEFAULT 1,
  last_tx_attempt_id TEXT,
  deleted_at TEXT DEFAULT NULL,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, session_id)
);

INSERT OR IGNORE INTO chat_session_states_v2
  (session_id, user_id, active_branch_id, version, updated_at)
SELECT session_id, user_id, active_branch_id, version, updated_at
FROM chat_session_states;

DROP TABLE IF EXISTS chat_session_states;
ALTER TABLE chat_session_states_v2 RENAME TO chat_session_states;

-- 3. Rebuild session_branches with composite PK (user_id, session_id, branch_id)
CREATE TABLE IF NOT EXISTS session_branches_v2 (
  session_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  topic TEXT NOT NULL DEFAULT '主线任务',
  head_commit_id TEXT,
  dominant_modalities TEXT DEFAULT '[]',
  last_summary TEXT DEFAULT '',
  lineage_asset_ids TEXT DEFAULT '[]',
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, session_id, branch_id)
);

INSERT OR IGNORE INTO session_branches_v2
  (session_id, branch_id, user_id, topic, head_commit_id, dominant_modalities, last_summary, lineage_asset_ids, updated_at)
SELECT session_id, branch_id, user_id, topic, head_commit_id, dominant_modalities, last_summary, lineage_asset_ids, updated_at
FROM session_branches;

DROP TABLE IF EXISTS session_branches;
ALTER TABLE session_branches_v2 RENAME TO session_branches;

-- 4. Rebuild session_commits with composite PK (user_id, session_id, commit_id) and UNIQUE(user_id, session_id, run_id)
CREATE TABLE IF NOT EXISTS session_commits_v2 (
  commit_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  parent_commit_id TEXT,
  source_refs_json TEXT DEFAULT '[]',
  round_index INTEGER NOT NULL DEFAULT 1,
  revision INTEGER NOT NULL DEFAULT 1,
  intent_op TEXT,
  user_prompt TEXT DEFAULT '',
  mounted_assets_json TEXT DEFAULT '[]',
  introduced_asset_ids_json TEXT DEFAULT '[]',
  generated_asset_ids_json TEXT DEFAULT '[]',
  template_id TEXT,
  output_summary TEXT DEFAULT '',
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, session_id, commit_id),
  UNIQUE (user_id, session_id, run_id)
);

INSERT OR IGNORE INTO session_commits_v2
  (commit_id, session_id, user_id, run_id, branch_id, parent_commit_id, source_refs_json, round_index, revision, intent_op, user_prompt, mounted_assets_json, introduced_asset_ids_json, generated_asset_ids_json, template_id, output_summary, created_at)
SELECT commit_id, session_id, user_id, run_id, branch_id, parent_commit_id, source_refs_json, round_index, revision, intent_op, user_prompt, mounted_assets_json, introduced_asset_ids_json, generated_asset_ids_json, template_id, output_summary, created_at
FROM session_commits;

DROP TABLE IF EXISTS session_commits;
ALTER TABLE session_commits_v2 RENAME TO session_commits;
CREATE INDEX IF NOT EXISTS idx_session_commits_session ON session_commits(user_id, session_id, round_index);

-- 5. Rebuild session_assets with composite PK (user_id, asset_id) + Shift-Left document persistence columns
CREATE TABLE IF NOT EXISTS session_assets_v2 (
  asset_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  branch_id TEXT,
  commit_id TEXT,
  filename TEXT,
  modality TEXT NOT NULL,
  mime_type TEXT,
  file_size INTEGER DEFAULT 0,
  r2_key TEXT NOT NULL DEFAULT '',
  source_digest TEXT,
  origin TEXT NOT NULL DEFAULT 'upload',
  introduced_round INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'UPLOADED',
  summary_snippet TEXT DEFAULT '',
  in_memory_text TEXT DEFAULT NULL,
  text_r2_key TEXT DEFAULT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, asset_id)
);

INSERT OR IGNORE INTO session_assets_v2
  (asset_id, session_id, user_id, branch_id, commit_id, filename, modality, mime_type, file_size, r2_key, source_digest, origin, introduced_round, status, summary_snippet, created_at)
SELECT asset_id, session_id, user_id, branch_id, commit_id, filename, modality, mime_type, file_size, COALESCE(r2_key, ''), source_digest, origin, introduced_round, status, summary_snippet, created_at
FROM session_assets;

DROP TABLE IF EXISTS session_assets;
ALTER TABLE session_assets_v2 RENAME TO session_assets;
CREATE INDEX IF NOT EXISTS idx_session_assets_r2_key ON session_assets(r2_key);
CREATE INDEX IF NOT EXISTS idx_session_assets_session_user ON session_assets(user_id, session_id, status);

-- 6. Rebuild dag_run_plans with composite PK (user_id, run_id), client_op_id idempotency & execution ownership fields
CREATE TABLE IF NOT EXISTS dag_run_plans_v2 (
  run_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  client_op_id TEXT,
  request_digest TEXT,
  plan_hash TEXT NOT NULL,
  dag_json TEXT NOT NULL,
  envelope_json TEXT NOT NULL,
  resolved_envelope_json TEXT,
  step_outputs_json TEXT DEFAULT '{}',
  is_rerun INTEGER NOT NULL DEFAULT 0,
  base_commit_id TEXT,
  expected_parent_commit_id TEXT,
  expected_base_revision INTEGER,
  exec_owner TEXT NOT NULL DEFAULT 'CLOUD',
  commit_state TEXT NOT NULL DEFAULT 'PENDING',
  client_commit_nonce_hash TEXT,
  tail_result_json TEXT,
  tail_result_hash TEXT,
  status TEXT NOT NULL DEFAULT 'RUNNING',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, run_id),
  UNIQUE (user_id, session_id, client_op_id)
);

INSERT OR IGNORE INTO dag_run_plans_v2
  (run_id, user_id, session_id, plan_hash, dag_json, envelope_json, resolved_envelope_json, step_outputs_json, exec_owner, commit_state, status, created_at, updated_at)
SELECT run_id, user_id, session_id, plan_hash, dag_json, envelope_json, envelope_json, step_outputs_json,
       'CLOUD', CASE WHEN status = 'COMPLETED' THEN 'COMMITTED' ELSE 'PENDING' END, status, created_at, updated_at
FROM dag_run_plans;

DROP TABLE IF EXISTS dag_run_plans;
ALTER TABLE dag_run_plans_v2 RENAME TO dag_run_plans;
CREATE INDEX IF NOT EXISTS idx_dag_run_plans_session_op ON dag_run_plans(user_id, session_id, client_op_id);

-- 7. Rebuild asset_perceptual_cache with composite PK (user_id, session_id, percept_key) & flush unscoped legacy rows
CREATE TABLE IF NOT EXISTS asset_perceptual_cache_v2 (
  percept_key TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  source_digest TEXT NOT NULL,
  modality TEXT NOT NULL,
  role_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  task_scope TEXT NOT NULL DEFAULT 'objective_full',
  prompt_digest TEXT DEFAULT 'default',
  extracted_text TEXT NOT NULL,
  summary_snippet TEXT DEFAULT '',
  updated_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, session_id, percept_key)
);

DROP TABLE IF EXISTS asset_perceptual_cache;
ALTER TABLE asset_perceptual_cache_v2 RENAME TO asset_perceptual_cache;
CREATE INDEX IF NOT EXISTS idx_perceptual_cache_session ON asset_perceptual_cache(user_id, session_id, source_digest);

-- 8. Rebuild dag_execution_cache with mandatory (user_id, session_id, cache_key) scoping (flush old global rows)
CREATE TABLE IF NOT EXISTS dag_execution_cache_v2 (
  cache_key TEXT NOT NULL,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  role_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  input_digest TEXT NOT NULL,
  injected_prompt TEXT NOT NULL,
  output_text TEXT NOT NULL,
  created_at TEXT DEFAULT (datetime('now')),
  PRIMARY KEY (user_id, session_id, cache_key)
);

DROP TABLE IF EXISTS dag_execution_cache;
ALTER TABLE dag_execution_cache_v2 RENAME TO dag_execution_cache;
CREATE INDEX IF NOT EXISTS idx_dag_cache_created ON dag_execution_cache(created_at);
CREATE INDEX IF NOT EXISTS idx_dag_cache_tenant ON dag_execution_cache(user_id, session_id);

-- 9. Per-stage billing idempotency table (REV-03)
CREATE TABLE IF NOT EXISTS run_billing_settlements (
  user_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  amount INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, run_id, phase)
);

-- 10. Durable R2 cleanup queues for session deletion & GDPR account purge (PLAN-07 & REV-06)
CREATE TABLE IF NOT EXISTS pending_r2_deletions (
  delete_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  r2_key TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  UNIQUE (user_id, r2_key)
);

CREATE TABLE IF NOT EXISTS pending_r2_prefix_purges (
  user_id TEXT PRIMARY KEY,
  prefixes_json TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

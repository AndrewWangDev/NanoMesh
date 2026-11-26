-- Migration 0024: Authoritative Git-DAG session state, ownership ledger, frozen run plans, and scoped L1 perceptual cache.
CREATE TABLE IF NOT EXISTS chat_session_states (
  session_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  active_branch_id TEXT NOT NULL DEFAULT 'main',
  version INTEGER NOT NULL DEFAULT 1,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS session_branches (
  session_id TEXT NOT NULL,
  branch_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  topic TEXT NOT NULL DEFAULT '主线任务',
  head_commit_id TEXT,
  dominant_modalities TEXT DEFAULT '[]',
  last_summary TEXT DEFAULT '',
  lineage_asset_ids TEXT DEFAULT '[]',
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (session_id, branch_id)
);

CREATE TABLE IF NOT EXISTS session_commits (
  commit_id TEXT PRIMARY KEY,
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
  UNIQUE(session_id, run_id)
);

CREATE TABLE IF NOT EXISTS session_assets (
  asset_id TEXT PRIMARY KEY,
  session_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  branch_id TEXT,
  commit_id TEXT,
  filename TEXT,
  modality TEXT NOT NULL,
  mime_type TEXT,
  file_size INTEGER DEFAULT 0,
  r2_key TEXT NOT NULL,
  source_digest TEXT,
  origin TEXT NOT NULL DEFAULT 'upload',
  introduced_round INTEGER DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'UPLOADED',
  summary_snippet TEXT DEFAULT '',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS dag_run_plans (
  run_id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  session_id TEXT NOT NULL,
  plan_hash TEXT NOT NULL,
  dag_json TEXT NOT NULL,
  envelope_json TEXT NOT NULL,
  step_outputs_json TEXT DEFAULT '{}',
  status TEXT NOT NULL DEFAULT 'RUNNING',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS asset_perceptual_cache (
  percept_key TEXT PRIMARY KEY,
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
  updated_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_assets_r2_key ON session_assets(r2_key);
CREATE INDEX IF NOT EXISTS idx_session_assets_session_user ON session_assets(session_id, user_id);
CREATE INDEX IF NOT EXISTS idx_session_commits_session ON session_commits(session_id, user_id);
CREATE INDEX IF NOT EXISTS idx_perceptual_cache_session ON asset_perceptual_cache(session_id, user_id, source_digest);

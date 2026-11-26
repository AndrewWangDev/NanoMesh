-- Migration 0026: Unified server-side session occupancy lease & failure terminal tracking
-- Covers NM-STATE-R01 (busy delete reject), R02 (concurrent input/canvas mutex),
-- R03 (AWAITING_COMMIT lock + abandon), R04 (terminal state + lock release on quota/abort/error),
-- and R05 (authoritative frozen baseline restoration).

ALTER TABLE chat_session_states ADD COLUMN active_run_id TEXT DEFAULT NULL;
ALTER TABLE chat_session_states ADD COLUMN active_client_op_id TEXT DEFAULT NULL;
ALTER TABLE chat_session_states ADD COLUMN occupancy_phase TEXT DEFAULT NULL;
ALTER TABLE chat_session_states ADD COLUMN lock_expires_at TEXT DEFAULT NULL;

ALTER TABLE dag_run_plans ADD COLUMN failure_status INTEGER DEFAULT NULL;
ALTER TABLE dag_run_plans ADD COLUMN failure_code TEXT DEFAULT NULL;
ALTER TABLE dag_run_plans ADD COLUMN failure_message TEXT DEFAULT NULL;

CREATE INDEX IF NOT EXISTS idx_chat_session_states_active_run
  ON chat_session_states(user_id, session_id, active_run_id);

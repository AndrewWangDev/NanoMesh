ALTER TABLE run_billing_settlements ADD COLUMN reserved_credits INTEGER;

CREATE TABLE IF NOT EXISTS pending_billing_settlements (
  user_id TEXT NOT NULL,
  run_id TEXT NOT NULL,
  phase TEXT NOT NULL,
  actual_cost INTEGER NOT NULL,
  reserved_credits INTEGER NOT NULL,
  detail_label TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (user_id, run_id, phase)
);

CREATE INDEX IF NOT EXISTS idx_pending_billing_settlements_created
  ON pending_billing_settlements(created_at);

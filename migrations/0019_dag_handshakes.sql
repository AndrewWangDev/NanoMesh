-- Migration: 0019_dag_handshakes.sql
-- Persistent handshake state tracking for multi-phase DAG continuation with atomic CAS anti-replay defense.

CREATE TABLE IF NOT EXISTS dag_handshakes (
    handshake_id    TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    session_id      TEXT NOT NULL,
    template_id     TEXT NOT NULL,
    next_step       INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'ISSUED', -- 'ISSUED', 'CONSUMED', 'ABORTED'
    expires_at      TEXT NOT NULL,
    created_at      TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

CREATE INDEX IF NOT EXISTS idx_handshake_cas ON dag_handshakes(handshake_id, user_id, status);
CREATE INDEX IF NOT EXISTS idx_handshake_expiry ON dag_handshakes(expires_at);

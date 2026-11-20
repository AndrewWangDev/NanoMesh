-- Migration: 0022_nocase_username.sql
-- Enforce case-insensitive uniqueness on users.username to prevent impersonation and identity spoofing
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_nocase ON users(username COLLATE NOCASE);

-- Migration: 0023_nocase_email.sql
-- Enforce case-insensitive uniqueness on users.email for defense-in-depth protection
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_nocase ON users(email COLLATE NOCASE);

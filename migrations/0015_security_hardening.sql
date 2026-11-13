-- Migration 0015: Security Hardening & Session Revocation
-- 1. Anti-brute force counter for email verification codes (locks code after 5 failed attempts)
ALTER TABLE verification_codes ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0;

-- 2. User token version for immediate session revocation upon password change / credential rotation
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 1;

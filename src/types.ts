/**
 * Cloudflare Workers environment bindings, secrets, and configuration variables.
 */
export interface Env {
  // Cloudflare Platform Bindings
  DB: D1Database;
  AI: any;
  R2: R2Bucket;
  ASSETS: Fetcher;

  // Authentication & Cryptographic Secrets
  JWT_SECRET: string;
  TURNSTILE_SECRET_KEY: string;
  RESEND_API_KEY: string;

  // OAuth Provider Credentials
  GITHUB_CLIENT_ID: string;
  GITHUB_CLIENT_SECRET: string;
  GOOGLE_CLIENT_ID: string;
  GOOGLE_CLIENT_SECRET: string;

  // Cloudflare R2 / S3-Compatible API Credentials
  R2_ACCESS_KEY_ID: string;
  R2_SECRET_ACCESS_KEY: string;
  Cloudflare_Account_ID?: string;
  CLOUDFLARE_ACCOUNT_ID?: string;

  // Operational & Gateway Settings
  ADMIN_PASSWORD?: string;
  TURNSTILE_SITE_KEY: string;
  RESEND_FROM_EMAIL: string;
  FRONTEND_URL: string;
  HEAVY_JWT_SECRET?: string;
  PERSISTENT_DATA_SALT?: string;
  GIFT_CARD_SALT?: string;
  ENVIRONMENT?: string;
}

/**
 * Core User entity representation in the D1 SQLite database.
 */
export interface User {
  user_id: string;
  username: string;
  email: string;
  avatar_url: string | null;
  credits: number;
  frozen_credits: number;
  token_version?: number;
}

/**
 * Decoded payload for signed JWT session tokens.
 */
export interface SessionPayload {
  userId: string;
  tokenVersion?: number;
  iat?: number;
  exp?: number;
}

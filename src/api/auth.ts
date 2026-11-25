import { Env, User } from "../types";
import { verifyTurnstile } from "../auth/turnstile";
import { signJWT, verifyJWT } from "../auth/jwt";
import { getSession } from "../auth/middleware";
import {
  getGitHubAuthURL,
  getGoogleAuthURL,
  handleGitHubCallback as ghCallback,
  handleGoogleCallback as goCallback
} from "../auth/oauth";
import { getPersistentSalt } from "./billing";
import * as bcrypt from "bcryptjs";
import { safeJsonBody } from "../lib/utils";

export const VALID_EMAIL_DOMAINS = [
  "gmail.com",
  "outlook.com",
  "yahoo.com",
  "protonmail.com",
  "proton.me",
  "icloud.com",
  "hotmail.com"
];

export function isValidEmailDomain(email: unknown): boolean {
  if (typeof email !== "string" || !email.trim()) return false;
  const parts = email.trim().split("@");
  if (parts.length !== 2) return false;
  if (!parts[0].trim() || !parts[1].trim()) return false;
  return VALID_EMAIL_DOMAINS.includes(parts[1].toLowerCase());
}

const SESSION_TTL_SECONDS = 30 * 24 * 3600; // 30 days (2,592,000s)

function setCookieHeaders(token: string | null): Headers {
  const headers = new Headers();
  if (token) {
    headers.set(
      "Set-Cookie",
      `session=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_SECONDS}; SameSite=Lax; Secure`
    );
  } else {
    headers.set("Set-Cookie", `session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax; Secure`);
  }
  headers.set("Content-Type", "application/json");
  return headers;
}

function generateReferralCode(): string {
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  let code = "NM-";
  for (let i = 0; i < 6; i++) {
    code += alphabet[bytes[i] % 32];
  }
  return code;
}

async function generateUniqueReferralCode(db: D1Database): Promise<string> {
  for (let attempt = 0; attempt < 5; attempt++) {
    const code = generateReferralCode();
    const existing = await db
      .prepare("SELECT user_id FROM users WHERE referral_code = ?")
      .bind(code)
      .first();
    if (!existing) return code;
  }
  return generateReferralCode();
}

function generateSecureVerificationCode(): string {
  const max = 900000;
  const limit = Math.floor(0xffffffff / max) * max;
  const array = new Uint32Array(1);
  do {
    crypto.getRandomValues(array);
  } while (array[0] >= limit);
  return (100000 + (array[0] % max)).toString();
}

async function generateOAuthUsername(
  db: D1Database,
  rawName?: string,
  rawEmail?: string
): Promise<string> {
  let base = (rawName || rawEmail?.split("@")[0] || "user")
    .replace(/[^a-zA-Z0-9]/g, "")
    .toLowerCase()
    .substring(0, 12);
  if (base.length < 3) base = "user";

  for (let i = 0; i < 5; i++) {
    const randBytes = crypto.getRandomValues(new Uint8Array(2));
    const suffix = Array.from(randBytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const candidate = `${base}_${suffix}`.substring(0, 20);
    const exists = await db
      .prepare("SELECT user_id FROM users WHERE username = ?")
      .bind(candidate)
      .first();
    if (!exists) return candidate;
  }
  return `user_${crypto.randomUUID().substring(0, 8)}`;
}

export async function handleRegister(req: Request, env: Env) {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const body: any = await safeJsonBody(req);

  let { username, email, password, code, turnstile_token, referral_code } = body;
  if (typeof email === "string") email = email.toLowerCase().trim();

  const clientIp =
    req.headers.get("CF-Connecting-IP") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    null;
  if (!(await verifyTurnstile(turnstile_token, env.TURNSTILE_SECRET_KEY, clientIp))) {
    return Response.json({ error: "error.invalidCaptcha" }, { status: 400 });
  }

  if (typeof email !== "string" || !isValidEmailDomain(email)) {
    return Response.json({ error: "error.unsupportedEmailDomain" }, { status: 400 });
  }

  if (!username || typeof username !== "string" || !/^[a-zA-Z0-9_-]{3,20}$/.test(username)) {
    return Response.json({ error: "error.invalidUsernameFormat" }, { status: 400 });
  }

  if (
    !password ||
    typeof password !== "string" ||
    password.length < 8 ||
    password.length > 64 ||
    !/[a-zA-Z]/.test(password) ||
    !/[0-9]/.test(password)
  ) {
    return Response.json({ error: "error.invalidPasswordFormat" }, { status: 400 });
  }

  if (!code || typeof code !== "string" || !/^\d{6}$/.test(code.trim())) {
    return Response.json({ error: "error.invalidCode" }, { status: 400 });
  }

  // Check code with anti-brute force tracking
  const activeCode = await env.DB.prepare(
    "SELECT id, code, attempts FROM verification_codes WHERE email = ? AND code NOT LIKE 'NOTICE_%' AND code != 'OAUTH_NOTICE' AND expires_at > datetime('now') ORDER BY id DESC LIMIT 1"
  )
    .bind(email || "")
    .first<{ id: number; code: string; attempts: number }>();

  if (!activeCode) {
    return Response.json({ error: "error.invalidCode" }, { status: 400 });
  }

  // Atomically increment attempts to prevent concurrency race conditions (anti-brute force CAS)
  const updateRes = await env.DB.prepare(
    "UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ? AND attempts < 5"
  )
    .bind(activeCode.id)
    .run();

  if (!updateRes.meta.changes || updateRes.meta.changes === 0) {
    await env.DB.prepare("DELETE FROM verification_codes WHERE id = ?").bind(activeCode.id).run();
    return Response.json({ error: "error.codeLockedTooManyAttempts" }, { status: 400 });
  }

  if (activeCode.code !== code.trim()) {
    return Response.json({ error: "error.invalidCode" }, { status: 400 });
  }

  // Check tombstone (90-day cooldown)
  const encoder = new TextEncoder();
  const emailData = encoder.encode(email + getPersistentSalt(env));
  const emailHashBuffer = await crypto.subtle.digest("SHA-256", emailData);
  const emailHash = Array.from(new Uint8Array(emailHashBuffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const tombstone = await env.DB.prepare(
    "SELECT expires_at FROM account_tombstones WHERE hash_id = ? AND expires_at > datetime('now')"
  )
    .bind(emailHash)
    .first();
  if (tombstone) {
    return Response.json({ error: "error.accountCooldown" }, { status: 403 });
  }

  // Check uniqueness (case-insensitive for email and username)
  const existing = await env.DB.prepare(
    "SELECT user_id FROM users WHERE LOWER(email) = LOWER(?) OR LOWER(username) = LOWER(?)"
  )
    .bind(email || "", username || "")
    .first();
  if (existing) {
    return Response.json({ error: "error.userOrEmailExists" }, { status: 400 });
  }

  // Validate referral code if provided
  let referrerId: string | null = null;
  if (referral_code && typeof referral_code === "string" && referral_code.trim()) {
    const referrer = await env.DB.prepare(
      "SELECT user_id FROM users WHERE referral_code = ? AND email NOT LIKE 'deleted_%'"
    )
      .bind(referral_code.trim().toUpperCase())
      .first<{ user_id: string }>();
    if (!referrer) {
      return Response.json({ error: "error.invalidReferralCode" }, { status: 400 });
    }
    referrerId = referrer.user_id;
  }

  const hash = bcrypt.hashSync(password, 10);
  const userId = crypto.randomUUID();
  const newReferralCode = await generateUniqueReferralCode(env.DB);
  const initialCredits = referrerId ? 150 : 100;

  const statements = [
    env.DB.prepare(
      `
      INSERT INTO users (user_id, username, email, password_hash, credits, referral_code, referred_by) 
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `
    ).bind(
      userId,
      username || "",
      email || "",
      hash || "",
      initialCredits,
      newReferralCode,
      referrerId
    ),

    // Write signup bonus ledger entry (100)
    env.DB.prepare(
      `
      INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail)
      VALUES (?, ?, 'signup_bonus', 100, 100, 'Signup Bonus', 'Welcome credit pack')
    `
    ).bind(crypto.randomUUID(), userId)
  ];

  // If referred, reward both the new user (+50) and the referrer (+50) atomically
  if (referrerId) {
    statements.push(
      // 1. Reward the new user +50 (bringing balance to 150)
      env.DB.prepare(
        `
        INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail, related_id)
        VALUES (?, ?, 'referral_reward', 50, 150, 'Referral Bonus', 'Invited by friend', ?)
      `
      ).bind(crypto.randomUUID(), userId, referrerId),

      // 2. Reward the referrer +50
      env.DB.prepare("UPDATE users SET credits = credits + 50 WHERE user_id = ?").bind(referrerId),

      // 3. Subquery ensures atomic snapshot of referrer credits without read-after-write race
      env.DB.prepare(
        `
        INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail, related_id)
        VALUES (?, ?, 'referral_reward', 50, (SELECT credits FROM users WHERE user_id = ?), 'Referral Reward', ?, ?)
      `
      ).bind(crypto.randomUUID(), referrerId, referrerId, username, userId)
    );
  }

  statements.push(
    env.DB.prepare("DELETE FROM verification_codes WHERE id = ?").bind(activeCode.id)
  );

  await env.DB.batch(statements);

  const token = await signJWT({ userId, tokenVersion: 1 }, env.JWT_SECRET, SESSION_TTL_SECONDS);

  return new Response(
    JSON.stringify({ user_id: userId || "", username, email, credits: initialCredits }),
    {
      headers: setCookieHeaders(token)
    }
  );
}

export async function handleLogin(req: Request, env: Env) {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const body: any = await safeJsonBody(req);

  let { email, password, turnstile_token } = body;
  if (typeof email === "string") email = email.toLowerCase().trim();

  const clientIp =
    req.headers.get("CF-Connecting-IP") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    null;
  if (!(await verifyTurnstile(turnstile_token, env.TURNSTILE_SECRET_KEY, clientIp))) {
    return Response.json({ error: "Invalid captcha" }, { status: 400 });
  }

  if (typeof email !== "string" || !email.trim() || typeof password !== "string" || !password) {
    return Response.json({ error: "Invalid credentials" }, { status: 401 });
  }

  const user = await env.DB.prepare("SELECT * FROM users WHERE LOWER(email) = ?")
    .bind(email || "")
    .first<User & { password_hash: string | null; token_version: number | null }>();
  if (!user) return Response.json({ error: "Invalid credentials" }, { status: 401 });

  if (!user.password_hash) {
    return Response.json({ error: "Invalid credentials" }, { status: 401 });
  }

  const valid = bcrypt.compareSync(password, user.password_hash);
  if (!valid) return Response.json({ error: "Invalid credentials" }, { status: 401 });

  const token = await signJWT(
    { userId: user.user_id, tokenVersion: user.token_version || 1 },
    env.JWT_SECRET,
    SESSION_TTL_SECONDS
  );

  return new Response(
    JSON.stringify({
      user_id: user.user_id,
      username: user.username,
      email: user.email,
      credits: user.credits
    }),
    { headers: setCookieHeaders(token) }
  );
}

export async function handleSendCode(req: Request, env: Env, ctx?: ExecutionContext) {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

  // Opportunistic cleanup of expired verification codes (> 1 day old), stale IP rate limits (> 24h old), and stale passkey challenge CAS entries (> 10m old)
  const cleanupPromise = Promise.all([
    env.DB.prepare("DELETE FROM verification_codes WHERE expires_at < datetime('now', '-1 day')")
      .run()
      .catch(() => {}),
    env.DB.prepare(
      "DELETE FROM system_counters WHERE (key LIKE 'ip_code_rate_20%' AND key < 'ip_code_rate_' || strftime('%Y-%m-%dT%H', 'now', '-24 hours')) OR (key LIKE 'ip_pwd_rate_20%' AND key < 'ip_pwd_rate_' || strftime('%Y-%m-%dT%H', 'now', '-24 hours'))"
    )
      .run()
      .catch(() => {}),
    env.DB.prepare(
      "DELETE FROM system_counters WHERE key LIKE 'pk_used_%' AND value < strftime('%s', 'now', '-10 minutes')"
    )
      .run()
      .catch(() => {})
  ]);
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(cleanupPromise);
  }

  const body: any = await safeJsonBody(req);
  let { email, turnstile_token, lang } = body;

  if (typeof email === "string") email = email.toLowerCase().trim();

  const clientIp =
    req.headers.get("CF-Connecting-IP") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown";
  if (
    !(await verifyTurnstile(
      turnstile_token,
      env.TURNSTILE_SECRET_KEY,
      clientIp !== "unknown" ? clientIp : null
    ))
  ) {
    return Response.json({ error: "error.invalidCaptcha" }, { status: 400 });
  }

  if (typeof email !== "string" || !isValidEmailDomain(email)) {
    return Response.json({ error: "error.unsupportedEmailDomain" }, { status: 400 });
  }

  const currentHourStr = new Date().toISOString().slice(0, 13); // YYYY-MM-DDTHH
  const ipHourlyKey = `ip_code_rate_${currentHourStr}_${clientIp}`;

  if (clientIp !== "unknown") {
    const ipCounter = await env.DB.prepare("SELECT value FROM system_counters WHERE key = ?")
      .bind(ipHourlyKey)
      .first<{ value: number }>();
    if (ipCounter && ipCounter.value >= 5) {
      return Response.json({ error: "error.ipRateLimit" }, { status: 429 });
    }
  }

  const todayStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const dailyKey = `emails_sent_${todayStr}`;

  const counter = await env.DB.prepare("SELECT value FROM system_counters WHERE key = ?")
    .bind(dailyKey)
    .first<{ value: number }>();
  if (counter && counter.value >= 500) {
    return Response.json({ error: "error.dailyEmailLimit" }, { status: 429 });
  }

  const recent = await env.DB.prepare(
    "SELECT id FROM verification_codes WHERE LOWER(email) = ? AND created_at > datetime('now', '-60 seconds')"
  )
    .bind(email || "")
    .first();
  if (recent) {
    return Response.json({ error: "error.wait60s" }, { status: 429 });
  }

  // Anti-account enumeration privacy preservation:
  // Verify whether email already belongs to an active user or remains in deletion cooldown
  const existingUser = await env.DB.prepare(
    "SELECT user_id, email FROM users WHERE LOWER(email) = LOWER(?)"
  )
    .bind(email)
    .first<{ user_id: string; email: string }>();

  let inCooldown = false;
  try {
    const persistentSalt = getPersistentSalt(env);
    const encoder = new TextEncoder();
    const emailData = encoder.encode(email + persistentSalt);
    const emailHashBuffer = await crypto.subtle.digest("SHA-256", emailData);
    const emailHash = Array.from(new Uint8Array(emailHashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
    const activeTombstone = await env.DB.prepare(
      "SELECT expires_at FROM account_tombstones WHERE hash_id = ? AND expires_at > datetime('now')"
    )
      .bind(emailHash)
      .first();
    if (activeTombstone) inCooldown = true;
  } catch (err) {
    // If salt check throws in production when not configured, fallback gracefully
  }

  if (existingUser || inCooldown) {
    if (clientIp !== "unknown") {
      await env.DB.prepare(
        "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
      )
        .bind(ipHourlyKey)
        .run();
    }
    await env.DB.prepare(
      "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
    )
      .bind(dailyKey)
      .run();

    const isZh = lang === "zh";
    const noticeSubject = isZh ? "[NanoMesh] 账户注册提醒" : "[NanoMesh] Account Notice";
    const noticeGreeting = isZh ? "您好！" : "Hello!";
    const noticeBody = isZh
      ? "我们收到了使用您邮箱注册 NanoMesh 的请求。但检测到该邮箱已注册或处于注销冷静期。如果您忘记密码，请前往登录页使用“找回密码”功能。如非您本人操作，请忽略此邮件。"
      : "We received a registration attempt for NanoMesh using your email address. However, this email is already registered or in deletion cooldown. If you forgot your password, please use 'Forgot Password' on the sign-in page. If this was not you, please ignore this email.";
    const noticeFooter = isZh
      ? "&copy; 2026 NanoMesh 灵微络. 保留所有权利。"
      : "&copy; 2026 NanoMesh. All rights reserved.";

    const noticeHtml = `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
        <h2 style="color: #00e5ff; margin-bottom: 24px; font-weight: normal;">NanoMesh ${isZh ? "灵微络" : ""}</h2>
        <p style="font-size: 16px; margin-bottom: 16px;">${noticeGreeting}</p>
        <p style="font-size: 14px; color: #4b5563; line-height: 1.6; margin-bottom: 24px;">${noticeBody}</p>
        <hr style="border: none; border-top: 1px solid #e5e7eb; margin-bottom: 16px;">
        <p style="font-size: 12px; color: #9ca3af; text-align: center;">${noticeFooter}</p>
      </div>
    `;

    await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: `NanoMesh <${env.RESEND_FROM_EMAIL}>`,
        to: email,
        subject: noticeSubject,
        html: noticeHtml
      })
    }).catch((err) => console.error("Failed to send notice email:", err));

    return Response.json({ success: true, message: "Code sent" });
  }

  const code = generateSecureVerificationCode();

  await env.DB.prepare(
    `
    INSERT INTO verification_codes (email, code, expires_at) 
    VALUES (?, ?, datetime('now', '+10 minutes'))
  `
  )
    .bind(email || "", code || "")
    .run();

  const isZh = lang === "zh";
  const subject = isZh ? "[NanoMesh] 您的注册验证码" : "[NanoMesh] Your Verification Code";

  const textGreeting = isZh
    ? "您好！感谢您注册 NanoMesh。"
    : "Hello! Thank you for registering for NanoMesh.";
  const textHint = isZh
    ? "该验证码将在 10 分钟后过期。如果您未请求此验证码，请忽略此邮件。"
    : "This code will expire in 10 minutes. If you did not request this code, please ignore this email.";
  const textFooter = isZh
    ? "&copy; 2026 NanoMesh 灵微络. 保留所有权利。"
    : "&copy; 2026 NanoMesh. All rights reserved.";

  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
      <h2 style="color: #00e5ff; margin-bottom: 24px; font-weight: normal;">NanoMesh ${isZh ? "灵微络" : ""}</h2>
      <p style="font-size: 16px; margin-bottom: 16px;">${textGreeting}</p>
      <div style="background-color: #f3f4f6; border-radius: 8px; padding: 24px; text-align: center; margin-bottom: 24px;">
        <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #111827;">${code}</span>
      </div>
      <p style="font-size: 14px; color: #6b7280; margin-bottom: 32px;">${textHint}</p>
      <hr style="border: none; border-top: 1px solid #e5e7eb; margin-bottom: 16px;">
      <p style="font-size: 12px; color: #9ca3af; text-align: center;">${textFooter}</p>
    </div>
  `;

  const resendRes = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: `NanoMesh <${env.RESEND_FROM_EMAIL}>`,
      to: email,
      subject: subject,
      html: htmlContent
    })
  });

  if (!resendRes.ok) {
    return Response.json({ error: "error.emailSendFailed" }, { status: 500 });
  }

  await env.DB.prepare(
    "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
  )
    .bind(dailyKey)
    .run();

  if (clientIp !== "unknown") {
    await env.DB.prepare(
      "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
    )
      .bind(ipHourlyKey)
      .run();
  }

  return Response.json({ success: true });
}

export async function handleLogout(req: Request, env: Env) {
  if (req.method !== "POST") {
    return new Response("Method not allowed", { status: 405 });
  }
  return new Response(JSON.stringify({ success: true }), { headers: setCookieHeaders(null) });
}

export async function handleMe(req: Request, env: Env) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405 });
  }
  const session = await getSession(req, env);
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const user = await env.DB.prepare(
    "SELECT user_id, username, email, credits, frozen_credits, avatar_url, avatar_updated_at, referral_code, password_hash IS NOT NULL as has_password FROM users WHERE user_id = ?"
  )
    .bind(session.userId || "")
    .first();
  if (!user) return Response.json({ error: "Not found" }, { status: 404 });

  return Response.json({ ...user, has_password: !!user.has_password });
}

export async function handleGitHubRedirect(req: Request, env: Env) {
  const urlObj = new URL(req.url);
  const action = urlObj.searchParams.get("action") || "login";
  let userId: string | undefined;
  if (action === "bind") {
    const session = await getSession(req, env);
    if (!session || !session.userId) {
      return Response.redirect(`${env.FRONTEND_URL}/login.html?error=unauthorized`);
    }
    userId = session.userId;
  }
  const url = await getGitHubAuthURL(env, action, userId);
  return Response.redirect(url, 302);
}

export async function handleGoogleRedirect(req: Request, env: Env) {
  const urlObj = new URL(req.url);
  const action = urlObj.searchParams.get("action") || "login";
  let userId: string | undefined;
  if (action === "bind") {
    const session = await getSession(req, env);
    if (!session || !session.userId) {
      return Response.redirect(`${env.FRONTEND_URL}/login.html?error=unauthorized`);
    }
    userId = session.userId;
  }
  const url = await getGoogleAuthURL(env, action, userId);
  return Response.redirect(url, 302);
}

async function handleOAuthCallback(
  req: Request,
  env: Env,
  provider: "github" | "google",
  callbackFn: any
) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state)
    return Response.redirect(`${env.FRONTEND_URL}/login.html?error=missing_params`);

  const payload = await verifyJWT(state, env.JWT_SECRET);
  if (!payload || !payload.nonce) {
    return Response.redirect(`${env.FRONTEND_URL}/login.html?error=invalid_state`);
  }

  const isBindAction = payload.action === "bind";

  try {
    const profile = await callbackFn(code, state, env);
    const session = await getSession(req, env);
    const avatarToSet = profile.avatar_url || profile.picture || null;
    let userId;

    // Check tombstone for OAuth ID
    const encoder = new TextEncoder();
    const persistentSalt = getPersistentSalt(env);
    const oauthData = encoder.encode(`${provider}:${profile.id}` + persistentSalt);
    const oauthHashBuffer = await crypto.subtle.digest("SHA-256", oauthData);
    const oauthHash = Array.from(new Uint8Array(oauthHashBuffer))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const tombstone = await env.DB.prepare(
      "SELECT expires_at FROM account_tombstones WHERE hash_id = ? AND expires_at > datetime('now')"
    )
      .bind(oauthHash || "")
      .first();
    if (tombstone) {
      return Response.redirect(`${env.FRONTEND_URL}/login.html?error=account_cooldown`);
    }

    // Check tombstone cooldown for profile email
    if (profile.email && typeof profile.email === "string") {
      const emailData = encoder.encode(profile.email.toLowerCase().trim() + persistentSalt);
      const emailHashBuffer = await crypto.subtle.digest("SHA-256", emailData);
      const emailHash = Array.from(new Uint8Array(emailHashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      const emailTombstone = await env.DB.prepare(
        "SELECT expires_at FROM account_tombstones WHERE hash_id = ? AND expires_at > datetime('now')"
      )
        .bind(emailHash)
        .first();
      if (emailTombstone) {
        return Response.redirect(`${env.FRONTEND_URL}/login.html?error=account_cooldown`);
      }
    }

    let activeUser = null;
    if (session && session.userId) {
      activeUser = await env.DB.prepare("SELECT user_id, avatar_url FROM users WHERE user_id = ?")
        .bind(session.userId)
        .first<any>();
    }

    if (isBindAction) {
      // CSRF and session hijacking prevention:
      // State payload must contain a valid userId that matches the authenticated session
      if (!payload.userId || !session || !session.userId || payload.userId !== session.userId) {
        return Response.redirect(`${env.FRONTEND_URL}/?error=bind_csrf_rejected#settings`);
      }

      if (!activeUser) {
        return Response.redirect(`${env.FRONTEND_URL}/?error=user_not_found#settings`);
      }

      // Track 2: User explicitly clicked "Bind" from Settings while logged in
      userId = activeUser.user_id;

      // 1. Guard against duplicate provider binding on current user
      const existingUserBinding = await env.DB.prepare(
        "SELECT provider_id FROM user_oauth_bindings WHERE user_id = ? AND provider = ?"
      )
        .bind(userId, provider)
        .first<{ provider_id: string }>();

      if (existingUserBinding) {
        return Response.redirect(`${env.FRONTEND_URL}/?error=oauth_already_bound#settings`);
      }

      // 2. Insert new binding record
      const bindResult = await env.DB.prepare(
        "INSERT OR IGNORE INTO user_oauth_bindings (user_id, provider, provider_id) VALUES (?, ?, ?)"
      )
        .bind(userId || "", provider, String(profile.id || ""))
        .run();

      // 3. Guard against provider_id already bound by another user
      if (!bindResult.meta.changes || bindResult.meta.changes === 0) {
        return Response.redirect(`${env.FRONTEND_URL}/?error=oauth_already_bound#settings`);
      }

      if (avatarToSet && !activeUser.avatar_url) {
        await env.DB.prepare("UPDATE users SET avatar_url = ? WHERE user_id = ?")
          .bind(avatarToSet, userId)
          .run();
      }
    } else {
      // Track 1: Login / Register
      let binding = await env.DB.prepare(
        "SELECT user_id FROM user_oauth_bindings WHERE provider = ? AND provider_id = ?"
      )
        .bind(provider, String(profile.id || ""))
        .first<any>();

      if (binding) {
        userId = binding.user_id;
        if (avatarToSet) {
          const existing = await env.DB.prepare("SELECT avatar_url FROM users WHERE user_id = ?")
            .bind(userId || "")
            .first<any>();
          if (!existing?.avatar_url) {
            await env.DB.prepare("UPDATE users SET avatar_url = ? WHERE user_id = ?")
              .bind(avatarToSet, userId || "")
              .run();
          }
        }
      } else {
        // Check if email already registered
        const existingUser = await env.DB.prepare(
          "SELECT user_id, avatar_url FROM users WHERE LOWER(email) = ?"
        )
          .bind((profile.email || "").toLowerCase())
          .first<any>();
        if (existingUser) {
          userId = existingUser.user_id;
          if (avatarToSet && !existingUser.avatar_url) {
            await env.DB.prepare("UPDATE users SET avatar_url = ? WHERE user_id = ?")
              .bind(avatarToSet, userId || "")
              .run();
          }
          // Bind to existing user
          await env.DB.prepare(
            "INSERT OR IGNORE INTO user_oauth_bindings (user_id, provider, provider_id) VALUES (?, ?, ?)"
          )
            .bind(userId || "", provider, String(profile.id || ""))
            .run();
        } else {
          userId = crypto.randomUUID();
          const oauthReferralCode = await generateUniqueReferralCode(env.DB);
          const safeUsername = await generateOAuthUsername(
            env.DB,
            profile.username || profile.name,
            profile.email
          );
          // Insert new user
          await env.DB.prepare(
            `
          INSERT INTO users (user_id, username, email, avatar_url, credits, referral_code)
          VALUES (?, ?, ?, ?, 100, ?)
        `
          )
            .bind(
              userId || "",
              safeUsername,
              (profile.email || "").toLowerCase(),
              avatarToSet,
              oauthReferralCode
            )
            .run();
          // Write signup bonus ledger
          await env.DB.prepare(
            `
          INSERT INTO credit_ledger (ledger_id, user_id, category, amount, balance, title, detail)
          VALUES (?, ?, 'signup_bonus', 100, 100, 'Signup Bonus', 'Welcome credit pack')
        `
          )
            .bind(crypto.randomUUID(), userId || "")
            .run();
          // Bind new user
          await env.DB.prepare(
            "INSERT INTO user_oauth_bindings (user_id, provider, provider_id) VALUES (?, ?, ?)"
          )
            .bind(userId || "", provider, String(profile.id || ""))
            .run();
        }
      }
    }

    const dbUser = await env.DB.prepare("SELECT token_version FROM users WHERE user_id = ?")
      .bind(userId)
      .first<{ token_version: number | null }>();
    const token = await signJWT(
      { userId, tokenVersion: dbUser?.token_version || 1 },
      env.JWT_SECRET,
      SESSION_TTL_SECONDS
    );
    // Cannot use Response.redirect() — it returns an immutable response.
    // Must manually construct response with Location + Set-Cookie.
    return new Response(null, {
      status: 302,
      headers: {
        Location: `${env.FRONTEND_URL}/`,
        "Set-Cookie": `session=${token}; HttpOnly; Path=/; Max-Age=${SESSION_TTL_SECONDS}; SameSite=Lax; Secure`
      }
    });
  } catch (e: any) {
    return Response.redirect(
      `${env.FRONTEND_URL}/login.html?error=${encodeURIComponent(e.message)}`
    );
  }
}

export async function handleGitHubCallback(req: Request, env: Env) {
  return handleOAuthCallback(req, env, "github", ghCallback);
}

export async function handleGoogleCallback(req: Request, env: Env) {
  return handleOAuthCallback(req, env, "google", goCallback);
}

export async function handleGetBindings(req: Request, env: Env) {
  if (req.method !== "GET" && req.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405 });
  }
  const session = await getSession(req, env);
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

  const bindings = await env.DB.prepare(
    "SELECT provider FROM user_oauth_bindings WHERE user_id = ?"
  )
    .bind(session.userId || "")
    .all();
  return Response.json({ bindings: bindings.results.map((r) => r.provider) });
}

export async function handleUnbindOAuth(req: Request, env: Env, provider: string) {
  const session = await getSession(req, env);
  if (!session) return Response.json({ error: "Unauthorized" }, { status: 401 });

  // Safety check: don't allow unbinding if they have no password, no other OAuth, and no passkeys
  const user = await env.DB.prepare("SELECT password_hash FROM users WHERE user_id = ?")
    .bind(session.userId || "")
    .first<any>();
  const bindings = await env.DB.prepare(
    "SELECT provider FROM user_oauth_bindings WHERE user_id = ?"
  )
    .bind(session.userId || "")
    .all();
  const passkeyCount = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM user_passkeys WHERE user_id = ?"
  )
    .bind(session.userId || "")
    .first<{ cnt: number }>();

  const hasPassword = !!(user && user.password_hash);
  const hasMultipleOAuth = !!(bindings.results && bindings.results.length > 1);
  const hasPasskey = (passkeyCount?.cnt ?? 0) > 0;

  if (!hasPassword && !hasMultipleOAuth && !hasPasskey) {
    return Response.json(
      { error: "Cannot unbind last login method without a password or passkey." },
      { status: 400 }
    );
  }

  await env.DB.prepare("DELETE FROM user_oauth_bindings WHERE user_id = ? AND provider = ?")
    .bind(session.userId, provider)
    .run();

  return Response.json({ success: true });
}

export async function handleForgotPassword(
  req: Request,
  env: Env,
  ctx?: ExecutionContext
): Promise<Response> {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });

  // Opportunistic cleanup of expired verification codes (> 1 day old) and stale IP rate limits (> 24h old)
  const cleanupPromise = Promise.all([
    env.DB.prepare("DELETE FROM verification_codes WHERE expires_at < datetime('now', '-1 day')")
      .run()
      .catch(() => {}),
    env.DB.prepare(
      "DELETE FROM system_counters WHERE (key LIKE 'ip_code_rate_20%' AND key < 'ip_code_rate_' || strftime('%Y-%m-%dT%H', 'now', '-24 hours')) OR (key LIKE 'ip_pwd_rate_20%' AND key < 'ip_pwd_rate_' || strftime('%Y-%m-%dT%H', 'now', '-24 hours'))"
    )
      .run()
      .catch(() => {})
  ]);
  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(cleanupPromise);
  }

  const body: any = await safeJsonBody(req);
  let { email, turnstile_token, lang } = body;
  if (typeof email === "string") email = email.toLowerCase().trim();

  const clientIp =
    req.headers.get("CF-Connecting-IP") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    "unknown";
  if (
    !(await verifyTurnstile(
      turnstile_token,
      env.TURNSTILE_SECRET_KEY,
      clientIp !== "unknown" ? clientIp : null
    ))
  ) {
    return Response.json({ error: "error.invalidCaptcha" }, { status: 400 });
  }

  if (typeof email !== "string" || !isValidEmailDomain(email)) {
    return Response.json({ error: "error.unsupportedEmailDomain" }, { status: 400 });
  }

  // Rate limiting (IP rate limit)
  const currentHourStr = new Date().toISOString().slice(0, 13);
  const ipHourlyKey = `ip_pwd_rate_${currentHourStr}_${clientIp}`;
  if (clientIp !== "unknown") {
    const ipCounter = await env.DB.prepare("SELECT value FROM system_counters WHERE key = ?")
      .bind(ipHourlyKey)
      .first<{ value: number }>();
    if (ipCounter && ipCounter.value >= 5) {
      return Response.json({ error: "error.ipRateLimit" }, { status: 429 });
    }
  }

  // Global daily email sending limit
  const todayStr = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const dailyKey = `emails_sent_${todayStr}`;
  const counter = await env.DB.prepare("SELECT value FROM system_counters WHERE key = ?")
    .bind(dailyKey)
    .first<{ value: number }>();
  if (counter && counter.value >= 500) {
    return Response.json({ error: "error.dailyEmailLimit" }, { status: 429 });
  }

  // 60-second cooldown per email
  const recent = await env.DB.prepare(
    "SELECT id FROM verification_codes WHERE LOWER(email) = ? AND created_at > datetime('now', '-60 seconds')"
  )
    .bind(email)
    .first();
  if (recent) {
    return Response.json({ error: "error.wait60s" }, { status: 429 });
  }

  // Check if user exists and has a password
  const user = await env.DB.prepare(
    "SELECT user_id, email, password_hash FROM users WHERE LOWER(email) = LOWER(?)"
  )
    .bind(email)
    .first<{ user_id: string; email: string; password_hash: string | null }>();

  // If user does not exist or has deleted account, return success to prevent account enumeration
  if (!user || user.email.startsWith("deleted_")) {
    return Response.json({
      success: true,
      message: "If this email is registered, a reset code has been sent."
    });
  }

  // Update IP hourly counter
  if (clientIp !== "unknown") {
    await env.DB.prepare(
      "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
    )
      .bind(ipHourlyKey)
      .run();
  }

  const isZh = lang === "zh";

  if (!user.password_hash) {
    // Record cooldown in verification_codes to protect OAuth users from being spammed (using unguessable notice token)
    const noticeToken = "NOTICE_OAUTH_" + crypto.randomUUID();
    await env.DB.prepare(
      "INSERT INTO verification_codes (email, code, expires_at) VALUES (?, ?, datetime('now', '+10 minutes'))"
    )
      .bind(email, noticeToken)
      .run();

    // User is OAuth-only, send helpful email
    const subject = isZh ? "[NanoMesh] 重置密码提醒" : "[NanoMesh] Password Reset Notice";
    const greeting = isZh ? "您好！" : "Hello!";
    const bodyText = isZh
      ? "您的账号是通过第三方快捷登录（Google / GitHub）创建的，未设置过密码。请直接在登录页面使用第三方快捷登录。"
      : "Your account was created via third-party login (Google / GitHub) and does not have a password. Please sign in directly using your third-party provider.";
    const footer = isZh
      ? "&copy; 2026 NanoMesh 灵微络. 保留所有权利。"
      : "&copy; 2026 NanoMesh. All rights reserved.";

    const resendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: `NanoMesh <${env.RESEND_FROM_EMAIL}>`,
        to: email,
        subject: subject,
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
            <h2 style="color: #00e5ff; margin-bottom: 24px; font-weight: normal;">NanoMesh ${isZh ? "灵微络" : ""}</h2>
            <p style="font-size: 16px; margin-bottom: 16px;">${greeting}</p>
            <p style="font-size: 14px; color: #4b5563; line-height: 1.6; margin-bottom: 24px;">${bodyText}</p>
            <hr style="border: none; border-top: 1px solid #e5e7eb; margin-bottom: 16px;">
            <p style="font-size: 12px; color: #9ca3af; text-align: center;">${footer}</p>
          </div>
        `
      })
    }).catch((err) => {
      console.error("Failed to send oauth reset notice email:", err);
      return null;
    });

    if (resendRes && resendRes.ok) {
      await env.DB.prepare(
        "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
      )
        .bind(dailyKey)
        .run();
    }

    return Response.json({
      success: true,
      message: "If this email is registered, a reset code has been sent."
    });
  }

  // Generate 6-digit reset code
  const code = generateSecureVerificationCode();
  await env.DB.prepare(
    `
    INSERT INTO verification_codes (email, code, expires_at) 
    VALUES (?, ?, datetime('now', '+10 minutes'))
  `
  )
    .bind(email, code)
    .run();

  const subject = isZh ? "[NanoMesh] 您的重置密码验证码" : "[NanoMesh] Your Password Reset Code";
  const greeting = isZh ? "您好！" : "Hello!";
  const hint = isZh
    ? "您正在申请重置 NanoMesh 账号密码。该验证码将在 10 分钟后过期。如非本人操作，请立即检查账号安全并忽略此邮件。"
    : "You requested to reset your NanoMesh password. This code will expire in 10 minutes. If you did not request this, please ignore this email.";
  const footer = isZh
    ? "&copy; 2026 NanoMesh 灵微络. 保留所有权利。"
    : "&copy; 2026 NanoMesh. All rights reserved.";

  const htmlContent = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; color: #333;">
      <h2 style="color: #00e5ff; margin-bottom: 24px; font-weight: normal;">NanoMesh ${isZh ? "灵微络" : ""}</h2>
      <p style="font-size: 16px; margin-bottom: 16px;">${greeting}</p>
      <div style="background-color: #f3f4f6; border-radius: 8px; padding: 24px; text-align: center; margin-bottom: 24px;">
        <span style="font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #111827;">${code}</span>
      </div>
      <p style="font-size: 14px; color: #6b7280; margin-bottom: 32px;">${hint}</p>
      <hr style="border: none; border-top: 1px solid #e5e7eb; margin-bottom: 16px;">
      <p style="font-size: 12px; color: #9ca3af; text-align: center;">${footer}</p>
    </div>
  `;

  const resendRes = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: `NanoMesh <${env.RESEND_FROM_EMAIL}>`,
      to: email,
      subject: subject,
      html: htmlContent
    })
  }).catch((err) => {
    console.error("Failed to send reset code email:", err);
    return null;
  });

  if (resendRes && resendRes.ok) {
    await env.DB.prepare(
      "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
    )
      .bind(dailyKey)
      .run();
  }

  return Response.json({
    success: true,
    message: "If this email is registered, a reset code has been sent."
  });
}

export async function handleResetPassword(
  req: Request,
  env: Env,
  ctx?: ExecutionContext
): Promise<Response> {
  if (req.method !== "POST") return new Response("Method not allowed", { status: 405 });
  const body: any = await safeJsonBody(req);
  let { email, code, newPassword } = body;
  if (typeof email === "string") email = email.toLowerCase().trim();

  if (typeof email !== "string" || !isValidEmailDomain(email)) {
    return Response.json({ error: "error.unsupportedEmailDomain" }, { status: 400 });
  }

  // Rate limiting (IP rate limit and email rate limit)
  const clientIp = req.headers.get("cf-connecting-ip") || "unknown";
  const currentMinuteStr = new Date().toISOString().slice(0, 16); // YYYY-MM-DDTHH:mm
  if (clientIp !== "unknown") {
    const ipKey = `ip_pwd_rate_${currentMinuteStr}_${clientIp}`;
    const ipCounter = await env.DB.prepare("SELECT value FROM system_counters WHERE key = ?")
      .bind(ipKey)
      .first<{ value: number }>();
    if (ipCounter && ipCounter.value >= 10) {
      return Response.json({ error: "error.ipRateLimit" }, { status: 429 });
    }
    await env.DB.prepare(
      "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
    )
      .bind(ipKey)
      .run();
  }

  const emailRateKey = `email_pwd_rate_${currentMinuteStr}_${email}`;
  const emailCounter = await env.DB.prepare("SELECT value FROM system_counters WHERE key = ?")
    .bind(emailRateKey)
    .first<{ value: number }>();
  if (emailCounter && emailCounter.value >= 5) {
    return Response.json({ error: "error.tooManyRequests" }, { status: 429 });
  }
  await env.DB.prepare(
    "INSERT INTO system_counters (key, value) VALUES (?, 1) ON CONFLICT(key) DO UPDATE SET value = value + 1"
  )
    .bind(emailRateKey)
    .run();

  if (!code || typeof code !== "string" || !/^\d{6}$/.test(code.trim())) {
    return Response.json({ error: "error.invalidCode" }, { status: 400 });
  }

  if (
    !newPassword ||
    typeof newPassword !== "string" ||
    newPassword.length < 8 ||
    newPassword.length > 64 ||
    !/[a-zA-Z]/.test(newPassword) ||
    !/[0-9]/.test(newPassword)
  ) {
    return Response.json({ error: "error.invalidPasswordFormat" }, { status: 400 });
  }

  // Check code with anti-brute force tracking FIRST to prevent account enumeration side channel
  const activeCode = await env.DB.prepare(
    "SELECT id, code, attempts FROM verification_codes WHERE LOWER(email) = ? AND code NOT LIKE 'NOTICE_%' AND code != 'OAUTH_NOTICE' AND expires_at > datetime('now') ORDER BY id DESC LIMIT 1"
  )
    .bind(email)
    .first<{ id: number; code: string; attempts: number }>();

  if (!activeCode || !/^\d{6}$/.test(activeCode.code)) {
    return Response.json({ error: "error.invalidCode" }, { status: 400 });
  }

  // Atomic lock check: only increment if attempts < 5 to prevent TOCTOU concurrency race
  const updateRes = await env.DB.prepare(
    "UPDATE verification_codes SET attempts = attempts + 1 WHERE id = ? AND attempts < 5"
  )
    .bind(activeCode.id)
    .run();

  if (!updateRes.meta.changes || updateRes.meta.changes === 0) {
    await env.DB.prepare("DELETE FROM verification_codes WHERE id = ?").bind(activeCode.id).run();
    return Response.json({ error: "error.codeLockedTooManyAttempts" }, { status: 400 });
  }

  if (activeCode.code !== code.trim()) {
    return Response.json({ error: "error.invalidCode" }, { status: 400 });
  }

  // Code is verified. Now verify user existence & password reset eligibility
  const user = await env.DB.prepare(
    "SELECT user_id, email, password_hash FROM users WHERE LOWER(email) = LOWER(?)"
  )
    .bind(email)
    .first<{ user_id: string; email: string; password_hash: string | null }>();

  // If user does not exist, is deleted, or is pure OAuth without password, return generic error.invalidCode to prevent enumeration
  if (!user || user.email.startsWith("deleted_") || !user.password_hash) {
    await env.DB.prepare("DELETE FROM verification_codes WHERE id = ?").bind(activeCode.id).run();
    return Response.json({ error: "error.invalidCode" }, { status: 400 });
  }

  // Hash new password using bcrypt
  const hash = bcrypt.hashSync(newPassword, 10);

  // Update password and invalidate verification code atomically
  await env.DB.batch([
    env.DB.prepare(
      `
      UPDATE users 
      SET password_hash = ?, token_version = token_version + 1 
      WHERE user_id = ?
    `
    ).bind(hash, user.user_id),
    env.DB.prepare("DELETE FROM verification_codes WHERE id = ?").bind(activeCode.id)
  ]);

  return Response.json({ success: true, message: "Password reset successful" });
}

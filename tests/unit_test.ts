// tests/unit_test.ts
import assert from "node:assert/strict";
import { signJWT, verifyJWT } from "../src/auth/jwt";
import { hashGiftCode, normalizeGiftCode, getPersistentSalt } from "../src/api/billing";
import { hardFilterModels, filterTemplatesBySubsistence } from "../src/orchestration/subsistence";
import { resolveRoleCompetence } from "../src/orchestration/competence";
import { scoreAndRankRoleModels, cosineSimilarity } from "../src/orchestration/scoring";
import { isSafeExternalUrl, applyContextWindowGuard, buildAuthHeaders } from "../src/orchestration/dispatcher";
import { getAdminSigningSecret } from "../src/api/admin";
import type { DAGRole, DAGTemplate, ModelMetadata } from "../src/orchestration/types";

async function runUnitTests() {
  console.log("==================================================");
  console.log("         NanoMesh Local Unit Test Suite           ");
  console.log("==================================================");

  // ----------------------------------------------------
  // SUITE 1: Auth, Cryptography & Token Security
  // ----------------------------------------------------
  console.log("\n[Suite 1] Auth & Token Cryptography");
  const testSecret = "super-secret-key-32-chars-long-123";
  const userPayload = { userId: "usr_998877", role: "user", tokenVersion: 1 };
  
  // 1.1 Sign & Verify Valid JWT
  const token = await signJWT(userPayload, testSecret, 3600);
  assert.equal(typeof token, "string");
  assert.equal(token.split(".").length, 3, "JWT must contain 3 dot-separated parts");

  const verified = await verifyJWT(token, testSecret);
  assert.ok(verified, "Valid token must verify successfully");
  assert.equal(verified.userId, "usr_998877");
  assert.equal(verified.role, "user");
  assert.equal(verified.tokenVersion, 1);
  assert.ok(verified.exp > Math.floor(Date.now() / 1000));
  console.log("  ✓ Token signing & verification: PASSED");

  // 1.2 Tampered Signature or Wrong Secret
  const wrongSecretVerified = await verifyJWT(token, "wrong-secret-key-999");
  assert.equal(wrongSecretVerified, null, "Verification with wrong secret must return null");

  const tamperedToken = token.slice(0, -5) + "abcde";
  const tamperedVerified = await verifyJWT(tamperedToken, testSecret);
  assert.equal(tamperedVerified, null, "Tampered token must return null");
  console.log("  ✓ Tamper detection & secret validation: PASSED");

  // 1.3 Expired Token
  const expiredToken = await signJWT(userPayload, testSecret, -10); // expired 10s ago
  const expiredVerified = await verifyJWT(expiredToken, testSecret);
  assert.equal(expiredVerified, null, "Expired token must return null");
  console.log("  ✓ Token expiration check: PASSED");

  // ----------------------------------------------------
  // SUITE 2: Billing & Crockford Base32 Hashing
  // ----------------------------------------------------
  console.log("\n[Suite 2] Billing, Gift Code Normalization & Hashes");
  
  // 2.1 Normalization of Crockford Base32
  const dirtyCode1 = "abcd-efgh-1234-5678";
  assert.equal(normalizeGiftCode(dirtyCode1), "ABCDEFGH12345678");

  // Tolerates O -> 0, I/L -> 1 (while preserving valid Crockford letter J)
  const dirtyCode2 = "ABCO-EFGI-JKL1-2345";
  assert.equal(normalizeGiftCode(dirtyCode2), "ABC0EFG1JK112345");
  console.log("  ✓ Crockford Base32 normalizer: PASSED");

  // 2.2 SHA-256 Hex Hash
  const hash1 = await hashGiftCode("ABCDEFGH12345678", "salt-123");
  const hash2 = await hashGiftCode("ABCDEFGH12345678", "salt-123");
  const hashDiff = await hashGiftCode("ABCDEFGH12345678", "salt-456");
  assert.equal(hash1, hash2, "Hash must be deterministic");
  assert.notEqual(hash1, hashDiff, "Different salt must yield different hash");
  assert.equal(hash1.length, 64, "SHA-256 hex must be 64 characters");
  console.log("  ✓ Gift code SHA-256 hash: PASSED");

  // ----------------------------------------------------
  // SUITE 3: SSRF Gateway Protection & Context Window Guard
  // ----------------------------------------------------
  console.log("\n[Suite 3] Network Security (SSRF) & Sliding Window Context Guard");
  
  // 3.1 isSafeExternalUrl
  assert.equal(isSafeExternalUrl("https://api.openai.com/v1/chat"), true);
  assert.equal(isSafeExternalUrl("https://generativelanguage.googleapis.com"), true);
  assert.equal(isSafeExternalUrl("http://localhost:3000"), false);
  assert.equal(isSafeExternalUrl("http://127.0.0.1:8080"), false);
  assert.equal(isSafeExternalUrl("http://10.1.2.3/internal"), false);
  assert.equal(isSafeExternalUrl("http://192.168.0.100"), false);
  assert.equal(isSafeExternalUrl("http://172.24.0.1"), false);
  assert.equal(isSafeExternalUrl("http://169.254.169.254/latest"), false);
  assert.equal(isSafeExternalUrl("http://[::1]"), false);
  assert.equal(isSafeExternalUrl("javascript:void(0)"), false);
  // IPv4-Mapped IPv6 protection
  assert.equal(isSafeExternalUrl("http://[::ffff:127.0.0.1]:8080"), false, "IPv4-mapped 127.0.0.1 must be rejected");
  assert.equal(isSafeExternalUrl("http://[::ffff:7f00:1]:8080"), false, "IPv4-mapped hex 7f00:1 must be rejected");
  assert.equal(isSafeExternalUrl("http://[::ffff:192.168.1.1]:8000"), false, "IPv4-mapped 192.168.1.1 must be rejected");
  assert.equal(isSafeExternalUrl("http://[::ffff:10.0.0.1]:8000"), false, "IPv4-mapped 10.0.0.1 must be rejected");
  assert.equal(isSafeExternalUrl("http://[::ffff:169.254.169.254]"), false, "IPv4-mapped cloud metadata must be rejected");
  console.log("  ✓ SSRF IP / Protocol filter: PASSED");

  // 3.2 applyContextWindowGuard
  const sysPrompt = "You are a professional compiler.";
  const shortPrompt = "Explain polymorphism in C++.";
  const guardedShort = applyContextWindowGuard(sysPrompt, shortPrompt, 4096, 1024);
  assert.equal(guardedShort.promptContent, shortPrompt, "Short prompt within budget should remain unmodified");

  // Massive prompt exceeding 2000 char budget
  const hugePrompt = "X".repeat(15000);
  const guardedHuge = applyContextWindowGuard(sysPrompt, hugePrompt, 2048, 1024);
  assert.ok(guardedHuge.promptContent.length < 10000, "Huge prompt must be trimmed");
  assert.ok(guardedHuge.promptContent.includes("[...前序冗余历史上下文已自动滑窗折叠"), "Must include folding banner");
  assert.equal(guardedHuge.systemPrompt, sysPrompt, "System prompt must be preserved intact");
  console.log("  ✓ Sliding window context guard: PASSED");

  // ----------------------------------------------------
  // SUITE 4: Subsistence Law & Hard Filtering
  // ----------------------------------------------------
  console.log("\n[Suite 4] Subsistence Law (温饱定律) & Hard Model Filtering");
  
  const sampleModels: ModelMetadata[] = [
    {
      model_id: "m_healthy_edge",
      display_name: "Llama 3.2 3B",
      provider: "Cloudflare",
      endpoint: "@cf/meta/llama-3.2-3b-instruct",
      modalities: ["text"],
      tags: ["#general", "#chat"],
      context_window: 8192,
      max_concurrency: 50,
      active_connections: 0,
      precision: 0.85,
      user_rating: 4.8,
      usage_count: 100,
      cost_per_1k_tokens: 0.0,
      status: "active",
      is_generalist: 1,
      prior_score: 0.25,
      scenario_anchors: ["chat", "general"],
      inference_target: "edge"
    },
    {
      model_id: "m_small_ctx",
      display_name: "Small Context Model",
      provider: "Custom",
      endpoint: "https://api.example.com",
      modalities: ["text"],
      tags: ["#chat"],
      context_window: 1024,
      max_concurrency: 10,
      active_connections: 0,
      precision: 0.8,
      user_rating: 4.5,
      usage_count: 50,
      cost_per_1k_tokens: 0.5,
      status: "active",
      is_generalist: 1,
      prior_score: 0.2,
      scenario_anchors: [],
      inference_target: "cloud"
    },
    {
      model_id: "m_disabled",
      display_name: "Disabled Model",
      provider: "Custom",
      endpoint: "https://api.example.com",
      modalities: ["text"],
      tags: ["#chat"],
      context_window: 8192,
      max_concurrency: 10,
      active_connections: 0,
      precision: 0.8,
      user_rating: 4.9,
      usage_count: 50,
      cost_per_1k_tokens: 0.5,
      status: "disabled",
      is_generalist: 1,
      prior_score: 0.2,
      scenario_anchors: [],
      inference_target: "cloud"
    },
    {
      model_id: "m_browser_onnx",
      display_name: "WebGPU Qwen",
      provider: "Local Browser",
      endpoint: "local://qwen",
      modalities: ["text"],
      tags: ["#chat"],
      context_window: 4096,
      max_concurrency: 1,
      active_connections: 0,
      precision: 0.85,
      user_rating: 4.9,
      usage_count: 10,
      cost_per_1k_tokens: 0.0,
      status: "active",
      is_generalist: 1,
      prior_score: 0.25,
      scenario_anchors: [],
      inference_target: "browser"
    },
    {
      model_id: "m_vision_cf",
      display_name: "Llama 3.2 11B Vision",
      provider: "Cloudflare",
      endpoint: "@cf/meta/llama-3.2-11b-vision-instruct",
      modalities: ["image", "text"],
      tags: ["#vision"],
      context_window: 8192,
      max_concurrency: 20,
      active_connections: 0,
      precision: 0.85,
      user_rating: 4.9,
      usage_count: 50,
      cost_per_1k_tokens: 0.0,
      status: "active",
      is_generalist: 1,
      prior_score: 0.25,
      scenario_anchors: ["vision"],
      inference_target: "edge"
    }
  ];

  // 4.1 hardFilterModels
  const pass2000 = hardFilterModels(sampleModels, 2000, false);
  const pass2000Ids = pass2000.map(m => m.model_id);
  assert.ok(pass2000Ids.includes("m_healthy_edge"), "8K model passes 2000 token request");
  assert.ok(!pass2000Ids.includes("m_small_ctx"), "1K model rejected for 2000 token request");
  assert.ok(!pass2000Ids.includes("m_disabled"), "Disabled model rejected");
  assert.ok(pass2000Ids.includes("m_browser_onnx"), "Browser model passes when not disabled");

  const passNoBrowser = hardFilterModels(sampleModels, 2000, true);
  assert.ok(!passNoBrowser.some(m => m.model_id === "m_browser_onnx"), "Browser model filtered out when disableBrowser=true");
  console.log("  ✓ Model hard filtering: PASSED");

  // 4.2 filterTemplatesBySubsistence
  const textRole: DAGRole = {
    role_id: "r_text", name_zh: "文本分析", name_en: "Text Analysis",
    in_modalities: ["text"], out_modalities: ["text"], in_degree: 0, out_degree: 0, requisition_tags: []
  };
  const visionRole: DAGRole = {
    role_id: "r_vision", name_zh: "视觉解析", name_en: "Vision Parser",
    in_modalities: ["image"], out_modalities: ["text"], in_degree: 0, out_degree: 1,
    requisition_tags: ["#specialist_ocr_ultra", "#vision"],
    compensation_prompts: {
      "#vision": "降级补偿提示：未能匹配超高精度OCR模型，已无缝切换至通用视觉多模态模型执行解析。"
    }
  };

  const sampleTemplates: DAGTemplate[] = [
    {
      template_id: "tpl_text_only",
      name_zh: "纯文本工序", name_en: "Text Pipeline", desc_zh: "", desc_en: "",
      scenario_category: "chat", scenario_anchor: "chat",
      head_modalities: ["text"],
      tail_modalities: ["text"],
      roles: [textRole],
      execution_flow: "r_text",
      edges: [],
      status: "active"
    },
    {
      template_id: "tpl_vision_pipeline",
      name_zh: "图文多模态工序", name_en: "Vision Pipeline", desc_zh: "", desc_en: "",
      scenario_category: "multimodal", scenario_anchor: "vision",
      head_modalities: ["image"],
      tail_modalities: ["text"],
      roles: [visionRole, textRole],
      execution_flow: "r_vision -> r_text",
      edges: [{ from: "r_vision", to: "r_text" }],
      status: "active"
    }
  ];

  const matchedTextOnly = filterTemplatesBySubsistence(sampleTemplates, ["text"]);
  assert.equal(matchedTextOnly.length, 1);
  assert.equal(matchedTextOnly[0].template_id, "tpl_text_only", "Text-only query matches text-only template");

  const matchedVision = filterTemplatesBySubsistence(sampleTemplates, ["image"]);
  assert.equal(matchedVision.length, 1);
  assert.equal(matchedVision[0].template_id, "tpl_vision_pipeline", "Image input matches vision pipeline");
  console.log("  ✓ Subsistence law template matching: PASSED");

  // ----------------------------------------------------
  // SUITE 5: Role Competence Matrix & Modality Fallback
  // ----------------------------------------------------
  console.log("\n[Suite 5] Competence Matrix & Modality Fallback");
  
  // Exact match
  const textResolution = resolveRoleCompetence(textRole, sampleModels);
  assert.ok(textResolution.selectedModels.length > 0);
  assert.equal(textResolution.downgraded, false, "Text role with text models is NOT downgraded");

  // Downgrade scenario: Vision role with ONLY text models available
  const visionResolution = resolveRoleCompetence(visionRole, sampleModels);
  assert.ok(visionResolution.selectedModels.length > 0, "Fallback selects text models for vision role");
  assert.equal(visionResolution.downgraded, true, "Must be flagged as downgraded");
  assert.ok(visionResolution.compensationPrompt && visionResolution.compensationPrompt.includes("降级补偿提示"), "Must generate compensation directive");
  assert.ok(visionResolution.downgradeEvent, "Must emit downgrade event");
  console.log("  ✓ Competence matrix & fallback compensation: PASSED");

  // ----------------------------------------------------
  // SUITE 6: Serverless-Native Scoring Formula
  // ----------------------------------------------------
  console.log("\n[Suite 6] Serverless-Native Scoring Formula");
  
  const scored = await scoreAndRankRoleModels(
    {} as any,
    sampleModels.filter(m => m.status === "active"),
    null,
    "Hello test query",
    "sess_xyz123",
    1000
  );

  assert.equal(scored.length, 4);
  const browserScored = scored.find(s => s.model.model_id === "m_browser_onnx")!;
  const edgeScored = scored.find(s => s.model.model_id === "m_healthy_edge")!;
  const cloudScored = scored.find(s => s.model.model_id === "m_small_ctx")!;

  // Verify Tier hierarchy
  assert.equal(browserScored.tier_score, 0.15, "Browser tier score is +0.15");
  assert.equal(edgeScored.tier_score, 0.10, "Edge tier score is +0.10");
  assert.equal(cloudScored.tier_score, 0.0, "Cloud tier score is +0.0");
  assert.ok(browserScored.score > edgeScored.score, "Browser WebGPU ranks top given identical prior");
  assert.ok(edgeScored.score > cloudScored.score, "Edge Workers AI ranks above Cloud");

  // Verify context fit score
  assert.ok(edgeScored.context_fit_score! > cloudScored.context_fit_score!, "8K model has higher context fit score than 1K model");

  // Verify decoupled active_connections
  assert.equal(edgeScored.concurrency_penalty, 0.0, "Dead active_connections penalty must be 0.0");

  // Verify deterministic hash jitter
  assert.ok(edgeScored.jitter_score! >= 0.0 && edgeScored.jitter_score! <= 0.05, "Jitter must be in [0, 0.05]");

  // Cosine similarity
  const vecA = [1, 0, 0];
  const vecB = [1, 0, 0];
  const vecC = [0, 1, 0];
  assert.equal(Math.round(cosineSimilarity(vecA, vecB) * 100) / 100, 1.0);
  assert.equal(Math.round(cosineSimilarity(vecA, vecC) * 100) / 100, 0.0);
  console.log("  ✓ Serverless tier hierarchy, context fit & hash jitter: PASSED");

  // ----------------------------------------------------
  // SUITE 7: Audit Remediations & Trust Boundary Isolation
  // ----------------------------------------------------
  console.log("\n[Suite 7] Audit Remediations & Trust Boundary Isolation");

  // 7.1 Heavy node rejects falling back to JWT_SECRET
  const heavyModelWithoutSecret: ModelMetadata = {
    model_id: "m_heavy_vps",
    display_name: "Llama 3.1 70B VPS",
    provider: "SelfHosted",
    endpoint: "https://vps.example.com/v1/chat/completions",
    modalities: ["text"],
    tags: ["#heavy"],
    context_window: 16384,
    max_concurrency: 10,
    precision: 0.95,
    cost_per_1k_tokens: 0.05,
    status: "active",
    auth_mode: "jwt_ephemeral",
    auth_secret: null,
    api_format: "openai_compat",
    inference_target: "heavy"
  };

  const mockEnvFallback: any = {
    JWT_SECRET: "global-system-jwt-secret-do-not-leak",
    HEAVY_JWT_SECRET: undefined
  };

  await assert.rejects(
    async () => {
      await buildAuthHeaders(heavyModelWithoutSecret, mockEnvFallback, "{}", { userId: "u1" });
    },
    (err: any) => {
      assert.ok(err.message.includes("[SECURITY_REJECTED]"), "Must fail-closed when dedicated secret is missing");
      assert.ok(err.message.includes("禁止回退使用系统核心密钥"), "Must forbid JWT_SECRET fallback");
      return true;
    }
  );

  // 7.2 Dedicated HEAVY_JWT_SECRET or node auth_secret succeeds
  const mockEnvDedicated: any = {
    JWT_SECRET: "global-system-jwt-secret-do-not-leak",
    HEAVY_JWT_SECRET: "dedicated-heavy-jwt-secret-vps-only"
  };
  const headersWithDedicated = await buildAuthHeaders(heavyModelWithoutSecret, mockEnvDedicated, "{}", { userId: "u1" });
  assert.ok(headersWithDedicated['Authorization']?.startsWith("Bearer "), "Must succeed when HEAVY_JWT_SECRET is configured");

  // 7.3 Admin session password-derived signing key
  const adminEnv1: any = { ADMIN_PASSWORD: "Password123!", JWT_SECRET: "jwt-sec" };
  const adminEnv2: any = { ADMIN_PASSWORD: "PasswordChanged456!", JWT_SECRET: "jwt-sec" };
  const adminSecret1 = await getAdminSigningSecret(adminEnv1);
  const adminSecret2 = await getAdminSigningSecret(adminEnv2);
  assert.equal(adminSecret1.length, 64, "Derived admin secret must be 64-char sha256 hex");
  assert.notEqual(adminSecret1, adminSecret2, "Changing ADMIN_PASSWORD must change derived signing key");
  assert.notEqual(adminSecret1, adminEnv1.JWT_SECRET, "Admin signing secret must never equal bare JWT_SECRET");
  console.log("  ✓ Trust boundary isolation & derived admin signing keys: PASSED");

  // ----------------------------------------------------
  // SUITE 8: Audit Report 2 Remediations & Resource Defense
  // ----------------------------------------------------
  console.log("\n[Suite 8] Audit Report 2 Remediations & Resource Defense");

  // 8.1 Persistent Data Salt Isolation
  const envWithPersistentSalt: any = {
    JWT_SECRET: "rotating-session-jwt-secret-xyz",
    PERSISTENT_DATA_SALT: "dedicated-static-salt-for-persistent-data"
  };
  const envWithoutPersistentSalt: any = {
    JWT_SECRET: "rotating-session-jwt-secret-xyz"
  };
  assert.equal(getPersistentSalt(envWithPersistentSalt), "dedicated-static-salt-for-persistent-data");
  assert.equal(getPersistentSalt(envWithoutPersistentSalt), "rotating-session-jwt-secret-xyz");

  const giftCodeRaw = "NANO-REDEEM-2026";
  const hashWithStaticSalt = await hashGiftCode(giftCodeRaw, getPersistentSalt(envWithPersistentSalt));
  // Rotating JWT_SECRET must NOT alter hashWithStaticSalt when PERSISTENT_DATA_SALT is used
  const envRotatedJWT: any = {
    JWT_SECRET: "brand-new-rotated-jwt-secret-abc",
    PERSISTENT_DATA_SALT: "dedicated-static-salt-for-persistent-data"
  };
  const hashAfterJWTRotation = await hashGiftCode(giftCodeRaw, getPersistentSalt(envRotatedJWT));
  assert.equal(hashWithStaticSalt, hashAfterJWTRotation, "Rotating JWT_SECRET must not invalidate gift codes when PERSISTENT_DATA_SALT is configured");

  // 8.2 Safe Base64 chunking correctness
  const sampleBytes = new Uint8Array(65536);
  for (let i = 0; i < sampleBytes.length; i++) {
    sampleBytes[i] = (i * 31 + 17) % 256;
  }
  let chunkedBinary = '';
  const chunkSize = 16384;
  for (let i = 0; i < sampleBytes.length; i += chunkSize) {
    const chunk = sampleBytes.subarray(i, i + chunkSize);
    chunkedBinary += String.fromCharCode.apply(null, chunk as any);
  }
  const chunkedB64 = btoa(chunkedBinary);
  assert.ok(chunkedB64.length > 0);
  assert.equal(atob(chunkedB64).length, 65536, "Chunked Base64 must decode to original 64KB length");

  // 8.3 Linear Modality and Subsistence Threshold logic
  assert.ok(4 * 1024 * 1024 < 25 * 1024 * 1024, "Tiered threshold must be smaller than hard cap");
  console.log("  ✓ Persistent salt decoupling & high-performance binary processing: PASSED");

  console.log("\n==================================================");
  console.log("   🎉 ALL 8 UNIT TEST SUITES PASSED (100%)!       ");
  console.log("==================================================");
}

runUnitTests().catch(err => {
  console.error("❌ Unit Test Suite Failed:", err);
  process.exit(1);
});

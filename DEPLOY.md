# 🚀 NanoMesh Open-Source Self-Hosting Deployment Guide

> **NanoMesh** is a lightweight, tri-tier distributed model arbitration and streaming orchestration engine built on Cloudflare edge computing (Workers + D1 + R2 + Workers AI) and client-side browser computing (WebGPU).
>
> This project is designed as an **independent dispatch and execution orchestrator** rather than a centralized cloud monolith. Developers and teams can fork this repository to deploy their own private AI orchestration hub with near-zero infrastructure overhead.

---

## Table of Contents
- [1. Architecture & Ecosystem Positioning](#1-architecture--ecosystem-positioning)
- [2. 15-Minute Rapid Edge Deployment](#2-15-minute-rapid-edge-deployment)
- [3. Tri-Tier Compute Node Self-Hosting Manual](#3-tri-tier-compute-node-self-hosting-manual)
  - [3.1 Light Node (Browser WebGPU)](#31-light-node-browser-webgpu)
  - [3.2 Medium Node (Workers AI Edge)](#32-medium-node-workers-ai-edge)
  - [3.3 Heavy Node (Self-Hosted VPS / Commercial API)](#33-heavy-node-self-hosted-vps--commercial-api)
- [4. Admin Console & Linear Pipeline Orchestration](#4-admin-console--linear-pipeline-orchestration)
- [5. Local Development & Automated Test Suites](#5-local-development--automated-test-suites)

---

## 1. Architecture & Ecosystem Positioning

### 1.1 Why a Dispatch Hub Instead of a Centralized Monolith?
Traditional centralized LLM aggregation platforms face three major engineering challenges:
1. **Heavy Infrastructure Costs**: High GPU server rental fees and continuous egress bandwidth consumption.
2. **Edge Stateless Write Lock Contention**: Centralized relational databases maintaining real-time concurrent sessions suffer cross-region network round-trip time (RTT) penalties and row-level lock contention.
3. **Deep Coupling of Regulatory and Compliance Liability**: Hosting multi-tenant uploaded models and user content introduces severe abuse handling and compliance overhead.

### 1.2 NanoMesh's Decentralized Solution (Tailscale-Style Distributed Topology)
NanoMesh uses a **tri-tier compute topology** combined with a **stateless traffic shaping system**:
- **Light Node (Client-Side)**: Small-parameter models (e.g., SmolLM2-135M, Qwen2.5-0.5B) are dispatched directly to the user's browser. Inference runs locally using WebGPU hardware acceleration with **zero server compute cost and zero API bills**.
- **Medium Node (Edge)**: Connects directly to native Workers AI serverless compute across Cloudflare's global edge network (300+ PoPs) for ultra-low latency text analysis, dense semantic embedding (`bge-m3`), and lightweight vision parsing.
- **Heavy Node (External)**: Decouples compute-heavy reasoning (e.g., DeepSeek-R1, Llama-3.3-70B, Gemini-1.5-Pro) behind standardized protocol adapters. You can attach private GPU workstations or connect commercial API keys.
- **Fully Autonomous Self-Hosting**: When you fork this repository, you operate as the root administrator (`/admin`) of your own cluster without dependency on third-party backend relays.

---

## 2. 15-Minute Rapid Edge Deployment

### Prerequisites
- [Node.js 22.12.0 or higher (Node.js 22 LTS recommended)](https://nodejs.org/)
- [Cloudflare Account (Free Tier supported)](https://dash.cloudflare.com/)
- Cloudflare Wrangler CLI installed locally:
  ```bash
  npm install -g wrangler
  wrangler login
  ```

---

### Step 1: Clone Repository and Install Dependencies
```bash
git clone https://github.com/AndrewWangDev/NanoMesh.git
cd NanoMesh/NanoMesh-Frontend
npm install
```

---

### Step 2: Provision Cloudflare Edge Infrastructure
Run the following commands to provision a D1 SQLite database and an R2 object storage bucket:

```bash
# 1. Create the D1 database (recommended name: nanomesh-db)
wrangler d1 create nanomesh-db

# Record the output database_id from your terminal:
# [[d1_databases]]
# binding = "DB"
# database_name = "nanomesh-db"
# database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# 2. Create the R2 asset bucket (recommended name: nanomesh-assets)
wrangler r2 bucket create nanomesh-assets
```

---

### Step 3: Configure `wrangler.toml`
Copy the sample configuration file and populate your actual IDs:

```bash
cp wrangler.toml.example wrangler.toml
```

Edit `wrangler.toml`:
```toml
name = "nanomesh-frontend"
main = "src/index.ts"
compatibility_date = "2024-09-23"
compatibility_flags = ["nodejs_compat"]

[assets]
directory = "./public"
binding = "ASSETS"

[ai]
binding = "AI"

[[d1_databases]]
binding = "DB"
database_name = "nanomesh-db"
database_id = "YOUR_DATABASE_ID_HERE"  # <-- Replace with your actual database_id

[[r2_buckets]]
binding = "R2"
bucket_name = "nanomesh-assets"

[vars]
ENVIRONMENT = "production"                                # Deployment environment flag (strictly enforces dedicated salt)
TURNSTILE_SITE_KEY = "YOUR_CLOUDFLARE_TURNSTILE_SITE_KEY"  # Bot protection site key
RESEND_FROM_EMAIL = "noreply@yourdomain.com"              # Verification email sender address
FRONTEND_URL = "https://nano.yourdomain.com"              # Fully qualified domain name of your frontend
```

---

### Step 4: Apply Database Migrations
Synchronize the schema and built-in roles and templates to the remote D1 database:

```bash
npx wrangler d1 migrations apply nanomesh-db --remote
```
*(Press `y` when prompted. The system will apply all migration scripts sequentially from `0001` through `0023`.)*

---

### Step 5: Configure Production Secrets
Inject sensitive keys securely via the Wrangler CLI (never commit plaintext secrets to Git):

```bash
# Strong password for the /admin dashboard (Required)
wrangler secret put ADMIN_PASSWORD

# JWT signing secret for user authentication and sessions (>= 32 random characters, Required)
wrangler secret put JWT_SECRET

# Dedicated signing key for external Heavy node (VPS) communications (Required for private VPS nodes; never reuse JWT_SECRET)
wrangler secret put HEAVY_JWT_SECRET

# Cloudflare Turnstile secret key (Required)
wrangler secret put TURNSTILE_SECRET_KEY

# Resend API key for outbound verification emails (Required)
wrangler secret put RESEND_API_KEY

# Cloudflare Account ID and R2 S3 API credentials for asset uploads (Required)
# (Note: Supports both Cloudflare_Account_ID and uppercase CLOUDFLARE_ACCOUNT_ID)
wrangler secret put Cloudflare_Account_ID
wrangler secret put R2_ACCESS_KEY_ID
wrangler secret put R2_SECRET_ACCESS_KEY

# Dedicated persistent data salt for gift card and tombstone hashes (>= 32 random characters, Required in production)
# (Important: Never reuse JWT_SECRET. An independent salt ensures that routine JWT key rotations do not invalidate stored gift cards or account deletion cooldowns)
wrangler secret put PERSISTENT_DATA_SALT
```

---

### Step 6: Build and Deploy
```bash
npm run deploy
```
Upon successful deployment, Wrangler will output your live Worker URL (e.g., `https://nanomesh-frontend.your-username.workers.dev`).

---

### Step 7: (Recommended) Configure Cloudflare WAF Rate Limiting
NanoMesh implements a layered defense model: inside the Worker, L1 zero-latency sliding-window limiters debounce bursts while atomic D1 ledger transactions prevent economic overdrafts. For cross-region DDoS mitigation, configure WAF rules in the Cloudflare Dashboard:
- **Target Paths**: `/api/chat*` and `/api/auth/*`
- **Rate Limit**: Maximum 20 requests per 10 seconds per IP, triggering a Managed Challenge or block when exceeded.

---

## 3. Tri-Tier Compute Node Self-Hosting Manual

Navigate to `/admin` on your deployed site and sign in with the `ADMIN_PASSWORD` configured in Step 5 to access the centralized node registry.

### 3.1 Light Node (Browser WebGPU)
- **Mechanism**: Model weights are stored in R2. The frontend fetches them via HTTP ranges and executes inference on the user's local GPU using WebGPU, incurring zero server compute costs.
- **Configuration Steps**:
  1. Open the Admin Console and click **Deploy New Compute Node**.
  2. **Tier Target**: Select `Browser WebGPU / WASM`.
  3. **Model Identifier**: Enter an identifier such as `browser-qwen-0.5b`.
  4. **Weight Distribution**: Upload your ONNX model files to R2 (stored under `models/light/` with immutable public cache headers).
  5. Click **Save** to activate the node in the client-side execution pool.

---

### 3.2 Medium Node (Workers AI Edge)
- **Mechanism**: Zero-maintenance serverless inference hosted across Cloudflare's global edge network.
- **Configuration Steps**:
  1. Click **Deploy New Compute Node**.
  2. **Tier Target**: Select `Cloudflare Edge (Workers AI)`.
  3. **Protocol Adapter**: Select `Workers AI Native (@cf/...)`.
  4. **Endpoint Identifier**: Enter the full Cloudflare model name:
     - Text generation: `@cf/meta/llama-3.2-3b-instruct`
     - Vision understanding: `@cf/meta/llama-3.2-11b-vision-instruct`
     - Dense text embeddings: `@cf/baai/bge-m3`
  5. **Authentication**: Select `None (Binding Invocation)`.
  6. Click **Save** to activate edge routing.

---

### 3.3 Heavy Node (Self-Hosted VPS / Commercial API)
NanoMesh abstracts heavy compute behind standardized protocol adapters, supporting both commercial API gateways and private self-hosted GPU clusters.

#### Pattern A: Commercial Model APIs (e.g., Google AI Studio, DeepSeek)
1. **Protocol Adapter**:
   - For Google Gemini: Select `Google AI Studio (Gemini REST)` with endpoint `https://generativelanguage.googleapis.com/v1beta`.
   - For DeepSeek / OpenAI-compatible APIs: Select `OpenAI Compatible Protocol (/v1/chat/completions)` with your provider's endpoint URL.
2. **Authentication Type**: Select `Static Bearer Token (API Key)`.
3. **Credentials**: Enter your API key (the UI automatically masks this as `••••••••` to prevent accidental credential leakage).
4. Save the configuration to register the node as an execution target.

#### Pattern B: Private VPS / Dedicated GPU Server
If you operate an on-premises GPU workstation or cloud instance (running vLLM, Ollama, or FastAPI):
1. **Protocol Adapter**: Select `OpenAI Compatible Protocol`.
2. **Endpoint URL**: Enter your server's public FQDN (e.g., `https://gpu.yourdomain.com/v1/chat/completions`).  
   *(Note: The built-in SSRF firewall strictly rejects loopback, RFC1918 private IPs, and cloud metadata endpoints).*
3. **Authentication Type**: Select `Dynamic Ephemeral JWT (jwt_ephemeral)`.
4. **Credentials**: Enter the node-specific communication secret (or use the global `HEAVY_JWT_SECRET`).
5. **Security Protocol**: When dispatching requests to your VPS, NanoMesh computes a SHA-256 digest of the request payload and signs a short-lived (60-second validity) tamper-proof JWT passed in the `Authorization: Bearer <token>` header. Your VPS verifies this token against the shared secret to guarantee request authenticity (internal `JWT_SECRET` keys are strictly prohibited from external dispatch).

---

## 4. Admin Console & Linear Pipeline Orchestration

Access the `/admin` console to manage the **Competence Matrix and Pipeline Splicer**:

### 4.1 Competence Matrix Diagnostics
The system computes the Cartesian intersection between registered DAG roles (e.g., Intent Extraction, Multimodal Vision Parsing, Polish) and the active compute pool:
- **🟢 Healthy**: 2 or more competent models available for the role (supports zero-latency automatic failover).
- **🟡 Warning**: Exactly 1 competent model available (single point of failure).
- **🔴 Critical Orphaned**: No active models satisfy the role's input/output modalities or operational tags.

### 4.2 Linear Pipeline Splicer
Administrators can compose custom multi-stage DAG pipelines with three built-in validation gates:
- **Gate 1 (Modality Continuity Check)**: Verifies that adjacent stages have matching modality intersections (e.g., prevents an `audio` output from being fed directly to an `image` input without transcoding).
- **Gate 2 (Active Model Availability Check)**: Verifies that every role in the pipeline has at least one active, healthy model registered.
- **Gate 3 (Closed-Loop Topology & Priority Assignment)**: Calculates pipeline head/tail modalities and registers the verified template for dynamic user routing.

---

## 5. Local Development & Automated Test Suites

Run the local automated test suite before opening pull requests or deploying changes:

```bash
# Run all 19 unit test suites and 18 mock-backed integration scenarios
npm test

# Run TypeScript static type check (source and test suites)
npm run typecheck
npm run typecheck:test

# Check code formatting and static lint rules
npm run format:check
npm run lint

# Start local Miniflare edge simulation server
npm run dev
```

> [!NOTE]
> **Mock-Backed Integration Testing Boundary**:
> The integration test suite (`tests/integration_test.ts`) executes in-memory against a high-fidelity Cloudflare Worker execution harness (mocked D1 SQLite database, mocked R2 bucket storage, and simulated fetch transport). It comprehensively validates SQL migration schema integrity, multi-controller state machines, SSE event streaming, token bucket rate limits, and defensive fallbacks without incurring live cloud billing or external network jitter.

### Test Suite Coverage Matrix
- **Unit Test Suite (`tests/unit_test.ts` - 19 Suites)**:
  - `[Suite 1]` Auth & Token Cryptography: JWT signing, verification, tampering defense, and expiration checks.
  - `[Suite 2]` Billing & Crockford Base32 Hashes: Character set normalization and SHA-256 gift card hashing.
  - `[Suite 3]` Network Security (SSRF) & Context Guard: Loopback, RFC1918, metadata IP filtering, and 4K sliding window compaction.
  - `[Suite 4]` Subsistence Law & Hard Model Filtering: Cumulative supply and no-orphan asset constraints.
  - `[Suite 5]` Competence Matrix & Modality Fallback: Bidirectional modality matching and compensation prompt injection.
  - `[Suite 6]` Serverless-Native Scoring Formula: Context fit, tier preference weights, and session hash jitter.
  - `[Suite 7]` Trust Boundary Isolation: Derived administrative signing keys and separation of privilege.
  - `[Suite 8]` Resource Defense & Persistent Salt Decoupling: Dedicated hash salting and binary stream handling.
  - `[Suite 9]` Arbitrary WebGPU Topology & Compaction: Attention-Sink linear compaction and blast-radius prompt formatting.
  - `[Suite 10]` Pipeline State & Downstream Document Propagation: Datetime normalization, continuation token locking, and cognitive document passthrough.
  - `[Suite 11]` Multimodal Orchestration & Targeted Claiming: Upstream media priority and user asset penetration rules.
  - `[Suite 12]` Cognitive Document Claiming & SSRF Defense: Unconsumed document propagation and external URL safety.
  - `[Suite 13]` Passkey Verification & Namespace Isolation: WebAuthn RS256/ES256 attestation and strict origin checks.
  - `[Suite 14]` Context Compaction Surrogate Healing & Session Sanitization: UTF-16 surrogate pair preservation and session path security.
  - `[Suite 15]` OAuth CSRF Defense & Provider Auth Headers: State user binding, static API key headers, and CSV formula neutralization.
  - `[Suite 16]` Turnstile Verification & Path Traversal Guards: Remote IP forwarding and asset key traversal sanitization.
  - `[Suite 17]` Multi-Modality Validation & Session Bounds: Role modality arrays, envelope serialization, and referral filtering.
  - `[Suite 18]` Safe JSON Handling & Environment Guards: Null/primitive JSON safety, 512KB payload limits, RFC 4180 CSV parsing, and production salt enforcement.
  - `[Suite 19]` Orchestration Defect Remediation & Defense-in-Depth Hardening: Template re-routing identifier normalization, defensive optional metadata handling, assets manifest array safety, /api/health configuration probe, and case-insensitive email constraints.

- **Integration Test Suite (`tests/integration_test.ts` - 18 Scenarios)**:
  - `[Scenario 1]` User Registration, Referral & Atomic Batch Ledger: Referral bonuses, balance ledger transactions, and input validation.
  - `[Scenario 2]` R2 Asset Management & Access Control Isolation: Public model distribution vs. private multi-tenant asset isolation.
  - `[Scenario 3]` Admin Node Registry, SSRF Guard & Secret Masking: Node registration, SSRF filtering, and credential masking.
  - `[Scenario 4]` Linear Pipeline Splicer & Validation Gates: Modality continuity, active model checks, and pipeline compilation.
  - `[Scenario 5]` End-to-End Chat Orchestration & Atomic Billing Settlement: SSE event streaming, heartbeat pinging, and atomic credit debiting.
  - `[Scenario 6]` Premature Stream Cancellation & Refund Handshake: Client disconnection detection and pre-billed credit refunds.
  - `[Scenario 7]` Account Deletion & GDPR Private Session Erasure: Cascading session erasure, asset removal, and tombstone insertion.
  - `[Scenario 8]` Distributed Topology & Stream Protocol Verification: Password rotation revocation and safe OAuth unbinding.
  - `[Scenario 9]` Arbitrary WebGPU Topology, Handshake CAS & Dynamic Billing: Multi-stage browser execution, CAS anti-replay, and credit settlement.
  - `[Scenario 10]` Multimodal Orchestration, ASR & Targeted Claiming: Audio transcription, image generation, and zero-byte fallback recovery.
  - `[Scenario 11]` Credit Bounds & Handshake Two-Phase Commitment: Zero-credit fallback blocking and non-destructive continuation retries.
  - `[Scenario 12]` Dynamic Node Failover, Budget Protection & Redirect Interception: Symmetrical cloud-to-browser failover and 302 redirect interception.
  - `[Scenario 13]` Rate Limiting, Modality Bounds & Continuation Guards: Node modality persistence, chat payload guards, and IP rate limiting.
  - `[Scenario 14]` Session Security, Deduplication & Atomic Key Lifecycle: CSRF binding defense, low-balance alerts, and challenge replay guards.
  - `[Scenario 15]` CORS Enforcement, Method Validation & Path Isolation: Read-only endpoint method enforcement and path traversal interception.
  - `[Scenario 16]` Referral Integrity, Admin Anti-DoS & CSRF Protection: Deleted account referrer filtering, admin login anti-DoS, and logout CSRF guards.
  - `[Scenario 17]` Payload Boundaries, Password Recovery & Storage Lifecycle: 512KB payload enforcement, deadlock-free password recovery, and avatar storage cleanup.
  - `[Scenario 18]` Template Re-Routing, Defensive Invariants & Health Diagnostics: Stream initiation without metadata or assets_manifest, /api/health probe readiness, tpl-direct-chat media pruning, and email NOCASE enforcement.

---

> **Epilogue**: The architectural goal of NanoMesh is to **put operational control back into the hands of developers**. Whether for individual study, academic showcases, technical portfolio demonstrations, or internal multi-model dispatching in small teams, NanoMesh delivers enterprise-grade reliability and extensibility with minimal operational overhead.

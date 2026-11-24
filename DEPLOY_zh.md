# 🚀 NanoMesh (灵微络) 开源自托管部署指南

> **NanoMesh** 是一个基于 Cloudflare 边缘计算（Workers + D1 + R2 + Workers AI）与浏览器端侧计算（WebGPU）构建的**轻·中·重多能级分布式模型仲裁与流式调度引擎**。
>
> 本项目定位为**“人人皆可独立部署的调度与执行中枢”**，而非承担庞大集中式流量的中心化云服务。开发者或团队 Fork 本仓库后，可以零成本或极低成本快速拉起专属的私有 AI 编排平台。

---

## 目录
- [一、 架构设计与生态定位](#一-架构设计与生态定位)
- [二、 15 分钟极速边缘部署](#二-15-分钟极速边缘部署)
- [三、 三级算力节点自托管实战手册](#三-三级算力节点自托管实战手册)
  - [1. 轻节点 (Light Node - Browser WebGPU)](#1-轻节点-light-node---browser-webgpu)
  - [2. 中节点 (Medium Node - Workers AI Edge)](#2-中节点-medium-node---workers-ai-edge)
  - [3. 重节点 (Heavy Node - 自备 VPS / 商业 API)](#3-重节点-heavy-node---自备-vps--商业-api)
- [四、 管理员后台与线性工作流编排](#四-管理员后台与线性工作流编排)
- [五、 本地开发与全量测试套件](#五-本地开发与全量测试套件)

---

## 一、 架构设计与生态定位

### 1. 为什么是“调度中枢”而非“中心化平台”？
传统的中心化大模型服务（如各类聚合 API 平台）面临三大困境：
1. **沉重的自建算力成本**：高昂的 GPU 服务器租金（每月数十至数百美元）与网络带宽；
2. **边缘无状态并发写锁冲突**：中心化数据库在维护实时并发连接时，易产生大量跨区网络往返时延（RTT）与锁争用；
3. **平台与用户利益绑定过深**：一旦开放用户上传模型与审核，需要承担安全合规审查与滥用风险。

### 2. NanoMesh 的去中心化解决方案 (Tailscale-style Distributed Architecture)
NanoMesh 采用 **轻·中·重分级算力拓扑** 与 **无状态流量塑形体系**：
- **轻节点（端侧）**：把小参数模型（如 SmolLM2-135M, Qwen2.5-0.5B）直接下发给用户浏览器，利用客户端 WebGPU 硬件加速完成端侧推理，**0 服务器成本，0 算力费用**；
- **中节点（边缘）**：直接接入 Cloudflare 全球 300+ 机房的 Workers AI 原生算力，就近就地完成文本分析、嵌入向量生成（`bge-m3`）与通用多模态理解；
- **重节点（外部）**：将重度推理（如 DeepSeek-R1、Llama-3.3-70B、Gemini-1.5-Pro）解耦为标准化协议接口。你可以接入自己闲置的 VPS / GPU 算力，也可直接填入 Google AI Studio 或 OpenAI 兼容 API Key。
- **Fork 实例完全自主管理**：Fork 仓库后，你就是自己集群的管理员（`/admin`），无需依赖任何第三方中继后端，成本完全可控。

---

## 二、 15 分钟极速边缘部署

### 前置环境准备
- [Node.js 22.12.0 或更高版本 (推荐 Node.js 22 LTS)](https://nodejs.org/)
- [Cloudflare 免费账户](https://dash.cloudflare.com/)
- 本地安装 Cloudflare CLI 工具 Wrangler：
  ```bash
  npm install -g wrangler
  wrangler login
  ```

---

### Step 1: 克隆仓库与安装依赖
```bash
git clone https://github.com/AndrewWangDev/NanoMesh.git
cd NanoMesh/NanoMesh-Frontend
npm install
```

---

### Step 2: 创建 Cloudflare 边缘基础设施资源
在终端中依次创建 D1 边缘数据库与 R2 对象存储存储桶：

```bash
# 1. 创建 D1 数据库 (名称推荐: nanomesh-db)
wrangler d1 create nanomesh-db

# 终端将输出类似如下信息，请记录下 database_id：
# [[d1_databases]]
# binding = "DB"
# database_name = "nanomesh-db"
# database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# 2. 创建 R2 资产存储桶 (名称推荐: nanomesh-assets)
wrangler r2 bucket create nanomesh-assets
```

---

### Step 3: 配置 `wrangler.toml`
复制示例配置文件并填入真实 ID：

```bash
cp wrangler.toml.example wrangler.toml
```

编辑 `wrangler.toml`：
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
database_id = "填入你刚刚生成的 database_id"  # <-- 替换此处

[[r2_buckets]]
binding = "R2"
bucket_name = "nanomesh-assets"

[vars]
ENVIRONMENT = "production"                                # 运行环境标识 (生产环境下强制要求独立持久化盐)
TURNSTILE_SITE_KEY = "你的_Cloudflare_Turnstile_Site_Key"  # 用于防刷人机验证
RESEND_FROM_EMAIL = "noreply@yourdomain.com"              # 验证码发信邮箱
FRONTEND_URL = "https://nano.yourdomain.com"              # 你的前端访问完整域名
```

---

### Step 4: 执行全量数据库迁移
将项目数据架构与内置独立岗位、流水线同步到远程 D1 数据库：

```bash
npx wrangler d1 migrations apply nanomesh-db --remote
```
*(确认提示按 `y` 即可，系统将自动依次执行 `0001` 到 `0023` 的全部结构与种子数据迁移)*

---

### Step 5: 设置生产环境机密密钥 (Secrets)
通过 Wrangler CLI 向 Cloudflare 安全注入密钥（绝不要将密码提交到 Git）：

```bash
# 管理员控制台登录强密码 (必填)
wrangler secret put ADMIN_PASSWORD

# 用户身份认证与会话签发 JWT 密钥 (至少 32 字符随机串, 必填)
wrangler secret put JWT_SECRET

# 外部重节点 (VPS) 动态通信签名专用密钥 (自建 VPS 算力集群时必填，切勿与 JWT_SECRET 复用)
wrangler secret put HEAVY_JWT_SECRET

# Cloudflare Turnstile 密钥 (必填)
wrangler secret put TURNSTILE_SECRET_KEY

# Resend 邮件服务 API Key (用于发送邮箱注册验证码, 必填)
wrangler secret put RESEND_API_KEY

# Cloudflare 账户与 R2 S3 鉴权凭证 (用于轻节点模型上传与多模态素材传输, 必填)
# (注：系统已支持 Cloudflare_Account_ID 与全大写 CLOUDFLARE_ACCOUNT_ID 双向容错兼容)
wrangler secret put Cloudflare_Account_ID
wrangler secret put R2_ACCESS_KEY_ID
wrangler secret put R2_SECRET_ACCESS_KEY

# 敏感数据持久化专用盐值 (用于礼品卡哈希与账号注销墓碑哈希派生，至少 32 字符随机串, 生产环境必填)
# (重要：切勿与 JWT_SECRET 复用！独立盐值可确保日常轮转 JWT 密钥时，已存礼品卡和注销冷静期哈希永久有效)
wrangler secret put PERSISTENT_DATA_SALT
```

---

### Step 6: 构建与一键部署
```bash
npm run deploy
```
部署成功后，控制台将输出你的 Worker 线上访问地址（例如 `https://nanomesh-frontend.your-username.workers.dev`）。

---

### Step 7: (推荐) 配置 Cloudflare WAF 全网全局频控 (Rate Limiting)
NanoMesh 采用分层防御模型：Worker 内部运行 L1 零延迟防抖限流，并通过 D1 数据库执行原子扣费保障经济安全。针对全网跨机房的恶意调用与 DDoS 缓解，推荐在 Cloudflare Dashboard 中开启 WAF 规则：
- **入口路径**：`/api/chat*` 及 `/api/auth/*`
- **限频规则**：限制同一 IP 每 10 秒不超过 20 次请求，超出时执行 Cloudflare 托管质询（Managed Challenge）或拦截。

---

## 三、 三级算力节点自托管实战手册

登录你的 NanoMesh 站点，访问 `/admin`（输入你在 Step 5 配置的 `ADMIN_PASSWORD`），进入统一节点治理面板。

### 1. 轻节点 (Light Node - Browser WebGPU)
- **原理**：权重存储于 R2，前端通过 WebGPU 在用户本地 GPU 直接运行，服务器零开销。
- **配置步骤**：
  1. 在管理员面板选择 **“部署新算力节点”**；
  2. **能级目标**：选择 `端侧浏览器 (WebGPU/WASM)`；
  3. **模型标识**：填写如 `browser-qwen-0.5b`；
  4. **权重分发**：点击“上传模型权重”，将你的 ONNX 模型文件上传到 R2（系统会自动存放在 `models/light/` 并生成带强缓存的免鉴权公开下载链接）；
  5. 点击保存，系统即刻在端侧可用模型列表中激活该节点。

---

### 2. 中节点 (Medium Node - Workers AI Edge)
- **原理**：零维护成本，直接调用 Cloudflare 边缘计算原生托管的 AI 模型。
- **配置步骤**：
  1. 点击 **“部署新算力节点”**；
  2. **能级目标**：选择 `Cloudflare 边缘就近 (Workers AI)`；
  3. **接口协议格式**：选择 `Workers AI 原生 (@cf/...)`；
  4. **终端调用地址**：直接填入 Cloudflare 模型全称，常用推荐：
     - 文本对话：`@cf/meta/llama-3.2-3b-instruct`
     - 视觉理解：`@cf/meta/llama-3.2-11b-vision-instruct`
     - 密集检索嵌入：`@cf/baai/bge-m3`
  5. **鉴权方式**：选择 `无鉴权 (直接调用绑定)`；
  6. 保存后即刻完成边缘就近调度配置。

---

### 3. 重节点 (Heavy Node - 自备 VPS / 商业 API)
NanoMesh 统一抽象了标准化协议接口，支持自建算力与第三方商用 API 两种形态：

#### 形态 A：接入商业大模型 API（如 Google AI Studio / DeepSeek）
1. **接口协议格式**：
   - 若使用 Google Gemini：选择 `Google AI Studio (Gemini REST)`，终端地址填入 `https://generativelanguage.googleapis.com/v1beta`；
   - 若使用 DeepSeek / OpenAI 兼容接口：选择 `OpenAI 兼容协议 (/v1/chat/completions)`，终端地址填入如 `https://api.deepseek.com/v1/chat/completions`；
2. **鉴权方式**：选择 `静态 Bearer 令牌 (API Key)`；
3. **认证凭据**：填入你的 API Key（**前端查询时系统会自动遮罩为 `••••••••`，杜绝凭据泄露**）；
4. 保存后，该节点即可作为复杂任务的保底算力。

#### 形态 B：接入自家 VPS / 私网 GPU 服务器
若你拥有一台自建 GPU 服务器（例如装有 vLLM、Ollama 或 FastAPI 的云主机）：
1. **接口协议格式**：选择 `OpenAI 兼容协议`；
2. **终端调用地址**：填写你的 VPS 域名（如 `https://gpu.yourdomain.com/v1/chat/completions`）；
   *(注意：NanoMesh 内置 SSRF 防御守卫，禁止填写 `127.0.0.1` 或内网私有 IP)*
3. **鉴权方式**：选择 `动态短期 JWT 凭据 (jwt_ephemeral)`；
4. **认证凭据**：填入该节点的私有通信密钥（或在 Step 5 配置全局 `HEAVY_JWT_SECRET`）；
5. **工作机制**：NanoMesh 调度器向你的 VPS 发起调用时，会根据请求体实时计算 SHA-256 摘要，并利用专用密钥即时签发 60 秒有效期的防篡改、防重放 JWT（通过 `Authorization: Bearer <Token>` 传递），你的 VPS 只需简单校验该 JWT 即可确保请求来源可信（系统严禁复用 `JWT_SECRET` 内部主密钥）。

---

## 四、 管理员后台与线性工作流编排

访问 `/admin` 控制台，进入 **“工序胜任度矩阵与流水线拼装”** 模块：

### 1. 胜任度健康矩阵诊断 (Competence Matrix)
系统自动对数据库中的独立岗位（如“意图理解”、“视觉多模态解析”、“语义润色”）与活跃节点池进行笛卡尔积能力交集计算：
- **🟢 胜任充裕 (Healthy)**：该岗位拥有 2 个以上可胜任模型（具备故障透明容灾转移能力）；
- **🟡 单点风险 (Warning)**：该岗位仅有 1 个胜任模型；
- **🔴 孤儿岗位 (Critical Orphaned)**：该岗位在当前节点池中缺少可用模型，需补充对应模态节点。

### 2. 线性流水线拼接器 (Linear Pipeline Splicer)
管理员可以自由挑选岗位，按需拼接全新工作流，系统内置**三大安全与语法门禁**：
- **门禁 1 (模态断裂硬校验)**：检查相邻两工序的模态交集。若前一工序输出 `[audio]`，后一工序要求输入 `[image]`，系统实时阻断并给出精准错误指引。
- **门禁 2 (胜任模型在存校验)**：检查链路中的所有工序是否至少拥有 1 个在存活跃模型，严禁保存空转流水线。
- **门禁 3 (合法闭环入库与优先级赋权)**：校验通过后，自动计算整条链路的头尾模态，生成可供前端直接调度的 DAG 工作流模板。

---

## 五、 本地开发与全量测试套件

在本地开发调试或提交 PR 之前，可运行本地全量自动化测试：

```bash
# 执行全量 19 大单元测试套件 + 18 大 Mock 集成测试场景
npm test

# 运行 TypeScript 严格类型检查（源码与测试套件）
npm run typecheck
npm run typecheck:test

# 执行代码风格与静态规则检查
npm run format:check
npm run lint

# 启动本地边缘仿真开发服务器
npm run dev
```

> [!NOTE]
> **Mock 集成测试边界说明**：
> 集成测试套件（`tests/integration_test.ts`）运行于基于内存的 Cloudflare Worker 运行沙箱（内置高保真 Mock D1 SQLite 数据库、Mock R2 对象存储与模拟 fetch 传输层）。该测试彻底覆盖了数据库迁移模型完整性、多控制器状态机流转、SSE 事件流推送、令牌桶限流与异常容灾，无需产生真实云端账单或依赖外部物理网络。

### 测试用例覆盖范畴
- **单元测试 (`tests/unit_test.ts` - 19 大测试套件)**：
  - [Suite 1] 身份认证与 Token 密码学校验（JWT 签名、验签、防篡改、过期拦截）；
  - [Suite 2] 礼品卡 Crockford Base32 规范化与 SHA-256 哈希校验；
  - [Suite 3] SSRF 网络防护（回环地址、RFC1918 私网段、云厂商元数据接口拦截）与 4K 滑窗保护；
  - [Suite 4] 广义温饱定律（$\Omega_i$ 累加供给与无孤儿资产公理）硬过滤与模态闭环；
  - [Suite 5] 解耦胜任定律矩阵计算与标签降级提示词补偿；
  - [Suite 6] Serverless-Native 无状态算分体系（上下文贴合度 + 能级偏好 + 会话哈希抖动）；
  - [Suite 7] 信任边界隔离与衍生管理员专用签名密钥；
  - [Suite 8] 持久化盐值解耦与高性能二进制数据流转；
  - [Suite 9] 任意 WebGPU 拓扑、注意力汇聚（Attention-Sink）线形压缩与防越界提示词拼装；
  - [Suite 10] 规范化时间比对、续接令牌锁步 Phase 2 执行与下游重节点附件穿透；
  - [Suite 11] 多模态编排、定向认领法则（P0 上游介质优先认领与 P1 用户附件穿透）；
  - [Suite 12] 认知文档向下继承、SSRF 严格拦截与文档模态统一规范化；
  - [Suite 13] Passkeys (WebAuthn) RS256/ES256 签名校验、Origin 精准防欺骗与 OAuth 墓碑哈希隔离；
  - [Suite 14] UTF-16 代理对保护、Session ID 防路径穿越与输入类型边界安全守卫；
  - [Suite 15] OAuth CSRF 防御、提供商鉴权请求头注入与 CSV 公式注入防护；
  - [Suite 16] Turnstile 人机验证 IP 透传、资产键防路径遍历与岗位模态校验；
  - [Suite 17] 多模态角色校验、信封资产清单规范化与会话安全边界；
  - [Suite 18] 安全 JSON 解析、请求体体积上限守卫与生产环境专用持久化盐强制校验；
  - [Suite 19] 调度缺陷修复与纵深防御加固（连字符模板重路由修剪、可选元数据判空保护、资产清单数组安全映射、/api/health 配置就绪检测探针及邮箱大小写不敏感索引）。
- **集成测试 (`tests/integration_test.ts` - 17 大集成场景)**：
  - [Scenario 1] 用户注册、推荐码奖励、双向积分账本原子事务与输入类型畸形拦截；
  - [Scenario 2] R2 资产下载隔离（轻节点公开免鉴权 vs 私有临时素材多租户隔离）；
  - [Scenario 3] 管理员节点注册、SSRF 守卫与敏感凭据脱敏防泄露；
  - [Scenario 4] 线性流水线拼接器三大语法与模态门禁校验；
  - [Scenario 5] 端到端 SSE 流式执行、心跳保活与最终扣费原子结算；
  - [Scenario 6] 客户端提前断流主动取消与预扣积分安全退还；
  - [Scenario 7] 用户注销物理擦除隐私会话、R2 资产与幂等墓碑插入；
  - [Scenario 8] 分布式拓扑调度与流式协议校验（密码更新凭证失效、Passkey 安全解绑）；
  - [Scenario 9] 任意 WebGPU 拓扑调度、D1 CAS 原子防重放与端云透明容灾转移；
  - [Scenario 10] 多模态 ASR 音频识别、商业绘图生成与 0 字节容灾兜底；
  - [Scenario 11] 零额度 WebGPU 降级越权拦截与二阶段 2PC 握手状态维护；
  - [Scenario 12] 动态节点容灾切换、用户余额保护与外部 Fetch 302 重定向拦截；
  - [Scenario 13] 节点模态持久化、指令字符串守卫与 IP 频控限流；
  - [Scenario 14] 会话安全治理、数据去重与 Passkey 原子挑战生命周期；
  - [Scenario 15] CORS 强制头注入、只读端点 HTTP Method 校验与资产路径隔离；
  - [Scenario 16] 推荐码完整性校验、管理员防 DoS 锁定与登出 CSRF 防御；
  - [Scenario 17] 请求体边界限制、用户自救找回密码免死锁与存储生命周期清理；
  - [Scenario 18] 模板重路由多模态修剪、缺失字段流式请求安全承接、/api/health 探针及 users.email 声明式唯一约束。

---

> **结语**：NanoMesh 架构的设计理念在于**“把控制权还给开发者”**。无论是单人学习、课程设计成果展示、求职简历作品，还是小型团队内部自建多模型调度中枢，NanoMesh 都能以最小的运维开销提供卓越的可靠性与扩展性。

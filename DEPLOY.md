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
- [Node.js 20.x 或更高版本](https://nodejs.org/)
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
*(确认提示按 `y` 即可，系统将自动依次执行 `0001` 到 `0017` 的全部结构与种子数据迁移)*

---

### Step 5: 设置生产环境机密密钥 (Secrets)
通过 Wrangler CLI 向 Cloudflare 安全注入密钥（绝不要将密码提交到 Git）：

```bash
# 管理员控制台登录强密码 (必填)
wrangler secret put ADMIN_PASSWORD

# 用户身份认证与会话签发 JWT 密钥 (至少 32 字符随机串, 必填)
wrangler secret put JWT_SECRET

# Cloudflare Turnstile 密钥 (必填)
wrangler secret put TURNSTILE_SECRET_KEY

# Resend 邮件服务 API Key (用于发送邮箱注册验证码, 必填)
wrangler secret put RESEND_API_KEY

# Cloudflare 账户与 R2 S3 鉴权凭证 (用于轻节点模型上传与多模态素材传输, 必填)
wrangler secret put Cloudflare_Account_ID
wrangler secret put R2_ACCESS_KEY_ID
wrangler secret put R2_SECRET_ACCESS_KEY
```

---

### Step 6: 构建与一键部署
```bash
npm run deploy
```
部署成功后，控制台将输出你的 Worker 线上访问地址（例如 `https://nanomesh-frontend.your-username.workers.dev`）。

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
4. **工作机制**：NanoMesh 调度器向你的 VPS 发起调用时，会根据请求体实时计算 SHA-256 摘要，并利用共享密钥即时签发 60 秒有效期的防篡改、防重放 JWT（通过 `Authorization: Bearer <Token>` 传递），你的 VPS 只需简单校验该 JWT 即可确保请求来源可信。

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
# 执行全量 6 大单元测试套件 + 6 大端到端集成测试场景
npm test

# 仅做 TypeScript 静态类型编译检查
npm run typecheck

# 启动本地边缘仿真开发服务器
npm run dev
```

### 测试用例覆盖范畴
- **单元测试 (`tests/unit_test.ts`)**：
  - JWT 签发、验签、防篡改、过期拦截；
  - 礼品卡 Crockford Base32 规范化与 SHA-256 哈希校验；
  - SSRF 网络防护（回环地址、RFC1918 私网段、云厂商元数据接口拦截）；
  - 4K 滑窗保护（历史冗余折叠与尾部最高优先级指令留存）；
  - 温饱定律硬过滤与模态闭环；
  - 胜任定律矩阵计算与标签降级提示词补偿；
  - Serverless 无状态算分体系（上下文贴合度 + 能级偏好 + 会话哈希抖动）。
- **集成测试 (`tests/integration_test.ts`)**：
  - 用户注册推荐码与双向积分账本的 D1 `batch` 原子事务；
  - R2 资产下载隔离（轻节点公开免鉴权 vs 私有临时素材多租户隔离）；
  - 管理员节点注册与敏感凭据脱敏防泄露；
  - 线性流水线拼接器三大门禁拦截验证；
  - 端到端 SSE 流式执行、心跳保活与最终扣费结算；
  - 客户端提前断流主动取消与预扣积分安全退还。

---

> **结语**：NanoMesh 架构的设计理念在于**“把控制权还给开发者”**。无论是单人学习、课程设计成果展示、求职简历作品，还是小型团队内部自建多模型调度中枢，NanoMesh 都能以最小的运维开销提供卓越的可靠性与扩展性。

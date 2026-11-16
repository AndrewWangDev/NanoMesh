// src/orchestration/dispatcher.ts
import { Env } from "../types";
import { sliceEnvelopeForNode } from "./slicing";
import { 
  computeDeterministicSignature, 
  lookupDeterministicCache, 
  storeDeterministicCache 
} from "./signature";
import { InstantiatedDAG, ModelMetadata, UnifiedProtocolEnvelope } from "./types";
import { signHeavyNodeToken } from "../auth/jwt";

export interface ExecutionOptions {
  userId: string;
  hasPreDeducted?: boolean;
}

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

async function computeSha256Hex(data: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export function isSafeExternalUrl(urlStr: string): boolean {
  try {
    const parsed = new URL(urlStr);
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return false;

    // Clean IPv6 host brackets (e.g. "[::1]" -> "::1")
    const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');

    // Loopback, all-interfaces, and unroutable addresses (IPv4 & IPv6)
    if (host === 'localhost' || host === '127.0.0.1' || host === '0.0.0.0' || host === '::1' || host === '::') return false;
    if (host.endsWith('.local') || host.endsWith('.internal')) return false;

    // IPv6 Private & Link-Local Ranges:
    // - fc00::/7 (Unique Local Address, covers fc00:: to fdff::)
    // - fe80::/10 (Link-Local)
    if (host.startsWith('fc') || host.startsWith('fd') || host.startsWith('fe80:')) return false;

    // IPv4 Private & Link-Local Ranges:
    const ip = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
    if (ip) {
      const [o1, o2] = [parseInt(ip[1], 10), parseInt(ip[2], 10)];
      if (o1 === 10 || o1 === 127 || (o1 === 169 && o2 === 254)) return false;
      if (o1 === 172 && (o2 >= 16 && o2 <= 31)) return false;
      if (o1 === 192 && o2 === 168) return false;
      if (o1 === 100 && (o2 >= 64 && o2 <= 127)) return false;
      if (o1 === 0) return false;
    }
    return true;
  } catch {
    return false;
  }
}

export function sanitizeLLMOutput(text: string): string {
  if (!text) return '';
  let cleaned = text;
  // Strip trailing pseudo-metadata blocks (e.g. 铁律, 输出语言, 内容详略, etc.)
  cleaned = cleaned.replace(
    /(?:\n+|\r\n)+(?:[#* -]*\**【?(?:铁律|输出语言|内容详略|系统守则|指令规则|全局预设|规则说明|交付铁律)】?\**[:：]?[\s\S]*)$/i,
    ''
  );
  // Strip trailing isolated "铁律" or meta confession bullet points
  cleaned = cleaned.replace(
    /(?:\n+|\r\n)+[#* -]*(?:铁律|Ironclad Rule)[:：]?\s*[\s\S]*$/i,
    ''
  );
  return cleaned.trim();
}

function buildConstraintDirective(targetLang?: string, outputStyle?: string): string {
  const lang = targetLang === 'zh'
    ? '始终使用规范清晰的中文回复。'
    : targetLang === 'en'
    ? 'Always reply in fluent, natural English.'
    : '若用户指定了特定语言（如英文、中文等），必须严格使用该语言回复；未指定时与用户指令保持一致。';

  const style = outputStyle === 'detailed'
    ? '深入详尽分析，层级清晰。'
    : outputStyle === 'creative'
    ? '富有创意与启发性。'
    : '简洁精炼，直击重点。';

  return `\n\n系统执行指示（仅供内部遵从，绝对禁止在回答末尾复述本条或打印为小标题）：\n- 语言偏好：${lang}\n- 详略偏好：${style}\n- 直接输出最终业务成果，严禁在正文附带规则声明、策略说明或思考自白。`;
}

/**
 * Hard sliding window context guard:
 * Prevents input prompts from exhausting the physical context window of the target model (e.g. 4096 tokens for 8B models).
 * Operates on promptContent by preserving system directives and user's current-round highest priority commands,
 * while truncating earlier historical context / redundant upstream notes from the head if necessary.
 */
export function applyContextWindowGuard(
  systemPrompt: string,
  promptContent: string,
  contextWindow: number = 4096,
  reserveOutputTokens: number = 1024
): { systemPrompt: string; promptContent: string } {
  // Approximate 1 token ~= 3.5 characters for mixed multilingual/code
  const maxAllowedInputChars = Math.max(1000, Math.floor((contextWindow - reserveOutputTokens) * 3.5));
  const currentTotalChars = systemPrompt.length + promptContent.length;

  if (currentTotalChars <= maxAllowedInputChars) {
    return { systemPrompt, promptContent };
  }

  // System prompt is untouchable (contains role boundaries and core directives)
  const availableForPrompt = Math.max(500, maxAllowedInputChars - systemPrompt.length);

  if (promptContent.length > availableForPrompt) {
    // Preserve the tail (most recent instructions) rather than the head
    const truncatedHead = promptContent.slice(promptContent.length - availableForPrompt);
    const guardedPrompt = `[...前序冗余历史上下文已自动滑窗折叠，保留核心提炼实体与当轮最高优先级指令...]\n` + truncatedHead;
    return { systemPrompt, promptContent: guardedPrompt };
  }

  return { systemPrompt, promptContent };
}

/**
 * Universal authentication header builder for disparate node providers:
 * - 'none': Local / Edge serverless (no special credentials)
 * - 'bearer_static': Google AI Studio Key / OpenAI API Key (Authorization: Bearer & x-goog-api-key)
 * - 'jwt_ephemeral': Private VPS / llama-server gateway with anti-tamper SHA-256 body digest & anti-replay jti
 */
async function buildAuthHeaders(
  model: ModelMetadata,
  env: Env,
  requestBodyStr: string,
  context: {
    userId?: string;
    sessionId?: string;
    envelopeId?: string;
    roleId?: string;
  }
): Promise<Record<string, string>> {
  const authMode = model.auth_mode || (model.endpoint.startsWith('http') ? 'jwt_ephemeral' : 'none');
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'NanoMesh-Edge-Dispatcher/1.0'
  };

  if (authMode === 'none') {
    return headers;
  }

  if (authMode === 'bearer_static') {
    const token = model.auth_secret || '';
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
      headers['x-goog-api-key'] = token;
    }
    return headers;
  }

  if (authMode === 'jwt_ephemeral') {
    const heavySecret = model.auth_secret || env.HEAVY_JWT_SECRET || env.JWT_SECRET;
    if (!heavySecret) {
      throw new Error(`[SECURITY_REJECTED] 算力节点【${model.display_name}】需要 jwt_ephemeral 鉴权，但服务器未配置对应密钥。`);
    }
    const bodyDigest = await computeSha256Hex(requestBodyStr);
    const heavyToken = await signHeavyNodeToken(
      {
        sub: context.userId || 'anonymous',
        sid: context.sessionId || 'session',
        eid: context.envelopeId || 'envelope',
        rid: context.roleId || 'role',
        mid: model.model_id,
        bdg: bodyDigest
      },
      heavySecret
    );
    headers['Authorization'] = `Bearer ${heavyToken}`;
    return headers;
  }

  if (model.api_format === 'google_ai' && model.auth_secret) {
    headers['x-goog-api-key'] = model.auth_secret;
  }

  return headers;
}

function extractChunkText(it: any): string {
  if (!it || typeof it !== 'object') return '';

  // 1. OpenAI-compatible delta format (Workers AI LLaMA 3.2 emits delta.content)
  if (Array.isArray(it.choices) && it.choices.length > 0) {
    const delta = it.choices[0]?.delta;
    if (delta && delta.content !== undefined && delta.content !== null) {
      return String(delta.content);
    }
  }

  // 2. Google Gemini API format: candidates[0].content.parts[0].text
  if (Array.isArray(it.candidates) && it.candidates.length > 0) {
    const parts = it.candidates[0]?.content?.parts;
    if (Array.isArray(parts) && parts.length > 0) {
      const text = parts.map((p: any) => p?.text || '').join('');
      if (text) {
        return text;
      }
    }
  }

  // 3. Cloudflare top-level response field (may be string or integer/number, e.g. {"response": 20})
  if (it.response !== undefined && it.response !== null) {
    return String(it.response);
  }

  // 4. Caption field
  if (it.caption !== undefined && it.caption !== null) {
    return String(it.caption);
  }

  // 5. Answer field
  if (it.answer !== undefined && it.answer !== null) {
    return String(it.answer);
  }

  return '';
}

async function parseAIResponse(aiRes: any, onChunk?: (chunk: string) => void): Promise<string> {
  if (!aiRes) return '';
  if (typeof aiRes === 'string') return sanitizeLLMOutput(aiRes);
  if (aiRes.description !== undefined && aiRes.description !== null && String(aiRes.description).trim()) {
    return sanitizeLLMOutput(String(aiRes.description));
  }
  if (aiRes.response !== undefined && aiRes.response !== null && String(aiRes.response).trim()) {
    return sanitizeLLMOutput(String(aiRes.response));
  }
  if (aiRes.answer !== undefined && aiRes.answer !== null && String(aiRes.answer).trim()) {
    return sanitizeLLMOutput(String(aiRes.answer));
  }
  if (aiRes.caption !== undefined && aiRes.caption !== null && String(aiRes.caption).trim()) {
    return sanitizeLLMOutput(String(aiRes.caption));
  }
  if (Array.isArray(aiRes.choices) && aiRes.choices.length > 0) {
    const content = aiRes.choices[0]?.message?.content;
    if (content !== undefined && content !== null && String(content).trim()) {
      return sanitizeLLMOutput(String(content));
    }
  }
  // Google Gemini JSON response: candidates[0].content.parts[0].text
  if (Array.isArray(aiRes.candidates) && aiRes.candidates.length > 0) {
    const parts = aiRes.candidates[0]?.content?.parts;
    if (Array.isArray(parts) && parts.length > 0) {
      const text = parts.map((p: any) => p?.text || '').join('');
      if (text.trim()) {
        return sanitizeLLMOutput(text);
      }
    }
  }

  // If aiRes is a ReadableStream (e.g. Workers AI streaming models)
  if (typeof aiRes.getReader === 'function') {
    try {
      const reader = aiRes.getReader();
      const decoder = new TextDecoder();
      let streamBuffer = '';
      let text = '';
      let latestAnswer = '';
      let latestReasoning = '';
      let rawAccumulated = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const decoded = decoder.decode(value, { stream: true });
        streamBuffer += decoded;
        rawAccumulated += decoded;

        const lines = streamBuffer.split('\n');
        streamBuffer = lines.pop() || ''; // Keep incomplete trailing fragment across chunk boundaries!

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('data: ') && trimmed !== 'data: [DONE]') {
            try {
              const parsed = JSON.parse(trimmed.slice(6));
              const items = Array.isArray(parsed) ? parsed : [parsed];
              for (const it of items) {
                const chunk = extractChunkText(it);
                if (chunk) {
                  text += chunk;
                  if (onChunk) onChunk(chunk);
                }
                if (it.answer !== undefined && it.answer !== null) {
                  latestAnswer += String(it.answer);
                }
                if (it.reasoning && typeof it.reasoning.text === 'string' && it.reasoning.text) {
                  latestReasoning = it.reasoning.text;
                }
                if (it.choices?.[0]?.delta?.reasoning_content) {
                  latestReasoning += String(it.choices[0].delta.reasoning_content);
                }
              }
            } catch (e) {}
          }
        }
      }

      // Check remaining tail buffer
      if (streamBuffer.trim().startsWith('data: ') && streamBuffer.trim() !== 'data: [DONE]') {
        try {
          const parsed = JSON.parse(streamBuffer.trim().slice(6));
          const items = Array.isArray(parsed) ? parsed : [parsed];
          for (const it of items) {
            const chunk = extractChunkText(it);
            if (chunk) {
              text += chunk;
              if (onChunk) onChunk(chunk);
            }
            if (it.answer !== undefined && it.answer !== null) {
              latestAnswer += String(it.answer);
            }
            if (it.reasoning && typeof it.reasoning.text === 'string') latestReasoning = it.reasoning.text;
            if (it.choices?.[0]?.delta?.reasoning_content) {
              latestReasoning += String(it.choices[0].delta.reasoning_content);
            }
          }
        } catch (e) {}
      }

      if (text.trim()) {
        const full = (latestReasoning && !text.includes(latestReasoning)) ? `${latestReasoning}\n\n${text}` : text;
        return sanitizeLLMOutput(full);
      }

      if (latestAnswer || latestReasoning) {
        const parts = [latestReasoning, latestAnswer].filter(Boolean);
        return sanitizeLLMOutput(parts.join('\n\n'));
      }

      if (text.trim()) return sanitizeLLMOutput(text);

      // Robust fallback: search in rawAccumulated
      const reasoningMatches = rawAccumulated.match(/"text"\s*:\s*"((?:[^"\\]|\\.)*)"/);
      if (reasoningMatches && reasoningMatches[1]) {
        try {
          const unescaped = JSON.parse(`"${reasoningMatches[1]}"`);
          if (unescaped && unescaped.trim()) return sanitizeLLMOutput(unescaped);
        } catch (e) {}
      }

      const answerMatches = rawAccumulated.match(/"answer"\s*:\s*"((?:[^"\\]|\\.)*)"/);
      if (answerMatches && answerMatches[1]) {
        try {
          const unescaped = JSON.parse(`"${answerMatches[1]}"`);
          if (unescaped && unescaped.trim()) return sanitizeLLMOutput(unescaped);
        } catch (e) {}
      }
    } catch (streamErr) {
      console.warn("Error reading stream from Workers AI:", streamErr);
    }
  }

  return '';
}

async function callWithTimeout<T>(fn: () => Promise<T>, timeoutMs: number): Promise<T> {
  let timer: any;
  const timeoutPromise = new Promise<T>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`Inference timed out after ${timeoutMs}ms`)), timeoutMs);
  });
  try {
    return await Promise.race([fn(), timeoutPromise]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Executes an instantiated DAG via SSE (Server-Sent Events) Stream
 */
export async function executeDAGStream(
  env: Env,
  dag: InstantiatedDAG,
  envelope: UnifiedProtocolEnvelope,
  options: ExecutionOptions
): Promise<ReadableStream> {
  const encoder = new TextEncoder();
  const abortController = new AbortController();
  let heartbeatTimer: any = null;
  let isStreamCancelled = false;
  let hasEmittedTokens = false;

  return new ReadableStream({
    async start(controller) {
      function sendEvent(eventType: string, data: any) {
        if (isStreamCancelled) return;
        try {
          const payload = `event: ${eventType}\ndata: ${JSON.stringify(data)}\n\n`;
          controller.enqueue(encoder.encode(payload));
        } catch (e) {}
      }

      async function refundReservedCredit() {
        if (options.hasPreDeducted) {
          options.hasPreDeducted = false;
          try {
            await env.DB.prepare(
              "UPDATE users SET credits = credits + 1 WHERE user_id = ?"
            ).bind(options.userId).run();
          } catch (refundErr) {
            console.error("[Dispatcher] Failed to refund reserved credit:", refundErr);
          }
        }
      }

      // SSE Keep-Alive Heartbeat to prevent edge gateway timeouts
      heartbeatTimer = setInterval(() => {
        if (isStreamCancelled) {
          clearInterval(heartbeatTimer);
          return;
        }
        try {
          controller.enqueue(encoder.encode(': keep-alive\n\n'));
        } catch (e) {
          clearInterval(heartbeatTimer);
        }
      }, 2500);

      let upstreamOutput = '';
      let totalCost = 0;
      const startTime = Date.now();

      try {
        // 1. Send DAG Plan & Reasoning Trace to frontend
        sendEvent('dag_plan', {
          template: {
            template_id: dag.template.template_id,
            name_zh: dag.template.name_zh,
            name_en: dag.template.name_en,
            desc_zh: dag.template.desc_zh,
          },
          candidate_templates: dag.candidate_templates.map(t => ({
            template_id: t.template_id,
            name_zh: t.name_zh,
            name_en: t.name_en
          })),
          nodes: dag.nodes.map(n => ({
            role_id: n.role.role_id,
            name_zh: n.role.name_zh,
            name_en: n.role.name_en,
            in_degree: n.role.in_degree,
            out_degree: n.role.out_degree,
            in_modalities: n.role.in_modalities,
            out_modalities: n.role.out_modalities,
            selected_model: {
              model_id: n.selected_model.model_id,
              display_name: n.selected_model.display_name,
              cost: n.selected_model.cost_per_1k_tokens,
              inference_target: n.selected_model.inference_target || 'cloud',
              browser_runtime: n.selected_model.browser_runtime,
              download_size_bytes: n.selected_model.download_size_bytes
            },
            standby_models: n.standby_models.map(m => ({
              model_id: m.model_id,
              display_name: m.display_name,
              cost: m.cost_per_1k_tokens,
              inference_target: m.inference_target || 'cloud',
              browser_runtime: m.browser_runtime,
              download_size_bytes: m.download_size_bytes
            })),
            downgraded: n.downgraded,
            compensation_prompt: n.compensation_prompt,
            custom_prompt: n.custom_prompt
          })),
          reasoning_trace: dag.reasoning_trace,
          is_security_violation: dag.is_security_violation,
          is_unreachable: dag.is_unreachable
        });

        // Fast-Failed Gateways (Security Violation or Capability Out-of-Bounds)
        if (dag.is_security_violation) {
          await refundReservedCredit();
          sendEvent('security_blocked', {
            is_blocked: true,
            duration_ms: Date.now() - startTime,
            message_zh: '抱歉，您的指令经安全网关审计，涉及未授权系统攻击、入侵工具武器化或侵犯版权等违规行为。该请求已被终止执行，未扣除算力点数。请参阅 NanoMesh 服务条款。\n\n如为您自建环境的防御性安全配置或学术分析，请调整表述明确防御上下文。如果您持续进行违规活动，您的账号可能被暂停。',
            message_en: 'Sorry, your instruction was audited by the Edge Firewall and flagged for unauthorized system attacks, weaponized exploits, or intellectual property infringements. Execution has been terminated without consuming compute credits. Please refer to NanoMesh Terms of Service.\n\nIf this was intended for defensive security configurations or academic research, please adjust your phrasing. Continued violations may lead to account suspension.'
          });

          sendEvent('dag_complete', {
            final_output: '',
            total_cost: 0,
            total_duration_ms: Date.now() - startTime,
            is_security_violation: true
          });
          return;
        }

        if (dag.is_unreachable) {
          await refundReservedCredit();
          sendEvent('capability_unreachable', {
            is_unreachable: true,
            duration_ms: Date.now() - startTime,
            message_zh: '当前工作流库未检索到能够胜任该业务意图的编排链路。NanoMesh 目前专精于多模态图文解析、实体信息抽取、跨语言重构与结构化表达润色。系统已在极短时间内快速熔断本轮执行，未消耗您的任何算力点数。\n\n*(建议：您可以尝试上传多模态图文材料，或细化您在文字润色、文档抽取方面的诉求)*',
            message_en: 'No workflow template in the current catalog matches your specific intent. NanoMesh is currently specialized in multimodal visual understanding, entity extraction, cross-lingual translation, and structured polishing. The system has fast-failed to protect your compute credits with 0 charges.\n\n*(Tip: Try uploading multimodal materials or refining your text analysis goals)*'
          });

          sendEvent('dag_complete', {
            final_output: '',
            total_cost: 0,
            total_duration_ms: Date.now() - startTime,
            is_unreachable: true
          });
          return;
        }

        // Deep clone assets manifest for this DAG run so that node-level consumption is isolated
        const runEnvelope: UnifiedProtocolEnvelope = {
          ...envelope,
          assets_manifest: envelope.assets_manifest.map(a => ({ ...a }))
        };

        // 2. Loop through each node sequentially
        for (let idx = 0; idx < dag.nodes.length; idx++) {
          const node = dag.nodes[idx];
          const parentNode = idx > 0 ? dag.nodes[idx - 1] : undefined;
          const parentRoleName = parentNode ? parentNode.role.name_zh : undefined;
          const nodeStartTime = Date.now();

          // Envelope slicing with instruction masking and downstream metadata
          const nodeCtx = sliceEnvelopeForNode(node, runEnvelope, upstreamOutput, parentRoleName);

          // 1. Prompt Assembly based on Role Responsibility
          let systemPrompt = '';
          let promptContent = '';

          // Extract attached text/document content from claimed assets if present
          const docTextBlocks = nodeCtx.claimed_assets
            .filter(a => a.in_memory_text && a.in_memory_text.trim())
            .map(a => a.in_memory_text!.trim());
          const attachedDocsSection = docTextBlocks.length > 0 ? `【文档材料】\n${docTextBlocks.join('\n\n')}` : '';

          // Check if this run is an incremental refinement on previous round output (ANCHOR_TAIL)
          let isIncrementalRefinement = false;
          let refinementBackground = '';
          let refinementUserQuery = envelope.instruction_payload;

          const bgMatch = envelope.instruction_payload.match(/^\[上轮产物背景:\s*([\s\S]*?)\]\n(?:用户追问|用户指令):\s*([\s\S]*)$/);
          if (bgMatch) {
            isIncrementalRefinement = true;
            refinementBackground = bgMatch[1].trim();
            refinementUserQuery = bgMatch[2].trim();
          }

          if (nodeCtx.is_head_masked) {
            // Case A: Head Node (in_degree === 0 && out_degree > 0)
            // Strictly MASK user prompt! Pure physical/perceptual feature extraction!
            systemPrompt = `You are NanoMesh Worker Role: ${node.role.name_zh}.\n` +
              (nodeCtx.compensation_prompt || `请对输入的图像或多模态数据进行全要素解析与无损特征提取：逐字逐行提取所有可见文字内容（包括标题、正文、微小注释、Logo文字），客观分析画面排版布局、构图与设计风格。保持客观客观，严禁进行翻译、二次创作或格式删减。`);
            
            promptContent = `请对输入的图像进行全要素解析与无损特征提取：逐字逐行提取所有文字内容与排版风格细节。\nDescribe all text, visual elements, layout, and details in this image in detail.`;
            if (nodeCtx.custom_prompt) {
              promptContent += `\n\n[User Custom Directive]:\n${nodeCtx.custom_prompt}`;
            }
          } else if (nodeCtx.is_downstream) {
            // Case B: Downstream Node (in_degree > 0)
            systemPrompt = `You are NanoMesh Worker Role: ${node.role.name_zh}.\n` +
              `你当前处于 NanoMesh 协作工作流的下游节点。\n` +
              `前置节点已为你完成了原始素材的物理感知与全要素解析，提取结果作为【前置提炼素材】提供给你。\n\n` +
              `【核心执行守则】：\n` +
              `1. 角色专注：作为【${node.role.name_zh}】，发挥本岗位专业能力，专注完成用户指令中属于本岗位职责的部分（如多语言翻译、版面风格评述、信息提炼、结构化整理等）。\n` +
              `2. 二次消化与实体提炼：【前置提炼素材】包含前置节点的客观观察笔记（可能含有英文视觉描述如 "The image shows..."）。你必须主动消化理解，并精准提取出其中真正的业务内容实体（例如海报上的片名、标语、作者/导演、年份版次等真实文字），严禁直接机械照抄“The image shows...”、“画面显示...”等上游观察者的笔记流水账。\n` +
              `3. 语言严格遵从：若用户指令或节点专有微调指令明确指定了输出语言（例如“使用英文回复我”、“用英文描述”、“Translate to English”等），你必须无条件将最终成果以该指定语言输出！严禁依然输出原语言（如中文）！\n` +
              `4. 零元语言自白：严禁在回答中出现“基于用户的原始指令”、“按照上下文约束”、“我将按照以下步骤”、“由于原文是英文故无需翻译”等任何思考过程、自我解释或客套废话。绝对禁止向用户提及上游节点、父节点或系统架构标签。\n` +
              `5. 直接交付最终成果：必须像资深专家交付最终成稿一样，直接输出排版优美、层次清晰的 Markdown 结果（使用加粗小标题或编号要点）。`;

            if (nodeCtx.compensation_prompt) {
              systemPrompt += `\n${nodeCtx.compensation_prompt}`;
            }
            systemPrompt += buildConstraintDirective(nodeCtx.target_language, nodeCtx.output_style);

            const upstreamSections = [nodeCtx.upstream_text, attachedDocsSection].filter(Boolean).join('\n\n');
            const finalUserDirective = isIncrementalRefinement ? refinementUserQuery : envelope.instruction_payload;
            const nodeTweak = (nodeCtx.custom_prompt && nodeCtx.custom_prompt !== finalUserDirective) ? `[节点特定微调指令]: ${nodeCtx.custom_prompt}` : '';
            const allDirectives = [finalUserDirective, nodeTweak].filter(Boolean).join('\n');

            promptContent = `【用户当轮最高优先级指令 (Highest Priority Command)】\n${allDirectives}\n\n【前置提炼素材】\n${upstreamSections}`;
            if (isIncrementalRefinement && refinementBackground && !upstreamSections.includes(refinementBackground)) {
              promptContent += `\n\n【历史背景补充】\n${refinementBackground}`;
            }
          } else {
            // Case C: Single-Node DAG (in_degree === 0 && out_degree === 0)
            if (isIncrementalRefinement) {
              systemPrompt = `You are NanoMesh Worker Role: ${node.role.name_zh}.\n` +
                `你当前承担对前置任务成果的【增量修改、翻译与多语言重构 (Incremental Refinement)】职责。\n\n` +
                `【核心执行守则】：\n` +
                `1. 增量重构与修改：你必须以【前序产物基础素材】为内容基准，严格贯彻【用户当轮最高优先级指令】进行精准处理（如多语言重构、风格润色、补充扩写、要点提炼等）。\n` +
                `2. 语言严格遵从：若【用户当轮最高优先级指令】明确指定了输出语言（例如“使用英文回复我”、“用英文描述”、“Translate to English”等），你必须无条件将基础素材全部重构并以该指定语言输出！严禁依然输出原语言（如中文）！\n` +
                `3. 零元语言自白：严禁输出“基于您的要求”、“遵从上下文约束”等任何自我说明或元分析，直接交付排版优美、层次清晰的 Markdown 最终成品。`;

              if (nodeCtx.compensation_prompt) {
                systemPrompt += `\n${nodeCtx.compensation_prompt}`;
              }
              systemPrompt += buildConstraintDirective(nodeCtx.target_language, nodeCtx.output_style);

              const nodeTweak = (nodeCtx.custom_prompt && nodeCtx.custom_prompt !== refinementUserQuery) ? `[节点特定微调指令]: ${nodeCtx.custom_prompt}` : '';
              const userDirectives = [refinementUserQuery, nodeTweak].filter(Boolean).join('\n');

              promptContent = `【用户当轮最高优先级指令 (Highest Priority Command)】\n${userDirectives}\n\n` +
                `【前序产物基础素材 (待处理素材)】\n${refinementBackground}` +
                (attachedDocsSection ? `\n\n${attachedDocsSection}` : '');
            } else {
              systemPrompt = `You are NanoMesh Worker Role: ${node.role.name_zh}.\n` +
                `【核心执行守则】：\n` +
                `1. 语言遵从：若用户指令指定了特定输出语言（如英文、中文等），必须严格以该指定语言输出！\n` +
                `2. 零元语言自白：严禁输出“基于上下文约束”、“根据您的要求”等任何客套自白或元分析，直接输出业务结果。\n` +
                `3. 直接输出成品：直接以排版优美的 Markdown 格式输出。`;
              if (nodeCtx.compensation_prompt) {
                systemPrompt += `\n${nodeCtx.compensation_prompt}`;
              }
              systemPrompt += buildConstraintDirective(nodeCtx.target_language, nodeCtx.output_style);

              promptContent = attachedDocsSection 
                ? `${attachedDocsSection}\n\n【用户指令】\n${envelope.instruction_payload}` 
                : envelope.instruction_payload;
              if (nodeCtx.custom_prompt) {
                promptContent += `\n\n[User Custom Directive]:\n${nodeCtx.custom_prompt}`;
              }
            }
          }

          // Compute input digest
          const assetDigests = nodeCtx.claimed_assets.map(a => a.source_digest).join('|');
          const inputDigest = `${nodeCtx.upstream_text}::${assetDigests}`;
          const fullPrompt = [
            nodeCtx.compensation_prompt,
            nodeCtx.injected_prompt,
            nodeCtx.custom_prompt ? `[User Injected Prompt]:\n${nodeCtx.custom_prompt}` : '',
            promptContent
          ].filter(Boolean).join('\n');

          // Deterministic Signature Check
          const cacheKey = await computeDeterministicSignature(
            node.role.role_id,
            node.selected_model.model_id,
            inputDigest,
            fullPrompt
          );

          const isTailNode = (node.role.out_degree === 0) || (idx === dag.nodes.length - 1);

          sendEvent('node_start', {
            role_id: node.role.role_id,
            role_name: node.role.name_zh,
            role_name_en: node.role.name_en,
            node_index: idx,
            model_name: node.selected_model.display_name,
            model_id: node.selected_model.model_id,
            inference_target: node.selected_model.inference_target || 'cloud',
            claimed_assets_count: nodeCtx.claimed_assets.length
          });

          if (node.selected_model.inference_target === 'browser') {
            sendEvent('client_exec_request', {
              role_id: node.role.role_id,
              role_name: node.role.name_zh,
              role_name_en: node.role.name_en,
              model_id: node.selected_model.model_id,
              model_name: node.selected_model.display_name,
              endpoint: node.selected_model.endpoint,
              system_prompt: systemPrompt,
              user_prompt: promptContent,
              is_tail_node: isTailNode
            });
            upstreamOutput = '';
            continue;
          }

          let nodeOutput = '';
          const cachedOutput = await lookupDeterministicCache(env, cacheKey);

          if (cachedOutput) {
            // Cache Hit: 0 cost, instant return!
            nodeOutput = cachedOutput;
            if (isTailNode) {
              sendEvent('text_chunk', {
                role_id: node.role.role_id,
                chunk: nodeOutput,
                cache_hit: true
              });
            }
            sendEvent('node_complete', {
              role_id: node.role.role_id,
              role_name: node.role.name_zh,
              role_name_en: node.role.name_en,
              model_id: node.selected_model.model_id,
              node_index: idx,
              duration_ms: Date.now() - nodeStartTime,
              cache_hit: true,
              cost: 0
            });
          } else {
            // Cache Miss: Perform Execution
            // 2. Fetch image from R2 bucket if required
            let imageB64: string | null = null;
            let imageBytes: number[] | null = null;
            const imageAsset = nodeCtx.claimed_assets.find(a => a.modality === 'image');

            if (imageAsset) {
              if (imageAsset.r2_key && env.R2) {
                // Security check (IDOR/BOLA prevention): Only allow access to current session's assets
                const userSafePrefix = `tmp/${options.userId}/`;
                if (!imageAsset.r2_key.startsWith(userSafePrefix)) {
                  console.error(`[Security IDOR] User ${options.userId} attempted to access unauthorized R2 key: ${imageAsset.r2_key}`);
                  throw new Error(`安全违规：拒绝访问未经授权的资产对象`);
                }
                try {
                  const r2Obj = await env.R2.get(imageAsset.r2_key);
                  if (r2Obj) {
                    const buf = await r2Obj.arrayBuffer();
                    imageBytes = Array.from(new Uint8Array(buf));
                    imageB64 = `data:${imageAsset.mime_type || 'image/jpeg'};base64,${arrayBufferToBase64(buf)}`;
                  } else {
                    console.error(`[Dispatcher] Image object not found in R2 for key: ${imageAsset.r2_key}`);
                  }
                } catch (r2Err) {
                  console.error("[Dispatcher] R2 asset retrieval error:", r2Err);
                }
              }
            }

            // 3. Fail-fast check: If node requires image, image MUST exist! Zero tolerance for missing assets!
            const isImageNode = node.role.in_modalities.includes('image') || node.selected_model.modalities.includes('image');
            if (isImageNode && !imageB64 && !imageBytes) {
              throw new Error(`工作流执行中断：岗位【${node.role.name_zh}】强依赖图像资产输入，但未能检索到图片实体（R2 Key: ${imageAsset?.r2_key || '未指定'}）。严禁越权降级或跳过执行。`);
            }

            // 4. Candidate Models: STRICTLY Top-1 Primary + Top-2/Top-3 Standby Models from Step 3 Arbitration!
            // Mathematically pre-filtered by hardFilterModels and ranked by scoreAndRankRoleModels.
            // ABSOLUTELY NO EXTERNAL ARBITRARY MODELS INJECTED!
            const candidateModels: ModelMetadata[] = [
              node.selected_model,
              ...node.standby_models
            ].filter((m, i, arr) => m && m.endpoint && arr.findIndex(x => x.model_id === m.model_id) === i);

            // 5. Execute candidate pool sequentially (Primary -> Standby Failover)
            let isExecutionSuccess = false;
            let didStreamChunks = false;
            let actualExecutingModel: ModelMetadata = node.selected_model;
            const candidateErrors: string[] = [];

            for (let attemptIdx = 0; attemptIdx < candidateModels.length; attemptIdx++) {
              const currentCandidate = candidateModels[attemptIdx];
              const endpoint = currentCandidate.endpoint;
              if (!env.AI && !endpoint.startsWith('http')) break;

              // Transparent failover notice: notify frontend explicitly when falling back to Standby models
              if (attemptIdx > 0) {
                const previousCandidate = candidateModels[attemptIdx - 1];
                sendEvent('node_failover', {
                  role_id: node.role.role_id,
                  role_name: node.role.name_zh,
                  failed_model: previousCandidate.display_name,
                  failed_model_id: previousCandidate.model_id,
                  fallback_model: currentCandidate.display_name,
                  fallback_model_id: currentCandidate.model_id,
                  attempt: attemptIdx + 1,
                  total_candidates: candidateModels.length,
                  reason_zh: `首选算力节点【${previousCandidate.display_name}】响应超时或不可用，透明故障转移至仲裁备选节点【${currentCandidate.display_name}】`,
                  reason_en: `Primary node [${previousCandidate.display_name}] timed out or unavailable, transparent failover to standby node [${currentCandidate.display_name}]`
                });
              }

              try {
                if (endpoint.startsWith('http')) {
                  if (!isSafeExternalUrl(endpoint)) {
                    console.warn(`[Dispatcher Security] Blocked SSRF attempt to unsafe endpoint: ${endpoint}`);
                    candidateErrors.push(`[${currentCandidate.display_name}]: 目标地址不安全或属于受保护的私有网络`);
                    continue;
                  }

                  // 1. Context Window Guard (sliding window tail preservation)
                  const { systemPrompt: guardedSysPrompt, promptContent: guardedPromptContent } = applyContextWindowGuard(
                    systemPrompt,
                    promptContent,
                    currentCandidate.context_window || 4096,
                    1024
                  );

                  // 2. Protocol Adapter: OpenAI Compatible vs Google AI Studio (Gemini)
                  const apiFormat = currentCandidate.api_format || 'openai_compat';
                  let targetUrl = endpoint;
                  let requestPayload: any;

                  if (apiFormat === 'google_ai') {
                    const isStream = isTailNode;
                    if (!targetUrl.includes(':generateContent') && !targetUrl.includes(':streamGenerateContent')) {
                      const baseUrl = targetUrl.replace(/\/+$/, '');
                      const action = isStream ? 'streamGenerateContent?alt=sse' : 'generateContent';
                      targetUrl = `${baseUrl}/${currentCandidate.model_id}:${action}`;
                    }
                    // Google AI Studio Key is passed securely via 'x-goog-api-key' HTTP header

                    requestPayload = {
                      system_instruction: {
                        parts: [{ text: guardedSysPrompt }]
                      },
                      contents: [
                        {
                          role: 'user',
                          parts: [{ text: guardedPromptContent }]
                        }
                      ],
                      generationConfig: {
                        temperature: 0.2,
                        maxOutputTokens: 2048
                      }
                    };
                  } else {
                    requestPayload = {
                      model: currentCandidate.model_id || "Meta-Llama-3.1-8B-Instruct",
                      messages: [
                        { role: "system", content: guardedSysPrompt },
                        { role: "user", content: guardedPromptContent }
                      ],
                      stream: isTailNode,
                      max_tokens: 2048,
                      temperature: 0.2
                    };
                  }

                  const payloadStr = JSON.stringify(requestPayload);
                  const reqHeaders = await buildAuthHeaders(
                    currentCandidate,
                    env,
                    payloadStr,
                    {
                      userId: options.userId,
                      sessionId: envelope.session_id,
                      envelopeId: envelope.envelope_id,
                      roleId: node.role.role_id
                    }
                  );

                  const parsed = await callWithTimeout(async () => {
                    const fRes = await fetch(targetUrl, {
                      method: 'POST',
                      headers: reqHeaders,
                      body: payloadStr,
                      signal: abortController.signal
                    });

                    // Fail-fast on authentication/tampering violations (NEVER failover on security errors!)
                    if (fRes.status === 401 || fRes.status === 403) {
                      const errText = await fRes.text().catch(() => '');
                      throw new Error(`[SECURITY_REJECTED] 算力网关鉴权拒绝 (HTTP ${fRes.status}): ${errText}`);
                    }

                    if (!fRes.ok) {
                      const errText = await fRes.text().catch(() => '');
                      throw new Error(`HTTP ${fRes.status}: ${errText || fRes.statusText}`);
                    }

                    if (isTailNode && fRes.body) {
                      return await parseAIResponse(fRes.body, (chunkText) => {
                        if (chunkText) {
                          didStreamChunks = true;
                          hasEmittedTokens = true;
                          sendEvent('text_chunk', {
                            role_id: node.role.role_id,
                            chunk: chunkText,
                            cache_hit: false
                          });
                        }
                      });
                    } else {
                      const jsonRes = await fRes.json();
                      return await parseAIResponse(jsonRes);
                    }
                  }, 45000);

                  if (parsed && parsed.length > 5) {
                    nodeOutput = parsed;
                    actualExecutingModel = currentCandidate;
                    isExecutionSuccess = true;
                    break;
                  } else {
                    candidateErrors.push(`[${currentCandidate.display_name}]: 输出过短或空 (len=${parsed?.length || 0})`);
                  }
                } else if (endpoint.includes('moondream') && imageB64) {
                  // Moondream 3.1 Vision Language Model (MoE 9B/2B active)
                  const aiRes = await callWithTimeout(
                    () => env.AI.run(endpoint as any, {
                      task: 'query',
                      prompt: promptContent,
                      image: imageB64
                    }),
                    35000
                  );
                  const parsed = await parseAIResponse(aiRes);
                  if (parsed && parsed.length > 5) {
                    nodeOutput = parsed;
                    actualExecutingModel = currentCandidate;
                    isExecutionSuccess = true;
                    break;
                  } else {
                    candidateErrors.push(`[${currentCandidate.display_name}]: 解析输出过短或空 (len=${parsed?.length || 0})`);
                  }
                } else if (endpoint.includes('llava') && imageBytes) {
                  // LLaVA 1.5 7B Vision Model
                  const aiRes = await callWithTimeout(
                    () => env.AI.run(endpoint as any, {
                      prompt: promptContent,
                      image: imageBytes,
                      max_tokens: 512
                    }),
                    40000
                  );
                  const parsed = await parseAIResponse(aiRes);
                  if (parsed && parsed.length > 5) {
                    nodeOutput = parsed;
                    actualExecutingModel = currentCandidate;
                    isExecutionSuccess = true;
                    break;
                  } else {
                    candidateErrors.push(`[${currentCandidate.display_name}]: 解析输出过短或空 (len=${parsed?.length || 0})`);
                  }
                } else if (isImageNode && imageBytes) {
                  // Other Workers AI Vision models (e.g. LLaMA Vision)
                  const aiRes = await callWithTimeout(
                    () => env.AI.run(endpoint as any, {
                      prompt: promptContent,
                      image: imageBytes,
                      max_tokens: 512
                    }),
                    40000
                  );
                  const parsed = await parseAIResponse(aiRes);
                  if (parsed && parsed.length > 5) {
                    nodeOutput = parsed;
                    actualExecutingModel = currentCandidate;
                    isExecutionSuccess = true;
                    break;
                  } else {
                    candidateErrors.push(`[${currentCandidate.display_name}]: 解析输出过短或空 (len=${parsed?.length || 0})`);
                  }
                } else if (!isImageNode && endpoint.startsWith('@cf/')) {
                  // Text Model Execution with token-by-token streaming on tail node
                  const timeoutMs = endpoint.includes('qwq') ? 45000 : 35000;
                  const aiRes = await callWithTimeout(
                    () => env.AI.run(endpoint as any, {
                      messages: [
                        { role: 'system', content: systemPrompt },
                        { role: 'user', content: promptContent }
                      ],
                      stream: isTailNode,
                      max_tokens: 2560,
                      temperature: 0.2
                    }),
                    timeoutMs
                  );
                  const parsed = await parseAIResponse(aiRes, (chunkText) => {
                    if (isTailNode && chunkText) {
                      didStreamChunks = true;
                      sendEvent('text_chunk', {
                        role_id: node.role.role_id,
                        chunk: chunkText,
                        cache_hit: false
                      });
                    }
                  });
                  if (parsed && parsed.length > 5) {
                    nodeOutput = parsed;
                    actualExecutingModel = currentCandidate;
                    isExecutionSuccess = true;
                    break;
                  } else {
                    candidateErrors.push(`[${currentCandidate.display_name}]: 解析输出过短或空 (len=${parsed?.length || 0})`);
                  }
                }
              } catch (execErr: any) {
                if (execErr.message?.includes('[SECURITY_REJECTED]')) {
                  throw execErr;
                }
                candidateErrors.push(`[${currentCandidate.display_name}]: ${execErr.message}`);
                console.warn(`Node [${node.role.name_zh}] candidate [${currentCandidate.display_name}] failed/timed out:`, execErr.message);
                // Failover to next candidate in this role's arbitrated pool!
              }
            }

            // 6. Fail-Fast: If all Top-3 models in this role's pool failed, ABORT! NO ARBITRARY FALLBACK!
            if (!isExecutionSuccess || !nodeOutput.trim()) {
              throw new Error(`岗位【${node.role.name_zh}】的仲裁候选模型池（${candidateModels.map(m => m.display_name).join(', ')}）全部执行失败或超时。原因：${candidateErrors.join('；')}`);
            }

            // Stream output chunk (only tail node or single-node outputs directly to final answer, if not already streamed)
            if (isTailNode && !didStreamChunks) {
              sendEvent('text_chunk', {
                role_id: node.role.role_id,
                chunk: nodeOutput,
                cache_hit: false
              });
            }

            // CACHE GATEKEEPER:
            // ONLY store in deterministic cache if execution actually succeeded and produced substantial content!
            // NEVER cache errors, exceptions, or fallback placeholders!
            const isSuspiciousNoImage = nodeOutput.includes('Please provide the') || 
                                        nodeOutput.includes("ready to assist you") || 
                                        nodeOutput.includes("What's the task") ||
                                        nodeOutput.startsWith('[执行未响应') ||
                                        nodeOutput.startsWith('已基于输入完成');

            if (isExecutionSuccess && !isSuspiciousNoImage && nodeOutput.length > 20) {
              const actualCacheKey = (actualExecutingModel.model_id === node.selected_model.model_id)
                ? cacheKey
                : await computeDeterministicSignature(
                    node.role.role_id,
                    actualExecutingModel.model_id,
                    inputDigest,
                    fullPrompt
                  );
              await storeDeterministicCache(
                env,
                actualCacheKey,
                node.role.role_id,
                actualExecutingModel.model_id,
                inputDigest,
                fullPrompt,
                nodeOutput
              );
            }

            // Calculate cost (derived from actual executing model's cost)
            const nodeCost = Math.max(1, Math.round(actualExecutingModel.cost_per_1k_tokens || 1));
            totalCost += nodeCost;

            sendEvent('node_complete', {
              role_id: node.role.role_id,
              role_name: node.role.name_zh,
              role_name_en: node.role.name_en,
              model_id: actualExecutingModel.model_id,
              model_name: actualExecutingModel.display_name,
              was_failover: actualExecutingModel.model_id !== node.selected_model.model_id,
              node_index: idx,
              duration_ms: Date.now() - nodeStartTime,
              cache_hit: false,
              cost: nodeCost
            });
          }

          upstreamOutput = nodeOutput;
        }

        // 3. Settle billing atomically (preventing transaction tearing & race conditions)
        if (options.hasPreDeducted) {
          if (totalCost === 0) {
            // Full cache hit: refund the 1 reserved base credit
            await refundReservedCredit();
          } else {
            // totalCost >= 1: 1 credit was already pre-deducted at entry. Settle remaining delta and ledger in batch.
            const remainingCost = totalCost - 1;
            try {
              const ledgerId = crypto.randomUUID();
              const statements = [];
              if (remainingCost > 0) {
                statements.push(
                  env.DB.prepare(
                    "UPDATE users SET credits = MAX(0, credits - ?) WHERE user_id = ?"
                  ).bind(remainingCost, options.userId)
                );
              }
              statements.push(
                env.DB.prepare(
                  `INSERT INTO credit_ledger 
                   (ledger_id, user_id, category, amount, balance, title, detail, created_at)
                   VALUES (?, ?, 'compute_cost', ?, (SELECT credits FROM users WHERE user_id = ?), 'DAG智能编排调用', ?, datetime('now'))`
                ).bind(
                  ledgerId,
                  options.userId,
                  -totalCost,
                  options.userId,
                  `执行模板: ${dag.template.name_zh}`
                )
              );
              await env.DB.batch(statements);
            } catch (billingErr) {
              console.error("[Dispatcher] Failed to settle credits atomically:", billingErr);
            }
          }
        } else if (totalCost > 0) {
          try {
            const ledgerId = crypto.randomUUID();
            await env.DB.batch([
              env.DB.prepare(
                "UPDATE users SET credits = MAX(0, credits - ?) WHERE user_id = ?"
              ).bind(totalCost, options.userId),
              env.DB.prepare(
                `INSERT INTO credit_ledger 
                 (ledger_id, user_id, category, amount, balance, title, detail, created_at)
                 VALUES (?, ?, 'compute_cost', ?, (SELECT credits FROM users WHERE user_id = ?), 'DAG智能编排调用', ?, datetime('now'))`
              ).bind(
                ledgerId,
                options.userId,
                -totalCost,
                options.userId,
                `执行模板: ${dag.template.name_zh}`
              )
            ]);
          } catch (billingErr) {
            console.error("[Dispatcher] Failed to deduct credits atomically:", billingErr);
          }
        }

        // 4. DAG Complete
        sendEvent('dag_complete', {
          final_output: sanitizeLLMOutput(upstreamOutput),
          total_cost: totalCost,
          total_duration_ms: Date.now() - startTime,
          has_client_exec: dag.nodes.some(n => n.selected_model.inference_target === 'browser')
        });

      } catch (err: any) {
        if (isStreamCancelled || err.name === 'AbortError') {
          // Client disconnected early, cancel() callback already triggered refund if eligible
          return;
        }
        // Unconditionally release pre-deducted reservation if DAG fails to deliver end-to-end (All-or-Nothing delivery)
        await refundReservedCredit();
        sendEvent('dag_error', {
          error: err.message || 'Execution error'
        });
      } finally {
        if (heartbeatTimer) clearInterval(heartbeatTimer);
        try { controller.close(); } catch (e) {}
      }
    },
    async cancel(reason) {
      isStreamCancelled = true;
      if (heartbeatTimer) clearInterval(heartbeatTimer);
      try { abortController.abort(); } catch (e) {}
      // If user aborted before any real tokens were generated, release pre-deducted reservation
      if (options.hasPreDeducted && !hasEmittedTokens) {
        options.hasPreDeducted = false;
        try {
          await env.DB.prepare(
            "UPDATE users SET credits = credits + 1 WHERE user_id = ?"
          ).bind(options.userId).run();
        } catch (refundErr) {
          console.error("[Dispatcher] Failed to refund reserved credit on cancel:", refundErr);
        }
      }
    }
  });
}

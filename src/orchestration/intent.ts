// src/orchestration/intent.ts
import { Env } from "../types";
import {
  AssetBindMode,
  AssetBindingDecision,
  AssetDescriptor,
  ClarificationPromptInfo,
  IntentState,
  PerceptualCacheEntry,
  SessionAssetLedgerItem
} from "./types";

export type { IntentState };

export interface BranchCatalogItem {
  branch_id: string;
  topic?: string;
  is_media?: boolean;
  last_summary?: string;
  is_active?: boolean;
  lineage_asset_ids?: string[];
  head_commit_id?: string;
}

export interface MultiRoundIntentAssetOptions {
  hasNewUploads?: boolean;
  newUploadModalities?: string[];
  assets?: AssetDescriptor[];
  sessionAssetLedger?: SessionAssetLedgerItem[];
  activeBranchSummary?: string;
  activeBranchId?: string;
  branchCatalog?: BranchCatalogItem[];
  perceptualCache?: Record<string, PerceptualCacheEntry>;
  resolvedClarificationTargetBranchId?: string;
  candidateBudgetK?: number;
}

export interface RecalledAssetCandidate {
  asset_id: string;
  filename: string;
  modality: string;
  origin: "upload" | "generated";
  branch_id: string;
  introduced_round: number;
  source_digest?: string;
  summary_snippet?: string;
  has_cached_text: boolean;
  recall_score: number;
}

export interface IntentClassificationResult {
  intent: IntentState;
  targetBranchId?: string;
  sourceBranchIds?: string[];
  assetBindings?: AssetBindingDecision[];
  mountBranchSummaries?: string[];
  deliveryConfidence?: "clear" | "ambiguous";
  escalationUsed?: boolean;
  candidatePoolSize?: number;
  clarification?: ClarificationPromptInfo;
}

type RawJevBindChoice = AssetBindMode | "UNCERTAIN";

interface JointJevDecision {
  intent_op: IntentState;
  target_branch_id: string | null;
  source_branch_ids: string[];
  asset_bindings: Array<{ asset_id: string; bind_mode: RawJevBindChoice }>;
  uncertain_asset_ids?: string[];
  branch_confidence?: "clear" | "uncertain";
  delivery_confidence: "clear" | "ambiguous";
  needs_wider_recall: boolean;
}

const DEFAULT_CANDIDATE_BUDGET_K = 8;
export const MAX_JEV_ASSET_QUESTIONS = 10;

function normalizeModalityTag(m: string | undefined): string {
  if (!m) return "text_doc";
  return m === "pdf" ? "text_doc" : m;
}

function extractSearchTerms(text: string): string[] {
  const lower = (text || "").toLowerCase();
  const terms = new Set<string>();
  const words = lower.match(/[a-z0-9_.-]{2,}|[\u4e00-\u9fa5]{2,}/g) || [];
  for (const w of words) {
    terms.add(w);
    if (/^[\u4e00-\u9fa5]{3,}$/.test(w)) {
      for (let i = 0; i <= w.length - 2; i++) {
        terms.add(w.slice(i, i + 2));
      }
    }
  }
  return Array.from(terms);
}

function scoreCandidateRelevance(
  prompt: string,
  terms: string[],
  item: RecalledAssetCandidate,
  branchMap: Map<string, BranchCatalogItem>,
  activeBranchId: string,
  maxRound: number
): number {
  const branch = branchMap.get(item.branch_id);
  const haystack = [
    item.filename,
    item.modality,
    item.origin === "generated" ? "generated 生成 产出 效果图 海报 图片" : "upload 上传 原件",
    item.summary_snippet || "",
    branch?.topic || "",
    (branch?.last_summary || "").slice(0, 160)
  ]
    .join(" ")
    .toLowerCase();

  let score = 0;
  for (const term of terms) {
    if (haystack.includes(term)) score += term.length >= 4 ? 4 : 2.5;
  }

  const lowerPrompt = prompt.toLowerCase();
  if (
    item.modality === "image" &&
    /(图|画|海报|照片|视觉|配色|logo|设计|image|pic|photo|poster)/i.test(lowerPrompt)
  ) {
    score += 3;
  }
  if (
    item.modality === "audio" &&
    /(音|语音|录音|音频|听|口述|会议|audio|voice|speech)/i.test(lowerPrompt)
  ) {
    score += 3;
  }
  if (
    item.modality === "text_doc" &&
    /(文档|表格|csv|pdf|报告|预算|合同|doc|file|sheet)/i.test(lowerPrompt)
  ) {
    score += 3;
  }
  if (item.origin === "generated" && /(生成|刚才|上一张|那张|画的|效果图|改)/i.test(lowerPrompt)) {
    score += 2.5;
  }

  const roundDelta = Math.max(0, maxRound - (item.introduced_round || 1));
  score += Math.max(0, 2 - roundDelta * 0.4);
  if (item.branch_id === activeBranchId) {
    score += 1.5;
  }
  return score;
}

/**
 * Stage 0A: Local zero-latency cross-branch candidate retrieval.
 * Simultaneously evaluates active branch and all historical branches under bounded budget K (<= 10).
 */
export function recallCrossBranchCandidates(
  currentPrompt: string,
  assetOptions?: MultiRoundIntentAssetOptions
): {
  allHistorical: RecalledAssetCandidate[];
  recalled: RecalledAssetCandidate[];
} {
  const activeBranchId = assetOptions?.activeBranchId || "main";
  const branchCatalog = assetOptions?.branchCatalog || [];
  const branchMap = new Map<string, BranchCatalogItem>();
  branchCatalog.forEach((b) => branchMap.set(b.branch_id, b));
  const perceptualCache = assetOptions?.perceptualCache || {};
  const budgetK = Math.max(
    4,
    Math.min(MAX_JEV_ASSET_QUESTIONS, assetOptions?.candidateBudgetK ?? DEFAULT_CANDIDATE_BUDGET_K)
  );

  const seenIds = new Set<string>();
  const allHistorical: RecalledAssetCandidate[] = [];

  const registerItem = (
    raw: Partial<SessionAssetLedgerItem> & Partial<AssetDescriptor> & { asset_id: string }
  ) => {
    if (!raw.asset_id || seenIds.has(raw.asset_id)) return;
    seenIds.add(raw.asset_id);
    const cacheEntry = raw.source_digest ? perceptualCache[raw.source_digest] : undefined;
    const cachedText = raw.cached_perceptual_text || cacheEntry?.extracted_text || "";
    const snippet =
      raw.summary_snippet ||
      cacheEntry?.summary_snippet ||
      (cachedText ? cachedText.slice(0, 120).replace(/\s+/g, " ") : "");
    allHistorical.push({
      asset_id: raw.asset_id,
      filename: raw.filename || "attachment",
      modality: normalizeModalityTag(raw.modality),
      origin: raw.origin === "generated" ? "generated" : "upload",
      branch_id: raw.branch_id || activeBranchId,
      introduced_round: raw.introduced_round || 1,
      source_digest: raw.source_digest,
      summary_snippet: snippet || undefined,
      has_cached_text: cachedText.trim().length > 0,
      recall_score: 0
    });
  };

  for (const ledgerItem of assetOptions?.sessionAssetLedger || []) {
    registerItem(ledgerItem);
  }
  for (const manifestAsset of assetOptions?.assets || []) {
    if (!manifestAsset.is_new) {
      registerItem(manifestAsset);
    }
  }

  if (allHistorical.length === 0) {
    return { allHistorical: [], recalled: [] };
  }

  const maxRound = Math.max(...allHistorical.map((a) => a.introduced_round || 1));
  const terms = extractSearchTerms(currentPrompt);
  for (const item of allHistorical) {
    item.recall_score = scoreCandidateRelevance(
      currentPrompt,
      terms,
      item,
      branchMap,
      activeBranchId,
      maxRound
    );
  }

  if (allHistorical.length <= budgetK) {
    return {
      allHistorical,
      recalled: [...allHistorical].sort((a, b) => b.recall_score - a.recall_score)
    };
  }

  // Reserve up to 3 slots for latest active-branch assets; fill rest globally across ALL branches
  const selectedIds = new Set<string>();
  const recalled: RecalledAssetCandidate[] = [];
  const activeBranchItems = allHistorical
    .filter((a) => a.branch_id === activeBranchId)
    .sort((a, b) => b.introduced_round - a.introduced_round || b.recall_score - a.recall_score);

  for (const item of activeBranchItems.slice(0, Math.min(3, Math.floor(budgetK / 3)))) {
    selectedIds.add(item.asset_id);
    recalled.push(item);
  }

  const globalRanked = [...allHistorical].sort(
    (a, b) => b.recall_score - a.recall_score || b.introduced_round - a.introduced_round
  );
  for (const item of globalRanked) {
    if (recalled.length >= budgetK) break;
    if (!selectedIds.has(item.asset_id)) {
      selectedIds.add(item.asset_id);
      recalled.push(item);
    }
  }

  return { allHistorical, recalled };
}

function selectExpandedShortlist(
  allHistorical: RecalledAssetCandidate[],
  alreadyRecalled: RecalledAssetCandidate[],
  currentPrompt: string
): RecalledAssetCandidate[] {
  const alreadyIds = new Set(alreadyRecalled.map((a) => a.asset_id));
  const mentionsImage = /(图|画|海报|照片|视觉|poster|image)/i.test(currentPrompt);
  const mentionsAudio = /(音|录音|语音|audio|voice)/i.test(currentPrompt);
  const mentionsGenerated = /(生成|刚才画|上一张|效果图)/i.test(currentPrompt);

  return [...allHistorical]
    .map((item) => {
      let boost = 0;
      if (!alreadyIds.has(item.asset_id)) boost += 3.0; // Prioritize unexamined candidates during expansion
      if (mentionsImage && item.modality === "image") boost += 2.5;
      if (mentionsAudio && item.modality === "audio") boost += 2.5;
      if (mentionsGenerated && item.origin === "generated") boost += 2.5;
      return { item, score: item.recall_score + boost };
    })
    .sort((a, b) => b.score - a.score || b.item.introduced_round - a.item.introduced_round)
    .slice(0, MAX_JEV_ASSET_QUESTIONS)
    .map((x) => x.item);
}

function extractJevChoice(jevRes: any, questionKey: string): string | undefined {
  const ans =
    jevRes?.result?.answers?.[questionKey] ||
    jevRes?.answers?.[questionKey] ||
    jevRes?.[questionKey];
  if (!ans || typeof ans !== "object") return undefined;
  return ans.choice || ans.decision;
}

function buildStateBlock(
  currentPrompt: string,
  newUploads: AssetDescriptor[],
  recalledAssets: RecalledAssetCandidate[],
  branchCatalog: BranchCatalogItem[],
  activeBranchId: string,
  activeBranchSummary: string
): string {
  const activeBranch = branchCatalog.find((b) => b.branch_id === activeBranchId) || {
    branch_id: activeBranchId,
    topic: "当前任务",
    last_summary: activeBranchSummary,
    is_active: true
  };
  const otherBranches = branchCatalog.filter(
    (b) => b.branch_id !== activeBranchId && (b.last_summary || b.topic)
  );

  const newUploadStr =
    newUploads.length > 0
      ? newUploads
          .map(
            (a, i) =>
              `[新附件 ${i + 1}] id=${a.asset_id}, 文件="${a.filename || "attachment"}", 模态=${normalizeModalityTag(a.modality)}`
          )
          .join("; ")
      : "无";

  const candidateStr =
    recalledAssets.length > 0
      ? recalledAssets
          .map(
            (a, i) =>
              `[候选 ${i + 1}] id="${a.asset_id}", 文件="${a.filename}", 模态=${a.modality}, 来源=${a.origin === "generated" ? "AI生成产物" : "用户上传原件"}, 所属分支="${a.branch_id}", 轮次=${a.introduced_round}, L1文本缓存=${a.has_cached_text ? "有" : "无"}${a.summary_snippet ? `, 内容摘要="${a.summary_snippet}"` : ""}`
          )
          .join("\n  ")
      : "无历史候选资产";

  const otherBranchesStr =
    otherBranches.length > 0
      ? otherBranches
          .map(
            (b) =>
              `  * 分支 "${b.branch_id}": 主题="${b.topic || "历史任务"}", 最新产物="${(b.last_summary || "").slice(0, 160).replace(/\s+/g, " ")}"`
          )
          .join("\n")
      : "  无其它历史分支";

  return `[会话Git状态账本]
- 当前活跃分支: "${activeBranch.branch_id}" (主题: "${activeBranch.topic || "当前任务"}")
- 当前分支最新产物摘要: "${(activeBranch.last_summary || activeBranchSummary || "无").slice(0, 260).replace(/\s+/g, " ")}"
- 本轮新上传附件: ${newUploadStr}
- 跨分支检索候选资产清册 (${recalledAssets.length} 份):
  ${candidateStr}
- 其它历史分支目录:
${otherBranchesStr}

[用户最新指令]: ${currentPrompt}`;
}

async function runJointJevPass(
  env: Env,
  currentPrompt: string,
  newUploads: AssetDescriptor[],
  recalledAssets: RecalledAssetCandidate[],
  branchCatalog: BranchCatalogItem[],
  activeBranchId: string,
  activeBranchSummary: string
): Promise<JointJevDecision | null> {
  if (!env.AI) return null;

  // Enforce fixed per-pass budget so bind_* questions are NEVER dropped
  const scopedCandidates = recalledAssets.slice(0, MAX_JEV_ASSET_QUESTIONS);
  const stateBlock = buildStateBlock(
    currentPrompt,
    newUploads,
    scopedCandidates,
    branchCatalog,
    activeBranchId,
    activeBranchSummary
  );

  const hasNewUploads = newUploads.length > 0;
  const otherBranches = branchCatalog.filter((b) => b.branch_id !== activeBranchId);
  const hasHistoricalMedia = scopedCandidates.some(
    (a) => a.modality === "image" || a.modality === "audio"
  );

  // 1. Primary: Native Clef-Flash multi-question joint choice
  try {
    const intentCriteria: Record<string, string> = {
      DETACH_RESET:
        "【正交全新独立任务】：开启完全独立的新任务（即使伴随新附件），无需继承或结合任何历史分支产物或历史资产。"
    };
    if (!hasNewUploads) {
      intentCriteria.ANCHOR_TAIL =
        "【当前分支摘要延续】：属于当前活跃分支且上下文已自洽包含在当前分支最新产物摘要中，仅需文本层面加工或直接使用缓存摘要。";
      if (hasHistoricalMedia || scopedCandidates.length > 0) {
        intentCriteria.REBIND_ROOT =
          "【穿透回溯底层资产】：属于当前活跃分支（或指定资产），但产物摘要缺失细节，必须穿透重新读取底层原始图片/音频/文档。";
      }
    }
    if (otherBranches.length > 0 && !hasNewUploads) {
      intentCriteria.SWITCH_BRANCH =
        "【切回并推进历史分支】：脱离当前分支，转而回到某个历史分支继续修改或基于其历史资产开展后续任务。";
    }
    if (hasNewUploads || (scopedCandidates.length > 0 && otherBranches.length > 0)) {
      intentCriteria.CROSS_FUSION =
        "【跨轮/跨分支/多源融合】：将新附件或当前任务与历史分支产物、先前上传素材或先前回合生成资产进行对比、风格借鉴、融合修改。";
    }

    const questions: Record<string, any> = {
      intent_op: {
        type: "choice",
        instructions: "结合会话Git状态账本与用户最新指令，判定最准确的拓扑算子：",
        criteria: intentCriteria
      }
    };

    if (branchCatalog.length > 1) {
      const targetBranchCriteria: Record<string, string> = {
        __UNCERTAIN__: "自然语言无法明确区分应写入当前活跃分支还是历史分支，需向用户澄清确认"
      };
      branchCatalog.forEach((b) => {
        targetBranchCriteria[b.branch_id] =
          `${b.branch_id === activeBranchId ? "[当前活跃分支·参考/合并默认写回此分支] " : "[历史分支·明确要回到此分支修改时选此项] "}主题:${b.topic || "任务"} | 摘要:${(b.last_summary || "").slice(0, 90).replace(/\s+/g, " ")}`;
      });
      questions.target_branch = {
        type: "choice",
        instructions:
          "判断本次提交结果应写入哪一条分支（仅‘参考历史分支素材继续当前任务’选当前活跃分支；明确说‘回到那个分支继续改’选历史分支；无法确定则选 __UNCERTAIN__）：",
        criteria: targetBranchCriteria
      };
    }

    for (const asset of scopedCandidates) {
      questions[`bind_${asset.asset_id}`] = {
        type: "choice",
        instructions: `针对候选资产 "${asset.filename}" (${asset.modality}, ${asset.origin === "generated" ? "AI生成" : "上传原件"}, 分支:${asset.branch_id}) 的挂载方式：`,
        criteria: {
          RAW_MEDIA: "明确需要挂载原始介质/完整原件参与本轮直接感知对比",
          CACHED_TEXT: "无需重复读原件，直接复用已提取文本/摘要缓存即可",
          DROP: "明确与本轮用户指令无关，无需挂载",
          UNCERTAIN: "无法确定用户是否指代或依赖该资产，建议确认"
        }
      };
    }

    const jevRes = await env.AI.run("@cf/cloudflare/clef-flash", {
      state: stateBlock,
      questions
    });

    const parsedOp = extractJevChoice(jevRes, "intent_op") as IntentState | undefined;
    if (parsedOp) {
      const rawTargetChoice = extractJevChoice(jevRes, "target_branch");
      const branchConfidence = rawTargetChoice === "__UNCERTAIN__" ? "uncertain" : "clear";
      const chosenTargetBranch =
        rawTargetChoice && rawTargetChoice !== "__UNCERTAIN__" ? rawTargetChoice : activeBranchId;

      const assetBindings: Array<{ asset_id: string; bind_mode: RawJevBindChoice }> = [];
      const uncertainAssetIds: string[] = [];

      for (const asset of scopedCandidates) {
        const mode = extractJevChoice(jevRes, `bind_${asset.asset_id}`) as
          RawJevBindChoice | undefined;
        if (mode === "RAW_MEDIA" || mode === "CACHED_TEXT" || mode === "DROP") {
          assetBindings.push({ asset_id: asset.asset_id, bind_mode: mode });
        } else if (mode === "UNCERTAIN") {
          uncertainAssetIds.push(asset.asset_id);
          assetBindings.push({ asset_id: asset.asset_id, bind_mode: "UNCERTAIN" });
        } else if (parsedOp === "ANCHOR_TAIL") {
          assetBindings.push({
            asset_id: asset.asset_id,
            bind_mode: asset.has_cached_text ? "CACHED_TEXT" : "DROP"
          });
        } else if (parsedOp === "DETACH_RESET") {
          assetBindings.push({ asset_id: asset.asset_id, bind_mode: "DROP" });
        } else {
          // Do NOT blindly default missing answer on media/cross-fusion tasks to RAW_MEDIA!
          uncertainAssetIds.push(asset.asset_id);
          assetBindings.push({ asset_id: asset.asset_id, bind_mode: "UNCERTAIN" });
        }
      }

      const referencedBranches = new Set<string>();
      assetBindings.forEach((b) => {
        if (b.bind_mode === "RAW_MEDIA" || b.bind_mode === "CACHED_TEXT") {
          const match = scopedCandidates.find((a) => a.asset_id === b.asset_id);
          if (match && match.branch_id !== chosenTargetBranch) {
            referencedBranches.add(match.branch_id);
          }
        }
      });

      const isDeliveryAmbiguous = branchConfidence === "uncertain" || uncertainAssetIds.length > 0;

      return {
        intent_op: parsedOp,
        target_branch_id: parsedOp === "DETACH_RESET" ? null : chosenTargetBranch,
        source_branch_ids: Array.from(referencedBranches),
        asset_bindings: assetBindings,
        uncertain_asset_ids: uncertainAssetIds,
        branch_confidence: branchConfidence,
        delivery_confidence: isDeliveryAmbiguous ? "ambiguous" : "clear",
        needs_wider_recall: false
      };
    }
  } catch (clefErr) {
    console.warn("Clef-Flash joint JEV error, falling back to Llama-3.1-FP8:", clefErr);
  }

  // 2. Secondary High-Reliability Structured JSON Resolver: Llama-3.1-8B-FP8
  try {
    const systemPrompt = `You are the NanoMesh Joint Git-DAG Intent & Dependency Resolver.
Given the session Git branch catalog, recalled cross-branch assets (with origin: upload vs generated), new uploads, and the user's current instruction, output a strict JSON object:
{
  "intent_op": "ANCHOR_TAIL" | "REBIND_ROOT" | "SWITCH_BRANCH" | "CROSS_FUSION" | "DETACH_RESET",
  "target_branch_id": "<branch_id where this commit should be written, default activeBranchId unless user explicitly returns to another branch, or null for DETACH_RESET>",
  "source_branch_ids": ["<read-only evidence branch_ids used as reference in CROSS_FUSION>"],
  "asset_bindings": [{"asset_id": "<id>", "bind_mode": "RAW_MEDIA" | "CACHED_TEXT" | "DROP" | "UNCERTAIN"}],
  "branch_confidence": "clear" | "uncertain",
  "delivery_confidence": "clear" | "ambiguous",
  "needs_wider_recall": false
}

Rules:
1. Default CROSS_FUSION write target is the ACTIVE branch unless the user clearly states to return to and continue modifying the historical branch. If genuinely ambiguous between writing to active branch vs historical branch, set branch_confidence="uncertain" and delivery_confidence="ambiguous".
2. Only bind assets specifically relevant to the query. Use "DROP" for unrelated assets, "CACHED_TEXT" if textual facts/summaries suffice, "RAW_MEDIA" when raw visual/audio/file content must be inspected/fused, and "UNCERTAIN" if unsure whether an asset is required.
3. Set needs_wider_recall=true ONLY if the query refers to an asset or branch that does not appear in the recalled list.
Output JSON only.`;

    const aiResponse = await env.AI.run("@cf/meta/llama-3.1-8b-instruct-fp8", {
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: stateBlock }
      ],
      max_tokens: 340,
      temperature: 0.0
    });

    const rawText = aiResponse?.response || "";
    const jsonMatch = rawText.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const parsed = JSON.parse(jsonMatch[0]);
      const validOps: IntentState[] = [
        "ANCHOR_TAIL",
        "REBIND_ROOT",
        "SWITCH_BRANCH",
        "CROSS_FUSION",
        "DETACH_RESET"
      ];
      const op = String(parsed.intent_op || "").toUpperCase() as IntentState;
      if (validOps.includes(op)) {
        const uncertainIds: string[] = [];
        const normalizedBindings: Array<{ asset_id: string; bind_mode: RawJevBindChoice }> =
          Array.isArray(parsed.asset_bindings)
            ? parsed.asset_bindings
                .filter((x: any) => x && typeof x.asset_id === "string")
                .map((x: any) => {
                  const rawMode = String(x.bind_mode || "").toUpperCase();
                  if (rawMode === "UNCERTAIN") {
                    uncertainIds.push(x.asset_id);
                    return { asset_id: x.asset_id, bind_mode: "UNCERTAIN" as const };
                  }
                  const bind_mode: RawJevBindChoice =
                    rawMode === "RAW_MEDIA" || rawMode === "CACHED_TEXT" ? rawMode : "DROP";
                  return { asset_id: x.asset_id, bind_mode };
                })
            : [];

        const branchConf = parsed.branch_confidence === "uncertain" ? "uncertain" : "clear";
        const isAmbig =
          parsed.delivery_confidence === "ambiguous" ||
          branchConf === "uncertain" ||
          uncertainIds.length > 0;

        return {
          intent_op: op,
          target_branch_id:
            typeof parsed.target_branch_id === "string" ? parsed.target_branch_id : activeBranchId,
          source_branch_ids: Array.isArray(parsed.source_branch_ids)
            ? parsed.source_branch_ids.filter((id: any) => typeof id === "string")
            : [],
          asset_bindings: normalizedBindings,
          uncertain_asset_ids: uncertainIds,
          branch_confidence: branchConf,
          delivery_confidence: isAmbig ? "ambiguous" : "clear",
          needs_wider_recall: !!parsed.needs_wider_recall
        };
      }
    }
  } catch (llamaErr) {
    console.warn("Llama-3.1 structured joint JEV error:", llamaErr);
  }

  return null;
}

function shouldEscalateRecall(
  decision: JointJevDecision | null,
  currentPrompt: string,
  recalled: RecalledAssetCandidate[],
  allHistorical: RecalledAssetCandidate[]
): boolean {
  if (!decision) return false;
  if (allHistorical.length <= recalled.length) return false;
  if (decision.needs_wider_recall) return true;
  if (decision.uncertain_asset_ids && decision.uncertain_asset_ids.length > 0) return true;

  const mentionsImage = /(图|画|海报|照片|视觉|poster|image)/i.test(currentPrompt);
  const mentionsAudio = /(音|录音|语音|audio|voice)/i.test(currentPrompt);
  const mentionsGenerated = /(生成|刚才画|上一张|效果图)/i.test(currentPrompt);
  if (mentionsImage && !recalled.some((a) => a.modality === "image")) return true;
  if (mentionsAudio && !recalled.some((a) => a.modality === "audio")) return true;
  if (mentionsGenerated && !recalled.some((a) => a.origin === "generated")) return true;

  return false;
}

function buildClarificationCandidates(
  activeBranchId: string,
  sourceBranchIds: string[],
  branchCatalog: BranchCatalogItem[]
): Array<{ branch_id: string; topic: string; relation: "current" | "historical" }> {
  const branchMap = new Map(branchCatalog.map((b) => [b.branch_id, b]));
  const activeInfo = branchMap.get(activeBranchId);
  const targets: Array<{ branch_id: string; topic: string; relation: "current" | "historical" }> = [
    {
      branch_id: activeBranchId,
      topic: activeInfo?.topic || "当前活跃分支",
      relation: "current"
    }
  ];
  const seen = new Set<string>([activeBranchId]);
  for (const sid of sourceBranchIds) {
    if (!seen.has(sid)) {
      seen.add(sid);
      const info = branchMap.get(sid);
      targets.push({
        branch_id: sid,
        topic: info?.topic || sid,
        relation: "historical"
      });
    }
  }
  for (const b of branchCatalog) {
    if (targets.length >= 3) break;
    if (!seen.has(b.branch_id)) {
      seen.add(b.branch_id);
      targets.push({
        branch_id: b.branch_id,
        topic: b.topic || b.branch_id,
        relation: "historical"
      });
    }
  }
  return targets;
}

/**
 * Deterministic Graph Invariant Guard:
 * Validates asset existence, enforces DETACH_RESET isolation firewall,
 * guarantees new uploads stay RAW_MEDIA, and routes uncertain branch/assets into clarification
 * instead of silently mounting an entire branch.
 */
export function applyIntentInvariantGuard(
  rawDecision: JointJevDecision,
  newUploads: AssetDescriptor[],
  allHistorical: RecalledAssetCandidate[],
  branchCatalog: BranchCatalogItem[],
  activeBranchId: string,
  resolvedClarificationTargetBranchId?: string
): IntentClassificationResult {
  const validAssetIds = new Set(allHistorical.map((a) => a.asset_id));
  const historicalMap = new Map(allHistorical.map((a) => [a.asset_id, a]));
  const validBranchIds = new Set(branchCatalog.map((b) => b.branch_id));
  validBranchIds.add(activeBranchId);

  let intent = rawDecision.intent_op;
  let targetBranchId: string | undefined =
    rawDecision.target_branch_id && validBranchIds.has(rawDecision.target_branch_id)
      ? rawDecision.target_branch_id
      : activeBranchId;

  const isClarificationResolved = !!(
    resolvedClarificationTargetBranchId && validBranchIds.has(resolvedClarificationTargetBranchId)
  );
  if (isClarificationResolved) {
    targetBranchId = resolvedClarificationTargetBranchId;
    rawDecision.delivery_confidence = "clear";
    rawDecision.branch_confidence = "clear";
  }

  // Filter hallucinated IDs and separate explicit uncertain bindings
  const uncertainAssetIds = new Set<string>();
  const bindingMap = new Map<string, AssetBindMode>();
  for (const item of rawDecision.asset_bindings || []) {
    if (!validAssetIds.has(item.asset_id)) continue;
    if (item.bind_mode === "UNCERTAIN") {
      uncertainAssetIds.add(item.asset_id);
      if (isClarificationResolved) {
        // After user explicitly confirms target branch in clarification, drop unresolved unrelated assets safely or keep target branch
        bindingMap.set(item.asset_id, "DROP");
      }
    } else {
      bindingMap.set(item.asset_id, item.bind_mode);
    }
  }

  const newUploadBindings: AssetBindingDecision[] = newUploads.map((u) => ({
    asset_id: u.asset_id,
    bind_mode: "RAW_MEDIA"
  }));

  // Invariant 1: DETACH_RESET strictly drops all historical assets and branch summaries
  if (intent === "DETACH_RESET") {
    return {
      intent: "DETACH_RESET",
      targetBranchId: undefined,
      sourceBranchIds: [],
      assetBindings: newUploadBindings,
      mountBranchSummaries: [],
      deliveryConfidence: "clear"
    };
  }

  // Invariant 2: SWITCH_BRANCH when staying on active branch -> REBIND_ROOT or ANCHOR_TAIL
  if (intent === "SWITCH_BRANCH" && targetBranchId === activeBranchId) {
    const activeHasRaw = Array.from(bindingMap.values()).some((m) => m === "RAW_MEDIA");
    intent = activeHasRaw ? "REBIND_ROOT" : "ANCHOR_TAIL";
  }

  // Invariant 3: Ensure ANCHOR_TAIL does not leak RAW_MEDIA heavy assets
  if (intent === "ANCHOR_TAIL") {
    for (const [id, mode] of bindingMap.entries()) {
      const asset = historicalMap.get(id);
      if (
        asset &&
        (asset.modality === "image" || asset.modality === "audio") &&
        mode === "RAW_MEDIA"
      ) {
        bindingMap.set(id, asset.has_cached_text ? "CACHED_TEXT" : "DROP");
      }
    }
  }

  const finalBindings: AssetBindingDecision[] = [
    ...Array.from(bindingMap.entries()).map(([asset_id, bind_mode]) => ({ asset_id, bind_mode })),
    ...newUploadBindings
  ];

  // Collect evidence-only source branches (distinct from delivery targetBranchId)
  const evidenceSourceSet = new Set<string>(
    (rawDecision.source_branch_ids || []).filter(
      (id) => validBranchIds.has(id) && id !== targetBranchId
    )
  );
  for (const [assetId, mode] of bindingMap.entries()) {
    if (mode !== "DROP") {
      const asset = historicalMap.get(assetId);
      if (asset && asset.branch_id && asset.branch_id !== targetBranchId) {
        evidenceSourceSet.add(asset.branch_id);
      }
    }
  }
  const sourceBranchIds = Array.from(evidenceSourceSet);

  // Ambiguity / Uncertain Clarification Gate:
  // Trigger clarification whenever:
  // (a) branch_confidence === 'uncertain' or delivery_confidence === 'ambiguous' across branches;
  // (b) any required asset was marked UNCERTAIN;
  // (c) REBIND_ROOT has zero resolved non-DROP assets while target branch actually holds historical media.
  const targetHasHistoricalMedia = allHistorical.some(
    (a) => a.branch_id === targetBranchId && (a.modality === "image" || a.modality === "audio")
  );
  const resolvedHistoricalCount = Array.from(bindingMap.values()).filter(
    (m) => m !== "DROP"
  ).length;
  const missingMediaForRebind =
    intent === "REBIND_ROOT" && resolvedHistoricalCount === 0 && targetHasHistoricalMedia;

  const needsClarification =
    !isClarificationResolved &&
    (rawDecision.branch_confidence === "uncertain" ||
      uncertainAssetIds.size > 0 ||
      missingMediaForRebind ||
      (rawDecision.delivery_confidence === "ambiguous" &&
        intent === "CROSS_FUSION" &&
        sourceBranchIds.length > 0));

  let clarification: ClarificationPromptInfo | undefined;
  let deliveryConfidence: "clear" | "ambiguous" = "clear";

  if (needsClarification) {
    deliveryConfidence = "ambiguous";
    const candidates = buildClarificationCandidates(activeBranchId, sourceBranchIds, branchCatalog);
    const uncertainNames = Array.from(uncertainAssetIds)
      .map((id) => historicalMap.get(id)?.filename || id)
      .slice(0, 3);
    const branchMap = new Map(branchCatalog.map((b) => [b.branch_id, b]));
    const activeInfo = branchMap.get(activeBranchId);
    const otherId = sourceBranchIds[0];
    const otherInfo = otherId ? branchMap.get(otherId) : undefined;

    const reasonZh =
      uncertainNames.length > 0 || missingMediaForRebind
        ? `检测到您的指令可能依赖历史资产（${uncertainNames.join("、") || "底层多模态素材"}），当前置信度不足。请通过输入框说明要关联哪份素材或写入哪条分支：`
        : `检测到您结合了历史分支【${otherInfo?.topic || otherId || "其它分支"}】与当前分支【${activeInfo?.topic || activeBranchId}】。请确认本次结果应写入哪条分支：`;
    const reasonEn =
      uncertainNames.length > 0 || missingMediaForRebind
        ? `Unable to deterministically confirm required historical assets (${uncertainNames.join(", ") || "underlying media"}). Please clarify the asset or target branch in the input box:`
        : `Detected cross-branch fusion between [${otherInfo?.topic || otherId || "other"}] and current branch [${activeInfo?.topic || activeBranchId}]. Please confirm where to commit the result:`;

    clarification = {
      reason_zh: reasonZh,
      reason_en: reasonEn,
      candidate_targets: candidates,
      recalled_asset_ids: Array.from(
        new Set([
          ...finalBindings.filter((b) => b.bind_mode !== "DROP").map((b) => b.asset_id),
          ...Array.from(uncertainAssetIds)
        ])
      )
    };
  }

  const mountBranchSummaries = Array.from(
    new Set(
      [targetBranchId, ...sourceBranchIds].filter(
        (id): id is string => typeof id === "string" && !!id
      )
    )
  );

  return {
    intent,
    targetBranchId,
    sourceBranchIds,
    assetBindings: finalBindings,
    mountBranchSummaries,
    deliveryConfidence,
    clarification
  };
}

/**
 * Unified Stage 0 Multi-Round Intent & Asset Dependency Resolver:
 * - Stage 0A: Local cross-branch candidate retrieval (0ms, budget K <= 10)
 * - Stage 0B: Single Joint JEV decision over recalled pool & branch catalog
 * - Stage 0C: Targeted escalation re-scoring full history and capping shortlist at <= 10 questions
 * - Deterministic Graph Invariant Guard (fail to clarification on uncertainty; never silently DETACH_RESET)
 */
export async function classifyMultiRoundIntent(
  env: Env,
  currentPrompt: string,
  hasPreviousRound: boolean,
  previousRoundSummary?: string,
  hadMediaAssets?: boolean,
  assetOptions?: MultiRoundIntentAssetOptions
): Promise<IntentClassificationResult> {
  const assets = assetOptions?.assets || [];
  const newUploads = assets.filter((a) => a.is_new);

  if (!hasPreviousRound) {
    return {
      intent: "DETACH_RESET",
      sourceBranchIds: [],
      assetBindings: newUploads.map((a) => ({ asset_id: a.asset_id, bind_mode: "RAW_MEDIA" })),
      mountBranchSummaries: [],
      deliveryConfidence: "clear",
      escalationUsed: false,
      candidatePoolSize: 0
    };
  }

  const activeBranchId = assetOptions?.activeBranchId || "main";
  const activeBranchSummary = assetOptions?.activeBranchSummary || previousRoundSummary || "";
  const branchCatalog: BranchCatalogItem[] =
    assetOptions?.branchCatalog && assetOptions.branchCatalog.length > 0
      ? assetOptions.branchCatalog
      : [
          {
            branch_id: activeBranchId,
            topic: "当前任务",
            is_media: !!hadMediaAssets,
            last_summary: activeBranchSummary,
            is_active: true
          }
        ];

  // Stage 0A: Local Cross-Branch Candidate Recall
  const { allHistorical, recalled } = recallCrossBranchCandidates(currentPrompt, assetOptions);

  // Stage 0B: Single Joint JEV Classification
  let decision = await runJointJevPass(
    env,
    currentPrompt,
    newUploads,
    recalled,
    branchCatalog,
    activeBranchId,
    activeBranchSummary
  );

  // Stage 0C: Targeted Escalation Gate (re-rank full history and slice fixed <= 10 shortlist)
  let escalationUsed = false;
  if (shouldEscalateRecall(decision, currentPrompt, recalled, allHistorical)) {
    escalationUsed = true;
    const expandedShortlist = selectExpandedShortlist(allHistorical, recalled, currentPrompt);
    const escalatedDecision = await runJointJevPass(
      env,
      currentPrompt,
      newUploads,
      expandedShortlist,
      branchCatalog,
      activeBranchId,
      activeBranchSummary
    );
    if (escalatedDecision) {
      decision = escalatedDecision;
    }
  }

  // If user already resolved clarification explicitly and AI failed, continue cleanly on confirmed branch
  if (!decision && assetOptions?.resolvedClarificationTargetBranchId) {
    const resolvedBranch = assetOptions.resolvedClarificationTargetBranchId;
    const scoped = allHistorical
      .filter((a) => a.branch_id === resolvedBranch)
      .slice(0, MAX_JEV_ASSET_QUESTIONS)
      .map((a) => ({
        asset_id: a.asset_id,
        bind_mode: (a.has_cached_text ? "CACHED_TEXT" : "RAW_MEDIA") as AssetBindMode
      }));
    return {
      intent: newUploads.length > 0 ? "CROSS_FUSION" : "ANCHOR_TAIL",
      targetBranchId: resolvedBranch,
      sourceBranchIds: [],
      assetBindings: [
        ...scoped,
        ...newUploads.map((u) => ({ asset_id: u.asset_id, bind_mode: "RAW_MEDIA" as const }))
      ],
      mountBranchSummaries: [resolvedBranch],
      deliveryConfidence: "clear",
      escalationUsed,
      candidatePoolSize: recalled.length
    };
  }

  if (!decision) {
    // When hasPreviousRound is true and intent classifier failed completely, do NOT auto-fork via DETACH_RESET!
    // Enter 0-credit clarification so the user explicitly confirms continuation/switch/new task.
    const candidates = buildClarificationCandidates(activeBranchId, [], branchCatalog);
    return {
      intent: "ANCHOR_TAIL",
      targetBranchId: activeBranchId,
      sourceBranchIds: [],
      assetBindings: newUploads.map((a) => ({ asset_id: a.asset_id, bind_mode: "RAW_MEDIA" })),
      mountBranchSummaries: [activeBranchId],
      deliveryConfidence: "ambiguous",
      escalationUsed,
      candidatePoolSize: recalled.length,
      clarification: {
        reason_zh:
          "意图识别服务暂时未能确定该指令是否沿用当前分支、切换历史分支或开启新任务。请在下方确认您希望写入的目标分支：",
        reason_en:
          "Intent classifier could not safely resolve branch/asset dependencies. Please confirm the target branch below to continue:",
        candidate_targets: candidates,
        recalled_asset_ids: recalled.map((a) => a.asset_id)
      }
    };
  }

  const guarded = applyIntentInvariantGuard(
    decision,
    newUploads,
    allHistorical,
    branchCatalog,
    activeBranchId,
    assetOptions?.resolvedClarificationTargetBranchId
  );

  return {
    ...guarded,
    escalationUsed,
    candidatePoolSize: recalled.length
  };
}

import { Env } from "../types";
import { BranchCatalogItem, classifyMultiRoundIntent, IntentState } from "./intent";
import { hardFilterModels, filterTemplatesBySubsistence } from "./subsistence";
import {
  rankCandidateTemplates,
  resolveRoleCompetence,
  SENTINEL_UNREACHABLE_TEMPLATE_ID,
  SENTINEL_UNREACHABLE_TEMPLATE
} from "./competence";
import { generatePromptEmbedding, scoreAndRankRoleModels } from "./scoring";
import { performGatewaySafetyAudit } from "./safety";
import {
  AssetBindingDecision,
  AssetDescriptor,
  ClarificationPromptInfo,
  DAGRole,
  DAGTemplate,
  InheritedContextSlice,
  InstantiatedDAG,
  InstantiatedDAGNode,
  ModelMetadata,
  PerceptualCacheEntry,
  SessionAssetLedgerItem,
  TopologyStageGroup,
  UnifiedProtocolEnvelope
} from "./types";

export interface OrchestrationOptions {
  reRouteMode?: "normal" | "switch_template" | "switch_model";
  continuationMode?: boolean;
  chosenTemplateId?: string;
  chosenRoleModels?: Record<string, string>; // role_id or node_id -> model_id
  customRolePrompts?: Record<string, string>; // role_id or node_id -> custom_prompt
  customNodePrompt?: string; // fallback single node custom prompt
  hasPreviousRound?: boolean;
  previousRoundSummary?: string;
  hadMediaAssets?: boolean;
  hasNewUploads?: boolean;
  newUploadModalities?: string[];
  sessionAssetLedger?: SessionAssetLedgerItem[];
  activeBranchId?: string;
  activeBranchSummary?: string;
  branchCatalog?: BranchCatalogItem[];
  perceptualCache?: Record<string, PerceptualCacheEntry>;
  resolvedClarificationTargetBranchId?: string;
  candidateBudgetK?: number;
  frozenResolvedPlan?: {
    intent_state?: IntentState | null;
    target_branch_id?: string;
    source_branch_ids?: string[];
    inherited_context_slices?: InheritedContextSlice[];
    mounted_asset_bindings?: AssetBindingDecision[];
  };
  disableBrowserInference?: boolean;
}

function hydrateManifestFromBindings(
  currentManifest: AssetDescriptor[],
  mountedAssetBindings: AssetBindingDecision[],
  sessionAssetLedger: SessionAssetLedgerItem[],
  perceptualCache: Record<string, PerceptualCacheEntry>,
  intentState: IntentState | null
): AssetDescriptor[] {
  const findObjectiveCacheHit = (digest?: string): string => {
    if (!digest) return "";
    const direct = perceptualCache[digest];
    if (
      direct &&
      direct.extracted_text &&
      (!direct.task_scope || direct.task_scope === "objective_full")
    ) {
      return direct.extracted_text;
    }
    const matches = Object.values(perceptualCache)
      .filter(
        (entry) =>
          entry &&
          entry.source_digest === digest &&
          entry.extracted_text &&
          (!entry.task_scope || entry.task_scope === "objective_full")
      )
      .sort((a, b) => (b.updated_at || 0) - (a.updated_at || 0));
    return matches[0]?.extracted_text || "";
  };

  const bindingMap = new Map<string, AssetBindingDecision["bind_mode"]>();
  mountedAssetBindings.forEach((b) => bindingMap.set(b.asset_id, b.bind_mode));

  const boundManifest: AssetDescriptor[] = [];
  for (const asset of currentManifest) {
    if (asset.is_new) {
      boundManifest.push({ ...asset, bind_mode: "RAW_MEDIA", consumed: false });
      continue;
    }
    const mode = bindingMap.get(asset.asset_id);
    if (!mode || mode === "DROP") {
      continue;
    }
    const cachedText = asset.cached_perceptual_text || findObjectiveCacheHit(asset.source_digest);
    if (
      mode === "CACHED_TEXT" &&
      !cachedText &&
      (asset.modality === "image" || asset.modality === "audio") &&
      intentState === "ANCHOR_TAIL"
    ) {
      continue;
    }
    boundManifest.push({
      ...asset,
      bind_mode: mode,
      cached_perceptual_text: cachedText || asset.cached_perceptual_text,
      consumed: false
    });
  }

  // Synthesize recalled ledger assets missing from client manifest (e.g. cross-branch recall or reRoute)
  const presentIds = new Set(boundManifest.map((a) => a.asset_id));
  for (const [assetId, mode] of bindingMap.entries()) {
    if (mode === "DROP" || presentIds.has(assetId)) continue;
    const ledgerItem = sessionAssetLedger.find((l) => l.asset_id === assetId);
    if (ledgerItem) {
      const cachedText =
        ledgerItem.cached_perceptual_text || findObjectiveCacheHit(ledgerItem.source_digest);
      boundManifest.push({
        asset_id: ledgerItem.asset_id,
        filename: ledgerItem.filename,
        modality: ledgerItem.modality,
        mime_type: ledgerItem.mime_type || "application/octet-stream",
        file_size: ledgerItem.file_size || 0,
        r2_key: ledgerItem.r2_key,
        source_digest: ledgerItem.source_digest || ledgerItem.r2_key || ledgerItem.asset_id,
        branch_id: ledgerItem.branch_id,
        origin: ledgerItem.origin,
        introduced_round: ledgerItem.introduced_round,
        bind_mode: mode,
        cached_perceptual_text: cachedText || undefined,
        in_memory_text: ledgerItem.in_memory_text,
        consumed: false
      });
    }
  }

  return boundManifest;
}

function safeJsonParse<T>(raw: any, fallback: T): T {
  if (!raw) return fallback;
  if (typeof raw !== "string") return raw;
  try {
    return JSON.parse(raw);
  } catch (e) {
    try {
      const cleaned = raw.replace(/\\#/g, "#").replace(/\\([,\[\]])/g, "$1");
      if (cleaned.startsWith("[") && !cleaned.includes('"')) {
        const parts = cleaned
          .slice(1, -1)
          .split(",")
          .map((s: string) => s.trim().replace(/^['"]|['"]$/g, ""))
          .filter(Boolean);
        return parts as any;
      }
      return JSON.parse(cleaned);
    } catch (e2) {
      return fallback;
    }
  }
}

function sanitizeNodeId(raw: string): string {
  return (raw || "item").replace(/[^a-zA-Z0-9_-]/g, "_").slice(0, 32);
}

function createSystemNoticeModel(id: string, name: string, status: string): ModelMetadata {
  return {
    model_id: id,
    display_name: name,
    provider: "NanoMesh Gateway",
    endpoint: "",
    modalities: ["text"],
    tags: [status],
    context_window: 4096,
    max_concurrency: 0,
    active_connections: 0,
    precision: 1,
    user_rating: 5,
    usage_count: 0,
    cost_per_1k_tokens: 0,
    status,
    is_generalist: 0,
    prior_score: 0,
    scenario_anchors: []
  };
}

function createUnreachableDAG(
  isReRoute: boolean,
  intentState: IntentState | null,
  targetBranchId: string | undefined,
  subsistenceCount: number,
  extraTrace: Partial<InstantiatedDAG["reasoning_trace"]> = {}
): InstantiatedDAG {
  const unreachableRole: DAGRole = {
    role_id: "role_unreachable",
    name_zh: "∅ 意图不可达",
    name_en: "∅ Unreachable",
    in_modalities: ["text"],
    out_modalities: ["text"],
    in_degree: 0,
    out_degree: 0,
    requisition_tags: ["unreachable"]
  };
  const unreachableModel = createSystemNoticeModel(
    "model_unreachable",
    "Unreachable",
    "unreachable"
  );

  return {
    template: SENTINEL_UNREACHABLE_TEMPLATE,
    candidate_templates: [],
    nodes: [
      {
        node_id: "node_unreachable",
        stage_group: "synthesis_output",
        depends_on: ["__ORIGIN__"],
        role: unreachableRole,
        selected_model: unreachableModel,
        standby_models: [],
        score_details: {
          model: unreachableModel,
          score: 0,
          sim: 0,
          concurrency_penalty: 0,
          specialist_score: 0
        },
        downgraded: false,
        claimed_assets: []
      }
    ],
    reasoning_trace: {
      intent_state: isReRoute ? null : intentState,
      target_branch_id: isReRoute ? undefined : targetBranchId,
      is_multi_round: !isReRoute && !!intentState,
      subsistence_filtered_count: subsistenceCount,
      selected_template_id: SENTINEL_UNREACHABLE_TEMPLATE_ID,
      downgrade_events: [],
      ...extraTrace
    },
    is_unreachable: true
  };
}

function createClarificationDAG(
  clarification: ClarificationPromptInfo,
  intentState: IntentState | null,
  targetBranchId: string | undefined,
  extraTrace: Partial<InstantiatedDAG["reasoning_trace"]> = {}
): InstantiatedDAG {
  const clarifyRole: DAGRole = {
    role_id: "role_branch_clarification",
    name_zh: "🔀 分支交付确认",
    name_en: "🔀 Branch Delivery Confirmation",
    in_modalities: ["text"],
    out_modalities: ["text"],
    in_degree: 0,
    out_degree: 0,
    requisition_tags: ["clarification"]
  };
  const clarifyModel = createSystemNoticeModel(
    "model_branch_clarifier",
    "Intent Clarifier",
    "clarification"
  );

  return {
    template: {
      template_id: "tpl_branch_clarification",
      name_zh: "分支写入目标确认",
      name_en: "Branch Target Clarification",
      desc_zh: clarification.reason_zh,
      desc_en: clarification.reason_en,
      head_modalities: ["text"],
      tail_modalities: ["text"],
      roles: [clarifyRole],
      priority: 0,
      status: "clarification"
    },
    candidate_templates: [],
    nodes: [
      {
        node_id: "node_clarification",
        stage_group: "synthesis_output",
        depends_on: ["__ORIGIN__"],
        role: clarifyRole,
        selected_model: clarifyModel,
        standby_models: [],
        score_details: {
          model: clarifyModel,
          score: 1,
          sim: 1,
          concurrency_penalty: 0,
          specialist_score: 0
        },
        downgraded: false,
        claimed_assets: []
      }
    ],
    reasoning_trace: {
      intent_state: intentState,
      target_branch_id: targetBranchId,
      is_multi_round: true,
      subsistence_filtered_count: 0,
      selected_template_id: "tpl_branch_clarification",
      downgrade_events: [],
      ...extraTrace
    },
    is_clarification_required: true,
    clarification
  };
}

async function instantiateNodeWithCompetence(
  role: DAGRole,
  candidateModels: ModelMetadata[],
  env: Env,
  promptEmbedding: number[] | null,
  pureDirective: string,
  envelope: UnifiedProtocolEnvelope,
  options: OrchestrationOptions,
  downgradeEvents: Array<{ role_id: string; original_tag: string; fallback_tag: string }>,
  nodeId: string,
  stageGroup: TopologyStageGroup,
  dependsOn: string[],
  claimedAssets: AssetDescriptor[] = [],
  extraProps: Partial<InstantiatedDAGNode> = {}
): Promise<InstantiatedDAGNode> {
  const roleResolution = resolveRoleCompetence(role, candidateModels);
  if (roleResolution.downgradeEvent) {
    downgradeEvents.push({ role_id: role.role_id, ...roleResolution.downgradeEvent });
  }

  const chosenModelId =
    options.chosenRoleModels?.[nodeId] || options.chosenRoleModels?.[role.role_id];
  const nodeCustomPrompt =
    options.customRolePrompts?.[nodeId] !== undefined
      ? options.customRolePrompts[nodeId]
      : options.customRolePrompts?.[role.role_id] !== undefined
        ? options.customRolePrompts[role.role_id]
        : options.customNodePrompt && !options.customRolePrompts
          ? options.customNodePrompt
          : "";

  if (options.reRouteMode === "switch_model") {
    let primaryModel: ModelMetadata;
    if (chosenModelId) {
      const customModel = roleResolution.selectedModels.find((m) => m.model_id === chosenModelId);
      if (customModel) {
        primaryModel = customModel;
      } else {
        console.warn(
          `[Orchestrator] Model [${chosenModelId}] is not competent for role [${role.role_id}], falling back to [${roleResolution.selectedModels[0]?.model_id}]`
        );
        primaryModel = roleResolution.selectedModels[0];
      }
    } else {
      primaryModel = roleResolution.selectedModels[0];
    }

    const standbyModels = roleResolution.selectedModels
      .filter((m) => m.model_id !== primaryModel.model_id)
      .slice(0, 6);

    return {
      node_id: nodeId,
      stage_group: stageGroup,
      depends_on: dependsOn,
      role,
      selected_model: primaryModel,
      standby_models: standbyModels,
      score_details: {
        model: primaryModel,
        score: 1.0,
        sim: 1.0,
        concurrency_penalty: 0,
        specialist_score: 1.0
      },
      downgraded: roleResolution.downgraded,
      compensation_prompt: roleResolution.compensationPrompt,
      custom_prompt: nodeCustomPrompt,
      claimed_assets: claimedAssets,
      ...extraProps
    };
  }

  const scoredModels = await scoreAndRankRoleModels(
    env,
    roleResolution.selectedModels,
    promptEmbedding,
    pureDirective,
    envelope.session_id,
    envelope.metadata?.estimated_input_tokens || 512
  );

  if (scoredModels.length === 0) {
    throw new Error(`岗位 [${role.name_zh}] 未能选出可用模型。`);
  }

  let primaryModel = scoredModels[0].model;
  if (chosenModelId) {
    const customModelMatch = roleResolution.selectedModels.find(
      (m) => m.model_id === chosenModelId
    );
    if (customModelMatch) {
      primaryModel = customModelMatch;
    }
  }

  const standbyModels = scoredModels
    .map((sm) => sm.model)
    .filter((m) => m.model_id !== primaryModel.model_id)
    .slice(0, 6);

  return {
    node_id: nodeId,
    stage_group: stageGroup,
    depends_on: dependsOn,
    role,
    selected_model: primaryModel,
    standby_models: standbyModels,
    score_details: scoredModels[0],
    downgraded: roleResolution.downgraded,
    compensation_prompt: roleResolution.compensationPrompt,
    custom_prompt: nodeCustomPrompt,
    claimed_assets: claimedAssets,
    ...extraProps
  };
}

function selectSensoryRoleForModality(
  modality: "image" | "audio",
  roleMap: Map<string, DAGRole>,
  allTemplates: DAGTemplate[]
): DAGRole {
  const fromMap = Array.from(roleMap.values()).find(
    (r) => r.in_modalities.includes(modality) && r.out_modalities.includes("text")
  );
  if (fromMap) {
    return { ...fromMap, in_degree: 0, out_degree: 1 };
  }
  for (const tpl of allTemplates) {
    const found = tpl.roles.find(
      (r) => r.in_modalities.includes(modality) && r.out_modalities.includes("text")
    );
    if (found) {
      return { ...found, in_degree: 0, out_degree: 1 };
    }
  }
  return modality === "image"
    ? {
        role_id: "role-vision-extractor",
        name_zh: "视觉元素与文字提取",
        name_en: "Vision & OCR Extraction",
        in_modalities: ["image"],
        out_modalities: ["text"],
        in_degree: 0,
        out_degree: 1,
        requisition_tags: ["#ocr_precise", "#multimodal_vision", "#general_vlm"]
      }
    : {
        role_id: "role-audio-asr",
        name_zh: "语音转录提取",
        name_en: "Speech Recognition",
        in_modalities: ["audio"],
        out_modalities: ["text"],
        in_degree: 0,
        out_degree: 1,
        requisition_tags: ["#asr", "#audio_processing"]
      };
}

function selectTemplateFromPool(
  pool: DAGTemplate[],
  options: OrchestrationOptions,
  pureDirective: string,
  userModalities: string[],
  env: Env
): Promise<{ selectedTemplate: DAGTemplate; candidateTop3: DAGTemplate[] }> {
  if (options.reRouteMode === "switch_template" && options.chosenTemplateId) {
    const found = pool.find((t) => t.template_id === options.chosenTemplateId);
    if (!found) {
      return Promise.reject(
        new Error(`指定的模板 [${options.chosenTemplateId}] 无法适配当前任务的输入模态或已被下线`)
      );
    }
    return Promise.resolve({
      selectedTemplate: found,
      candidateTop3: [found, ...pool.filter((t) => t.template_id !== found.template_id)].slice(0, 3)
    });
  }

  if (options.reRouteMode === "switch_model" && options.chosenTemplateId) {
    const found = pool.find((t) => t.template_id === options.chosenTemplateId);
    if (!found) {
      return Promise.reject(
        new Error(
          `当前基础模板 [${options.chosenTemplateId}] 无法适配当前任务的输入模态或已被下线，请先切换可用模板`
        )
      );
    }
    return Promise.resolve({
      selectedTemplate: found,
      candidateTop3: [found, ...pool.filter((t) => t.template_id !== found.template_id)].slice(0, 3)
    });
  }

  return rankCandidateTemplates(env, pool, pureDirective, userModalities).then((candidateTop3) => ({
    selectedTemplate: candidateTop3[0],
    candidateTop3
  }));
}

export async function runOrchestrationPipeline(
  env: Env,
  envelope: UnifiedProtocolEnvelope,
  options: OrchestrationOptions = {}
): Promise<InstantiatedDAG> {
  // ----------------------------------------------------
  // Guardrail 1: Gateway safety audit (strictly on pure user directive)
  // ----------------------------------------------------
  const pureDirective = envelope.instruction_payload;
  const safetyAudit = await performGatewaySafetyAudit(env, pureDirective);
  if (!safetyAudit.isSafe) {
    const firewallRole: DAGRole = {
      role_id: "role_edge_firewall",
      name_zh: "🛡️ 边界防御网关",
      name_en: "🛡️ Edge Firewall",
      in_modalities: ["text"],
      out_modalities: ["text"],
      in_degree: 0,
      out_degree: 0,
      requisition_tags: ["security_blocked"]
    };
    const firewallModel = createSystemNoticeModel(
      "model_edge_firewall",
      "Edge Firewall 3.0",
      "blocked"
    );

    return {
      template: {
        template_id: "tpl_edge_firewall",
        name_zh: "🛡️ 边界防御网关",
        name_en: "🛡️ Edge Firewall",
        desc_zh: "安全合规网关审计阻断",
        desc_en: "Security Policy Guardrail Blocked",
        head_modalities: ["text"],
        tail_modalities: ["text"],
        roles: [firewallRole],
        priority: 0,
        status: "blocked"
      },
      candidate_templates: [],
      nodes: [
        {
          node_id: "node_edge_firewall",
          stage_group: "synthesis_output",
          depends_on: ["__ORIGIN__"],
          role: firewallRole,
          selected_model: firewallModel,
          standby_models: [],
          score_details: {
            model: firewallModel,
            score: 0,
            sim: 0,
            concurrency_penalty: 0,
            specialist_score: 0
          },
          downgraded: false,
          claimed_assets: []
        }
      ],
      reasoning_trace: {
        intent_state: null,
        is_multi_round: false,
        subsistence_filtered_count: 0,
        selected_template_id: "tpl_edge_firewall",
        downgrade_events: []
      },
      is_security_violation: true
    };
  }

  // ----------------------------------------------------
  // Step 0: Stage 0 Joint Intent & Dependency Resolution (Three-Channel Isolation)
  // ----------------------------------------------------
  let intentState: IntentState | null = null;
  let targetBranchId: string | undefined = undefined;
  let sourceBranchIds: string[] = [];
  let mountedAssetBindings: AssetBindingDecision[] = [];
  let inheritedContextSlices: InheritedContextSlice[] = [];
  let escalationUsed = false;
  let candidatePoolSize = 0;
  let deliveryConfidence: "clear" | "ambiguous" = "clear";

  const isReRoute =
    !options.continuationMode &&
    (options.reRouteMode === "switch_template" || options.reRouteMode === "switch_model");

  // Deep clone assets manifest and normalize document modality ('pdf' -> 'text_doc') upfront
  envelope.assets_manifest = Array.isArray(envelope.assets_manifest)
    ? envelope.assets_manifest.map((a) => ({
        ...a,
        modality: (a.modality as string) === "pdf" ? "text_doc" : a.modality
      }))
    : [];

  const perceptualCache = options.perceptualCache || {};

  if (isReRoute) {
    // Re-routing (model/template/prompt modification on current round):
    // Reset consumed flags to re-claim frozen assets; preserve pureDirective; reuse frozen trace & bindings.
    intentState = null;
    if (options.frozenResolvedPlan) {
      inheritedContextSlices = options.frozenResolvedPlan.inherited_context_slices || [];
      sourceBranchIds = options.frozenResolvedPlan.source_branch_ids || [];
      mountedAssetBindings = options.frozenResolvedPlan.mounted_asset_bindings || [];
    }
    if (mountedAssetBindings.length > 0) {
      envelope.assets_manifest = hydrateManifestFromBindings(
        envelope.assets_manifest,
        mountedAssetBindings,
        options.sessionAssetLedger || [],
        perceptualCache,
        null
      );
    } else {
      envelope.assets_manifest.forEach((a) => {
        a.consumed = false;
      });
    }
  } else if (options.hasPreviousRound) {
    const classification = await classifyMultiRoundIntent(
      env,
      pureDirective,
      true,
      options.previousRoundSummary,
      options.hadMediaAssets,
      {
        hasNewUploads: options.hasNewUploads,
        newUploadModalities: options.newUploadModalities,
        assets: envelope.assets_manifest,
        sessionAssetLedger: options.sessionAssetLedger,
        activeBranchSummary: options.activeBranchSummary,
        activeBranchId: options.activeBranchId,
        branchCatalog: options.branchCatalog,
        perceptualCache,
        resolvedClarificationTargetBranchId: options.resolvedClarificationTargetBranchId,
        candidateBudgetK: options.candidateBudgetK
      }
    );

    intentState = classification.intent;
    targetBranchId = classification.targetBranchId;
    sourceBranchIds = classification.sourceBranchIds || [];
    mountedAssetBindings = classification.assetBindings || [];
    escalationUsed = !!classification.escalationUsed;
    candidatePoolSize = classification.candidatePoolSize || 0;
    deliveryConfidence = classification.deliveryConfidence || "clear";

    if (classification.clarification) {
      return createClarificationDAG(classification.clarification, intentState, targetBranchId, {
        source_branch_ids: sourceBranchIds,
        mounted_asset_bindings: mountedAssetBindings,
        escalation_used: escalationUsed,
        candidate_pool_size: candidatePoolSize,
        delivery_confidence: deliveryConfidence
      });
    }

    if (intentState === "DETACH_RESET") {
      envelope.assets_manifest = envelope.assets_manifest.filter((a) => a.is_new);
      const hasExistingBranchHistory =
        !!options.hasPreviousRound || (options.branchCatalog || []).some((b) => !!b.head_commit_id);
      if (
        hasExistingBranchHistory &&
        (!targetBranchId || targetBranchId === "main" || targetBranchId === options.activeBranchId)
      ) {
        const hasDetachedMedia = envelope.assets_manifest.some(
          (a) => a.modality === "image" || a.modality === "audio" || a.modality === "text_doc"
        );
        targetBranchId = `${hasDetachedMedia ? "branch_media_" : "branch_chat_"}${crypto.randomUUID().slice(0, 8)}`;
      }
    } else {
      envelope.assets_manifest = hydrateManifestFromBindings(
        envelope.assets_manifest,
        mountedAssetBindings,
        options.sessionAssetLedger || [],
        perceptualCache,
        intentState
      );
    }

    // Build structured inherited_context_slices (Channel 2) instead of mutating pureDirective
    const branchMap = new Map((options.branchCatalog || []).map((b) => [b.branch_id, b]));
    const summaryBranchIds = classification.mountBranchSummaries || [];
    for (const bid of summaryBranchIds) {
      const br = branchMap.get(bid);
      const summaryText =
        br?.last_summary ||
        (bid === (options.activeBranchId || "main")
          ? options.activeBranchSummary || options.previousRoundSummary || ""
          : "");
      if (summaryText && summaryText.trim().length > 0) {
        inheritedContextSlices.push({
          branch_id: bid,
          topic: br?.topic || "历史分支",
          commit_id: br?.head_commit_id,
          summary: summaryText.trim(),
          relation:
            bid === targetBranchId
              ? intentState === "SWITCH_BRANCH"
                ? "recalled"
                : "active"
              : "evidence"
        });
      }
    }
    if (
      inheritedContextSlices.length === 0 &&
      intentState !== "DETACH_RESET" &&
      intentState !== "REBIND_ROOT"
    ) {
      const fallbackSummary = options.activeBranchSummary || options.previousRoundSummary || "";
      if (fallbackSummary.trim().length > 0) {
        inheritedContextSlices.push({
          branch_id: targetBranchId || options.activeBranchId || "main",
          topic: "前序任务产物",
          summary: fallbackSummary.trim(),
          relation: "active"
        });
      }
    }
  }

  envelope.assets_manifest.forEach((a) => {
    a.consumed = false;
  });

  // Partition active assets for Subsistence & Compositional Planning
  const rawSensoryAssets = envelope.assets_manifest.filter(
    (a) => (a.modality === "image" || a.modality === "audio") && a.bind_mode !== "CACHED_TEXT"
  );
  const cachedSensoryAssets = envelope.assets_manifest.filter(
    (a) =>
      (a.modality === "image" || a.modality === "audio") &&
      a.bind_mode === "CACHED_TEXT" &&
      !!(a.cached_perceptual_text && a.cached_perceptual_text.trim().length > 0)
  );
  const symbolicAssets = envelope.assets_manifest.filter(
    (a) =>
      a.modality === "text_doc" ||
      (a.modality === "text" && a.asset_id !== "virtual-text-asset" && !!a.in_memory_text)
  );

  // Raw media modalities that STILL need physical model input (excludes CACHED_TEXT assets already reduced to L1 text!)
  const mediaModalities = Array.from(new Set(rawSensoryAssets.map((a) => a.modality)));
  const hasUserText =
    !!(pureDirective && pureDirective.trim().length > 0) ||
    envelope.assets_manifest.some((a) => a.modality === "text" || a.modality === "text_doc") ||
    cachedSensoryAssets.length > 0;

  // Ensure empty assets manifest has a virtual text asset
  if (envelope.assets_manifest.length === 0) {
    envelope.assets_manifest.push({
      asset_id: "virtual-text-asset",
      modality: "text",
      mime_type: "text/plain",
      file_size: pureDirective.length,
      in_memory_text: pureDirective,
      consumed: false,
      source_digest: "text-digest"
    });
  }

  const userModalities = Array.from(
    new Set([
      ...mediaModalities,
      ...(hasUserText ? ["text"] : []),
      ...symbolicAssets.map((a) => a.modality)
    ])
  );

  // ----------------------------------------------------
  // Step 1: Load DB metadata & Hard Filter
  // ----------------------------------------------------
  const rawRoles = await env.DB.prepare("SELECT * FROM dag_roles")
    .all<any>()
    .catch(() => ({ results: [] }));

  const roleMap = new Map<string, DAGRole>();
  for (const r of rawRoles.results || []) {
    roleMap.set(r.role_id, {
      role_id: r.role_id,
      name_zh: r.name_zh,
      name_en: r.name_en,
      in_modalities: safeJsonParse<string[]>(r.in_modalities, []),
      out_modalities: safeJsonParse<string[]>(r.out_modalities, []),
      in_degree: 0,
      out_degree: 0,
      requisition_tags: safeJsonParse<string[]>(r.requisition_tags, []),
      compensation_prompts: safeJsonParse<Record<string, string>>(r.compensation_prompts, {})
    });
  }

  const rawTemplates = await env.DB.prepare(
    "SELECT * FROM dag_templates WHERE status = 'active'"
  ).all<any>();

  const allTemplates: DAGTemplate[] = (rawTemplates.results || []).map((r) => {
    const roleSequence = safeJsonParse<string[]>(r.role_sequence, []);
    let resolvedRoles: DAGRole[] = [];

    if (roleSequence.length > 0 && roleMap.size > 0) {
      resolvedRoles = roleSequence
        .map((roleId, idx) => {
          const baseRole = roleMap.get(roleId);
          if (!baseRole) return null;
          return {
            ...baseRole,
            in_degree: idx === 0 ? 0 : 1,
            out_degree: idx === roleSequence.length - 1 ? 0 : 1
          };
        })
        .filter((x): x is DAGRole => x !== null);
    }

    if (resolvedRoles.length === 0) {
      resolvedRoles = safeJsonParse<DAGRole[]>(r.roles, []);
    }

    return {
      template_id: r.template_id,
      name_zh: r.template_id === "tpl-vision-ocr-summary" ? "视觉多模态全景分析" : r.name_zh,
      name_en:
        r.template_id === "tpl-vision-ocr-summary" ? "Multimodal Vision Analysis" : r.name_en,
      desc_zh:
        r.template_id === "tpl-vision-ocr-summary"
          ? "两阶段图像综合分析：第一阶段进行高精度视觉主体理解、艺术排版与风格解析及OCR提取，第二阶段由语言模型进行结构化梳理与润色"
          : r.desc_zh,
      desc_en:
        r.template_id === "tpl-vision-ocr-summary"
          ? "Two-stage visual analysis pipeline: high-precision visual understanding, style/layout analysis, and OCR extraction followed by structured synthesis"
          : r.desc_en,
      head_modalities: safeJsonParse<string[]>(r.head_modalities, []),
      tail_modalities: safeJsonParse<string[]>(r.tail_modalities, []),
      roles: resolvedRoles,
      role_sequence: roleSequence,
      priority: r.priority || 1,
      status: r.status || "active"
    };
  });

  const rawModels = await env.DB.prepare("SELECT * FROM models WHERE status = 'active'").all<any>();
  const allModels: ModelMetadata[] = (rawModels.results || []).map((r) => ({
    model_id: r.model_id,
    display_name: r.display_name,
    provider: r.provider,
    endpoint: r.endpoint,
    modalities: safeJsonParse<string[]>(r.modalities, []),
    in_modalities: r.in_modalities ? safeJsonParse<string[]>(r.in_modalities, ["text"]) : undefined,
    out_modalities: r.out_modalities
      ? safeJsonParse<string[]>(r.out_modalities, ["text"])
      : undefined,
    tags: safeJsonParse<string[]>(r.tags, []),
    context_window: r.context_window || 4096,
    max_concurrency: r.max_concurrency || 50,
    active_connections: r.active_connections || 0,
    precision: r.precision || 0.8,
    user_rating: r.user_rating || 5.0,
    usage_count: r.usage_count || 0,
    cost_per_1k_tokens:
      r.cost_per_1k_tokens !== undefined && r.cost_per_1k_tokens !== null
        ? Number(r.cost_per_1k_tokens)
        : 1.0,
    cost_per_invocation:
      r.cost_per_invocation !== undefined && r.cost_per_invocation !== null
        ? Number(r.cost_per_invocation)
        : 0.0,
    status: r.status,
    is_generalist: r.is_generalist || 0,
    prior_score: r.prior_score || 0.0,
    scenario_anchors: safeJsonParse<string[]>(r.scenario_anchors, []),
    anchor_embeddings: r.anchor_embeddings
      ? safeJsonParse<number[][] | null>(r.anchor_embeddings, null)
      : null,
    inference_target: r.inference_target || "cloud",
    browser_runtime: r.browser_runtime || undefined,
    download_size_bytes: r.download_size_bytes || 0,
    auth_mode: r.auth_mode || "none",
    auth_secret: r.auth_secret || null,
    api_format: r.api_format || "workers_ai"
  }));

  const candidateModels = hardFilterModels(
    allModels,
    envelope.metadata?.estimated_input_tokens,
    !!options.disableBrowserInference
  );

  const directSubsistenceTemplates = filterTemplatesBySubsistence(allTemplates, {
    mediaModalities,
    hasUserText
  });

  // Determine whether compositional Map-Reduce Subgraph Synthesis is needed:
  // Triggers when >1 raw sensory assets (multi-image, image+audio, etc.), mixed raw + cached sensory assets,
  // or arbitrary sensory combination that no single static linear template satisfies directly.
  const totalSensoryCount = rawSensoryAssets.length + cachedSensoryAssets.length;
  const needsCompositionalDag =
    !options.continuationMode &&
    (rawSensoryAssets.length > 1 ||
      (rawSensoryAssets.length >= 1 && cachedSensoryAssets.length >= 1) ||
      (cachedSensoryAssets.length >= 1 && mediaModalities.length === 0) ||
      (directSubsistenceTemplates.length === 0 && totalSensoryCount > 0));

  const traceBase: Partial<InstantiatedDAG["reasoning_trace"]> = {
    source_branch_ids: sourceBranchIds,
    mounted_asset_bindings: mountedAssetBindings,
    inherited_context_slices: inheritedContextSlices,
    escalation_used: escalationUsed,
    candidate_pool_size: candidatePoolSize,
    delivery_confidence: deliveryConfidence
  };

  // ----------------------------------------------------
  // Path A: Compositional Two-Phase Subgraph Synthesis (Map-Reduce for Arbitrary Multimodal Inputs)
  // ----------------------------------------------------
  if (needsCompositionalDag) {
    const textSynthesisPool = filterTemplatesBySubsistence(allTemplates, {
      mediaModalities: [],
      hasUserText: true
    });
    if (textSynthesisPool.length === 0) {
      throw new Error(`当前没有适合处理综合推理与生成的可用文本/创作尾模板。`);
    }

    const { selectedTemplate, candidateTop3 } = await selectTemplateFromPool(
      textSynthesisPool,
      options,
      pureDirective,
      ["text"],
      env
    );

    if (selectedTemplate.template_id === SENTINEL_UNREACHABLE_TEMPLATE_ID) {
      return createUnreachableDAG(
        isReRoute,
        intentState,
        targetBranchId,
        textSynthesisPool.length,
        traceBase
      );
    }

    const promptEmbedding =
      options.reRouteMode === "switch_model"
        ? null
        : await generatePromptEmbedding(env, pureDirective);

    const downgradeEvents: Array<{ role_id: string; original_tag: string; fallback_tag: string }> =
      [];
    const instantiatedNodes: InstantiatedDAGNode[] = [];
    const prepNodeIds: string[] = [];

    // Phase I: Evidence Preparation Group (1 sensory asset = 1 small-model subgraph node, or L1 cache hit)
    // Keep compositional evidence preparation on server/edge targets so a multi-branch prep step never fragments across browser WebGPU handovers.
    const cloudEdgePrepModels = candidateModels.filter((m) => m.inference_target !== "browser");
    const prepCandidateModels =
      cloudEdgePrepModels.length > 0 ? cloudEdgePrepModels : candidateModels;

    const sensoryPrepAssets = [...rawSensoryAssets, ...cachedSensoryAssets];
    for (let i = 0; i < sensoryPrepAssets.length; i++) {
      const asset = sensoryPrepAssets[i];
      const mod = asset.modality === "audio" ? "audio" : "image";
      const role = selectSensoryRoleForModality(mod, roleMap, allTemplates);
      const nodeId = `prep-${mod}-${i}-${sanitizeNodeId(asset.asset_id)}`;
      const isL1Cached =
        asset.bind_mode === "CACHED_TEXT" &&
        !!(asset.cached_perceptual_text && asset.cached_perceptual_text.trim().length > 0);

      const prepNode = await instantiateNodeWithCompetence(
        role,
        prepCandidateModels,
        env,
        promptEmbedding,
        pureDirective,
        envelope,
        options,
        downgradeEvents,
        nodeId,
        "evidence_prep",
        ["__ORIGIN__"],
        [asset],
        {
          perceptual_cache_hit: isL1Cached,
          cached_output: isL1Cached ? asset.cached_perceptual_text : undefined,
          task_scope: "objective_full",
          parallel_group:
            !isL1Cached && rawSensoryAssets.length > 1 ? "prep_parallel_batch" : undefined
        }
      );
      // Only mark parallel_group when node actually runs in cloud/edge (browser WebGPU nodes serialize on worker)
      if (prepNode.selected_model.inference_target === "browser") {
        prepNode.parallel_group = undefined;
      }
      instantiatedNodes.push(prepNode);
      prepNodeIds.push(nodeId);
    }

    // Add lightweight symbolic document reader node in Evidence Prep when documents accompany sensory inputs
    if (symbolicAssets.length > 0) {
      const docRole: DAGRole = {
        role_id: "role_doc_reader",
        name_zh: "文档内容读取",
        name_en: "Document Reader",
        in_modalities: ["text_doc"],
        out_modalities: ["text"],
        in_degree: 0,
        out_degree: 1,
        requisition_tags: ["#analysis"]
      };
      const docModel = createSystemNoticeModel("sys_doc_reader", "本地无损解析器", "active");
      const docNodeId = "prep-doc-0";
      instantiatedNodes.push({
        node_id: docNodeId,
        stage_group: "evidence_prep",
        depends_on: ["__ORIGIN__"],
        is_reducer: true, // Instant deterministic read (0 cost)
        perceptual_cache_hit: true,
        cached_output: symbolicAssets
          .map(
            (d, idx) => `[文档 ${idx + 1}: ${d.filename || d.asset_id}]\n${d.in_memory_text || ""}`
          )
          .join("\n\n"),
        role: docRole,
        selected_model: docModel,
        standby_models: [],
        score_details: {
          model: docModel,
          score: 1,
          sim: 1,
          concurrency_penalty: 0,
          specialist_score: 1
        },
        downgraded: false,
        claimed_assets: symbolicAssets
      });
      prepNodeIds.push(docNodeId);
    }

    // Phase II: Deterministic Reducer Merge Node (converges all Evidence Prep branches)
    const reducerId = "reducer-merge";
    const reducerRole: DAGRole = {
      role_id: "role_evidence_reducer",
      name_zh: "多源证据汇总",
      name_en: "Evidence Reducer",
      in_modalities: ["text"],
      out_modalities: ["text"],
      in_degree: 1,
      out_degree: 1,
      requisition_tags: ["#structuring"]
    };
    const reducerModel = createSystemNoticeModel(
      "sys_evidence_reducer",
      "Deterministic Reducer",
      "active"
    );
    instantiatedNodes.push({
      node_id: reducerId,
      stage_group: "reducer_merge",
      depends_on: prepNodeIds.length > 0 ? prepNodeIds : ["__ORIGIN__"],
      is_reducer: true,
      role: reducerRole,
      selected_model: reducerModel,
      standby_models: [],
      score_details: {
        model: reducerModel,
        score: 1,
        sim: 1,
        concurrency_penalty: 0,
        specialist_score: 1
      },
      downgraded: false,
      claimed_assets: []
    });

    // Phase III: Cognitive Synthesis / Generative Tail DAG
    for (let roleIdx = 0; roleIdx < selectedTemplate.roles.length; roleIdx++) {
      const baseRole = selectedTemplate.roles[roleIdx];
      const synthRole: DAGRole = {
        ...baseRole,
        in_degree: 1, // Downstream of reducer-merge
        out_degree: roleIdx === selectedTemplate.roles.length - 1 ? 0 : 1
      };
      const nodeId = `synth-${roleIdx}-${baseRole.role_id}`;
      const depId =
        roleIdx === 0
          ? reducerId
          : `synth-${roleIdx - 1}-${selectedTemplate.roles[roleIdx - 1].role_id}`;
      const synthNode = await instantiateNodeWithCompetence(
        synthRole,
        candidateModels,
        env,
        promptEmbedding,
        pureDirective,
        envelope,
        options,
        downgradeEvents,
        nodeId,
        "synthesis_output",
        [depId]
      );
      instantiatedNodes.push(synthNode);
    }

    return {
      template: selectedTemplate,
      candidate_templates: candidateTop3,
      nodes: instantiatedNodes,
      topology_mode: "compositional",
      reasoning_trace: {
        intent_state: isReRoute ? null : intentState,
        target_branch_id: isReRoute ? undefined : targetBranchId,
        is_multi_round: !isReRoute && !!options.hasPreviousRound,
        subsistence_filtered_count: textSynthesisPool.length,
        selected_template_id: selectedTemplate.template_id,
        downgrade_events: downgradeEvents,
        ...traceBase
      }
    };
  }

  // ----------------------------------------------------
  // Path B: Standard Homogeneous / Fast-Path Template Selection
  // ----------------------------------------------------
  if (directSubsistenceTemplates.length === 0) {
    throw new Error(`当前没有适合处理 [${userModalities.join(", ")}] 输入模态的可用模板。`);
  }

  let selectedTemplate: DAGTemplate;
  let candidateTop3: DAGTemplate[];

  if (options.continuationMode && options.chosenTemplateId) {
    const found =
      directSubsistenceTemplates.find((t) => t.template_id === options.chosenTemplateId) ||
      allTemplates.find((t) => t.template_id === options.chosenTemplateId) ||
      directSubsistenceTemplates[0];
    selectedTemplate = found;
    candidateTop3 = [
      selectedTemplate,
      ...directSubsistenceTemplates.filter((t) => t.template_id !== selectedTemplate.template_id)
    ].slice(0, 3);
  } else {
    const res = await selectTemplateFromPool(
      directSubsistenceTemplates,
      options,
      pureDirective,
      userModalities,
      env
    );
    selectedTemplate = res.selectedTemplate;
    candidateTop3 = res.candidateTop3;
  }

  if (selectedTemplate.template_id === SENTINEL_UNREACHABLE_TEMPLATE_ID) {
    return createUnreachableDAG(
      isReRoute,
      intentState,
      targetBranchId,
      directSubsistenceTemplates.length,
      traceBase
    );
  }

  const promptEmbedding =
    options.reRouteMode === "switch_model"
      ? null
      : await generatePromptEmbedding(env, pureDirective);

  const instantiatedNodes: InstantiatedDAGNode[] = [];
  const downgradeEvents: Array<{ role_id: string; original_tag: string; fallback_tag: string }> =
    [];

  for (let roleIdx = 0; roleIdx < selectedTemplate.roles.length; roleIdx++) {
    const role = selectedTemplate.roles[roleIdx];
    const isMultiNode = selectedTemplate.roles.length > 1;
    const stageGroup: TopologyStageGroup =
      isMultiNode && roleIdx === 0 ? "evidence_prep" : "synthesis_output";
    const depId = roleIdx === 0 ? "__ORIGIN__" : selectedTemplate.roles[roleIdx - 1].role_id;
    const node = await instantiateNodeWithCompetence(
      role,
      candidateModels,
      env,
      promptEmbedding,
      pureDirective,
      envelope,
      options,
      downgradeEvents,
      role.role_id,
      stageGroup,
      [depId]
    );
    instantiatedNodes.push(node);
  }

  return {
    template: selectedTemplate,
    candidate_templates: candidateTop3,
    nodes: instantiatedNodes,
    topology_mode: "standard",
    reasoning_trace: {
      intent_state: isReRoute ? null : intentState,
      target_branch_id: isReRoute ? undefined : targetBranchId,
      is_multi_round: !isReRoute && !!options.hasPreviousRound,
      subsistence_filtered_count: directSubsistenceTemplates.length,
      selected_template_id: selectedTemplate.template_id,
      downgrade_events: downgradeEvents,
      ...traceBase
    }
  };
}

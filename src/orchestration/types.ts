// src/orchestration/types.ts

export type Modality = "text" | "image" | "audio" | "text_doc";

export type AssetOrigin = "upload" | "generated";
export type AssetBindMode = "RAW_MEDIA" | "CACHED_TEXT" | "DROP";
export type IntentState =
  "ANCHOR_TAIL" | "REBIND_ROOT" | "CROSS_FUSION" | "SWITCH_BRANCH" | "DETACH_RESET";
export type TopologyStageGroup = "evidence_prep" | "reducer_merge" | "synthesis_output";
export type NodeExecutionState =
  | "pending"
  | "waiting_resource"
  | "running"
  | "parallel_running"
  | "cache_hit"
  | "completed"
  | "failed";

export interface AssetDescriptor {
  asset_id: string;
  modality: Modality;
  mime_type: string;
  file_size: number;
  r2_key?: string; // e.g. tmp/... or assets/...
  in_memory_text?: string; // Plain text / Markdown table extracted client-side
  in_memory_data?: string; // Base64 data URL for images/multimodal assets
  consumed: boolean; // Cursor: whether consumed by a DAG node
  source_digest: string; // SHA-256 digest of content
  is_new?: boolean; // Whether uploaded in the current round
  filename?: string; // Original filename for display and receipt
  origin?: AssetOrigin;
  branch_id?: string;
  introduced_round?: number;
  introduced_commit_id?: string;
  bind_mode?: AssetBindMode;
  summary_snippet?: string;
  cached_perceptual_text?: string;
}

export type PerceptualTaskScope = "objective_full" | "focused_or_custom";

export interface PerceptualCacheEntry {
  source_digest: string;
  modality: "image" | "audio";
  role_id: string;
  model_id: string;
  task_scope?: PerceptualTaskScope;
  prompt_digest?: string;
  percept_key?: string;
  extracted_text: string;
  summary_snippet: string;
  updated_at: number;
}

export interface InheritedContextSlice {
  branch_id: string;
  topic: string;
  commit_id?: string;
  summary: string;
  relation: "active" | "recalled" | "evidence";
}

export interface AssetBindingDecision {
  asset_id: string;
  bind_mode: AssetBindMode;
}

export interface SourceRefEntry {
  asset_id: string;
  branch_id: string;
  commit_id?: string;
  bind_mode: AssetBindMode;
}

export interface CommitNode {
  commit_id: string;
  parents: string[];
  branch_id: string;
  evidence_source_branches: string[];
  source_refs?: SourceRefEntry[];
  round_index: number;
  revision: number;
  intent_op: IntentState | null;
  user_prompt: string;
  mounted_assets: Array<{ asset_id: string; bind_mode: Exclude<AssetBindMode, "DROP"> }>;
  introduced_asset_ids: string[];
  generated_asset_ids: string[];
  template_id?: string;
  output_summary: string;
  timestamp: number;
}

export interface BranchPointer {
  branch_id: string;
  topic: string;
  head_commit_id: string;
  dominant_modalities: string[];
  last_summary: string;
  lineage_asset_ids: string[];
}

export interface ConstraintContext {
  target_language: "auto" | "zh" | "en";
  output_style: "concise" | "detailed" | "creative";
}

/**
 * Immutable client-to-gateway request envelope carrying multi-turn state, assets, and environmental constraints.
 */
export interface UnifiedProtocolEnvelope {
  envelope_id: string;
  session_id: string;
  user_id?: string;
  round_index: number;
  instruction_payload: string;
  assets_manifest: AssetDescriptor[];
  constraint_context: ConstraintContext;
  metadata: {
    client_timestamp: number;
    char_count_total: number;
    estimated_input_tokens: number;
    has_new_upload?: boolean;
    new_upload_count?: number;
    new_upload_modalities?: string[];
  };
}

/**
 * Functional role unit in an orchestration graph (e.g. perception, analysis, synthesis).
 */
export interface DAGRole {
  role_id: string;
  name_zh: string;
  name_en: string;
  in_modalities: string[];
  out_modalities: string[];
  in_degree: number;
  out_degree: number;
  requisition_tags: string[];
  compensation_prompts?: Record<string, string>;
}

/**
 * Top-level Directed Acyclic Graph (DAG) pipeline template definition.
 */
export interface DAGTemplate {
  template_id: string;
  name_zh: string;
  name_en: string;
  desc_zh: string;
  desc_en: string;
  head_modalities: string[];
  tail_modalities: string[];
  roles: DAGRole[];
  role_sequence?: string[];
  priority: number;
  status: string;
}

/**
 * Compute node and model metadata across Light (browser), Medium (edge), and Heavy (cloud/VPS) tiers.
 */
export interface ModelMetadata {
  model_id: string;
  display_name: string;
  provider: string;
  endpoint: string;
  modalities: string[];
  in_modalities?: string[];
  out_modalities?: string[];
  tags: string[];
  context_window: number;
  max_concurrency: number;
  active_connections: number;
  precision: number;
  user_rating: number;
  usage_count: number;
  cost_per_1k_tokens: number;
  cost_per_invocation?: number;
  status: string;
  is_generalist: number;
  prior_score: number;
  scenario_anchors: string[];
  anchor_embeddings?: number[][] | null;
  inference_target?: "cloud" | "browser" | "heavy" | "edge";
  browser_runtime?: "webgpu" | "wasm";
  download_size_bytes?: number;
  auth_mode?: "none" | "jwt_ephemeral" | "bearer_static";
  auth_secret?: string | null;
  api_format?: "workers_ai" | "openai_compat" | "google_ai";
}

export interface ScoredModel {
  model: ModelMetadata;
  score: number;
  sim: number;
  concurrency_penalty: number;
  specialist_score: number;
  context_fit_score?: number;
  tier_score?: number;
  jitter_score?: number;
}

export interface InstantiatedDAGNode {
  node_id?: string; // Unique execution instance ID (prevents role_id collisions in parallel fan-out)
  stage_group?: TopologyStageGroup;
  depends_on?: string[];
  parallel_group?: string;
  is_reducer?: boolean;
  perceptual_cache_hit?: boolean;
  cached_output?: string;
  focus_hint?: string;
  task_scope?: PerceptualTaskScope;
  prompt_digest?: string;
  role: DAGRole;
  selected_model: ModelMetadata;
  standby_models: ModelMetadata[]; // Top 2 & Top 3 for user switching & failover
  score_details: ScoredModel;
  downgraded: boolean;
  compensation_prompt?: string;
  custom_prompt?: string;
  claimed_assets: AssetDescriptor[];
  upstream_output?: string;
  final_prompt?: string;
  cache_hit?: boolean;
  artifact_bundle?: ArtifactBundle;
}

export interface SessionAssetLedgerItem {
  asset_id: string;
  filename?: string;
  modality: Modality;
  mime_type?: string;
  file_size?: number;
  introduced_round?: number;
  introduced_commit_id?: string;
  branch_id?: string;
  r2_key?: string;
  text_r2_key?: string;
  in_memory_text?: string;
  source_digest?: string;
  origin?: AssetOrigin;
  summary_snippet?: string;
  cached_perceptual_text?: string;
}

export interface MediaArtifact {
  asset_id: string;
  modality: "image" | "audio";
  mime_type: string;
  file_size: number;
  r2_key: string;
  source_digest: string;
  url?: string;
  metadata?: Record<string, any>;
}

export interface ArtifactBundle {
  text_context: string; // Text reasoning context from parent
  generated_media: MediaArtifact[]; // Media directly produced by parent step
  inherited_assets: AssetDescriptor[]; // Cumulative available assets in execution space S
  execution_trace?: {
    role_id: string;
    model_id: string;
    cost: number;
    duration_ms: number;
  };
}

export interface ClarificationPromptInfo {
  reason_zh: string;
  reason_en: string;
  candidate_targets: Array<{
    branch_id: string;
    topic: string;
    relation: "current" | "historical";
  }>;
  recalled_asset_ids: string[];
}

export interface InstantiatedDAG {
  template: DAGTemplate;
  candidate_templates: DAGTemplate[]; // Top 3 candidate templates
  nodes: InstantiatedDAGNode[];
  topology_mode?: "standard" | "compositional";
  reasoning_trace: {
    intent_state: IntentState | null;
    target_branch_id?: string;
    source_branch_ids?: string[];
    source_refs?: SourceRefEntry[];
    mounted_asset_bindings?: AssetBindingDecision[];
    inherited_context_slices?: InheritedContextSlice[];
    escalation_used?: boolean;
    candidate_pool_size?: number;
    delivery_confidence?: "clear" | "ambiguous";
    plan_hash?: string;
    is_multi_round: boolean;
    subsistence_filtered_count: number;
    selected_template_id: string;
    downgrade_events: Array<{ role_id: string; original_tag: string; fallback_tag: string }>;
  };
  is_security_violation?: boolean;
  is_unreachable?: boolean;
  is_clarification_required?: boolean;
  clarification?: ClarificationPromptInfo;
}

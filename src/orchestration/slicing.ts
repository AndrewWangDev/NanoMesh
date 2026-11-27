// src/orchestration/slicing.ts
import {
  ArtifactBundle,
  AssetDescriptor,
  InstantiatedDAGNode,
  MediaArtifact,
  PerceptualCacheEntry,
  UnifiedProtocolEnvelope
} from "./types";

const HANDOVER_KEY_MEDIA = "__nm_generated_media";
const HANDOVER_KEY_CONSUMED = "__nm_consumed_assets";
const HANDOVER_KEY_PERCEPTUAL = "__nm_perceptual_updates";
const HANDOVER_KEY_ALLOW_FAILOVER = "__nm_allow_standby_failover";

export interface ExtractedHandoverBundle {
  nodeTextOutputs: Record<string, string>;
  generatedMedia: MediaArtifact[];
  consumedAssetIds: string[];
  perceptualUpdates: PerceptualCacheEntry[];
  allowStandbyFailover?: boolean;
}

/**
 * Serializes node text outputs together with Phase 1 generated media, consumed asset IDs,
 * perceptual cache updates, and standby failover policy into step_outputs_json.
 */
export function serializeHandoverBundleToStepOutputs(params: {
  nodeTextOutputs: Record<string, string>;
  generatedMedia: MediaArtifact[];
  consumedAssetIds: string[];
  perceptualUpdates: PerceptualCacheEntry[];
  allowStandbyFailover: boolean;
}): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(params.nodeTextOutputs || {})) {
    if (!k.startsWith("__nm_") && typeof v === "string") {
      out[k] = v;
    }
  }
  if (params.generatedMedia.length > 0) {
    out[HANDOVER_KEY_MEDIA] = JSON.stringify(params.generatedMedia);
  }
  if (params.consumedAssetIds.length > 0) {
    out[HANDOVER_KEY_CONSUMED] = JSON.stringify(params.consumedAssetIds);
  }
  if (params.perceptualUpdates.length > 0) {
    out[HANDOVER_KEY_PERCEPTUAL] = JSON.stringify(params.perceptualUpdates);
  }
  out[HANDOVER_KEY_ALLOW_FAILOVER] = params.allowStandbyFailover ? "true" : "false";
  return out;
}

/**
 * Extracts node text outputs and Phase 1 server-trusted multimodal bundle state from step_outputs_json.
 */
export function extractHandoverBundleFromStepOutputs(
  stepOutputs?: Record<string, string>
): ExtractedHandoverBundle {
  const nodeTextOutputs: Record<string, string> = {};
  let generatedMedia: MediaArtifact[] = [];
  let consumedAssetIds: string[] = [];
  let perceptualUpdates: PerceptualCacheEntry[] = [];
  let allowStandbyFailover: boolean | undefined = undefined;

  if (!stepOutputs || typeof stepOutputs !== "object") {
    return {
      nodeTextOutputs,
      generatedMedia,
      consumedAssetIds,
      perceptualUpdates,
      allowStandbyFailover
    };
  }

  for (const [k, v] of Object.entries(stepOutputs)) {
    if (k === HANDOVER_KEY_MEDIA) {
      try {
        const parsed = JSON.parse(v);
        if (Array.isArray(parsed)) generatedMedia = parsed;
      } catch {}
    } else if (k === HANDOVER_KEY_CONSUMED) {
      try {
        const parsed = JSON.parse(v);
        if (Array.isArray(parsed)) consumedAssetIds = parsed.map(String);
      } catch {}
    } else if (k === HANDOVER_KEY_PERCEPTUAL) {
      try {
        const parsed = JSON.parse(v);
        if (Array.isArray(parsed)) perceptualUpdates = parsed;
      } catch {}
    } else if (k === HANDOVER_KEY_ALLOW_FAILOVER) {
      allowStandbyFailover = v !== "false";
    } else if (!k.startsWith("__nm_") && typeof v === "string") {
      nodeTextOutputs[k] = v;
    }
  }

  return {
    nodeTextOutputs,
    generatedMedia,
    consumedAssetIds,
    perceptualUpdates,
    allowStandbyFailover
  };
}

export interface NodeExecutionContext {
  claimed_assets: AssetDescriptor[];
  upstream_text: string;
  injected_prompt: string;
  is_head_masked: boolean;
  is_downstream: boolean;
  parent_role_name?: string;
  custom_prompt?: string;
  compensation_prompt?: string;
  target_language: string;
  output_style: string;
  previous_bundle?: ArtifactBundle;
}

/**
 * Step 4: Targeted Claiming Law & Envelope Slicing
 *
 * Rules:
 * - P0: Claims matching media generated directly by the preceding node (ArtifactBundle.generated_media).
 * - P1: Penetrates to claim unconsumed matching user initial assets from envelope.assets_manifest.
 * - Instruction Masking:
 *   - Head Node in multi-node DAG (in=0 && out>0): Strictly MASKS user prompt (is_head_masked = true)
 *     so perception is purely driven by role requisition prompt without downstream contamination.
 *   - Single-Node & Downstream Nodes: Receives user prompt.
 */
function supportsModality(set: Set<string>, modality: string): boolean {
  if (set.has(modality)) return true;
  if (modality === "text_doc" && set.has("text")) return true;
  if (modality === "text" && set.has("text_doc")) return true;
  return false;
}

export function sliceEnvelopeForNode(
  node: InstantiatedDAGNode,
  envelope: UnifiedProtocolEnvelope,
  parentOutput?: string,
  parentRoleName?: string,
  previousBundle?: ArtifactBundle
): NodeExecutionContext {
  const claimedAssets: AssetDescriptor[] = [];
  const requiredInModalities = new Set(node.role.in_modalities);
  const modelInModalities = new Set(
    node.selected_model.in_modalities || node.selected_model.modalities
  );

  // 1. P0 Priority: Claim matching media generated directly by preceding nodes (Reverse Chronological: Latest First)
  if (
    previousBundle &&
    previousBundle.generated_media &&
    previousBundle.generated_media.length > 0
  ) {
    for (let i = previousBundle.generated_media.length - 1; i >= 0; i--) {
      const media = previousBundle.generated_media[i];
      if (requiredInModalities.has(media.modality) && modelInModalities.has(media.modality)) {
        claimedAssets.push({
          asset_id: media.asset_id,
          modality: media.modality,
          mime_type: media.mime_type,
          file_size: media.file_size,
          r2_key: media.r2_key,
          consumed: true,
          source_digest: media.source_digest
        });
        requiredInModalities.delete(media.modality);
      }
    }
  }

  // 2. P1 Priority: If compositional planner pre-assigned bound assets to this node, claim them deterministically.
  // Otherwise, penetrate to claim unconsumed matching user initial assets from envelope.
  const isHeadNode = node.role.in_degree === 0;
  const isTailNode = node.role.out_degree === 0;
  const isMaskedHeadNode = isHeadNode && !isTailNode;
  const isSensoryHeadRole =
    node.role.in_modalities.includes("image") || node.role.in_modalities.includes("audio");

  if (Array.isArray(node.claimed_assets) && node.claimed_assets.length > 0) {
    for (const preBound of node.claimed_assets) {
      const envAsset = envelope.assets_manifest.find((a) => a.asset_id === preBound.asset_id);
      if (envAsset) {
        envAsset.consumed = true;
        claimedAssets.push(envAsset);
      } else {
        claimedAssets.push({ ...preBound, consumed: true });
      }
    }
  } else {
    for (const asset of envelope.assets_manifest) {
      if (asset.consumed) continue;

      const isSensoryModality = asset.modality === "image" || asset.modality === "audio";

      // Sensory masked head nodes focus purely on image/audio extraction
      // and leave cognitive documents (text, text_doc) for downstream synthesis nodes.
      if (isMaskedHeadNode && isSensoryHeadRole && !isSensoryModality) {
        continue;
      }

      const isExplicitlyNeeded =
        supportsModality(requiredInModalities, asset.modality) &&
        supportsModality(modelInModalities, asset.modality);
      const isTailHarvest = isTailNode && supportsModality(modelInModalities, asset.modality);
      const isHeadHarvest = isHeadNode && supportsModality(modelInModalities, asset.modality);

      if (isExplicitlyNeeded || isTailHarvest || isHeadHarvest) {
        asset.consumed = true;
        claimedAssets.push(asset);
        requiredInModalities.delete(asset.modality);
        if (asset.modality === "text_doc") requiredInModalities.delete("text");
      }
    }
  }

  // 3. Upstream text from parent (or previous bundle text context)
  const upstreamText = parentOutput || previousBundle?.text_context || "";
  const isDownstream = node.role.in_degree > 0;

  // 4. Instruction & Constraints Injection Responsibility
  // Head Node in multi-node DAG (in=0 && out>0): Strictly MASK user prompt!
  // Single-node DAG (in=0 && out=0): Receives user prompt.
  // Downstream Node (in>0): Receives user prompt (anchored by System Prompt guidance).
  const isHeadMasked = node.role.in_degree === 0 && node.role.out_degree > 0;
  const injectedPrompt = isHeadMasked ? "" : envelope.instruction_payload || "";

  return {
    claimed_assets: claimedAssets,
    upstream_text: upstreamText,
    injected_prompt: injectedPrompt,
    is_head_masked: isHeadMasked,
    is_downstream: isDownstream,
    parent_role_name: parentRoleName,
    custom_prompt: node.custom_prompt,
    compensation_prompt: node.compensation_prompt,
    target_language: envelope.constraint_context?.target_language,
    output_style: envelope.constraint_context?.output_style,
    previous_bundle: previousBundle
  };
}

// src/orchestration/slicing.ts
import { ArtifactBundle, AssetDescriptor, InstantiatedDAGNode, UnifiedProtocolEnvelope } from "./types";

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
 * Step 4: Targeted Claiming Law (定向认领法则) & Envelope Slicing
 * 
 * Rules:
 * - P0: Claims matching media generated directly by the preceding node (ArtifactBundle.generated_media).
 * - P1: Penetrates to claim unconsumed matching user initial assets from envelope.assets_manifest.
 * - Instruction Masking:
 *   - Head Node in multi-node DAG (in=0 && out>0): Strictly MASKS user prompt (is_head_masked = true)
 *     so perception is purely driven by role requisition prompt without downstream contamination.
 *   - Single-Node & Downstream Nodes: Receives user prompt.
 */
export function sliceEnvelopeForNode(
  node: InstantiatedDAGNode,
  envelope: UnifiedProtocolEnvelope,
  parentOutput?: string,
  parentRoleName?: string,
  previousBundle?: ArtifactBundle
): NodeExecutionContext {
  const claimedAssets: AssetDescriptor[] = [];
  const requiredInModalities = new Set(node.role.in_modalities);
  const modelInModalities = new Set(node.selected_model.in_modalities || node.selected_model.modalities);

  // 1. P0 Priority: Claim matching media generated directly by the preceding node
  if (previousBundle && previousBundle.generated_media && previousBundle.generated_media.length > 0) {
    for (const media of previousBundle.generated_media) {
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

  // 2. P1 Priority: Claim unconsumed matching user initial assets from envelope
  // Head nodes claim all unconsumed assets matching their input modalities.
  // Intermediate nodes claim assets if their required modalities were not satisfied by P0.
  // Tail nodes claim remaining unconsumed matching assets.
  const isHeadNode = node.role.in_degree === 0;
  const isTailNode = node.role.out_degree === 0;

  for (const asset of envelope.assets_manifest) {
    if (asset.consumed) continue;

    const isExplicitlyNeeded = requiredInModalities.has(asset.modality) && modelInModalities.has(asset.modality);
    const isTailHarvest = isTailNode && modelInModalities.has(asset.modality);
    const isHeadHarvest = isHeadNode && modelInModalities.has(asset.modality);

    if (isExplicitlyNeeded || isTailHarvest || isHeadHarvest) {
      asset.consumed = true;
      claimedAssets.push(asset);
      requiredInModalities.delete(asset.modality);
    }
  }

  // 3. Upstream text from parent (or previous bundle text context)
  const upstreamText = parentOutput || previousBundle?.text_context || '';
  const isDownstream = node.role.in_degree > 0;

  // 4. Instruction & Constraints Injection Responsibility
  // Head Node in multi-node DAG (in=0 && out>0): Strictly MASK user prompt!
  // Single-node DAG (in=0 && out=0): Receives user prompt.
  // Downstream Node (in>0): Receives user prompt (anchored by System Prompt guidance).
  const isHeadMasked = node.role.in_degree === 0 && node.role.out_degree > 0;
  const injectedPrompt = isHeadMasked ? '' : (envelope.instruction_payload || '');

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

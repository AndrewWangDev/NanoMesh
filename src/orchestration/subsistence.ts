// src/orchestration/subsistence.ts
import { DAGTemplate, ModelMetadata } from "./types";

/**
 * Step 1: Hard Filtering for Models
 * Drops models with user rating < 1.0, status inactive, or insufficient context window
 */
export function hardFilterModels(
  models: ModelMetadata[],
  estimatedTokens: number = 512,
  disableBrowser: boolean = false
): ModelMetadata[] {
  return models.filter(m => {
    // 0. Disable browser inference filter
    if (disableBrowser && m.inference_target === 'browser') return false;

    // 1. Rating check: Rm >= 1.0
    if ((m.user_rating || 5.0) < 1.0) return false;

    // 2. Physical context window check: token budget must fit within model's context window
    if (m.context_window < estimatedTokens) return false;

    // 3. Status active
    if (m.status !== 'active') return false;

    return true;
  });
}

export interface SubsistenceModalityContext {
  mediaModalities?: string[];
  hasUserText?: boolean;
}

/**
 * Step 1: Generalized Subsistence Law (广义温饱定律) for DAG Templates
 * 
 * Axioms:
 * 1. Single-Node DAG: Exact Equivalence for Physical Media Assets:
 *    M(A_user) ≡ M(N_in) and (text ∈ N_in => hasUserText)
 * 2. Multi-Node DAG:
 *    - No-Starvation Axiom: For every node R_i, R_i.in ⊆ Ω_i, where Ω_i = A_user ∪ ⋃_{j < i} R_j.out
 *    - No-Orphan Media Axiom: All user physical media assets must be claimed by at least one node:
 *      M(A_user) ⊆ ⋃_{k=0}^{n-1} R_k.in
 */
export function filterTemplatesBySubsistence(
  templates: DAGTemplate[],
  userModalities: string[] | SubsistenceModalityContext
): DAGTemplate[] {
  let mediaModalities: string[];
  let hasUserText: boolean;
  let userModalitySet: Set<string>;

  if (Array.isArray(userModalities)) {
    const rawList = userModalities.length ? userModalities : ['text'];
    mediaModalities = rawList.filter(m => m !== 'text' && m !== 'text_doc');
    hasUserText = rawList.includes('text') || rawList.includes('text_doc');
    userModalitySet = new Set(rawList);
    if (hasUserText) userModalitySet.add('text');
  } else {
    mediaModalities = userModalities.mediaModalities || [];
    hasUserText = userModalities.hasUserText !== undefined ? userModalities.hasUserText : true;
    userModalitySet = new Set(mediaModalities);
    if (hasUserText) userModalitySet.add('text');
    if (userModalitySet.size === 0) userModalitySet.add('text');
  }

  return templates.filter(tpl => {
    if (tpl.status !== 'active') return false;

    // Check single-node DAG case
    const isSingleNode = tpl.roles.length === 1 && tpl.roles[0].in_degree === 0 && tpl.roles[0].out_degree === 0;
    if (isSingleNode) {
      const role = tpl.roles[0];
      const roleInSet = new Set(role.in_modalities);
      const roleMedia = (role.in_modalities || []).filter(m => m !== 'text' && m !== 'text_doc');
      const roleRequiresText = roleInSet.has('text') || roleInSet.has('text_doc');

      // 1. Physical Media Equivalence: user uploaded media must match role's physical requirements exactly
      const userMediaSet = new Set(mediaModalities);
      const roleMediaSet = new Set(roleMedia);
      if (userMediaSet.size !== roleMediaSet.size) return false;
      for (const m of userMediaSet) {
        if (!roleMediaSet.has(m)) return false;
      }

      // 2. Text Requirement: If role requires text, user must supply text
      if (roleRequiresText && !hasUserText) {
        return false;
      }

      return true;
    }

    if (!tpl.roles || tpl.roles.length === 0) {
      // Legacy fallback if roles array is unpopulated
      const headSet = new Set(tpl.head_modalities);
      const combinedSet = new Set([...tpl.head_modalities, ...tpl.tail_modalities]);
      for (const m of headSet) {
        if (!userModalitySet.has(m)) return false;
      }
      for (const m of mediaModalities) {
        if (!combinedSet.has(m)) return false;
      }
      return true;
    }

    // Multi-Node DAG under Generalized Subsistence Law:
    // 1. Axiom 1: No-Starvation (Every node R_i must have its input satisfied by Ω_i)
    const cumulativeSupply = new Set<string>(userModalitySet);
    for (let i = 0; i < tpl.roles.length; i++) {
      const role = tpl.roles[i];
      for (const requiredIn of role.in_modalities) {
        if (!cumulativeSupply.has(requiredIn)) {
          return false;
        }
      }
      // Add this role's outputs to cumulative supply for downstream nodes
      for (const outM of (role.out_modalities || ['text'])) {
        cumulativeSupply.add(outM);
      }
    }

    // 2. Axiom 2: No-Orphan (User physical media assets cannot contain orphan modalities unconsumed by any node)
    const allClaimableInputs = new Set<string>();
    for (const role of tpl.roles) {
      for (const inM of role.in_modalities) {
        allClaimableInputs.add(inM);
      }
    }
    // All physical media assets must be claimable by at least one node
    for (const m of mediaModalities) {
      if (!allClaimableInputs.has(m)) {
        return false;
      }
    }
    // If user provided ONLY text (no media), the pipeline must consume text
    if (mediaModalities.length === 0 && hasUserText) {
      if (!allClaimableInputs.has('text') && !allClaimableInputs.has('text_doc')) {
        return false;
      }
    }

    return true;
  });
}

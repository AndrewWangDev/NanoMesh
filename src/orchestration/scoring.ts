// src/orchestration/scoring.ts
import { Env } from "../types";
import { ModelMetadata, ScoredModel } from "./types";

/**
 * Computes Cosine Similarity between two L2-normalized float vectors
 */
export function cosineSimilarity(vecA: number[], vecB: number[]): number {
  if (!vecA || !vecB || vecA.length !== vecB.length || vecA.length === 0) return 0;
  let dot = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < vecA.length; i++) {
    dot += vecA[i] * vecB[i];
    normA += vecA[i] * vecA[i];
    normB += vecB[i] * vecB[i];
  }
  const denom = Math.sqrt(normA) * Math.sqrt(normB);
  return denom === 0 ? 0 : dot / denom;
}

/**
 * Generate embedding using @cf/baai/bge-m3 via Workers AI
 */
export async function generatePromptEmbedding(env: Env, text: string): Promise<number[] | null> {
  try {
    if (env.AI) {
      const res = await env.AI.run('@cf/baai/bge-m3', { text: [text.slice(0, 500)] });
      if (res && Array.isArray(res.data) && res.data[0]) {
        return res.data[0];
      }
    }
  } catch (err) {
    console.warn("bge-m3 embedding failed, falling back to keyword heuristics:", err);
  }
  return null;
}

/**
 * Computes deterministic hash jitter in range [0, 0.05] (up to 5% bonus)
 * Provides stateless tie-breaking and spreads concurrent traffic evenly across identical candidates
 * without centralized locks or DB write contention.
 */
function computeHashJitter(seed: string): number {
  let hash = 0;
  for (let i = 0; i < seed.length; i++) {
    hash = (hash * 31 + seed.charCodeAt(i)) >>> 0;
  }
  return (hash % 50) / 1000.0;
}

/**
 * Step 3: Serverless-Native Scoring Formula & Stateless Traffic Shaping
 * 
 * Formula:
 * S = μ0 + α * max(0, sim - τ) + β * (Rm / 5) + ω_fit * Fit(m, L_req) + Tier(m) + δ_jitter
 * 
 * Parameters:
 * - μ0: Generalist prior (0.25 for generalist, 0.0 for specialist)
 * - α: 0.50 (Specialist boost)
 * - τ: 0.65 (Gating threshold)
 * - β: 0.25 (User rating weight)
 * - ω_fit: 0.15 (Context window headroom and fit weight)
 * - Tier(m): Architecture tier affinity (Browser: +0.15, Edge: +0.10, Cloud/Heavy: 0.0)
 * - δ_jitter: Stateless session-hash jitter [0.0, 0.05] for thundering-herd prevention
 */
export async function scoreAndRankRoleModels(
  env: Env,
  roleModels: ModelMetadata[],
  promptEmbedding: number[] | null,
  rawPrompt: string,
  sessionId?: string,
  estimatedTokens: number = 512
): Promise<ScoredModel[]> {
  const ALPHA = 0.50;
  const TAU = 0.65;
  const BETA = 0.25;
  const OMEGA_FIT = 0.15;

  const scoredList: ScoredModel[] = [];

  for (const model of roleModels) {
    // 1. Generalist Prior
    const mu0 = model.is_generalist ? (model.prior_score || 0.25) : 0.0;

    // 2. Scenario Anchor Similarity (sim)
    // Strictly computed via vector cosine similarity between prompt embedding and model anchor embeddings
    let maxSim = 0.0;
    if (promptEmbedding && model.anchor_embeddings && model.anchor_embeddings.length > 0) {
      for (const anchorVec of model.anchor_embeddings) {
        if (Array.isArray(anchorVec) && anchorVec.length > 0) {
          const sim = cosineSimilarity(promptEmbedding, anchorVec);
          if (sim > maxSim) maxSim = sim;
        }
      }
    }

    // 3. Specialist gated score
    const specialistScore = ALPHA * Math.max(0, maxSim - TAU);

    // 4. Rating score: β * (Rm / 5)
    const ratingScore = BETA * (Math.min(5, Math.max(0, model.user_rating || 4.5)) / 5);

    // 5. Serverless Context Fit Score: penalizes models near context exhaustion
    const contextWindow = model.context_window || 4096;
    const fitRatio = Math.max(0, 1.0 - (estimatedTokens / contextWindow));
    const contextFitScore = OMEGA_FIT * fitRatio;

    // 6. Tier Affinity Score: prioritize client WebGPU and edge Worker AI over commercial APIs / heavy VPS
    let tierScore = 0.0;
    if (model.inference_target === 'browser') {
      tierScore = 0.15;
    } else if (model.inference_target === 'edge') {
      tierScore = 0.10;
    }

    // 7. Stateless Hash Jitter for thundering herd prevention
    const jitterScore = computeHashJitter((sessionId || 'session') + '_' + model.model_id);

    // Final Score
    const totalScore = mu0 + specialistScore + ratingScore + contextFitScore + tierScore + jitterScore;

    scoredList.push({
      model,
      score: totalScore,
      sim: maxSim,
      concurrency_penalty: 0.0, // Backwards compatibility: D1 active_connections decoupled
      specialist_score: specialistScore,
      context_fit_score: contextFitScore,
      tier_score: tierScore,
      jitter_score: jitterScore
    });
  }

  // Sort descending by score
  scoredList.sort((a, b) => b.score - a.score);
  return scoredList;
}

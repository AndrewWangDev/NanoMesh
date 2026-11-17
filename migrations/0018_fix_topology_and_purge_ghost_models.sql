-- Migration: 0018_fix_topology_and_purge_ghost_models.sql
-- 1. Standardize Cloudflare Workers AI models to 'edge' inference_target
UPDATE models
SET inference_target = 'edge'
WHERE endpoint LIKE '@cf/%' OR provider LIKE '%cloudflare%';

-- 2. Ensure browser model is 'browser' and dedicated heavy model is 'heavy'
UPDATE models
SET inference_target = 'browser'
WHERE model_id = 'browser-smollm2-135m';

UPDATE models
SET inference_target = 'heavy'
WHERE model_id = 'heavy-llama-3.1-8b';

-- 3. Permanently purge ghost / mock placeholder models with dead endpoints
DELETE FROM models
WHERE endpoint = '/api/infer'
   OR model_id IN (
       'model-qwen2-vl-7b',
       'model-deepseek-r1',
       'model-llama3-01',
       'model-qwen3-01',
       'model-whisper-01'
   );

-- Migration: 0020_multimodal_schema_v2.sql
-- Decouple model in_modalities and out_modalities, add cost_per_invocation, and register Flux-1 Schnell image generator

-- 1. Extend models table
ALTER TABLE models ADD COLUMN in_modalities TEXT DEFAULT '["text"]';
ALTER TABLE models ADD COLUMN out_modalities TEXT DEFAULT '["text"]';
ALTER TABLE models ADD COLUMN cost_per_invocation REAL DEFAULT 0.0;

-- 2. Align existing models
UPDATE models SET in_modalities = '["text"]', out_modalities = '["text"]' WHERE modalities = '["text"]' OR modalities IS NULL;
UPDATE models SET in_modalities = '["image","text"]', out_modalities = '["text"]' WHERE model_id IN ('cf-llava-1.5-7b', 'cf-moondream-9b');
UPDATE models SET in_modalities = '["audio"]', out_modalities = '["text"]' WHERE model_id = 'cf-whisper';
UPDATE models SET in_modalities = '["text"]', out_modalities = '["text"]' WHERE model_id = 'heavy-llama-3.1-8b';
UPDATE models SET in_modalities = '["text"]', out_modalities = '["text"]' WHERE model_id = 'browser-smollm2-135m';

-- 3. Register Workers AI Flux-1-Schnell for edge image generation
INSERT OR REPLACE INTO models (
    model_id, display_name, provider, endpoint, in_modalities, out_modalities, modalities,
    tags, context_window, max_concurrency, active_connections, precision, user_rating, usage_count,
    cost_per_1k_tokens, cost_per_invocation, status, is_generalist, prior_score, scenario_anchors,
    inference_target, api_format, auth_mode
) VALUES (
    'cf-flux-schnell',
    'Flux-1 Schnell 敏捷生图',
    'Black Forest Labs/CF',
    '@cf/black-forest-labs/flux-1-schnell',
    '["text"]',
    '["image"]',
    '["text","image"]',
    '["#image_generation","#visual_art","#general"]',
    2048, 20, 0, 0.98, 4.95, 100,
    0.0, 2.0, 'active', 0, 0.0,
    '["根据提示词生成高清艺术图片","商业配图绘制","概念视觉草图设计"]',
    'edge', 'workers_ai', 'none'
);

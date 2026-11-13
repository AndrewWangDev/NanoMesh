-- Migration: 0016_heavy_node_and_model_cleanup.sql
-- Purge legacy placeholder models and register dedicated AWS Lightsail Heavy Node

-- 1. Deactivate legacy mock / placeholder models
UPDATE models SET status = 'inactive' WHERE model_id IN ('model-qwen2-vl-7b', 'model-deepseek-r1', 'model-llama3-01', 'model-qwen3-01', 'model-whisper-01');

-- 2. Register Dedicated AWS Lightsail Heavy Node (Llama-3.1-8B-Instruct)
INSERT OR REPLACE INTO models (
    model_id, display_name, provider, endpoint, modalities, tags, context_window, max_concurrency, active_connections, precision, user_rating, usage_count, cost_per_1k_tokens, status, is_generalist, prior_score, scenario_anchors, inference_target
) VALUES (
    'heavy-llama-3.1-8b',
    'Llama-3.1-8B 深度推演 (Dedicated)',
    'AWS Lightsail (Dedicated)',
    'https://ai.andrewwangdev.com/v1/chat/completions',
    '["text"]',
    '["#reasoning","#analysis","#deep_inference","#text_generation","#code","#general"]',
    4096,
    10,
    0,
    0.96,
    4.95,
    50,
    1.5,
    'active',
    0,
    0.35,
    '["复杂逻辑链条推演","学术研报长文深度归因分析","代码安全审计与重构","高阶结构化梳理"]',
    'heavy'
);

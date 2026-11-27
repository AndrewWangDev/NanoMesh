-- Keep historical model IDs intact. Only replace still-active stock endpoints.
WITH replacements(old_id, old_endpoint, new_id, name, provider, endpoint) AS (
  VALUES
    ('cf-llama-3.1-8b', '@cf/meta/llama-3.1-8b-instruct-fp8', 'cf-llama-3.1-8b-fast', 'Llama-3.1-8B Fast 表达润色', 'Meta', '@cf/meta/llama-3.1-8b-instruct-fast'),
    ('cf-qwq-32b', '@cf/qwen/qwq-32b', 'cf-qwen3.8-27b', 'Qwen3.8-27B 深度推理', 'Qwen', '@cf/qwen/qwen3.8-27b'),
    ('cf-llama-3.2-3b', '@cf/meta/llama-3.2-3b-instruct', 'cf-gemma-4-26b-a4b', 'Gemma 4 26B A4B 对话', 'Google', '@cf/google/gemma-4-26b-a4b-it')
)
INSERT INTO models (model_id, display_name, provider, endpoint, modalities, tags,
  context_window, max_concurrency, cost_per_1k_tokens, cost_per_invocation,
  inference_target, api_format, in_modalities, out_modalities, is_generalist, prior_score, scenario_anchors)
SELECT r.new_id, r.name, r.provider, r.endpoint, m.modalities, m.tags,
  MIN(8192, m.context_window), m.max_concurrency, m.cost_per_1k_tokens, m.cost_per_invocation,
  'edge', 'workers_ai', m.in_modalities, m.out_modalities, m.is_generalist, m.prior_score, m.scenario_anchors
FROM models m JOIN replacements r ON m.model_id = r.old_id AND m.endpoint = r.old_endpoint
WHERE m.status = 'active'
ON CONFLICT(model_id) DO NOTHING;

UPDATE models SET status = 'inactive', updated_at = datetime('now')
WHERE endpoint IN ('@cf/meta/llama-3.1-8b-instruct-fp8', '@cf/qwen/qwq-32b',
  '@cf/meta/llama-3.2-3b-instruct', '@cf/llava-hf/llava-1.5-7b-hf');

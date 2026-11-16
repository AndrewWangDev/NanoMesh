-- Migration: 0017_unified_node_and_linear_dag.sql
-- Decouple independent DAG roles, simplify linear template sequencing, and abstract unified node authentication & protocol format.

-- 1. Extend models table for unified node provider abstraction
ALTER TABLE models ADD COLUMN auth_mode TEXT DEFAULT 'none';
    -- 'none' (Cloudflare Workers AI / Browser WebGPU)
    -- 'jwt_ephemeral' (Dedicated VPS with anti-replay/anti-tamper gateway)
    -- 'bearer_static' (Google AI Studio API Key / OpenAI API Key)

ALTER TABLE models ADD COLUMN auth_secret TEXT DEFAULT NULL;
    -- Secret credentials (JWT Secret or Static Bearer Token). Admin-only, masked in API.

ALTER TABLE models ADD COLUMN api_format TEXT DEFAULT 'workers_ai';
    -- 'workers_ai' (Cloudflare env.AI.run)
    -- 'openai_compat' (Standard OpenAI /v1/chat/completions)
    -- 'google_ai' (Google AI Studio Gemini API format)

-- Update active models to their proper protocol and authentication defaults
UPDATE models SET auth_mode = 'none', api_format = 'workers_ai' WHERE model_id LIKE 'cf-%';
UPDATE models SET auth_mode = 'none', api_format = 'workers_ai' WHERE model_id = 'browser-smollm2-135m';
UPDATE models SET auth_mode = 'jwt_ephemeral', api_format = 'openai_compat' WHERE model_id = 'heavy-llama-3.1-8b';

-- 2. Create independent dag_roles table (Role Registry)
CREATE TABLE IF NOT EXISTS dag_roles (
    role_id               TEXT PRIMARY KEY,
    name_zh               TEXT NOT NULL,
    name_en               TEXT NOT NULL,
    in_modalities         TEXT NOT NULL, -- JSON array e.g. ["image"]
    out_modalities        TEXT NOT NULL, -- JSON array e.g. ["text"]
    requisition_tags      TEXT NOT NULL, -- JSON array e.g. ["#ocr_precise"]
    compensation_prompts  TEXT DEFAULT '{}', -- JSON object e.g. {"#general": "..."}
    created_at            TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_dag_roles_created ON dag_roles(created_at);

-- Seed 5 standard roles extracted from initial monolithic templates
INSERT OR REPLACE INTO dag_roles (role_id, name_zh, name_en, in_modalities, out_modalities, requisition_tags, compensation_prompts)
VALUES 
(
    'role-direct-chat',
    '综合理解与生成',
    'General Synthesis',
    '["text"]',
    '["text"]',
    '["#chat","#text_generation","#general"]',
    '{"#general":"【系统约束】你是一个专业的AI助手，请直接全面回答用户的问题。"}'
),
(
    'role-vision-extractor',
    '视觉元素与文字提取',
    'Vision & OCR Extraction',
    '["image"]',
    '["text"]',
    '["#ocr_precise","#multimodal_vision","#general_vlm"]',
    '{"#multimodal_vision":"【系统约束】你当前扮演高精度OCR识别专家，请忽略背景无关干扰，逐字逐行输出图片中识别出的所有可见文字与排版结构。","#general_vlm":"【系统约束】请尽可能详细地提取并描述图片内的文字、表格以及核心视觉数据。"}'
),
(
    'role-synthesis-polish',
    '结构化分析与润色',
    'Structuring & Refinement',
    '["text"]',
    '["text"]',
    '["#reasoning","#analysis","#text_generation"]',
    '{"#text_generation":"【系统约束】请根据下游提取的文档文字信息，结合用户意图进行结构化整理和润色输出。"}'
),
(
    'role-audio-asr',
    '语音转录提取',
    'Speech Recognition',
    '["audio"]',
    '["text"]',
    '["#asr","#audio_processing"]',
    '{"#audio_processing":"【系统约束】请精准转写音频流内容为自然文本，过滤杂音。"}'
),
(
    'role-action-extractor',
    '行动项总结与决策',
    'Action Items Extractor',
    '["text"]',
    '["text"]',
    '["#reasoning","#analysis","#text_generation"]',
    '{"#text_generation":"【系统约束】请根据会议或录音转写内容，提炼出清晰的关键行动项和结论。"}'
);

-- 3. Extend dag_templates with linear role_sequence
ALTER TABLE dag_templates ADD COLUMN role_sequence TEXT DEFAULT '[]';

-- Update existing linear templates with their respective role sequence
UPDATE dag_templates SET role_sequence = '["role-direct-chat"]' WHERE template_id = 'tpl-direct-chat';
UPDATE dag_templates SET role_sequence = '["role-vision-extractor","role-synthesis-polish"]' WHERE template_id = 'tpl-vision-ocr-summary';
UPDATE dag_templates SET role_sequence = '["role-audio-asr","role-action-extractor"]' WHERE template_id = 'tpl-audio-action-items';
UPDATE dag_templates SET role_sequence = '["role-vision-extractor","role-synthesis-polish"]' WHERE template_id = 'tpl-multimodal-fusion';

-- 4. Note on user_uploaded_models:
-- The legacy community model upload & review workflow is deprecated in favor of admin-managed node registry.
-- user_uploaded_models table is preserved for historical compatibility and is no longer written to.

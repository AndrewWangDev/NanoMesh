-- Migration: 0021_add_image_generation_seed.sql
-- Seed official image generation role and default text-to-image pipeline template

INSERT OR IGNORE INTO dag_roles (
    role_id, name_zh, name_en, in_modalities, out_modalities, requisition_tags, compensation_prompts
) VALUES (
    'role_flux_draw',
    '视觉概念与图像生成',
    'Visual Concept & Image Generation',
    '["text"]',
    '["image"]',
    '["#image_generation","#visual_art","#general"]',
    '{"#image_generation":"【系统约束】你当前承接视觉概念与图像生成职责，请根据用户提供的文本提示词，构思并生成高质量、具有视觉美感的高清艺术图像。"}'
);

INSERT OR IGNORE INTO dag_templates (
    template_id, name_zh, name_en, desc_zh, desc_en, head_modalities, tail_modalities, roles, priority, status, role_sequence
) VALUES (
    'tpl-text-to-image',
    '文生图创作流水线',
    'Text-to-Image Generation Pipeline',
    '接收文本提示词，调度 FLUX 敏捷生图模型进行端到端概念视觉图像创作',
    'Generate visual concept assets from text prompt directives via edge FLUX model',
    '["text"]',
    '["image"]',
    '["role_flux_draw"]',
    5,
    'active',
    '["role_flux_draw"]'
);

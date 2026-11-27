-- Tune model ratings, context windows, and prior_score so fast edge models rank ahead of slow self-hosted heavy nodes by default.
UPDATE models
SET context_window = 32768,
    user_rating = 4.96,
    prior_score = 0.0
WHERE model_id = 'cf-llama-3.1-8b-fast';

UPDATE models
SET context_window = 32768,
    user_rating = 4.95,
    prior_score = 0.0
WHERE model_id = 'cf-qwen3.8-27b';

UPDATE models
SET context_window = 32768,
    user_rating = 4.94,
    prior_score = 0.25
WHERE model_id = 'cf-gemma-4-26b-a4b';

UPDATE models
SET prior_score = 0.0,
    user_rating = 4.75
WHERE model_id = 'heavy-llama-3.1-8b';

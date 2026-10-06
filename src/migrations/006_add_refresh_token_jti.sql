ALTER TABLE refresh_tokens
ADD COLUMN IF NOT EXISTS jti UUID;

CREATE UNIQUE INDEX IF NOT EXISTS idx_refresh_tokens_jti
ON refresh_tokens (jti);

UPDATE refresh_tokens
SET jti = gen_random_uuid()
WHERE jti IS NULL;

ALTER TABLE refresh_tokens
ALTER COLUMN jti SET NOT NULL;

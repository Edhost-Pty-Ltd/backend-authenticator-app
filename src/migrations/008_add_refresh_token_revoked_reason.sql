ALTER TABLE refresh_tokens
ADD COLUMN IF NOT EXISTS revoked_reason VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked_reason
ON refresh_tokens (revoked_reason);

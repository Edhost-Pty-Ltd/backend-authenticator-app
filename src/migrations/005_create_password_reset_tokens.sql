CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_reset_tokens_user
ON password_reset_tokens (user_id, used_at, expires_at);

ALTER TABLE refresh_tokens
ADD COLUMN IF NOT EXISTS revoked_reason VARCHAR(32);

CREATE INDEX IF NOT EXISTS idx_refresh_tokens_revoked_reason
ON refresh_tokens (revoked_reason);
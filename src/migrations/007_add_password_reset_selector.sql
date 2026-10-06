ALTER TABLE password_reset_tokens ADD COLUMN IF NOT EXISTS selector TEXT;

UPDATE password_reset_tokens
SET selector = encode(gen_random_bytes(16), 'hex')
WHERE selector IS NULL;

ALTER TABLE password_reset_tokens ALTER COLUMN selector SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS idx_password_reset_tokens_selector
ON password_reset_tokens (selector);

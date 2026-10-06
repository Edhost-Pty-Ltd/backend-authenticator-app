CREATE TABLE IF NOT EXISTS applications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled', 'revoked')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_applications_status ON applications (status);

CREATE TABLE IF NOT EXISTS external_mfa_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    external_user_id TEXT NOT NULL,
    identifier TEXT,
    encrypted_totp_secret TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    last_used_timestep BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    UNIQUE (application_id, external_user_id)
);

CREATE INDEX IF NOT EXISTS idx_external_mfa_accounts_application
ON external_mfa_accounts (application_id, external_user_id);

CREATE INDEX IF NOT EXISTS idx_external_mfa_accounts_enabled
ON external_mfa_accounts (application_id, enabled, revoked_at);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id UUID REFERENCES applications(id) ON DELETE SET NULL,
    external_user_id TEXT,
    event_type VARCHAR(64) NOT NULL,
    success BOOLEAN NOT NULL,
    ip_address INET,
    user_agent TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_application_created
ON audit_logs (application_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_external_user
ON audit_logs (application_id, external_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_event
ON audit_logs (event_type, created_at DESC);

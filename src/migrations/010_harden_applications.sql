ALTER TABLE applications
ADD COLUMN IF NOT EXISTS credential_version INTEGER NOT NULL DEFAULT 1;

ALTER TABLE applications
ADD CONSTRAINT applications_credential_version_positive
CHECK (credential_version > 0);

CREATE INDEX IF NOT EXISTS idx_applications_credential_version
ON applications (id, credential_version);

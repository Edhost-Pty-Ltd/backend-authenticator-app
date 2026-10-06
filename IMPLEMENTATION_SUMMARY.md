# Backend completion summary

This backend is the completed baseline for the standalone multi-system MFA provider. Existing `/auth/*` and `/internal/*` functionality remains intact.

## Core authentication

- User registration/login
- bcrypt password hashing
- Short-lived JWT access tokens
- Refresh tokens with rotation and reuse detection
- Logout/session revocation
- Password reset token lifecycle
- User TOTP enrollment, activation, verification, disable, status
- Recovery/backup codes
- TOTP replay protection
- AES-256-GCM encryption for stored TOTP secrets

## External MFA provider

- Per-application client IDs and secrets
- Client secrets stored only as bcrypt hashes
- Short-lived application service JWTs
- Dedicated service-token audience/type/scope
- Application-scoped external users
- External TOTP enrollment, QR provisioning, activation, verification, status, revoke
- Application isolation by `(application_id, external_user_id)`
- External MFA replay protection
- Audit logging
- Dedicated provider rate limiting

## Application management hardening

- Application registration is administrator-protected.
- `X-Admin-API-Key` protects application management.
- Applications can be listed and inspected by an administrator.
- Applications can be enabled, disabled, or permanently revoked.
- Disabling/revoking/reactivating increments `credential_version`, invalidating previously issued service tokens.
- Client-secret rotation increments `credential_version` and immediately invalidates previously issued service tokens.
- Application audit history can be retrieved by an administrator.
- Revoked applications cannot be reactivated.

## New administrator endpoints

- `POST /api/admin/applications`
- `GET /api/admin/applications`
- `GET /api/admin/applications/:id`
- `PATCH /api/admin/applications/:id/status`
- `POST /api/admin/applications/:id/rotate-secret`
- `GET /api/admin/applications/:id/audit`

The existing `POST /api/applications/register` remains as a compatibility endpoint, but is now also administrator-protected.

## Security configuration

Production now requires:

- `DATABASE_URL`
- `JWT_SECRET` >= 32 characters
- `TOTP_ENCRYPTION_KEY` exactly 64 hex characters
- `ADMIN_API_KEY` >= 32 characters
- `MYANGANO_SERVICE_API_KEY` >= 32 characters

The administrator key and all application client secrets must remain server-side and must never be placed in the Expo/mobile application.

## Validation completed in this packaging environment

- JavaScript syntax check: PASS.
- Dependency install/test execution: BLOCKED by this environment's unavailable npm registry/cache; no application dependency failure was observed.
- PostgreSQL integration execution: BLOCKED because this packaging environment does not provide PostgreSQL.

Run these commands on the development machine with the project's PostgreSQL database:

```powershell
npm ci
npm run migrate
npm test
npm run check
```

For production, also verify HTTPS, PostgreSQL TLS where required, network restriction of `/internal/*`, secret-manager usage, database backup/restore, and a security/penetration review.

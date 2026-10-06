# Backend completion checklist

This project is considered **backend-complete for the standalone multi-system MFA provider scope** when all items below are true.

## Core authentication

- [x] Registration
- [x] Login
- [x] bcrypt password hashing
- [x] Short-lived JWT access tokens
- [x] Refresh-token rotation
- [x] Refresh-token reuse detection
- [x] Logout/session revocation
- [x] Password reset token storage and one-time consumption
- [x] 2FA login with TOTP
- [x] Backup/recovery codes

## Authenticator/MFA

- [x] TOTP secret generation
- [x] AES-256-GCM secret encryption at rest
- [x] QR provisioning
- [x] Manual provisioning
- [x] TOTP activation
- [x] TOTP verification
- [x] TOTP replay protection
- [x] Backup-code one-time consumption
- [x] External-application MFA accounts
- [x] External-user isolation by application
- [x] External MFA enrollment/activation/status/revoke

## External application platform

- [x] Per-application client ID
- [x] Per-application client secret
- [x] Client secret hashing
- [x] Short-lived application service tokens
- [x] Service-token scope and audience separation
- [x] Application status enforcement
- [x] Application credential versioning
- [x] Credential rotation invalidates previously issued service tokens
- [x] Administrator-protected application registration
- [x] Administrator application listing/details
- [x] Administrator enable/disable/revoke
- [x] Administrator secret rotation
- [x] Application audit retrieval

## Security/operations

- [x] Helmet
- [x] CORS allowlisting
- [x] Body-size limits
- [x] Global and endpoint rate limits
- [x] Input validation
- [x] Parameterized SQL
- [x] Graceful shutdown
- [x] Health/readiness endpoints
- [x] Security/audit event logging for external provider operations
- [x] Production secret validation
- [x] Syntax checks

## Verification required in the deployment environment

- [ ] `npm ci` completes successfully
- [ ] `npm test` passes with dependencies installed
- [ ] `npm run migrate` completes against the real PostgreSQL instance
- [ ] PostgreSQL integration tests pass against a disposable test database
- [ ] HTTPS/TLS is enforced by the production reverse proxy
- [ ] PostgreSQL TLS is configured where required
- [ ] `/internal/*` is network-restricted or intentionally protected for the deployment
- [ ] Production secrets are stored in a secret manager/environment, not source control
- [ ] A production backup/restore procedure is tested
- [ ] External penetration/security review is completed

## Deliberately outside this backend scope

OAuth 2.0/OpenID Connect is not required for the current MFA-provider contract. Add OIDC only if external systems must delegate their **entire user login/identity** to Multi-Auth rather than using Multi-Auth as an MFA provider.

# Security hardening status

This repository is intended to be the authentication backend consumed by the standalone authenticator application and other trusted systems.

## Completed in this hardening pass

- Removed insecure JWT and TOTP encryption-key fallbacks.
- Validated the TOTP AES-256 key as exactly 32 bytes supplied as 64 hex characters.
- Added JWT issuer/audience validation and restricted verification to HS256.
- Reduced the default access-token lifetime from 1 hour to 15 minutes.
- Added exact CORS origin allowlisting.
- Reduced request-body limits.
- Added global and endpoint-specific rate limits.
- Added strict validation for UUIDs, TOTP codes, backup-code format, emails, and passwords.
- Added atomic TOTP timestep consumption.
- Corrected TOTP replay tracking when the ±1 timestep window is used.
- Added atomic one-time backup-code consumption.
- Added refresh-token `jti` records and rotation/reuse detection.
- Added indexed selectors for password-reset tokens.
- Invalidated previous unused password-reset tokens when a new reset is requested.
- Prevented re-enrollment from silently replacing an enabled authenticator.
- Added async error forwarding for Express 4 route handlers.
- Added PostgreSQL connection limits/timeouts and graceful shutdown.
- Added a database-backed `/ready` endpoint.
- Disabled Express `X-Powered-By`.
- Added syntax checks and expanded unit-level security tests.

## Still required before production

1. **Run the complete test suite with a real disposable PostgreSQL database.**
   The current environment used for this hardening pass could not complete dependency installation, so `npm test` could not execute.

2. **Add PostgreSQL integration tests.**
   Test registration, login, 2FA enrollment/activation, TOTP replay/concurrency, recovery-code replay/concurrency, refresh-token rotation/reuse, password reset, logout, and internal service authentication.

3. **Use the managed application identity model for consuming systems.**
   Each consuming application now has its own credential, status, scope, credential version, rotation, and revocation.

4. **Add account-aware authentication throttling if threat modeling requires it.**
   IP rate limits are already present; a distributed deployment can add carefully designed per-account failure controls without creating an account-lockout denial-of-service vector.

5. **Add an email/SMS delivery provider for password resets.**
   Production responses must never return reset tokens.

6. **Use TLS everywhere outside local development.
   PostgreSQL TLS should be enabled when required by the deployment, and the API should sit behind HTTPS.

7. **Add structured security/audit logging.**
   Log authentication events without logging passwords, TOTP secrets, backup codes, access tokens, refresh tokens, or reset tokens.

8. **Add operational secret rotation.**
   JWT signing-key and TOTP encryption-key rotation need a deliberate key-versioning strategy before production rotation is required.

9. **Review deployment isolation.**
   The `/internal` API must not be exposed directly to the public internet unless its service-authentication model and network controls are intentionally designed for that deployment.

10. **Keep administrator application-management credentials out of frontend/mobile code.**

11. **Perform an external security review/penetration test before production use.**

## Important migration note

Run all migrations in order. Migration `006_add_refresh_token_jti.sql` assigns identifiers to existing refresh-token records; refresh tokens issued before the new JWT `jti` model are not accepted by the application because the old JWT itself does not contain a matching `jti`.

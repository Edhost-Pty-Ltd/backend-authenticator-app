# Multi Auth Backend

Hardened Node.js/Express authentication backend extended into a reusable standalone MFA provider for external applications such as Myanango Legal Cloud.

The existing `/auth/*` user-authentication system remains intact. The new `/api/applications/*` and `/api/mfa/*` APIs add application-to-MFA-provider integration without making the Multi-Auth backend the external application's user database.

## Stack

- Node.js + Express
- JavaScript ES Modules
- PostgreSQL
- JWT / HS256
- TOTP via Speakeasy
- QRCode provisioning
- bcrypt
- AES-256-GCM encryption for TOTP secrets
- Helmet, CORS allowlisting, express-rate-limit

## Existing functionality preserved

- User registration/login
- Password hashing
- JWT access tokens
- Refresh tokens and rotation
- Refresh-token reuse detection
- Logout/session revocation
- Password reset
- User TOTP enrollment/activation/verification/status/disable
- Recovery/backup codes
- TOTP replay protection
- Health/readiness endpoints
- Existing `/internal/*` service endpoints

## New external MFA-provider functionality

- Administrator-protected external application registration
- Hashed application client secrets
- Short-lived application service JWTs
- Application enable/disable/revoke state
- Application credential rotation with versioned token invalidation
- Application-scoped external-user MFA accounts
- TOTP enrollment and QR provisioning
- TOTP activation
- External MFA verification
- MFA status
- MFA revoke
- Audit logging
- Application isolation
- Dedicated rate limits
- Administrator application management and audit retrieval

## Architecture

```text
External Application Backend (Myanango)
        |
        | client credentials -> service token
        v
Multi-Auth Backend
        |
        +-- Application authentication
        +-- External user -> MFA mapping
        +-- MFA enrollment / activation
        +-- MFA verification
        +-- MFA status / revoke
        +-- Audit logs
        |
        v
PostgreSQL

Authenticator App
        |
        | enrollment data / TOTP workflow
        v
Multi-Auth Backend
```

The external application owns its own users. For example, Myanango remains the source of truth for `Gift` and external user ID `7845`. Multi-Auth stores only the MFA relationship:

```text
application = Myanango
external_user_id = 7845
encrypted TOTP secret = stored by Multi-Auth
MFA enabled = true/false
```

The external application's client secret must remain on its backend/server and must never be placed in a browser or mobile application.

## Installation

1. Copy `.env.example` to `.env`.
2. Configure PostgreSQL.
3. Generate secrets. PowerShell/Node examples:

```powershell
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
node -e "console.log(require('crypto').randomBytes(48).toString('base64'))"
```

Use the first output for `TOTP_ENCRYPTION_KEY` and the second for `JWT_SECRET`.

4. Install dependencies:

```powershell
npm install
```

5. Run migrations:

```powershell
npm run migrate
```

6. Start the backend:

```powershell
npm start
```

Development mode:

```powershell
npm run dev
```

Default port: `4000`.

## Configuration

Required:

- `DATABASE_URL`
- `JWT_SECRET` — at least 32 characters outside tests
- `TOTP_ENCRYPTION_KEY` — exactly 64 hexadecimal characters

JWT:

- `JWT_ISSUER` — default `multiauth`
- `JWT_AUDIENCE` — default `multiauth-client`
- `JWT_SERVICE_AUDIENCE` — default `multiauth-service`

Existing service integration:

- `MYANGANO_SERVICE_API_KEY`
- `MYANGANO_WEBHOOK_URL`
- `ADMIN_API_KEY` — administrator key for application registration and management; required in production

Infrastructure:

- `CORS_ORIGINS`
- `TRUST_PROXY`
- `DB_POOL_MAX`
- `DB_SSL`
- `DB_SSL_REJECT_UNAUTHORIZED`

Do not commit `.env` or production secrets.

## Database migrations

The external MFA provider is introduced by migration `009_create_external_mfa_provider.sql`.

It creates:

### `applications`

Stores external application identity and a bcrypt hash of the client secret.

### `external_mfa_accounts`

Stores the relationship between an application and its external user. The TOTP secret is encrypted with the existing AES-256-GCM mechanism.

The uniqueness rule is:

```sql
UNIQUE(application_id, external_user_id)
```

### `audit_logs`

Stores security events without storing passwords, OTP codes, TOTP secrets, client secrets, access tokens, or refresh tokens.


## Administrator application management

Application registration is not a public endpoint. Send the administrator key in `X-Admin-API-Key`.

```http
POST /api/admin/applications
X-Admin-API-Key: <admin-key>
Content-Type: application/json
```

The response returns the client secret exactly once. Additional management endpoints are available to an administrator:

- `GET /api/admin/applications`
- `GET /api/admin/applications/:id`
- `PATCH /api/admin/applications/:id/status`
- `POST /api/admin/applications/:id/rotate-secret`
- `GET /api/admin/applications/:id/audit`

Rotating a client secret increments the application's credential version and immediately invalidates previously issued application service tokens. Disabling or revoking an application also invalidates its current service tokens.

The legacy `POST /api/applications/register` endpoint remains available as an administrator-protected compatibility endpoint.

## External application API

### 1. Register an application

```http
POST /api/applications/register
Content-Type: application/json
```

Request:

```json
{
  "name": "Myanango"
}
```

Response:

```json
{
  "application": {
    "id": "uuid",
    "name": "Myanango",
    "client_id": "app_xxxxx",
    "status": "active",
    "created_at": "..."
  },
  "clientId": "app_xxxxx",
  "clientSecret": "sec_xxxxx",
  "message": "Save the client secret now. It will not be returned again."
}
```

The raw client secret is returned only during creation and is never stored. PostgreSQL stores only its bcrypt hash.

### 2. Obtain a service token

```http
POST /api/applications/token
Content-Type: application/json
```

Request:

```json
{
  "clientId": "app_xxxxx",
  "clientSecret": "sec_xxxxx"
}
```

Response:

```json
{
  "access_token": "...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

Use it only from the external application's backend:

```http
Authorization: Bearer <service_access_token>
```

Service tokens are short-lived JWTs with a dedicated `service` type and `mfa:provider` scope.

### 3. Enroll an external user

```http
POST /api/mfa/enroll
Authorization: Bearer <service_access_token>
Content-Type: application/json
```

Request:

```json
{
  "externalUserId": "7845",
  "identifier": "gift@example.com"
}
```

Response includes the provisioning QR data and manual TOTP entry value needed by the authenticator enrollment flow.

```json
{
  "account": {
    "id": "uuid",
    "external_user_id": "7845",
    "identifier": "gift@example.com",
    "enabled": false
  },
  "qrCode": "data:image/png;base64,...",
  "manualEntryCode": "BASE32SECRET",
  "provisioningUri": "otpauth://totp/...",
  "message": "Scan the QR code, then activate MFA with a current 6-digit code."
}
```

The encrypted database value is never returned.

### 4. Activate MFA

After the authenticator scans the QR code and generates its first code:

```http
POST /api/mfa/activate
Authorization: Bearer <service_access_token>
Content-Type: application/json
```

```json
{
  "externalUserId": "7845",
  "code": "482913"
}
```

Successful response:

```json
{
  "enabled": true,
  "verified": true,
  "message": "MFA activated"
}
```

The code used for activation is recorded in replay protection so it cannot immediately be reused.

### 5. Check MFA status

```http
GET /api/mfa/status/7845
Authorization: Bearer <service_access_token>
```

Response:

```json
{
  "enabled": true
}
```

No secret is returned.

### 6. Verify MFA

```http
POST /api/mfa/verify
Authorization: Bearer <service_access_token>
Content-Type: application/json
```

```json
{
  "externalUserId": "7845",
  "code": "482913"
}
```

Response:

```json
{
  "verified": true
}
```

Invalid, expired, or replayed codes return:

```json
{
  "verified": false
}
```

The application is derived from the service token. A caller cannot submit an arbitrary `applicationId` to select another application's account.

### 7. Revoke MFA

```http
POST /api/mfa/revoke
Authorization: Bearer <service_access_token>
Content-Type: application/json
```

```json
{
  "externalUserId": "7845"
}
```

Response:

```json
{
  "revoked": true
}
```

The revoked credential cannot be verified until a new enrollment is performed.

### 8. Revoke an application

A currently authenticated application can revoke its own application credentials:

```http
POST /api/applications/revoke
Authorization: Bearer <service_access_token>
```

After revocation, future service-token authentication fails and existing application access is rejected because the application is checked against its current database status.

## Myanango integration flow

```text
Gift registers on Myanango
        |
        v
Myanango creates Gift's user account
        |
        v
Myanango backend obtains a Multi-Auth service token
        |
        v
POST /api/mfa/enroll
        |
        v
Multi-Auth creates application-scoped MFA relationship
        |
        v
Authenticator scans QR code
        |
        v
Authenticator generates 6-digit TOTP
        |
        v
POST /api/mfa/activate
        |
        v
MFA becomes enabled
        |
        v
Gift logs into Myanango
        |
        v
Myanango verifies password
        |
        v
Myanango asks Gift for MFA code
        |
        v
Myanango backend calls POST /api/mfa/verify
        |
        v
Multi-Auth returns verified=true/false
        |
        v
Myanango makes its own authorization decision
```

## Application isolation

All external MFA operations are scoped to the authenticated application:

```text
application_id + external_user_id
```

Therefore:

```text
Myanango + 7845
```

is different from:

```text
OtherApplication + 7845
```

No external MFA endpoint queries by `external_user_id` alone.

## Audit events

The implementation records important provider events including:

- `APPLICATION_REGISTERED`
- `APPLICATION_AUTH_FAILED`
- `APPLICATION_DISABLED`
- `MFA_ENROLLED`
- `MFA_ACTIVATED`
- `MFA_VERIFICATION_SUCCESS`
- `MFA_VERIFICATION_FAILED`
- `MFA_REVOKED`

Audit logs intentionally exclude passwords, raw OTP codes, TOTP secrets, client secrets, access tokens, and refresh tokens.

## Security model

- Client secrets are generated with cryptographically secure randomness.
- Client secrets are bcrypt-hashed before storage.
- Service JWTs are short-lived and use a separate audience from user tokens.
- Service JWTs carry a dedicated token type and scope.
- Application status is checked against PostgreSQL for every protected provider request.
- TOTP secrets are encrypted using the existing AES-256-GCM implementation.
- TOTP replay protection uses the matched TOTP timestep.
- MFA accounts are isolated by `(application_id, external_user_id)`.
- External provider endpoints are rate limited.
- Existing Helmet, CORS, request-size limits, JWT validation, password hashing, and existing `/auth/*` security remain enabled.
- Application client secrets must never be placed in browser/mobile/frontend code.

## Existing API

The original APIs remain available, including:

- `POST /auth/register`
- `POST /auth/login`
- `POST /auth/refresh`
- `POST /auth/logout`
- `GET /auth/me`
- `POST /auth/password-reset/request`
- `POST /auth/password-reset`
- `POST /auth/2fa/verify`
- `POST /auth/2fa/enroll`
- `POST /auth/2fa/activate`
- `GET /auth/2fa/status`
- `POST /auth/2fa/disable`
- `POST /auth/2fa/backup-codes/regenerate`

Existing internal endpoints remain available under `/internal`.

## Testing

Run:

```powershell
npm test
```

For Windows PowerShell syntax validation, because the historical `npm run check` command uses Unix `find/xargs`, use:

```powershell
Get-ChildItem -Path src,tests -Recurse -Filter *.js |
  ForEach-Object { node --check $_.FullName }
```

The test suite covers the existing JWT/TOTP security behavior plus application service-token separation.

## Production notes

Application registration is administrator-protected by default; do not expose the administrator key to browser or mobile clients.

Run PostgreSQL migrations before starting a deployment:

```powershell
npm run migrate
```

Use HTTPS/TLS in production and keep all client credentials server-side.

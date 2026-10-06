import QRCode from 'qrcode';
import { pool } from '../db/pool.js';
import { encryptSecret, decryptSecret } from '../utils/encryption.js';
import { generateSecret, verifyTokenDelta, currentTimestep } from '../utils/totp.js';
import { isSixDigitCode } from '../utils/validators.js';
import { writeAuditLog } from '../utils/audit.js';

function validExternalUserId(value) {
  return typeof value === 'string' && value.trim().length > 0 && value.length <= 255;
}

function genericMfaError(res) {
  return res.status(400).json({ error: 'MFA operation could not be completed' });
}

export async function enrollExternalMfa(req, res) {
  const externalUserId = typeof req.body.externalUserId === 'string' ? req.body.externalUserId.trim() : '';
  const identifier = typeof req.body.identifier === 'string' ? req.body.identifier.trim() : '';
  if (!validExternalUserId(externalUserId) || identifier.length > 254) {
    return res.status(400).json({ error: 'Valid externalUserId is required' });
  }

  const existing = await pool.query(
    `SELECT id, enabled, revoked_at FROM external_mfa_accounts
     WHERE application_id = $1 AND external_user_id = $2`,
    [req.application.id, externalUserId]
  );

  if (existing.rows.length && existing.rows[0].enabled && !existing.rows[0].revoked_at) {
    return res.status(409).json({ error: 'MFA is already enabled for this user' });
  }

  const secret = generateSecret(identifier || `${req.application.name}:${externalUserId}`);
  const encrypted = encryptSecret(secret.base32);
  const client = await pool.connect();
  let account;
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `INSERT INTO external_mfa_accounts
       (application_id, external_user_id, identifier, encrypted_totp_secret, enabled, last_used_timestep, revoked_at)
       VALUES ($1, $2, $3, $4, FALSE, 0, NULL)
       ON CONFLICT (application_id, external_user_id)
       DO UPDATE SET identifier = EXCLUDED.identifier,
                     encrypted_totp_secret = EXCLUDED.encrypted_totp_secret,
                     enabled = FALSE,
                     last_used_timestep = 0,
                     revoked_at = NULL,
                     updated_at = NOW()
       RETURNING id, external_user_id, identifier, enabled, created_at, updated_at`,
      [req.application.id, externalUserId, identifier || null, encrypted]
    );
    account = result.rows[0];
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  const qrCode = await QRCode.toDataURL(secret.otpauth_url);
  await writeAuditLog(req, {
    applicationId: req.application.id,
    externalUserId,
    eventType: 'MFA_ENROLLED',
    success: true,
  });

  return res.status(201).json({
    account,
    qrCode,
    manualEntryCode: secret.base32,
    provisioningUri: secret.otpauth_url,
    message: 'Scan the QR code, then activate MFA with a current 6-digit code.',
  });
}

async function findExternalAccount(applicationId, externalUserId) {
  const result = await pool.query(
    `SELECT id, external_user_id, identifier, encrypted_totp_secret, enabled, last_used_timestep, revoked_at
     FROM external_mfa_accounts
     WHERE application_id = $1 AND external_user_id = $2`,
    [applicationId, externalUserId]
  );
  return result.rows[0] || null;
}

async function activateOrVerify(account, applicationId, externalUserId, code, eventType) {
  if (!account || account.revoked_at || !account.encrypted_totp_secret) return { ok: false, reason: 'not_found' };
  if (!isSixDigitCode(code)) return { ok: false, reason: 'invalid_code' };

  const secret = decryptSecret(account.encrypted_totp_secret);
  const step = currentTimestep();
  if (account.last_used_timestep >= step) return { ok: false, reason: 'replayed' };

  const delta = verifyTokenDelta(secret, code);
  if (!delta) return { ok: false, reason: 'invalid_code' };

  const matchedStep = step + delta.delta;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const update = eventType === 'MFA_ACTIVATED'
      ? `UPDATE external_mfa_accounts
         SET enabled = TRUE, last_used_timestep = $1, updated_at = NOW()
         WHERE id = $2 AND application_id = $3 AND enabled = FALSE AND revoked_at IS NULL AND last_used_timestep < $1
         RETURNING id`
      : `UPDATE external_mfa_accounts
         SET last_used_timestep = $1, updated_at = NOW()
         WHERE id = $2 AND application_id = $3 AND enabled = TRUE AND revoked_at IS NULL AND last_used_timestep < $1
         RETURNING id`;
    const updated = await client.query(update, [matchedStep, account.id, applicationId]);
    if (!updated.rows.length) {
      await client.query('ROLLBACK');
      return { ok: false, reason: 'replayed_or_state_changed' };
    }
    await client.query('COMMIT');
    return { ok: true };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function activateExternalMfa(req, res) {
  const externalUserId = typeof req.body.externalUserId === 'string' ? req.body.externalUserId.trim() : '';
  const code = typeof req.body.code === 'string' ? req.body.code.trim() : '';
  if (!validExternalUserId(externalUserId) || !isSixDigitCode(code)) return res.status(400).json({ error: 'Valid externalUserId and 6-digit code are required' });

  const account = await findExternalAccount(req.application.id, externalUserId);
  const result = await activateOrVerify(account, req.application.id, externalUserId, code, 'MFA_ACTIVATED');
  await writeAuditLog(req, {
    applicationId: req.application.id,
    externalUserId,
    eventType: 'MFA_ACTIVATED',
    success: result.ok,
  });
  if (!result.ok) return genericMfaError(res);
  return res.json({ enabled: true, verified: true, message: 'MFA activated' });
}

export async function verifyExternalMfa(req, res) {
  const externalUserId = typeof req.body.externalUserId === 'string' ? req.body.externalUserId.trim() : '';
  const code = typeof req.body.code === 'string' ? req.body.code.trim() : '';
  if (!validExternalUserId(externalUserId) || !isSixDigitCode(code)) return res.status(400).json({ verified: false, error: 'Valid externalUserId and 6-digit code are required' });

  const account = await findExternalAccount(req.application.id, externalUserId);
  const result = await activateOrVerify(account, req.application.id, externalUserId, code, 'MFA_VERIFICATION_SUCCESS');
  await writeAuditLog(req, {
    applicationId: req.application.id,
    externalUserId,
    eventType: result.ok ? 'MFA_VERIFICATION_SUCCESS' : 'MFA_VERIFICATION_FAILED',
    success: result.ok,
  });
  return res.json({ verified: result.ok });
}

export async function getExternalMfaStatus(req, res) {
  const externalUserId = req.params.externalUserId;
  if (!validExternalUserId(externalUserId)) return res.status(400).json({ error: 'Invalid externalUserId' });

  const account = await findExternalAccount(req.application.id, externalUserId);
  return res.json({ enabled: Boolean(account?.enabled && !account.revoked_at) });
}

export async function revokeExternalMfa(req, res) {
  const externalUserId = typeof req.body.externalUserId === 'string' ? req.body.externalUserId.trim() : '';
  if (!validExternalUserId(externalUserId)) return res.status(400).json({ error: 'Valid externalUserId is required' });

  const result = await pool.query(
    `UPDATE external_mfa_accounts
     SET enabled = FALSE, revoked_at = NOW(), updated_at = NOW()
     WHERE application_id = $1 AND external_user_id = $2 AND revoked_at IS NULL
     RETURNING id`,
    [req.application.id, externalUserId]
  );

  await writeAuditLog(req, {
    applicationId: req.application.id,
    externalUserId,
    eventType: 'MFA_REVOKED',
    success: result.rows.length > 0,
  });

  return res.json({ revoked: true });
}

import bcrypt from 'bcrypt';
import QRCode from 'qrcode';
import { pool } from '../db/pool.js';
import { encryptSecret, decryptSecret } from '../utils/encryption.js';
import { generateSecret, verifyToken, verifyTokenDelta, currentTimestep } from '../utils/totp.js';
import {
  generateBackupCodes,
  hashBackupCodes,
  verifyBackupCode,
} from '../utils/backupCodes.js';
import { signToken, signRefreshToken, verifyToken as verifyJwt } from '../utils/jwt.js';
import { notifyMyangano2FAChange } from '../utils/notifyMyangano.js';
import { isBackupCodeFormat, isSixDigitCode } from '../utils/validators.js';

export async function enrollTOTP(req, res) {
  const userId = req.user.id;

  const userRow = await pool.query(
    `SELECT u.email, t.enabled
     FROM users u
     LEFT JOIN user_totp t ON t.user_id = u.id
     WHERE u.id = $1`,
    [userId]
  );
  if (userRow.rows.length === 0) return res.status(404).json({ error: 'User not found' });
  if (userRow.rows[0].enabled) {
    return res.status(400).json({ error: '2FA is already enabled; disable it before enrolling a new authenticator' });
  }

  const secret = generateSecret(userRow.rows[0].email);
  const encrypted = encryptSecret(secret.base32);

  await pool.query(
    `INSERT INTO user_totp (user_id, totp_secret, enabled, last_used_timestep)
     VALUES ($1, $2, FALSE, 0)
     ON CONFLICT (user_id)
     DO UPDATE SET totp_secret = EXCLUDED.totp_secret,
                   enabled = FALSE,
                   last_used_timestep = 0,
                   created_at = NOW()`,
    [userId, encrypted]
  );

  const qrCode = await QRCode.toDataURL(secret.otpauth_url);

  res.json({
    qrCode,
    manualEntryCode: secret.base32,
    message: 'Scan the QR, then verify a code to activate 2FA.',
  });
}

export async function activateTOTP(req, res) {
  const { token } = req.body;
  const userId = req.user.id;

  if (!isSixDigitCode(token)) return res.status(400).json({ error: 'A 6-digit code is required' });

  const result = await pool.query(
    'SELECT totp_secret, enabled FROM user_totp WHERE user_id = $1',
    [userId]
  );

  if (result.rows.length === 0) return res.status(400).json({ error: 'Start enrollment first' });
  if (result.rows[0].enabled) return res.status(400).json({ error: '2FA already enabled' });

  const plainSecret = decryptSecret(result.rows[0].totp_secret);
  if (!verifyToken(plainSecret, token)) return res.status(400).json({ error: 'Invalid code' });

  const plainCodes = generateBackupCodes(10);
  const hashedCodes = await hashBackupCodes(plainCodes);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      'UPDATE user_totp SET enabled = TRUE, last_used_timestep = $1 WHERE user_id = $2',
      [currentTimestep() - 1, userId]
    );
    await client.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    for (const hash of hashedCodes) {
      await client.query(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)',
        [userId, hash]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  notifyMyangano2FAChange(userId, true).catch(err =>
    console.error('Webhook failed:', err.message)
  );

  res.json({
    message: '2FA activated. Save these backup codes now.',
    backupCodes: plainCodes,
  });
}

async function issueRefreshTokenFor2FA(userId) {
  const refreshToken = signRefreshToken(userId);
  const payload = verifyJwt(refreshToken, 'refresh');
  const tokenHash = await bcrypt.hash(refreshToken, 12);
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await pool.query(
    'INSERT INTO refresh_tokens (user_id, jti, token_hash, expires_at) VALUES ($1, $2, $3, $4)',
    [userId, payload.jti, tokenHash, expiresAt]
  );
  return refreshToken;
}

async function consumeBackupCode(userId, code) {
  if (!isBackupCodeFormat(code)) return false;

  const codes = await pool.query(
    'SELECT code_id, code_hash FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL',
    [userId]
  );

  for (const row of codes.rows) {
    if (await verifyBackupCode(code.toUpperCase(), row.code_hash)) {
      const consumed = await pool.query(
        `UPDATE recovery_codes SET used_at = NOW()
         WHERE code_id = $1 AND used_at IS NULL
         RETURNING code_id`,
        [row.code_id]
      );
      if (consumed.rows.length > 0) return true;
    }
  }
  return false;
}

export async function verifyTOTPLogin(req, res) {
  const { pendingToken, token, isBackupCode = false } = req.body;
  if (typeof pendingToken !== 'string' || pendingToken.length > 4096) {
    return res.status(400).json({ error: 'Pending token is required' });
  }

  let userId;
  try {
    const payload = verifyJwt(pendingToken, '2fa-pending');
    userId = payload.sub;
  } catch {
    return res.status(401).json({ error: 'Invalid or expired pending token' });
  }

  const result = await pool.query(
    'SELECT totp_secret, enabled, last_used_timestep FROM user_totp WHERE user_id = $1',
    [userId]
  );

  if (result.rows.length === 0 || !result.rows[0].enabled) {
    return res.status(400).json({ error: '2FA not enabled' });
  }

  if (isBackupCode) {
    if (typeof token !== 'string' || !isBackupCodeFormat(token)) {
      return res.status(400).json({ error: 'Invalid backup code' });
    }

    if (await consumeBackupCode(userId, token)) {
      return res.json({
        token: signToken(userId),
        refreshToken: await issueRefreshTokenFor2FA(userId),
        message: 'Login complete',
      });
    }
    return res.status(400).json({ error: 'Invalid backup code' });
  }

  if (!isSixDigitCode(token)) return res.status(400).json({ error: 'A 6-digit code is required' });

  const plainSecret = decryptSecret(result.rows[0].totp_secret);
  const step = currentTimestep();

  if (result.rows[0].last_used_timestep >= step) {
    return res.status(400).json({ error: 'Code already used' });
  }

  const delta = verifyTokenDelta(plainSecret, token);
  if (!delta) {
    return res.status(400).json({ error: 'Invalid or expired code' });
  }

  const matchedStep = step + delta.delta;
  const consumed = await pool.query(
    `UPDATE user_totp
     SET last_used_timestep = $1
     WHERE user_id = $2 AND enabled = TRUE AND last_used_timestep < $1
     RETURNING user_id`,
    [matchedStep, userId]
  );

  if (consumed.rows.length === 0) {
    return res.status(400).json({ error: 'Code already used' });
  }

  res.json({
    token: signToken(userId),
    refreshToken: await issueRefreshTokenFor2FA(userId),
    message: 'Login complete',
  });
}

async function verifyPasswordAndTotp(userId, password, token) {
  if (typeof password !== 'string' || !isSixDigitCode(token)) return false;

  const userRow = await pool.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
  if (userRow.rows.length === 0 || !(await bcrypt.compare(password, userRow.rows[0].password_hash))) return false;

  const totp = await pool.query(
    'SELECT totp_secret, enabled FROM user_totp WHERE user_id = $1',
    [userId]
  );
  if (totp.rows.length === 0 || !totp.rows[0].enabled) return false;

  return verifyToken(decryptSecret(totp.rows[0].totp_secret), token);
}

export async function disableTOTP(req, res) {
  const { password, token } = req.body;
  const userId = req.user.id;

  if (!(await verifyPasswordAndTotp(userId, password, token))) {
    return res.status(401).json({ error: 'Invalid password or TOTP code' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    await client.query('UPDATE user_totp SET enabled = FALSE WHERE user_id = $1', [userId]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  notifyMyangano2FAChange(userId, false).catch(err =>
    console.error('Webhook failed:', err.message)
  );

  res.json({ message: '2FA disabled' });
}

export async function regenerateBackupCodes(req, res) {
  const { password, token } = req.body;
  const userId = req.user.id;

  if (!(await verifyPasswordAndTotp(userId, password, token))) {
    return res.status(401).json({ error: 'Invalid password or TOTP code' });
  }

  const plainCodes = generateBackupCodes(10);
  const hashedCodes = await hashBackupCodes(plainCodes);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM recovery_codes WHERE user_id = $1', [userId]);
    for (const hash of hashedCodes) {
      await client.query(
        'INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)',
        [userId, hash]
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  res.json({
    message: 'New backup codes generated. Old codes are now invalid.',
    backupCodes: plainCodes,
  });
}

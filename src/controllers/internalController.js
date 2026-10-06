import { pool } from '../db/pool.js';
import { decryptSecret } from '../utils/encryption.js';
import { verifyBackupCode } from '../utils/backupCodes.js';
import { verifyToken, currentTimestep } from '../utils/totp.js';
import { isBackupCodeFormat, isSixDigitCode, isUuid } from '../utils/validators.js';

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

export async function verifyTOTPForService(req, res) {
  const { authServiceUserId, code, isBackupCode = false } = req.body;

  if (!isUuid(authServiceUserId) || typeof code !== 'string' || typeof isBackupCode !== 'boolean') {
    return res.status(400).json({ valid: false, message: 'Invalid parameters' });
  }

  try {
    const result = await pool.query(
      'SELECT totp_secret, enabled, last_used_timestep FROM user_totp WHERE user_id = $1',
      [authServiceUserId]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ valid: false, message: 'User not found' });
    }

    const { totp_secret, enabled, last_used_timestep } = result.rows[0];
    if (!enabled) return res.status(400).json({ valid: false, message: '2FA not enabled' });

    if (isBackupCode) {
      if (await consumeBackupCode(authServiceUserId, code)) {
        return res.json({ valid: true, message: 'Backup code accepted' });
      }
      return res.status(400).json({ valid: false, message: 'Invalid backup code' });
    }

    if (!isSixDigitCode(code)) {
      return res.status(400).json({ valid: false, message: 'Invalid TOTP code' });
    }

    const plainSecret = decryptSecret(totp_secret);
    const step = currentTimestep();
    if (last_used_timestep >= step) {
      return res.status(400).json({ valid: false, message: 'Code already used' });
    }

    const delta = verifyTokenDelta(plainSecret, code);
    if (!delta) {
      return res.status(400).json({ valid: false, message: 'Invalid or expired code' });
    }

    const matchedStep = step + delta.delta;
    const consumed = await pool.query(
      `UPDATE user_totp
       SET last_used_timestep = $1
       WHERE user_id = $2 AND enabled = TRUE AND last_used_timestep < $1
       RETURNING user_id`,
      [matchedStep, authServiceUserId]
    );

    if (consumed.rows.length === 0) {
      return res.status(400).json({ valid: false, message: 'Code already used' });
    }

    return res.json({ valid: true, message: 'Code accepted' });
  } catch (err) {
    console.error('Service verification error:', err);
    return res.status(500).json({ valid: false, message: 'Internal error' });
  }
}

export async function get2FAStatusForService(req, res) {
  const { authServiceUserId } = req.query;
  if (!isUuid(authServiceUserId)) return res.status(400).json({ error: 'Invalid authServiceUserId' });

  const result = await pool.query(
    'SELECT enabled FROM user_totp WHERE user_id = $1',
    [authServiceUserId]
  );

  res.json({ enabled: result.rows.length > 0 && result.rows[0].enabled });
}

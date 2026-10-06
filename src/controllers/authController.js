import bcrypt from 'bcrypt';
import crypto from 'crypto';
import { pool } from '../db/pool.js';
import { signToken, signRefreshToken, verifyRefreshToken } from '../utils/jwt.js';
import { isStrongPassword, isValidEmail } from '../utils/validators.js';

const REFRESH_DAYS = 7;

async function issueRefreshToken(userId) {
  const refreshToken = signRefreshToken(userId);
  const payload = verifyRefreshToken(refreshToken);
  const tokenHash = await bcrypt.hash(refreshToken, 12);
  const expiresAt = new Date(Date.now() + REFRESH_DAYS * 24 * 60 * 60 * 1000);

  await pool.query(
    `INSERT INTO refresh_tokens (user_id, jti, token_hash, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [userId, payload.jti, tokenHash, expiresAt]
  );

  return refreshToken;
}

async function findRefreshToken(refreshToken) {
  const payload = verifyRefreshToken(refreshToken);
  if (!payload.jti) return null;

  const result = await pool.query(
   `SELECT id, user_id, jti, token_hash, expires_at, revoked_at, revoked_reason
 FROM refresh_tokens
 WHERE jti = $1 AND expires_at > NOW()`
    , [payload.jti]
  );

  const row = result.rows[0];
  if (!row) return null;

  const valid = await bcrypt.compare(refreshToken, row.token_hash);
  return valid ? row : null;
}

export async function register(req, res) {
  const email = String(req.body.email || '').trim().toLowerCase();
  const { password } = req.body;

  if (!isValidEmail(email) || !password || !isStrongPassword(password)) {
    return res.status(400).json({
      error: 'Provide a valid email and a password with 8-72 UTF-8 bytes, uppercase, lowercase, and a number',
    });
  }

  const hash = await bcrypt.hash(password, 12);

  try {
    const result = await pool.query(
      'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, created_at',
      [email, hash]
    );

    const user = result.rows[0];
    const refreshToken = await issueRefreshToken(user.id);

    res.status(201).json({
      message: 'Account created',
      user,
      token: signToken(user.id),
      refreshToken,
    });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    throw err;
  }
}

export async function login(req, res) {
  const email = String(req.body.email || '').trim().toLowerCase();
  const { password } = req.body;

  if (!isValidEmail(email) || typeof password !== 'string' || password.length === 0) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  const result = await pool.query(
    'SELECT id, email, password_hash FROM users WHERE email = $1',
    [email]
  );

  if (result.rows.length === 0) {
    // Keep roughly the same password-hash work for unknown users.
    await bcrypt.hash(password, 12);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const user = result.rows[0];
  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

  const totp = await pool.query(
    'SELECT enabled FROM user_totp WHERE user_id = $1',
    [user.id]
  );
  const twoFactorEnabled = totp.rows.length > 0 && totp.rows[0].enabled;

  if (twoFactorEnabled) {
    const pendingToken = signToken(user.id, '5m', '2fa-pending');
    return res.json({
      requires2FA: true,
      pendingToken,
      message: 'Enter your 6-digit code or backup code',
    });
  }

  return res.json({
    token: signToken(user.id),
    refreshToken: await issueRefreshToken(user.id),
    message: 'Login successful',
  });
}

export async function refresh(req, res) {
  const { refreshToken } = req.body;
  if (typeof refreshToken !== 'string' || refreshToken.length > 4096) {
    return res.status(400).json({ error: 'Refresh token required' });
  }

  try {
    const payload = verifyRefreshToken(refreshToken);
    const stored = await findRefreshToken(refreshToken);

    if (!stored || stored.user_id !== payload.sub) {
      return res.status(401).json({ error: 'Invalid or revoked refresh token' });
    }

      if (stored.revoked_at) {
      if (stored.revoked_reason === 'rotation') {
        // A previously rotated refresh token was reused.
        // Revoke the user's remaining sessions.
        await pool.query(
          `UPDATE refresh_tokens
           SET revoked_at = NOW(), revoked_reason = 'reuse'
           WHERE user_id = $1 AND revoked_at IS NULL`,
          [stored.user_id]
        );

        return res.status(401).json({
          error: 'Refresh token reuse detected; sessions revoked',
        });
      }

      // Token was intentionally revoked for another reason,
      // such as logout or password reset.
      return res.status(401).json({
        error: 'Invalid or revoked refresh token',
      });
    }

    const rotated = await pool.query(
      `UPDATE refresh_tokens
       SET revoked_at = NOW(), revoked_reason = 'rotation'
       WHERE id = $1 AND revoked_at IS NULL
       RETURNING id`,
      [stored.id]
    );

    if (rotated.rows.length === 0) {
      await pool.query(
        `UPDATE refresh_tokens
         SET revoked_at = NOW(), revoked_reason = 'reuse'
         WHERE user_id = $1 AND revoked_at IS NULL`,
        [stored.user_id]
      );

      return res.status(401).json({
        error: 'Refresh token reuse detected; sessions revoked',
      });
    }

    return res.json({
      token: signToken(payload.sub),
      refreshToken: await issueRefreshToken(payload.sub),
      message: 'Token refreshed',
    });
  } catch {
    return res.status(401).json({
      error: 'Invalid or expired refresh token',
    });
  }
}

export async function getCurrentUser(req, res) {
  const result = await pool.query(
    'SELECT id, email, created_at FROM users WHERE id = $1',
    [req.user.id]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
  res.json({ user: result.rows[0] });
}

export async function requestPasswordReset(req, res) {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!isValidEmail(email)) return res.status(400).json({ error: 'Valid email is required' });

  const user = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
  const response = { message: 'If an account exists for that email, a reset link has been sent.' };

  if (user.rows.length === 0) return res.json(response);

  const selector = crypto.randomBytes(16).toString('hex');
  const secret = crypto.randomBytes(32).toString('hex');
  const token = `${selector}.${secret}`;
  const tokenHash = await bcrypt.hash(secret, 12);
  const expiresAt = new Date(Date.now() + 30 * 60 * 1000);

  await pool.query(
    `UPDATE password_reset_tokens SET used_at = NOW()
     WHERE user_id = $1 AND used_at IS NULL`,
    [user.rows[0].id]
  );

  await pool.query(
    `INSERT INTO password_reset_tokens (user_id, selector, token_hash, expires_at)
     VALUES ($1, $2, $3, $4)`,
    [user.rows[0].id, selector, tokenHash, expiresAt]
  );

  if (process.env.NODE_ENV !== 'production') response.resetToken = token;

  return res.json(response);
}

export async function resetPassword(req, res) {
  const { token, password } = req.body;
  if (typeof token !== 'string' || !token || !isStrongPassword(password)) {
    return res.status(400).json({ error: 'Reset token and a strong password are required' });
  }

  
  const separator = token.indexOf('.');
  if (separator <= 0 || separator === token.length - 1) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  const selector = token.slice(0, separator);
  const secret = token.slice(separator + 1);
  if (!/^[0-9a-f]{32}$/i.test(selector) || !/^[0-9a-f]{64}$/i.test(secret)) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  const result = await pool.query(
    `SELECT id, user_id, token_hash
     FROM password_reset_tokens
     WHERE selector = $1 AND used_at IS NULL AND expires_at > NOW()`,
    [selector]
  );

  const matched = result.rows[0];
  if (!matched || !(await bcrypt.compare(secret, matched.token_hash))) {
    return res.status(400).json({ error: 'Invalid or expired reset token' });
  }

  const passwordHash = await bcrypt.hash(password, 12);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const consumed = await client.query(
      `UPDATE password_reset_tokens SET used_at = NOW()
       WHERE id = $1 AND used_at IS NULL
       RETURNING id`,
      [matched.id]
    );
    if (consumed.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    await client.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, matched.user_id]);
    await client.query(
  `UPDATE refresh_tokens
   SET revoked_at = NOW(), revoked_reason = 'password_reset'
   WHERE user_id = $1 AND revoked_at IS NULL`,
  [matched.user_id]
);
    await client.query('UPDATE password_reset_tokens SET used_at = NOW() WHERE user_id = $1 AND used_at IS NULL', [matched.user_id]);
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }

  res.json({ message: 'Password updated successfully' });
}

export async function logout(req, res) {
  const { refreshToken } = req.body;
  if (typeof refreshToken === 'string' && refreshToken.length <= 4096) {
    try {
      const stored = await findRefreshToken(refreshToken);
      if (stored && stored.user_id === req.user.id && !stored.revoked_at) {
       await pool.query(
  `UPDATE refresh_tokens
   SET revoked_at = NOW(), revoked_reason = 'logout'
   WHERE id = $1 AND revoked_at IS NULL`,
  [stored.id]
);
      }
    } catch {
      // Logout is intentionally idempotent.
    }
  }
  res.json({ message: 'Logged out' });
}

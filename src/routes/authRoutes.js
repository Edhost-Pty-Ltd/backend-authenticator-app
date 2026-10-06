import express from 'express';
import { pool } from '../db/pool.js';
import { requireAuth } from '../middleware/requiredAuth.js';
import { asyncHandler } from '../middleware/asyncHandler.js';
import { loginLimiter, registrationLimiter, passwordResetLimiter, sensitiveAuthLimiter } from '../middleware/rateLimiters.js';
import {
  register,
  login,
  refresh,
  logout,
  getCurrentUser,
  requestPasswordReset,
  resetPassword,
} from '../controllers/authController.js';
import {
  enrollTOTP,
  activateTOTP,
  verifyTOTPLogin,
  disableTOTP,
  regenerateBackupCodes,
} from '../controllers/totpController.js';

const router = express.Router();

router.post('/register', registrationLimiter, asyncHandler(register));
router.post('/login', loginLimiter, asyncHandler(login));
router.post('/refresh', sensitiveAuthLimiter, asyncHandler(refresh));
router.post('/logout', requireAuth, asyncHandler(logout));
router.get('/me', requireAuth, asyncHandler(getCurrentUser));
router.post('/password-reset/request', passwordResetLimiter, asyncHandler(requestPasswordReset));
router.post('/password-reset', sensitiveAuthLimiter, asyncHandler(resetPassword));
router.post('/2fa/verify', sensitiveAuthLimiter, (req, res, next) => {
  if (req.body.isBackupCode !== undefined && typeof req.body.isBackupCode !== 'boolean') {
    return res.status(400).json({ error: 'isBackupCode must be boolean' });
  }
  next();
}, asyncHandler(verifyTOTPLogin));

router.post('/2fa/enroll', requireAuth, sensitiveAuthLimiter, asyncHandler(enrollTOTP));
router.post('/2fa/activate', requireAuth, sensitiveAuthLimiter, asyncHandler(activateTOTP));
router.get('/2fa/status', requireAuth, asyncHandler(async (req, res) => {
  const result = await pool.query('SELECT enabled FROM user_totp WHERE user_id = $1', [req.user.id]);
  res.json({ enabled: result.rows.length > 0 && result.rows[0].enabled });
}));
router.post('/2fa/disable', requireAuth, sensitiveAuthLimiter, asyncHandler(disableTOTP));
router.post('/2fa/backup-codes/regenerate', requireAuth, sensitiveAuthLimiter, asyncHandler(regenerateBackupCodes));

export default router;

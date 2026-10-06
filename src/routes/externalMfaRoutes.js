import express from 'express';
import { asyncHandler } from '../middleware/asyncHandler.js';
import { requireApplicationAuth } from '../middleware/applicationAuth.js';
import { externalMfaLimiter } from '../middleware/rateLimiters.js';
import {
  enrollExternalMfa,
  activateExternalMfa,
  verifyExternalMfa,
  getExternalMfaStatus,
  revokeExternalMfa,
} from '../controllers/externalMfaController.js';

const router = express.Router();
router.use(requireApplicationAuth, externalMfaLimiter);
router.post('/enroll', asyncHandler(enrollExternalMfa));
router.post('/activate', asyncHandler(activateExternalMfa));
router.post('/verify', asyncHandler(verifyExternalMfa));
router.get('/status/:externalUserId', asyncHandler(getExternalMfaStatus));
router.post('/revoke', asyncHandler(revokeExternalMfa));

export default router;

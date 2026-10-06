import express from 'express';
import { asyncHandler } from '../middleware/asyncHandler.js';
import { requireApplicationAuth } from '../middleware/applicationAuth.js';
import { requireAdminAuth } from '../middleware/adminAuth.js';
import {
  applicationRegistrationLimiter,
  applicationTokenLimiter,
} from '../middleware/rateLimiters.js';
import {
  registerApplication,
  createApplicationToken,
  revokeApplication,
} from '../controllers/applicationController.js';

const router = express.Router();
router.post('/register', applicationRegistrationLimiter, requireAdminAuth, asyncHandler(registerApplication));
router.post('/token', applicationTokenLimiter, asyncHandler(createApplicationToken));
router.post('/revoke', requireApplicationAuth, applicationTokenLimiter, asyncHandler(revokeApplication));

export default router;

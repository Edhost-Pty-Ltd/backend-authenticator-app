import express from 'express';
import { asyncHandler } from '../middleware/asyncHandler.js';
import { requireAdminAuth } from '../middleware/adminAuth.js';
import { adminLimiter } from '../middleware/rateLimiters.js';
import {
  adminCreateApplication,
  listApplications,
  getApplication,
  setApplicationStatus,
  rotateApplicationSecret,
  getApplicationAudit,
} from '../controllers/adminApplicationController.js';

const router = express.Router();
router.use(adminLimiter, requireAdminAuth);
router.post('/applications', asyncHandler(adminCreateApplication));
router.get('/applications', asyncHandler(listApplications));
router.get('/applications/:id', asyncHandler(getApplication));
router.patch('/applications/:id/status', asyncHandler(setApplicationStatus));
router.post('/applications/:id/rotate-secret', asyncHandler(rotateApplicationSecret));
router.get('/applications/:id/audit', asyncHandler(getApplicationAudit));

export default router;

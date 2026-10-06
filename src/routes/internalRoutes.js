import express from 'express';
import { requireServiceAuth } from '../middleware/serviceAuth.js';
import { asyncHandler } from '../middleware/asyncHandler.js';
import {
  verifyTOTPForService,
  get2FAStatusForService,
} from '../controllers/internalController.js';

const router = express.Router();

router.use(requireServiceAuth);
router.post('/2fa/verify', asyncHandler(verifyTOTPForService));
router.get('/2fa/status', asyncHandler(get2FAStatusForService));

export default router;

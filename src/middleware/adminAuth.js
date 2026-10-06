import crypto from 'crypto';
import { config } from '../config.js';

export function requireAdminAuth(req, res, next) {
  const provided = req.get('x-admin-api-key');
  const expected = config.adminApiKey;

  if (!expected || typeof provided !== 'string') {
    return res.status(401).json({ error: 'Missing administrator credentials' });
  }

  const providedDigest = crypto.createHash('sha256').update(provided).digest();
  const expectedDigest = crypto.createHash('sha256').update(expected).digest();

  if (!crypto.timingSafeEqual(providedDigest, expectedDigest)) {
    return res.status(403).json({ error: 'Invalid administrator credentials' });
  }

  next();
}

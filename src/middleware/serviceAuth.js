import crypto from 'crypto';
import { config } from '../config.js';

export function requireServiceAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing service credentials' });
  }

  const apiKey = auth.slice(7).trim();
  const expected = config.myanganoServiceApiKey;

  const providedDigest = crypto.createHash('sha256').update(apiKey).digest();
  const expectedDigest = crypto.createHash('sha256').update(expected).digest();

  if (!expected || !crypto.timingSafeEqual(providedDigest, expectedDigest)) {
    return res.status(403).json({ error: 'Invalid service credentials' });
  }

  next();
}

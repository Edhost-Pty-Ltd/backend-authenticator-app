import { verifyToken } from '../utils/jwt.js';

export function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !/^Bearer [^\s]+$/.test(header)) {
    return res.status(401).json({ error: 'Missing token' });
  }

  try {
    const payload = verifyToken(header.slice(7));
    req.user = { id: payload.sub };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

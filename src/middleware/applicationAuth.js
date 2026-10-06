import { authenticateApplicationToken } from '../utils/applicationAuth.js';

export async function requireApplicationAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !/^Bearer [^\s]+$/.test(header)) {
    return res.status(401).json({ error: 'Missing service credentials' });
  }

  try {
    req.application = await authenticateApplicationToken(header.slice(7));
    return next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired service credentials' });
  }
}

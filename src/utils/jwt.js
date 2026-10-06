import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { config } from '../config.js';

const SECRET = config.jwtSecret;

export function signToken(userId, expiresIn = '15m', tokenType = 'access', options = {}) {
  return jwt.sign(
    { sub: userId, type: tokenType },
    SECRET,
    { expiresIn, issuer: config.jwtIssuer, audience: config.jwtAudience, ...options }
  );
}

export function verifyToken(token, expectedType = 'access') {
  if (typeof token !== 'string' || token.length > 4096) throw new Error('Invalid token');

  const payload = jwt.verify(token, SECRET, {
    algorithms: ['HS256'],
    issuer: config.jwtIssuer,
    audience: config.jwtAudience,
  });

  if (!payload || typeof payload !== 'object' || typeof payload.sub !== 'string') {
    throw new Error('Invalid token payload');
  }

  if (expectedType && payload.type !== expectedType) {
    throw new Error('Invalid token type');
  }

  return payload;
}

export function signRefreshToken(userId, expiresIn = '7d') {
  return signToken(userId, expiresIn, 'refresh', { jwtid: crypto.randomUUID() });
}

export function verifyRefreshToken(token) {
  return verifyToken(token, 'refresh');
}

export function signApplicationToken(applicationId, credentialVersion = 1, expiresIn = '1h') {
  return jwt.sign(
    { sub: applicationId, type: 'service', scope: 'mfa:provider', credentialVersion },
    SECRET,
    { expiresIn, issuer: config.jwtIssuer, audience: config.jwtServiceAudience, jwtid: crypto.randomUUID() }
  );
}

export function verifyApplicationToken(token) {
  if (typeof token !== 'string' || token.length > 4096) throw new Error('Invalid token');

  const payload = jwt.verify(token, SECRET, {
    algorithms: ['HS256'],
    issuer: config.jwtIssuer,
    audience: config.jwtServiceAudience,
  });

  if (!payload || typeof payload !== 'object' || typeof payload.sub !== 'string' || payload.type !== 'service' || payload.scope !== 'mfa:provider' || !Number.isInteger(payload.credentialVersion) || payload.credentialVersion < 1) {
    throw new Error('Invalid application token payload');
  }

  return payload;
}

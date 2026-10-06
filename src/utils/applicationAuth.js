import crypto from 'crypto';
import bcrypt from 'bcrypt';
import { pool } from '../db/pool.js';
import { signApplicationToken, verifyApplicationToken } from './jwt.js';

export function generateClientId() {
  return `app_${crypto.randomBytes(18).toString('base64url')}`;
}

export function generateClientSecret() {
  return `sec_${crypto.randomBytes(36).toString('base64url')}`;
}

export async function hashClientSecret(secret) {
  return bcrypt.hash(secret, 12);
}

export async function authenticateApplicationCredentials(clientId, clientSecret) {
  const result = await pool.query(
    `SELECT id, name, client_secret_hash, status, credential_version
     FROM applications
     WHERE client_id = $1`,
    [clientId]
  );
  const app = result.rows[0];
  if (!app) return null;

  const valid = await bcrypt.compare(clientSecret, app.client_secret_hash);
  if (!valid || app.status !== 'active') return null;
  return app;
}

export function issueApplicationToken(applicationId, credentialVersion = 1) {
  return signApplicationToken(applicationId, credentialVersion);
}

export async function authenticateApplicationToken(token) {
  const payload = verifyApplicationToken(token);
  const result = await pool.query(
    `SELECT id, name, status, credential_version
     FROM applications
     WHERE id = $1`,
    [payload.sub]
  );
  const app = result.rows[0];
  if (!app || app.status !== 'active') throw new Error('Application is not active');
  if (payload.credentialVersion !== app.credential_version) throw new Error('Application credentials have been rotated');
  return app;
}

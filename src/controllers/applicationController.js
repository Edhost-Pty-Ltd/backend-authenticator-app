import { pool } from '../db/pool.js';
import {
  generateClientId,
  generateClientSecret,
  hashClientSecret,
  authenticateApplicationCredentials,
  issueApplicationToken,
} from '../utils/applicationAuth.js';
import { writeAuditLog } from '../utils/audit.js';

export async function registerApplication(req, res) {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  if (!name || name.length > 200) return res.status(400).json({ error: 'Application name is required and must be 1-200 characters' });

  const clientId = generateClientId();
  const clientSecret = generateClientSecret();
  const clientSecretHash = await hashClientSecret(clientSecret);

  try {
    const result = await pool.query(
      `INSERT INTO applications (name, client_id, client_secret_hash)
       VALUES ($1, $2, $3)
       RETURNING id, name, client_id, status, credential_version, created_at`,
      [name, clientId, clientSecretHash]
    );
    const application = result.rows[0];

    await writeAuditLog(req, {
      applicationId: application.id,
      eventType: 'APPLICATION_REGISTERED',
      success: true,
      metadata: { applicationName: name },
    });

    return res.status(201).json({
      application,
      clientId,
      clientSecret,
      message: 'Save the client secret now. It will not be returned again.',
    });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Application registration conflict; retry' });
    throw err;
  }
}

export async function createApplicationToken(req, res) {
  const clientId = typeof req.body.clientId === 'string' ? req.body.clientId.trim() : '';
  const clientSecret = typeof req.body.clientSecret === 'string' ? req.body.clientSecret : '';

  if (!clientId || !clientSecret || clientId.length > 200 || clientSecret.length > 512) {
    return res.status(400).json({ error: 'Client credentials are required' });
  }

  const application = await authenticateApplicationCredentials(clientId, clientSecret);
  if (!application) {
    await writeAuditLog(req, { eventType: 'APPLICATION_AUTH_FAILED', success: false });
    return res.status(401).json({ error: 'Invalid application credentials' });
  }

  const accessToken = issueApplicationToken(application.id, application.credential_version);
  return res.json({ access_token: accessToken, token_type: 'Bearer', expires_in: 3600 });
}

export async function revokeApplication(req, res) {
  const result = await pool.query(
    `UPDATE applications
     SET status = 'revoked', updated_at = NOW()
     WHERE id = $1 AND status <> 'revoked'
     RETURNING id, name, client_id, status, updated_at`,
    [req.application.id]
  );

  if (result.rows.length === 0) return res.status(404).json({ error: 'Application not found' });

  await writeAuditLog(req, {
    applicationId: req.application.id,
    eventType: 'APPLICATION_DISABLED',
    success: true,
  });

  return res.json({ application: result.rows[0], message: 'Application revoked' });
}

import { pool } from '../db/pool.js';
import { generateClientId, generateClientSecret, hashClientSecret } from '../utils/applicationAuth.js';
import { isUuid } from '../utils/validators.js';
import { writeAuditLog } from '../utils/audit.js';

function validName(value) {
  return typeof value === 'string' && value.trim().length >= 1 && value.trim().length <= 200;
}

export async function adminCreateApplication(req, res) {
  const name = typeof req.body.name === 'string' ? req.body.name.trim() : '';
  if (!validName(name)) return res.status(400).json({ error: 'Application name is required and must be 1-200 characters' });

  const clientId = generateClientId();
  const clientSecret = generateClientSecret();
  const clientSecretHash = await hashClientSecret(clientSecret);

  const result = await pool.query(
    `INSERT INTO applications (name, client_id, client_secret_hash)
     VALUES ($1, $2, $3)
     RETURNING id, name, client_id, status, credential_version, created_at, updated_at`,
    [name, clientId, clientSecretHash]
  );

  await writeAuditLog(req, {
    applicationId: result.rows[0].id,
    eventType: 'APPLICATION_REGISTERED',
    success: true,
    metadata: { applicationName: name, actor: 'admin' },
  });

  return res.status(201).json({
    application: result.rows[0],
    clientId,
    clientSecret,
    message: 'Save the client secret now. It will not be returned again.',
  });
}

export async function listApplications(req, res) {
  const result = await pool.query(
    `SELECT id, name, client_id, status, credential_version, created_at, updated_at
     FROM applications ORDER BY created_at DESC`
  );
  return res.json({ applications: result.rows });
}

export async function getApplication(req, res) {
  const id = req.params.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'Invalid application id' });

  const result = await pool.query(
    `SELECT id, name, client_id, status, credential_version, created_at, updated_at
     FROM applications WHERE id = $1`,
    [id]
  );
  if (!result.rows.length) return res.status(404).json({ error: 'Application not found' });

  const counts = await pool.query(
    `SELECT
       COUNT(*)::int AS total_accounts,
       COUNT(*) FILTER (WHERE enabled = TRUE AND revoked_at IS NULL)::int AS enabled_accounts
     FROM external_mfa_accounts WHERE application_id = $1`,
    [id]
  );

  return res.json({ application: result.rows[0], mfa: counts.rows[0] });
}

export async function setApplicationStatus(req, res) {
  const id = req.params.id;
  const status = typeof req.body.status === 'string' ? req.body.status.trim() : '';
  if (!isUuid(id)) return res.status(400).json({ error: 'Invalid application id' });
  if (!['active', 'disabled', 'revoked'].includes(status)) {
    return res.status(400).json({ error: 'Status must be active, disabled, or revoked' });
  }

  const current = await pool.query('SELECT status FROM applications WHERE id = $1', [id]);
  if (!current.rows.length) return res.status(404).json({ error: 'Application not found' });
  if (current.rows[0].status === 'revoked' && status !== 'revoked') {
    return res.status(409).json({ error: 'Revoked applications cannot be reactivated' });
  }

  const result = await pool.query(
    `UPDATE applications
     SET status = $1, credential_version = credential_version + 1, updated_at = NOW()
     WHERE id = $2
     RETURNING id, name, client_id, status, credential_version, created_at, updated_at`,
    [status, id]
  );
  if (!result.rows.length) return res.status(404).json({ error: 'Application not found' });

  await writeAuditLog(req, {
    applicationId: id,
    eventType: status === 'active' ? 'APPLICATION_ENABLED' : 'APPLICATION_DISABLED',
    success: true,
    metadata: { actor: 'admin', status },
  });

  return res.json({ application: result.rows[0] });
}

export async function rotateApplicationSecret(req, res) {
  const id = req.params.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'Invalid application id' });

  const clientSecret = generateClientSecret();
  const clientSecretHash = await hashClientSecret(clientSecret);
  const result = await pool.query(
    `UPDATE applications
     SET client_secret_hash = $1,
         credential_version = credential_version + 1,
         updated_at = NOW()
     WHERE id = $2 AND status <> 'revoked'
     RETURNING id, name, client_id, status, credential_version, created_at, updated_at`,
    [clientSecretHash, id]
  );
  if (!result.rows.length) return res.status(404).json({ error: 'Application not found or revoked' });

  await writeAuditLog(req, {
    applicationId: id,
    eventType: 'APPLICATION_SECRET_ROTATED',
    success: true,
    metadata: { actor: 'admin' },
  });

  return res.json({
    application: result.rows[0],
    clientId: result.rows[0].client_id,
    clientSecret,
    message: 'The previous client secret and all previously issued service tokens are now invalid.',
  });
}

export async function getApplicationAudit(req, res) {
  const id = req.params.id;
  if (!isUuid(id)) return res.status(400).json({ error: 'Invalid application id' });

  const limit = Math.min(Math.max(Number.parseInt(req.query.limit || '50', 10) || 50, 1), 200);
  const result = await pool.query(
    `SELECT id, external_user_id, event_type, success, ip_address, user_agent, metadata, created_at
     FROM audit_logs WHERE application_id = $1
     ORDER BY created_at DESC LIMIT $2`,
    [id, limit]
  );
  return res.json({ audit: result.rows });
}


import { pool } from '../db/pool.js';

export async function writeAuditLog(req, {
  applicationId = null,
  externalUserId = null,
  eventType,
  success,
  metadata = {},
}) {
  try {
    await pool.query(
      `INSERT INTO audit_logs
       (application_id, external_user_id, event_type, success, ip_address, user_agent, metadata)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
      [
        applicationId,
        externalUserId,
        eventType,
        success,
        req.ip || null,
        req.get('user-agent')?.slice(0, 1000) || null,
        JSON.stringify(metadata),
      ]
    );
  } catch (err) {
    console.error('Audit log write failed:', err.message);
  }
}

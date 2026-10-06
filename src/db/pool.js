import pg from 'pg';
import { config } from '../config.js';

const { Pool } = pg;

export const pool = new Pool({
  connectionString: config.databaseUrl,
  max: Number.parseInt(process.env.DB_POOL_MAX || '10', 10),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  ...(process.env.DB_SSL === 'true' ? { ssl: { rejectUnauthorized: process.env.DB_SSL_REJECT_UNAUTHORIZED !== 'false' } } : {}),
});

pool.on('error', err => {
  console.error('Unexpected PostgreSQL pool error:', err);
});

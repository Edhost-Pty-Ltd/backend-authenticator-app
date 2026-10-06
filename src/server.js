import app from './app.js';
import { config } from './config.js';
import { pool } from './db/pool.js';

const server = app.listen(config.port, async () => {
  try {
    await pool.query('SELECT 1');
    console.log(`Auth app running on port ${config.port}`);
  } catch (err) {
    console.error('Database connection failed during startup:', err.message);
    server.close(() => process.exit(1));
  }
});

async function shutdown(signal) {
  console.log(`${signal} received; shutting down`);
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
}

process.once('SIGTERM', () => shutdown('SIGTERM'));
process.once('SIGINT', () => shutdown('SIGINT'));

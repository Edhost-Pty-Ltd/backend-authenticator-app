import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { config } from './config.js';
import { apiLimiter } from './middleware/rateLimiters.js';
import authRoutes from './routes/authRoutes.js';
import internalRoutes from './routes/internalRoutes.js';
import applicationRoutes from './routes/applicationRoutes.js';
import externalMfaRoutes from './routes/externalMfaRoutes.js';
import adminApplicationRoutes from './routes/adminApplicationRoutes.js';
import { notFoundHandler, errorHandler } from './middleware/errorHandler.js';
import { pool } from './db/pool.js';

const app = express();

if (config.trustProxy) app.set('trust proxy', 1);

app.disable('x-powered-by');
app.use(helmet());

const allowedOrigins = new Set(config.corsOrigins);
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) return callback(null, true);
    return callback(null, false);
  },
  credentials: false,
}));

app.use(express.json({ limit: '32kb' }));
app.use(express.urlencoded({ extended: false, limit: '8kb' }));
app.use(apiLimiter);


app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'auth-backend' });
});

app.get('/ready', async (req, res, next) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ready', service: 'auth-backend' });
  } catch (err) {
    next(Object.assign(new Error('Database unavailable'), { statusCode: 503, cause: err }));
  }
});

app.use('/auth', authRoutes);
app.use('/internal', internalRoutes);
app.use('/api/applications', applicationRoutes);
app.use('/api/admin', adminApplicationRoutes);
app.use('/api/mfa', externalMfaRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

export default app;

import 'dotenv/config';

const isProduction = process.env.NODE_ENV === 'production';
const isTest = process.env.NODE_ENV === 'test';

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function parseHexKey(name, expectedBytes) {
  const value = required(name);
  const expectedLength = expectedBytes * 2;
  if (!new RegExp(`^[0-9a-fA-F]{${expectedLength}}$`).test(value)) {
    throw new Error(`${name} must be exactly ${expectedLength} hexadecimal characters`);
  }
  return Buffer.from(value, 'hex');
}

function parseOrigins(value) {
  if (!value?.trim()) return [];
  return value.split(',').map(origin => origin.trim()).filter(Boolean);
}

export const config = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: Number.parseInt(process.env.PORT || '4000', 10),
  databaseUrl: required('DATABASE_URL'),
  jwtSecret: required('JWT_SECRET'),
  jwtIssuer: process.env.JWT_ISSUER?.trim() || 'multiauth',
  jwtAudience: process.env.JWT_AUDIENCE?.trim() || 'multiauth-client',
  jwtServiceAudience: process.env.JWT_SERVICE_AUDIENCE?.trim() || 'multiauth-service',
  totpEncryptionKey: parseHexKey('TOTP_ENCRYPTION_KEY', 32),
  myanganoServiceApiKey: process.env.MYANGANO_SERVICE_API_KEY?.trim() || '',
  myanganoWebhookUrl: process.env.MYANGANO_WEBHOOK_URL?.trim() || '',
  adminApiKey: process.env.ADMIN_API_KEY?.trim() || '',
  corsOrigins: parseOrigins(process.env.CORS_ORIGINS),
  trustProxy: process.env.TRUST_PROXY === 'true',
  isProduction,
  isTest,
};

if (config.port < 1 || config.port > 65535) {
  throw new Error('PORT must be between 1 and 65535');
}

if (config.jwtSecret.length < 32 && !isTest) {
  throw new Error('JWT_SECRET must be at least 32 characters');
}

if (isProduction && config.adminApiKey.length < 32) {
  throw new Error('ADMIN_API_KEY must be at least 32 characters in production');
}

if (isProduction && config.myanganoServiceApiKey.length < 32) {
  throw new Error('MYANGANO_SERVICE_API_KEY must be at least 32 characters in production');
}

if (isProduction && config.myanganoWebhookUrl && !config.myanganoServiceApiKey) {
  throw new Error('MYANGANO_SERVICE_API_KEY is required when MYANGANO_WEBHOOK_URL is configured');
}

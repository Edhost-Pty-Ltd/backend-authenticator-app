process.env.NODE_ENV = 'test';
process.env.DATABASE_URL = process.env.DATABASE_URL || 'postgresql://test:test@localhost:5432/test';
process.env.JWT_SECRET = process.env.JWT_SECRET || 'test-only-jwt-secret-abcdefghijklmnopqrstuvwxyz';
process.env.TOTP_ENCRYPTION_KEY = process.env.TOTP_ENCRYPTION_KEY || '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
process.env.MYANGANO_SERVICE_API_KEY = process.env.MYANGANO_SERVICE_API_KEY || 'test-service-key';
process.env.ADMIN_API_KEY = process.env.ADMIN_API_KEY || 'test-admin-key-abcdefghijklmnopqrstuvwxyz';

import crypto from 'crypto';
import bcrypt from 'bcrypt';

export function generateBackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    codes.push(crypto.randomBytes(5).toString('hex').toUpperCase());
  }
  return codes;
}

export async function hashBackupCodes(codes) {
  return Promise.all(codes.map(c => bcrypt.hash(c, 10)));
}

export async function verifyBackupCode(plainCode, hash) {
  return bcrypt.compare(plainCode, hash);
}

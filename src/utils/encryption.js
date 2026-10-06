import crypto from 'crypto';
import { config } from '../config.js';

const KEY = config.totpEncryptionKey;

export function encryptSecret(plainText) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);

  let encrypted = cipher.update(plainText, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

export function decryptSecret(storedValue) {
  if (typeof storedValue !== 'string') throw new Error('Invalid encrypted secret');

  const parts = storedValue.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted secret format');

  const [ivHex, authTagHex, ciphertext] = parts;
  if (!/^[0-9a-f]+$/i.test(ivHex) || ivHex.length !== 24) throw new Error('Invalid IV');
  if (!/^[0-9a-f]+$/i.test(authTagHex) || authTagHex.length !== 32) throw new Error('Invalid auth tag');
  if (!/^[0-9a-f]*$/i.test(ciphertext)) throw new Error('Invalid ciphertext');

  const decipher = crypto.createDecipheriv(
    'aes-256-gcm',
    KEY,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

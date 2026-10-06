export function isValidEmail(value) {
  return typeof value === 'string' && value.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());
}

export function isStrongPassword(value) {
  if (typeof value !== 'string') return false;
  const bytes = Buffer.byteLength(value, 'utf8');
  return bytes >= 8 && bytes <= 72 && /[A-Z]/.test(value) && /[a-z]/.test(value) && /\d/.test(value);
}

export function isSixDigitCode(value) {
  return typeof value === 'string' && /^\d{6}$/.test(value);
}

export function isBackupCodeFormat(value) {
  return typeof value === 'string' && /^[A-Fa-f0-9]{10}$/.test(value);
}

export function isUuid(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

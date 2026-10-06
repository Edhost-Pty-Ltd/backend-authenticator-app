import test from 'node:test';
import assert from 'node:assert/strict';

import {
  signToken,
  verifyToken,
  signRefreshToken,
  verifyRefreshToken,
} from '../src/utils/jwt.js';
import { encryptSecret, decryptSecret } from '../src/utils/encryption.js';
import { isStrongPassword, isValidEmail, isSixDigitCode, isBackupCodeFormat } from '../src/utils/validators.js';

test('access tokens sign and verify', () => {
  const token = signToken('user-123');
  const payload = verifyToken(token);

  assert.equal(payload.sub, 'user-123');
  assert.equal(payload.type, 'access');
  assert.equal(payload.iss, 'multiauth');
  assert.equal(payload.aud, 'multiauth-client');
});

test('refresh tokens have a unique jti and verify as refresh tokens', () => {
  const first = signRefreshToken('user-123');
  const second = signRefreshToken('user-123');
  const firstPayload = verifyRefreshToken(first);
  const secondPayload = verifyRefreshToken(second);

  assert.equal(firstPayload.sub, 'user-123');
  assert.equal(firstPayload.type, 'refresh');
  assert.ok(firstPayload.jti);
  assert.notEqual(firstPayload.jti, secondPayload.jti);
});

test('wrong token type is rejected', () => {
  const accessToken = signToken('user-123');
  assert.throws(() => verifyRefreshToken(accessToken));
});

test('tampered token is rejected', () => {
  const token = signToken('user-123');
  const tampered = `${token.slice(0, -1)}${token.endsWith('a') ? 'b' : 'a'}`;
  assert.throws(() => verifyToken(tampered));
});

test('TOTP secret encryption round-trips and detects tampering', () => {
  const stored = encryptSecret('JBSWY3DPEHPK3PXP');
  assert.equal(decryptSecret(stored), 'JBSWY3DPEHPK3PXP');

  const [iv, tag, ciphertext] = stored.split(':');
  const last = ciphertext.at(-1);
  const changed = `${ciphertext.slice(0, -1)}${last === '0' ? '1' : '0'}`;
  assert.throws(() => decryptSecret(`${iv}:${tag}:${changed}`));
});

test('validators reject malformed authentication input', () => {
  assert.equal(isValidEmail('person@example.com'), true);
  assert.equal(isValidEmail('not-an-email'), false);
  assert.equal(isStrongPassword('GoodPass1'), true);
  assert.equal(isStrongPassword('weakpassword'), false);
  assert.equal(isSixDigitCode('123456'), true);
  assert.equal(isSixDigitCode('12345'), false);
  assert.equal(isBackupCodeFormat('A1B2C3D4E5'), true);
  assert.equal(isBackupCodeFormat('A1B2-C3D4'), false);
});

test('app and internal routes can be imported without crashing', async () => {
  await import('../src/app.js');
  await import('../src/routes/internalRoutes.js');
});

test('application service tokens are distinct from user access tokens', async () => {
  const { signApplicationToken, verifyApplicationToken } = await import('../src/utils/jwt.js');
  const token = signApplicationToken('application-123');
  const payload = verifyApplicationToken(token);

  assert.equal(payload.sub, 'application-123');
  assert.equal(payload.type, 'service');
  assert.equal(payload.scope, 'mfa:provider');
  assert.equal(payload.aud, 'multiauth-service');
  assert.throws(() => verifyToken(token));
});


test('application service tokens carry a credential version', async () => {
  const { signApplicationToken, verifyApplicationToken } = await import('../src/utils/jwt.js');
  const token = signApplicationToken('application-123', 7);
  const payload = verifyApplicationToken(token);
  assert.equal(payload.credentialVersion, 7);
});

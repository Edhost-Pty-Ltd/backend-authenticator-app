import test from 'node:test';
import assert from 'node:assert/strict';
import { generateClientId, generateClientSecret, hashClientSecret } from '../src/utils/applicationAuth.js';

test('application credentials are cryptographically random and correctly prefixed', async () => {
  const clientId = generateClientId();
  const clientSecret = generateClientSecret();

  assert.match(clientId, /^app_[A-Za-z0-9_-]{24}$/);
  assert.match(clientSecret, /^sec_[A-Za-z0-9_-]{48}$/);
  assert.notEqual(clientId, generateClientId());
  assert.notEqual(clientSecret, generateClientSecret());

  const hash = await hashClientSecret(clientSecret);
  assert.notEqual(hash, clientSecret);
});


test('admin middleware rejects missing and invalid credentials', async () => {
  const { requireAdminAuth } = await import('../src/middleware/adminAuth.js');
  const makeRes = () => ({ statusCode: 200, body: null, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } });

  const missingRes = makeRes();
  requireAdminAuth({ get: () => undefined }, missingRes, () => assert.fail('missing admin key should not continue'));
  assert.equal(missingRes.statusCode, 401);

  const invalidRes = makeRes();
  requireAdminAuth({ get: () => 'wrong-admin-key' }, invalidRes, () => assert.fail('invalid admin key should not continue'));
  assert.equal(invalidRes.statusCode, 403);

  const okRes = makeRes();
  let continued = false;
  requireAdminAuth({ get: () => process.env.ADMIN_API_KEY }, okRes, () => { continued = true; });
  assert.equal(continued, true);
});

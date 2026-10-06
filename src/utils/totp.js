import speakeasy from 'speakeasy';

export function generateSecret(email) {
  return speakeasy.generateSecret({
    name: `MultiAuth (${email})`,
    issuer: 'MultiAuth',
    length: 32,
  });
}

export function verifyToken(base32Secret, token) {
  return speakeasy.totp.verify({
    secret: base32Secret,
    encoding: 'base32',
    token,
    window: 1,
  });
}

export function verifyTokenDelta(base32Secret, token) {
  return speakeasy.totp.verifyDelta({
    secret: base32Secret,
    encoding: 'base32',
    token,
    window: 1,
  });
}

export function currentTimestep() {
  return Math.floor(Date.now() / 1000 / 30);
}

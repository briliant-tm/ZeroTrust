require('dotenv').config();

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const issuer = 'zero-trust-demo';

function getSecret() {
  const secret = process.env.JWT_SECRET;
  if (!secret) {
    throw new Error('JWT_SECRET is required');
  }
  return secret;
}

function signAccessToken(user) {
  return jwt.sign(
    { role: user.role },
    getSecret(),
    { subject: String(user.id), issuer, audience: 'zero-trust-api', expiresIn: process.env.ACCESS_TOKEN_TTL || '10m' }
  );
}

function signRefreshToken(user) {
  return jwt.sign(
    { tokenType: 'refresh' },
    getSecret(),
    { subject: String(user.id), issuer, audience: 'zero-trust-refresh', expiresIn: process.env.REFRESH_TOKEN_TTL || '1d' }
  );
}

function signServiceToken(serviceName) {
  return jwt.sign(
    { role: 'service', service: serviceName },
    getSecret(),
    { subject: serviceName, issuer, audience: 'transkrip-sync', expiresIn: process.env.SERVICE_TOKEN_TTL || '5m' }
  );
}

function verifyAccessToken(token) {
  const decoded = jwt.verify(token, getSecret(), { issuer, audience: 'zero-trust-api' });
  if (decoded.tokenType || !decoded.sub || !decoded.role) {
    throw new Error('Invalid access token claims');
  }
  return decoded;
}

function verifyRefreshToken(token) {
  const decoded = jwt.verify(token, getSecret(), { issuer, audience: 'zero-trust-refresh' });
  if (decoded.tokenType !== 'refresh' || !decoded.sub) {
    throw new Error('Invalid refresh token claims');
  }
  return decoded;
}

function verifyServiceToken(token) {
  const decoded = jwt.verify(token, getSecret(), { issuer, audience: 'transkrip-sync' });
  if (decoded.role !== 'service' || decoded.service !== 'nilai') {
    throw new Error('Invalid service token claims');
  }
  return decoded;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function constantTimeEqual(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') {
    return false;
  }
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && crypto.timingSafeEqual(leftBuffer, rightBuffer);
}

module.exports = {
  signAccessToken,
  signRefreshToken,
  signServiceToken,
  verifyAccessToken,
  verifyRefreshToken,
  verifyServiceToken,
  hashToken,
  constantTimeEqual
};

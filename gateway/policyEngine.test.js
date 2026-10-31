const assert = require('node:assert/strict');
const test = require('node:test');
const { evaluate } = require('./policyEngine');

test('matches policy against the full original URL when Express trims a mounted prefix', async () => {
  const result = await evaluate({
    method: 'POST',
    path: '/sinkron',
    originalUrl: '/transkrip/sinkron?kelasId=1',
    get: () => undefined
  });

  assert.deepEqual(result, {
    allowed: false,
    status: 401,
    reason: 'Service Token wajib dikirim.'
  });
});

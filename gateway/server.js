require('dotenv').config();

const path = require('path');
const express = require('express');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');
const policyEngine = require('./policyEngine');
const auditLogger = require('./auditLogger');
const { constantTimeEqual } = require('../utils/jwt');

const app = express();
app.use(express.json({ limit: '1mb' }));

async function recordDecision(req, userId, decision, reason) {
  await auditLogger.logDecision({
    userId: userId || null,
    method: req.method,
    path: req.originalUrl.split('?')[0],
    decision,
    reason,
    deviceId: req.get('X-Device-ID') || null
  });
}

app.use(express.static(path.join(__dirname, 'public')));

async function handleAuth(req, res, handler, label) {
  try {
    const result = await handler(req);
    await recordDecision(req, result.userId, result.payload.decision, result.reason);
    return res.status(result.status).json(result.payload);
  } catch (error) {
    console.error(`${label} request failed:`, error);
    if (!res.headersSent) res.status(500).json({ decision: 'DENY', reason: `${label} gagal karena kesalahan server.` });
  }
}

app.post('/auth/login', (req, res) => handleAuth(req, res, policyEngine.login, 'Login'));
app.post('/auth/refresh', (req, res) => handleAuth(req, res, policyEngine.refresh, 'Refresh'));
app.post('/auth/logout', (req, res) => handleAuth(req, res, policyEngine.logout, 'Logout'));
app.post('/auth/service', (req, res) => handleAuth(req, res, policyEngine.issueServiceToken, 'Service token'));

app.use(['/nilai', '/kelas', '/transkrip', '/audit'], async (req, res, next) => {
  let result;
  try {
    result = await policyEngine.evaluate(req);
    await recordDecision(
      req,
      result.userId,
      result.allowed ? 'ALLOW' : 'DENY',
      result.reason || (result.allowed ? 'Kebijakan akses terpenuhi.' : 'Request ditolak.')
    );
  } catch (error) {
    console.error('Policy evaluation or audit logging failed:', error);
    return res.status(500).json({ decision: 'DENY', reason: 'Evaluasi kebijakan gagal.' });
  }

  if (!result.allowed) {
    return res.status(result.status || 403).json({ decision: 'DENY', reason: result.reason });
  }
  if (req.path === '/audit' && req.method === 'GET') {
    try {
      const logs = await auditLogger.getRecentLogs(req.query.limit);
      return res.json({ decision: 'ALLOW', logs });
    } catch (error) {
      console.error('Audit log retrieval failed:', error);
      return res.status(500).json({ decision: 'DENY', reason: 'Audit log tidak dapat dimuat.' });
    }
  }
  return next();
});

const proxy = createProxyMiddleware({
  pathFilter: ['/nilai', '/kelas', '/transkrip'],
  router: (req) => (req.path.startsWith('/transkrip')
    ? (process.env.TRANSKRIP_URL || 'http://localhost:3002')
    : (process.env.NILAI_URL || 'http://localhost:3001')),
  changeOrigin: true,
  on: {
    error: (error, req, res) => {
      console.error(`Proxy request failed for ${req.url}:`, error);
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ decision: 'DENY', reason: 'Service tujuan tidak tersedia.' }));
      }
    },
    proxyReq: (proxyReq, req) => {
      proxyReq.setHeader('X-Gateway-Secret', process.env.GATEWAY_SECRET || '');
      fixRequestBody(proxyReq, req);
    }
  }
});
app.use(proxy);

app.use((error, req, res, next) => {
  console.error('Gateway request failed:', error);
  if (!res.headersSent) {
    res.status(500).json({ decision: 'DENY', reason: 'Gateway mengalami kesalahan.' });
  }
  next(error);
});

const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`Zero Trust API Gateway listening on http://localhost:${port}`);
});

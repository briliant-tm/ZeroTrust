require('dotenv').config();

const express = require('express');
const transkripController = require('./transkripController');
const { constantTimeEqual } = require('../../utils/jwt');

const app = express();
app.use(express.json({ limit: '1mb' }));

app.use((req, res, next) => {
  const expected = process.env.GATEWAY_SECRET || '';
  const provided = req.get('X-Gateway-Secret');
  if (!expected || !constantTimeEqual(provided, expected)) {
    return res.status(403).json({ decision: 'DENY', reason: 'Request harus melewati API Gateway.' });
  }
  next();
});

app.get('/transkrip/:nim', transkripController.getTranskrip);
app.post('/transkrip/sinkron', transkripController.syncTranskrip);

app.use((error, req, res, next) => {
  console.error('Transkrip service request failed:', error);
  if (!res.headersSent) {
    res.status(500).json({ decision: 'DENY', reason: 'Service Transkrip mengalami kesalahan.' });
  }
  next(error);
});

const port = Number(process.env.TRANSKRIP_PORT || 3002);
app.listen(port, () => {
  console.log(`Transkrip service listening on http://localhost:${port}`);
});

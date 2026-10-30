const pool = require('../utils/db');

async function logDecision({ userId = null, method, path, decision, reason, deviceId = null }) {
  await pool.execute(
    `INSERT INTO audit_logs (user_id, method, path, decision, reason, device_id)
     VALUES (?, ?, ?, ?, ?, ?)`,
    [userId, method, path, decision, reason, deviceId]
  );
}

async function getRecentLogs(limit = 50) {
  const safeLimit = Math.min(Math.max(Number(limit) || 50, 1), 100);
  const [rows] = await pool.query(
    `SELECT a.id, a.user_id, u.username, a.method, a.path, a.decision, a.reason,
            a.device_id, a.created_at
     FROM audit_logs a
     LEFT JOIN users u ON u.id = a.user_id
     ORDER BY a.id DESC
     LIMIT ?`,
    [safeLimit]
  );
  return rows;
}

module.exports = { logDecision, getRecentLogs };

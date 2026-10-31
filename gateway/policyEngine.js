require('dotenv').config();

const pool = require('../utils/db');
const {
  signAccessToken,
  signRefreshToken,
  signServiceToken,
  verifyAccessToken,
  verifyRefreshToken,
  verifyServiceToken,
  hashToken,
  constantTimeEqual
} = require('../utils/jwt');
const { verifyPassword } = require('../utils/password');

function decisionResult(status, payload, userId = null) {
  return { status, payload, userId, reason: payload.reason || payload.message || payload.decision };
}

function getBearerToken(req) {
  const header = req.get('authorization') || '';
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

function currentLocalHour() {
  const timeZone = process.env.TIME_ZONE || 'Asia/Jakarta';
  const hour = new Intl.DateTimeFormat('en-GB', {
    timeZone,
    hour: '2-digit',
    hourCycle: 'h23'
  }).format(new Date());
  return Number(hour);
}

async function hasRegisteredDevice(userId, req) {
  const deviceId = req.get('X-Device-ID');
  if (!deviceId) {
    return false;
  }
  const [devices] = await pool.execute(
    'SELECT id FROM devices WHERE user_id = ? AND device_id = ?',
    [userId, deviceId]
  );
  return devices.length > 0;
}

async function login(req) {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return decisionResult(400, { decision: 'DENY', reason: 'Username dan password wajib diisi.' });
  }

  const [rows] = await pool.execute(
    'SELECT id, username, password_hash, role, nim, full_name FROM users WHERE username = ?',
    [username]
  );
  const user = rows[0];
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return decisionResult(401, { decision: 'DENY', reason: 'Kredensial tidak valid.' });
  }

  const deviceId = req.get('X-Device-ID');
  if (!deviceId) {
    return decisionResult(403, { decision: 'DENY', reason: 'Header X-Device-ID wajib dikirim.' }, user.id);
  }
  const [devices] = await pool.execute(
    'SELECT id FROM devices WHERE user_id = ? AND device_id = ?',
    [user.id, deviceId]
  );
  if (devices.length === 0) {
    return decisionResult(403, { decision: 'DENY', reason: 'Device tidak terdaftar untuk pengguna ini.' }, user.id);
  }

  const accessToken = signAccessToken(user);
  const refreshToken = signRefreshToken(user);
  const refreshExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);
  await pool.execute(
    'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
    [user.id, hashToken(refreshToken), refreshExpiresAt]
  );

  const payload = {
    decision: 'ALLOW',
    accessToken,
    refreshToken,
    user: { id: user.id, username: user.username, role: user.role, nim: user.nim, fullName: user.full_name },
    deviceId
  };
  return decisionResult(200, payload, user.id);
}

async function refresh(req) {
  const { refreshToken } = req.body || {};
  if (typeof refreshToken !== 'string') {
    return decisionResult(400, { decision: 'DENY', reason: 'Refresh token wajib diisi.' });
  }
  let claims;
  try {
    claims = verifyRefreshToken(refreshToken);
  } catch (error) {
    return decisionResult(401, { decision: 'DENY', reason: 'Refresh token tidak valid atau kedaluwarsa.' });
  }
  if (!(await hasRegisteredDevice(claims.sub, req))) {
    return decisionResult(403, { decision: 'DENY', reason: 'Device tidak terdaftar untuk pengguna ini.' }, claims.sub);
  }

  const tokenHash = hashToken(refreshToken);
  const [tokens] = await pool.execute(
    `SELECT id, user_id FROM refresh_tokens
     WHERE token_hash = ? AND revoked_at IS NULL AND expires_at > UTC_TIMESTAMP()`,
    [tokenHash]
  );
  const savedToken = tokens[0];
  if (!savedToken || String(savedToken.user_id) !== String(claims.sub)) {
    return decisionResult(401, { decision: 'DENY', reason: 'Refresh token telah dicabut atau tidak ditemukan.' }, savedToken?.user_id);
  }

  const [users] = await pool.execute(
    'SELECT id, username, role, nim, full_name FROM users WHERE id = ?',
    [savedToken.user_id]
  );
  const user = users[0];
  if (!user) {
    return decisionResult(401, { decision: 'DENY', reason: 'Pengguna refresh token tidak ditemukan.' }, savedToken.user_id);
  }

  const newAccessToken = signAccessToken(user);
  const newRefreshToken = signRefreshToken(user);
  const connection = await pool.getConnection();
  try {
    await connection.beginTransaction();
    const [updateResult] = await connection.execute(
      'UPDATE refresh_tokens SET revoked_at = UTC_TIMESTAMP() WHERE id = ? AND revoked_at IS NULL',
      [savedToken.id]
    );
    if (updateResult.affectedRows !== 1) {
      await connection.rollback();
      return decisionResult(401, { decision: 'DENY', reason: 'Refresh token sudah digunakan atau dicabut.' }, user.id);
    }
    await connection.execute(
      'INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
      [user.id, hashToken(newRefreshToken), new Date(Date.now() + 24 * 60 * 60 * 1000)]
    );
    await connection.commit();
  } catch (error) {
    await connection.rollback();
    throw error;
  } finally {
    connection.release();
  }

  return decisionResult(200, { decision: 'ALLOW', accessToken: newAccessToken, refreshToken: newRefreshToken }, user.id);
}

async function logout(req) {
  const { refreshToken } = req.body || {};
  if (typeof refreshToken !== 'string') {
    return decisionResult(400, { decision: 'DENY', reason: 'Refresh token wajib diisi.' });
  }
  let claims;
  try {
    claims = verifyRefreshToken(refreshToken);
  } catch (error) {
    return decisionResult(401, { decision: 'DENY', reason: 'Refresh token tidak valid atau kedaluwarsa.' });
  }
  if (!(await hasRegisteredDevice(claims.sub, req))) {
    return decisionResult(403, { decision: 'DENY', reason: 'Device tidak terdaftar untuk pengguna ini.' }, claims.sub);
  }
  const [result] = await pool.execute(
    'UPDATE refresh_tokens SET revoked_at = UTC_TIMESTAMP() WHERE token_hash = ? AND revoked_at IS NULL',
    [hashToken(refreshToken)]
  );
  return decisionResult(200, { decision: 'ALLOW', revoked: result.affectedRows > 0 }, claims.sub);
}

async function issueServiceToken(req) {
  const expectedKey = process.env.SERVICE_AUTH_KEY;
  const providedKey = req.get('X-Service-Key');
  if (!expectedKey || !constantTimeEqual(providedKey, expectedKey)) {
    return decisionResult(403, { decision: 'DENY', reason: 'Kredensial penerbitan token service tidak valid.' });
  }
  if ((req.body || {}).service !== 'nilai') {
    return decisionResult(400, { decision: 'DENY', reason: 'Token hanya dapat diterbitkan untuk service nilai.' });
  }
  return decisionResult(200, { decision: 'ALLOW', serviceToken: signServiceToken('nilai') });
}

async function authenticate(req, expectedRole) {
  const token = getBearerToken(req);
  if (!token) {
    return { allowed: false, status: 401, reason: 'Bearer access token wajib dikirim.' };
  }
  let claims;
  try {
    claims = verifyAccessToken(token);
  } catch (error) {
    return { allowed: false, status: 401, reason: 'Access token tidak valid atau kedaluwarsa.' };
  }
  if (expectedRole && claims.role !== expectedRole) {
    return { allowed: false, status: 403, reason: 'Role tidak memiliki izin untuk endpoint ini.', userId: claims.sub };
  }

  const [users] = await pool.execute(
    'SELECT id, role FROM users WHERE id = ?',
    [claims.sub]
  );
  const user = users[0];
  if (!user || user.role !== claims.role) {
    return { allowed: false, status: 401, reason: 'Identitas token tidak lagi valid.', userId: claims.sub };
  }

  const deviceId = req.get('X-Device-ID');
  if (!deviceId) {
    return { allowed: false, status: 403, reason: 'Header X-Device-ID wajib dikirim.', userId: user.id };
  }
  const [devices] = await pool.execute(
    'SELECT id FROM devices WHERE user_id = ? AND device_id = ?',
    [user.id, deviceId]
  );
  if (devices.length === 0) {
    return { allowed: false, status: 403, reason: 'Device tidak terdaftar untuk pengguna ini.', userId: user.id };
  }
  return { allowed: true, userId: user.id, role: user.role, deviceId };
}

async function evaluate(req) {
  const method = req.method.toUpperCase();
  const pathname = new URL(req.originalUrl || req.url || req.path, 'http://localhost').pathname;

  if (method === 'POST' && pathname === '/transkrip/sinkron') {
    const token = getBearerToken(req);
    if (!token) {
      return { allowed: false, status: 401, reason: 'Service Token wajib dikirim.' };
    }
    try {
      const claims = verifyServiceToken(token);
      return { allowed: true, userId: null, role: 'service', deviceId: null, subject: claims.sub };
    } catch (error) {
      return { allowed: false, status: 401, reason: 'Service Token tidak valid atau kedaluwarsa.' };
    }
  }

  const auth = await authenticate(req);
  if (!auth.allowed) {
    return auth;
  }

  const timeRestricted = (method === 'PUT' && /^\/nilai\/\d+$/.test(pathname))
    || (method === 'POST' && /^\/kelas\/\d+\/finalisasi$/.test(pathname));
  if (timeRestricted) {
    const startHour = Number(process.env.ACCESS_START_HOUR ?? 7);
    const endHour = Number(process.env.ACCESS_END_HOUR ?? 21);
    if (!Number.isInteger(startHour) || !Number.isInteger(endHour) ||
        startHour < 0 || startHour > 23 || endHour < 0 || endHour > 24 || startHour >= endHour) {
      return { allowed: false, status: 503, reason: 'Konfigurasi jam akses tidak valid.', userId: auth.userId };
    }
    const hour = currentLocalHour();
    if (hour < startHour || hour >= endHour) {
      return {
        allowed: false,
        status: 403,
        reason: `Aksi perubahan hanya diizinkan pukul ${String(startHour).padStart(2, '0')}.00-${String(endHour).padStart(2, '0')}.00.`,
        userId: auth.userId
      };
    }
  }

  if (method === 'GET' && pathname === '/nilai') {
    if (!['mahasiswa', 'dosen'].includes(auth.role)) {
      return { allowed: false, status: 403, reason: 'Hanya Mahasiswa atau Dosen yang dapat melihat nilai.', userId: auth.userId };
    }
    let scopedRows;
    if (auth.role === 'mahasiswa') {
      [scopedRows] = await pool.execute(
        'SELECT COUNT(*) AS owned_count FROM nilai WHERE mahasiswa_id = ?',
        [auth.userId]
      );
    } else {
      [scopedRows] = await pool.execute(
        `SELECT COUNT(*) AS owned_count FROM kelas k
         JOIN nilai n ON n.kelas_id = k.id WHERE k.dosen_id = ?`,
        [auth.userId]
      );
    }
    return {
      ...auth,
      allowed: true,
      reason: `Owner-scoped records checked (${scopedRows[0].owned_count}).`
    };
  }

  const nilaiMatch = pathname.match(/^\/nilai\/(\d+)$/);
  if (method === 'PUT' && nilaiMatch) {
    if (auth.role !== 'dosen') {
      return { allowed: false, status: 403, reason: 'Hanya Dosen yang dapat mengubah nilai.', userId: auth.userId };
    }
    const [rows] = await pool.execute(
      `SELECT n.id FROM nilai n
       JOIN kelas k ON k.id = n.kelas_id
       WHERE n.id = ? AND k.dosen_id = ? AND k.finalized = 0`,
      [nilaiMatch[1], auth.userId]
    );
    if (rows.length === 0) {
      return { allowed: false, status: 403, reason: 'Nilai bukan milik kelas Dosen ini atau kelas sudah final.', userId: auth.userId };
    }
    return { ...auth, allowed: true };
  }

  const finalisasiMatch = pathname.match(/^\/kelas\/(\d+)\/finalisasi$/);
  if (method === 'POST' && finalisasiMatch) {
    if (auth.role !== 'dosen') {
      return { allowed: false, status: 403, reason: 'Hanya Dosen yang dapat memfinalisasi kelas.', userId: auth.userId };
    }
    const [rows] = await pool.execute(
      'SELECT id FROM kelas WHERE id = ? AND dosen_id = ?',
      [finalisasiMatch[1], auth.userId]
    );
    if (rows.length === 0) {
      return { allowed: false, status: 403, reason: 'Kelas bukan milik Dosen ini.', userId: auth.userId };
    }
    return { ...auth, allowed: true };
  }

  const transcriptMatch = pathname.match(/^\/transkrip\/([^/]+)$/);
  if (method === 'GET' && transcriptMatch) {
    if (auth.role === 'mahasiswa') {
      const [rows] = await pool.execute('SELECT nim FROM users WHERE id = ?', [auth.userId]);
      if (!rows[0] || rows[0].nim !== decodeURIComponent(transcriptMatch[1])) {
        return { allowed: false, status: 403, reason: 'Mahasiswa hanya dapat melihat transkrip miliknya.', userId: auth.userId };
      }
      return { ...auth, allowed: true };
    }
    if (auth.role === 'admin') {
      return { ...auth, allowed: true };
    }
    return { allowed: false, status: 403, reason: 'Role tidak diizinkan melihat transkrip.', userId: auth.userId };
  }

  if (method === 'GET' && pathname === '/audit' && auth.role === 'admin') {
    return { ...auth, allowed: true };
  }
  return { allowed: false, status: 403, reason: 'Tidak ada kebijakan akses yang mengizinkan request ini.', userId: auth.userId };
}

module.exports = { login, refresh, logout, issueServiceToken, evaluate, getBearerToken };

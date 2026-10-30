const pool = require('../../utils/db');
const { verifyAccessToken } = require('../../utils/jwt');

function requestClaims(req) {
  const authorization = req.get('authorization') || '';
  const match = authorization.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    throw new Error('Bearer token wajib dikirim.');
  }
  return verifyAccessToken(match[1]);
}

async function getNilai(req, res) {
  const claims = requestClaims(req);
  let rows;
  if (claims.role === 'mahasiswa') {
    [rows] = await pool.execute(
      `SELECT n.id, k.id AS kelas_id, k.nama AS kelas, u.full_name AS mahasiswa,
              n.nilai, k.finalized
       FROM nilai n JOIN kelas k ON k.id = n.kelas_id
       JOIN users u ON u.id = n.mahasiswa_id
       WHERE n.mahasiswa_id = ? ORDER BY k.nama`,
      [claims.sub]
    );
  } else if (claims.role === 'dosen') {
    [rows] = await pool.execute(
      `SELECT n.id, k.id AS kelas_id, k.nama AS kelas, u.full_name AS mahasiswa,
              n.nilai, k.finalized
       FROM nilai n JOIN kelas k ON k.id = n.kelas_id
       JOIN users u ON u.id = n.mahasiswa_id
       WHERE k.dosen_id = ? ORDER BY k.nama, u.full_name`,
      [claims.sub]
    );
  } else {
    return res.status(403).json({ decision: 'DENY', reason: 'Role tidak diizinkan melihat nilai.' });
  }
  return res.json({ decision: 'ALLOW', nilai: rows });
}

async function updateNilai(req, res) {
  const claims = requestClaims(req);
  const nilai = Number(req.body?.nilai);
  if (!Number.isFinite(nilai) || nilai < 0 || nilai > 100) {
    return res.status(400).json({ decision: 'DENY', reason: 'Nilai harus berupa angka antara 0 sampai 100.' });
  }
  if (claims.role !== 'dosen') {
    return res.status(403).json({ decision: 'DENY', reason: 'Hanya Dosen yang dapat mengubah nilai.' });
  }
  const [result] = await pool.execute(
    `UPDATE nilai n JOIN kelas k ON k.id = n.kelas_id
     SET n.nilai = ?
     WHERE n.id = ? AND k.dosen_id = ? AND k.finalized = 0`,
    [nilai, req.params.id, claims.sub]
  );
  if (result.affectedRows !== 1) {
    return res.status(403).json({ decision: 'DENY', reason: 'Nilai tidak ditemukan, bukan milik Dosen ini, atau kelas sudah final.' });
  }
  return res.json({ decision: 'ALLOW', message: 'Nilai berhasil diperbarui.', id: Number(req.params.id), nilai });
}

async function finalizeClass(req, res) {
  const claims = requestClaims(req);
  if (claims.role !== 'dosen') {
    return res.status(403).json({ decision: 'DENY', reason: 'Hanya Dosen yang dapat memfinalisasi kelas.' });
  }

  const [classes] = await pool.execute(
    'SELECT id, nama FROM kelas WHERE id = ? AND dosen_id = ?',
    [req.params.id, claims.sub]
  );
  if (classes.length === 0) {
    return res.status(403).json({ decision: 'DENY', reason: 'Kelas bukan milik Dosen ini.' });
  }
  await pool.execute('UPDATE kelas SET finalized = 1 WHERE id = ?', [req.params.id]);

  try {
    const tokenResponse = await fetch(`${process.env.GATEWAY_URL || 'http://localhost:3000'}/auth/service`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Service-Key': process.env.SERVICE_AUTH_KEY || ''
      },
      body: JSON.stringify({ service: 'nilai' })
    });
    const tokenResult = await tokenResponse.json();
    if (!tokenResponse.ok || tokenResult.decision !== 'ALLOW' || !tokenResult.serviceToken) {
      throw new Error(`Gateway menolak penerbitan service token (${tokenResponse.status}).`);
    }

    const syncResponse = await fetch(`${process.env.GATEWAY_URL || 'http://localhost:3000'}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${tokenResult.serviceToken}`
      },
      body: JSON.stringify({ kelasId: Number(req.params.id) })
    });
    const syncResult = await syncResponse.json();
    if (!syncResponse.ok || syncResult.decision !== 'ALLOW') {
      throw new Error(`Sinkronisasi transkrip gagal (${syncResponse.status}): ${syncResult.reason || 'respons tidak valid'}`);
    }
    return res.json({
      decision: 'ALLOW',
      message: `Kelas ${classes[0].nama} final dan transkrip berhasil disinkronkan.`,
      sync: syncResult
    });
  } catch (error) {
    console.error('Transcript synchronization failed after finalization:', error);
    return res.status(502).json({
      decision: 'DENY',
      reason: 'Kelas telah difinalisasi, tetapi sinkronisasi transkrip gagal. Ulangi finalisasi untuk mencoba sinkronisasi kembali.'
    });
  }
}

module.exports = { getNilai, updateNilai, finalizeClass };

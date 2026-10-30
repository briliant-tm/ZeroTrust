const pool = require('../../utils/db');
const { verifyAccessToken, verifyServiceToken } = require('../../utils/jwt');

function bearerToken(req) {
  const match = (req.get('authorization') || '').match(/^Bearer\s+(.+)$/i);
  if (!match) {
    throw new Error('Bearer token wajib dikirim.');
  }
  return match[1];
}

async function getTranskrip(req, res) {
  const claims = verifyAccessToken(bearerToken(req));
  if (!['mahasiswa', 'admin'].includes(claims.role)) {
    return res.status(403).json({ decision: 'DENY', reason: 'Role tidak diizinkan melihat transkrip.' });
  }
  if (claims.role === 'mahasiswa') {
    const [owners] = await pool.execute('SELECT nim FROM users WHERE id = ?', [claims.sub]);
    if (!owners[0] || owners[0].nim !== req.params.nim) {
      return res.status(403).json({ decision: 'DENY', reason: 'Mahasiswa hanya dapat melihat transkrip miliknya.' });
    }
  }
  const [rows] = await pool.execute(
    `SELECT u.nim, u.full_name AS mahasiswa, k.id AS kelas_id, k.nama AS kelas,
            t.nilai_akhir, t.synced_at
     FROM users u
     LEFT JOIN transkrip t ON t.mahasiswa_id = u.id
     LEFT JOIN kelas k ON k.id = t.kelas_id
     WHERE u.nim = ? ORDER BY k.nama`,
    [req.params.nim]
  );
  if (rows.length === 0) {
    return res.status(404).json({ decision: 'DENY', reason: 'NIM tidak ditemukan.' });
  }
  return res.json({ decision: 'ALLOW', transkrip: rows });
}

async function syncTranskrip(req, res) {
  const claims = verifyServiceToken(bearerToken(req));
  if (claims.service !== 'nilai') {
    return res.status(403).json({ decision: 'DENY', reason: 'Hanya Service Nilai yang dapat menyinkronkan transkrip.' });
  }
  const kelasId = Number(req.body?.kelasId);
  if (!Number.isInteger(kelasId) || kelasId < 1) {
    return res.status(400).json({ decision: 'DENY', reason: 'kelasId wajib berupa bilangan bulat positif.' });
  }

  const [classes] = await pool.execute('SELECT id, finalized FROM kelas WHERE id = ?', [kelasId]);
  if (classes.length === 0 || !classes[0].finalized) {
    return res.status(409).json({ decision: 'DENY', reason: 'Kelas tidak ditemukan atau belum difinalisasi.' });
  }
  const [result] = await pool.execute(
    `INSERT INTO transkrip (kelas_id, mahasiswa_id, nilai_akhir)
     SELECT kelas_id, mahasiswa_id, nilai FROM nilai WHERE kelas_id = ?
     ON DUPLICATE KEY UPDATE nilai_akhir = VALUES(nilai_akhir), synced_at = CURRENT_TIMESTAMP`,
    [kelasId]
  );
  return res.json({
    decision: 'ALLOW',
    message: 'Sinkronisasi transkrip berhasil.',
    kelasId,
    affectedRows: result.affectedRows
  });
}

module.exports = { getTranskrip, syncTranskrip };

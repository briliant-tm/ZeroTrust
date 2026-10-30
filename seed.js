require('dotenv').config();

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const { hashPassword } = require('./utils/password');

let connection;

async function seed() {
  connection = await mysql.createConnection({
    host: process.env.DB_HOST || 'localhost',
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD || '',
    multipleStatements: true,
    timezone: 'Z',
    decimalNumbers: true
  });
  const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
  await connection.query(schema);

  const usersToSeed = [
    { username: 'admin', password: 'Admin123!', role: 'admin', nim: null, fullName: 'Administrator' },
    { username: 'dosen1', password: 'Dosen123!', role: 'dosen', nim: null, fullName: 'Dr. Dosen Satu' },
    { username: 'dosen2', password: 'Dosen123!', role: 'dosen', nim: null, fullName: 'Dr. Dosen Dua' },
    { username: 'mhs1', password: 'Mhs123!', role: 'mahasiswa', nim: '230001', fullName: 'Mahasiswa Satu' },
    { username: 'mhs2', password: 'Mhs123!', role: 'mahasiswa', nim: '230002', fullName: 'Mahasiswa Dua' },
    { username: 'mhs3', password: 'Mhs123!', role: 'mahasiswa', nim: '230003', fullName: 'Mahasiswa Tiga' }
  ];

  const userIds = {};
  for (const user of usersToSeed) {
    const passwordHash = await hashPassword(user.password);
    await connection.execute(
      `INSERT INTO users (username, password_hash, role, nim, full_name)
       VALUES (?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = VALUES(role),
         nim = VALUES(nim), full_name = VALUES(full_name)`,
      [user.username, passwordHash, user.role, user.nim, user.fullName]
    );
    const [rows] = await connection.execute('SELECT id FROM users WHERE username = ?', [user.username]);
    userIds[user.username] = rows[0].id;

    await connection.execute(
      `INSERT INTO devices (user_id, device_id) VALUES (?, ?)
       ON DUPLICATE KEY UPDATE user_id = VALUES(user_id)`,
      [userIds[user.username], `device-${user.username}-001`]
    );
  }

  const classes = [
    { name: 'Keamanan Informasi A', lecturer: userIds.dosen1 },
    { name: 'Keamanan Informasi B', lecturer: userIds.dosen2 }
  ];
  const classIds = {};
  for (const item of classes) {
    await connection.execute(
      `INSERT INTO kelas (nama, dosen_id, finalized) VALUES (?, ?, 0)
       ON DUPLICATE KEY UPDATE dosen_id = VALUES(dosen_id), finalized = 0`,
      [item.name, item.lecturer]
    );
    const [rows] = await connection.execute('SELECT id FROM kelas WHERE nama = ?', [item.name]);
    classIds[item.name] = rows[0].id;
  }

  const initialGrades = [
    { className: 'Keamanan Informasi A', student: 'mhs1', grade: 88 },
    { className: 'Keamanan Informasi A', student: 'mhs2', grade: 91 },
    { className: 'Keamanan Informasi B', student: 'mhs2', grade: 82 },
    { className: 'Keamanan Informasi B', student: 'mhs3', grade: 95 }
  ];
  for (const item of initialGrades) {
    const kelasId = classIds[item.className];
    const mahasiswaId = userIds[item.student];
    await connection.execute(
      `INSERT INTO nilai (kelas_id, mahasiswa_id, nilai) VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE nilai = VALUES(nilai)`,
      [kelasId, mahasiswaId, item.grade]
    );
    await connection.execute(
      `INSERT INTO transkrip (kelas_id, mahasiswa_id, nilai_akhir) VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE nilai_akhir = VALUES(nilai_akhir)`,
      [kelasId, mahasiswaId, item.grade]
    );
  }

  console.log('Database schema and demo data are ready.');
  console.log('Demo logins: admin/Admin123!, dosen1/Dosen123!, dosen2/Dosen123!, mhs1/Mhs123!.');
}

seed()
  .catch((error) => {
    console.error('Database seeding failed:', error);
    process.exitCode = 1;
  })
  .finally(async () => {
    if (connection) {
      await connection.end();
    }
  });

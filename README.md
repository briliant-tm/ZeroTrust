# Zero Trust Security Demo

Demo microservices untuk praktikum keamanan informasi yang mengadaptasi prinsip **Zero Trust** dari NIST SP 800-207. Semua request aplikasi masuk melalui API Gateway dan dievaluasi berdasarkan identitas, role, device terdaftar, kepemilikan data, serta konteks waktu.

## Fitur

- Autentikasi pengguna dengan access token dan refresh token JWT.
- Pemeriksaan device melalui header `X-Device-ID`.
- Policy Engine untuk role-based access dan pembatasan akses ke data milik pengguna.
- API Gateway dengan audit log keputusan `ALLOW` dan `DENY`.
- Dua layanan terpisah: Nilai dan Transkrip.
- Finalisasi kelas yang memicu sinkronisasi nilai ke transkrip menggunakan service token.
- Antarmuka demo berbahasa Indonesia di halaman utama Gateway.

> Proyek ini ditujukan untuk demonstrasi dan pembelajaran, bukan konfigurasi siap produksi. Ganti semua kredensial demo dan rahasia, serta tambahkan kontrol keamanan sesuai kebutuhan sebelum digunakan di lingkungan nyata.

## Arsitektur

```text
Browser / Client
       |
       v
API Gateway (:3000) -- Policy Engine + Audit Log
       |                                  |
       +--> Nilai Service (:3001)         +--> MySQL
       |
       +--> Transkrip Service (:3002)
```

Service Nilai dan Transkrip menolak request yang tidak membawa rahasia Gateway yang valid. Endpoint sinkronisasi transkrip juga memerlukan service token khusus yang diterbitkan Gateway.

## Persyaratan

- Node.js 18 atau lebih baru
- MySQL
- npm

## Instalasi dan konfigurasi

1. Pasang dependency:

   ```bash
   npm install
   ```

2. Buat file `.env` di direktori utama proyek. Contoh:

   ```dotenv
   # MySQL
   DB_HOST=localhost
   DB_PORT=3306
   DB_USER=root
   DB_PASSWORD=
   DB_NAME=zerotrust_db

   # Wajib diisi dengan nilai acak yang kuat dan berbeda
   JWT_SECRET=ganti-dengan-rahasia-acak-minimal-32-karakter
   GATEWAY_SECRET=ganti-dengan-rahasia-internal-acak
   SERVICE_AUTH_KEY=ganti-dengan-kunci-service-acak

   # Port dan alamat service
   PORT=3000
   NILAI_PORT=3001
   TRANSKRIP_PORT=3002
   NILAI_URL=http://localhost:3001
   TRANSKRIP_URL=http://localhost:3002
   GATEWAY_URL=http://localhost:3000

   # Kebijakan token dan jam akses
   ACCESS_TOKEN_TTL=10m
   REFRESH_TOKEN_TTL=1d
   SERVICE_TOKEN_TTL=5m
   TIME_ZONE=Asia/Jakarta
   ACCESS_START_HOUR=7
   ACCESS_END_HOUR=21
   ```

   `ACCESS_START_HOUR` inklusif dan `ACCESS_END_HOUR` eksklusif. Contoh di atas mengizinkan aksi perubahan nilai dan finalisasi kelas pukul 07.00 hingga sebelum 21.00 waktu `TIME_ZONE`.

3. Buat schema dan isi data demo:

   ```bash
   npm run seed
   ```

   Akun MySQL pada konfigurasi harus memiliki izin membuat database dan tabel. `schema.sql` membuat database `zerotrust_db`; karena itu, pertahankan `DB_NAME=zerotrust_db`.

## Menjalankan aplikasi

Jalankan setiap proses di terminal terpisah dari direktori proyek:

```bash
npm run nilai
```

```bash
npm run transkrip
```

```bash
npm run gateway
```

Buka **http://localhost:3000** untuk menggunakan antarmuka demo. Pengguna mengakses endpoint aplikasi melalui Gateway, bukan langsung ke service.

## Akun demo

| Role | Username | Password | Device ID |
|---|---|---|---|
| Admin | `admin` | `Admin123!` | `device-admin-001` |
| Dosen | `dosen1` | `Dosen123!` | `device-dosen1-001` |
| Dosen | `dosen2` | `Dosen123!` | `device-dosen2-001` |
| Mahasiswa | `mhs1` | `Mhs123!` | `device-mhs1-001` |
| Mahasiswa | `mhs2` | `Mhs123!` | `device-mhs2-001` |
| Mahasiswa | `mhs3` | `Mhs123!` | `device-mhs3-001` |

Data awal memiliki kelas `Keamanan Informasi A` untuk `dosen1` dan `Keamanan Informasi B` untuk `dosen2`. Keduanya memiliki ID kelas 1 dan 2 pada seed baru. Nilai awal sudah tersedia, tetapi kelas belum difinalisasi.

> Kredensial ini hanya untuk demo lokal. Jangan gunakan di lingkungan bersama atau produksi.

## Endpoint Gateway

Endpoint selain login memerlukan header `Authorization: Bearer <access-token>` dan `X-Device-ID` yang terdaftar untuk pengguna.

| Method | Path | Akses dan fungsi |
|---|---|---|
| `POST` | `/auth/login` | Login; memerlukan `username`, `password`, dan `X-Device-ID`. Menghasilkan access dan refresh token. |
| `POST` | `/auth/refresh` | Memutar refresh token; body berisi `refreshToken`, dengan `X-Device-ID`. |
| `POST` | `/auth/logout` | Mencabut refresh token; body berisi `refreshToken`, dengan `X-Device-ID`. |
| `GET` | `/nilai` | Dosen melihat nilai kelas yang diajarnya; mahasiswa melihat nilainya sendiri. |
| `PUT` | `/nilai/:id` | Dosen mengubah nilai pada kelas miliknya yang belum final. Body: `{"nilai": 90}`. |
| `POST` | `/kelas/:id/finalisasi` | Dosen memfinalisasi kelas miliknya dan memicu sinkronisasi transkrip. |
| `GET` | `/transkrip/:nim` | Mahasiswa melihat transkrip sendiri; admin dapat melihat transkrip berdasarkan NIM. |
| `GET` | `/audit?limit=30` | Admin melihat audit log terbaru; jumlah dibatasi maksimal 100. |

Sinkronisasi internal `POST /transkrip/sinkron` hanya menerima service token yang sah dan tidak dimaksudkan sebagai endpoint untuk dipanggil langsung oleh pengguna.

### Contoh penggunaan API

Login (ganti username, password, dan device sesuai akun demo):

```bash
curl.exe -X POST http://localhost:3000/auth/login -H "Content-Type: application/json" -H "X-Device-ID: device-mhs1-001" --data-raw "{\"username\":\"mhs1\",\"password\":\"Mhs123!\"}"
```

Gunakan `accessToken` dari respons login untuk mengambil nilai:

```bash
curl.exe http://localhost:3000/nilai -H "Authorization: Bearer <access-token>" -H "X-Device-ID: device-mhs1-001"
```

## Pengujian

Jalankan test Policy Engine yang tersedia:

```bash
node --test gateway/policyEngine.test.js
```

## Struktur proyek

```text
gateway/
  public/                 Antarmuka demo
  auditLogger.js          Pencatatan dan pembacaan audit log
  policyEngine.js         Autentikasi dan evaluasi kebijakan akses
  server.js               API Gateway dan reverse proxy
  policyEngine.test.js    Test Policy Engine
services/
  nilai/                  Layanan dan controller nilai
  transkrip/              Layanan dan controller transkrip
utils/
  db.js                   Pool koneksi MySQL
  jwt.js                  Pembuatan dan verifikasi token
  password.js             Hash dan verifikasi password
schema.sql                Skema database
seed.js                   Pembuatan schema dan data demo
```

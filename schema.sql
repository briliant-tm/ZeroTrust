CREATE DATABASE IF NOT EXISTS zerotrust_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE zerotrust_db;

CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(80) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'dosen', 'mahasiswa') NOT NULL,
  nim VARCHAR(30) NULL,
  full_name VARCHAR(150) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_username (username),
  UNIQUE KEY uq_users_nim (nim)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS devices (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  device_id VARCHAR(120) NOT NULL,
  registered_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_devices_device_id (device_id),
  KEY idx_devices_user_id (user_id),
  CONSTRAINT fk_devices_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_refresh_tokens_hash (token_hash),
  KEY idx_refresh_tokens_user_id (user_id),
  CONSTRAINT fk_refresh_tokens_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS kelas (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  nama VARCHAR(150) NOT NULL,
  dosen_id INT UNSIGNED NOT NULL,
  finalized TINYINT(1) NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_kelas_nama (nama),
  KEY idx_kelas_dosen_id (dosen_id),
  CONSTRAINT fk_kelas_dosen FOREIGN KEY (dosen_id) REFERENCES users(id)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS nilai (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  kelas_id INT UNSIGNED NOT NULL,
  mahasiswa_id INT UNSIGNED NOT NULL,
  nilai DECIMAL(5,2) NOT NULL,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_nilai_kelas_mahasiswa (kelas_id, mahasiswa_id),
  KEY idx_nilai_mahasiswa (mahasiswa_id),
  CONSTRAINT fk_nilai_kelas FOREIGN KEY (kelas_id) REFERENCES kelas(id) ON DELETE CASCADE,
  CONSTRAINT fk_nilai_mahasiswa FOREIGN KEY (mahasiswa_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS transkrip (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT,
  kelas_id INT UNSIGNED NOT NULL,
  mahasiswa_id INT UNSIGNED NOT NULL,
  nilai_akhir DECIMAL(5,2) NOT NULL,
  synced_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_transkrip_kelas_mahasiswa (kelas_id, mahasiswa_id),
  KEY idx_transkrip_mahasiswa (mahasiswa_id),
  CONSTRAINT fk_transkrip_kelas FOREIGN KEY (kelas_id) REFERENCES kelas(id) ON DELETE CASCADE,
  CONSTRAINT fk_transkrip_mahasiswa FOREIGN KEY (mahasiswa_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id INT UNSIGNED NULL,
  method VARCHAR(10) NOT NULL,
  path VARCHAR(255) NOT NULL,
  decision ENUM('ALLOW', 'DENY') NOT NULL,
  reason VARCHAR(500) NOT NULL,
  device_id VARCHAR(120) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  KEY idx_audit_logs_created_at (created_at),
  KEY idx_audit_logs_user_id (user_id),
  CONSTRAINT fk_audit_logs_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

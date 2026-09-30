const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

let db = null;

function initDatabase(customPath = null) {
  const dbPath = customPath || process.env.DB_PATH || path.join(__dirname, '..', 'data', 'licenses.db');
  const dir = path.dirname(dbPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  db = new DatabaseSync(dbPath);

  // configure wal mode and foreign keys
  db.exec('PRAGMA journal_mode = WAL;');
  db.exec('PRAGMA foreign_keys = ON;');

  // create schema tables
  db.exec(`
    CREATE TABLE IF NOT EXISTS admin_users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      must_change_password INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS licenses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key_hash TEXT UNIQUE NOT NULL,
      masked_key TEXT NOT NULL,
      user_note TEXT NULL,
      status TEXT NOT NULL DEFAULT 'UNUSED' CHECK(status IN ('UNUSED', 'ACTIVE', 'REVOKED')),
      duration_seconds INTEGER NOT NULL DEFAULT 86400,
      device_id TEXT NULL,
      ip_address TEXT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      activated_at TEXT NULL,
      expires_at TEXT NULL,
      revoked_at TEXT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);
    CREATE INDEX IF NOT EXISTS idx_licenses_device_id ON licenses(device_id);
  `);

  try {
    db.exec('ALTER TABLE licenses ADD COLUMN user_note TEXT NULL;');
  } catch (e) {
    // column already exists
  }

  db.exec(`

    CREATE TABLE IF NOT EXISTS client_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      license_id INTEGER NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      device_id TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_sessions_license ON client_sessions(license_id);

    CREATE TABLE IF NOT EXISTS admin_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      ip_address TEXT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      expires_at TEXT NOT NULL,
      FOREIGN KEY(user_id) REFERENCES admin_users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_admin_sessions_token ON admin_sessions(token_hash);

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_type TEXT NOT NULL,
      license_id INTEGER NULL,
      actor TEXT NOT NULL,
      ip_address TEXT NULL,
      details TEXT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE SET NULL
    );

    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);
  `);

  bootstrapAdmin();
  cleanExpiredRecords();

  return db;
}

function getDb() {
  if (!db) {
    return initDatabase();
  }
  return db;
}

function runImmediateTransaction(fn) {
  const database = getDb();
  database.exec('BEGIN IMMEDIATE;');
  try {
    const result = fn(database);
    database.exec('COMMIT;');
    return result;
  } catch (err) {
    database.exec('ROLLBACK;');
    throw err;
  }
}

function bootstrapAdmin() {
  const row = db.prepare('SELECT COUNT(*) as count FROM admin_users').get();
  if (row.count === 0) {
    const initialPassword = process.env.ADMIN_INITIAL_PASSWORD || crypto.randomBytes(12).toString('hex');
    const passwordHash = bcrypt.hashSync(initialPassword, 12);
    db.prepare(`
      INSERT INTO admin_users (username, password_hash, must_change_password)
      VALUES (?, ?, 1)
    `).run('admin', passwordHash);

    console.log('[security bootstrap] initial admin account created:');
    console.log(`[security bootstrap] username: admin`);
    console.log(`[security bootstrap] password: ${initialPassword}`);
    console.log('[security bootstrap] password change required upon first login.');
  }
}

function cleanExpiredRecords() {
  try {
    db.prepare("DELETE FROM client_sessions WHERE datetime(expires_at) < datetime('now', '-30 days')").run();
    db.prepare("DELETE FROM admin_sessions WHERE datetime(expires_at) < datetime('now', '-7 days')").run();
    db.prepare("DELETE FROM audit_logs WHERE datetime(created_at) < datetime('now', '-90 days')").run();
  } catch (err) {
    console.error('database cleanup error:', err.message);
  }
}

function backupDatabase(destPath) {
  const normalizedPath = path.resolve(destPath).replace(/\\/g, '/');
  const dir = path.dirname(normalizedPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  if (fs.existsSync(normalizedPath)) {
    fs.unlinkSync(normalizedPath);
  }
  getDb().exec(`VACUUM INTO '${normalizedPath}';`);
  return normalizedPath;
}

module.exports = {
  initDatabase,
  getDb,
  runImmediateTransaction,
  backupDatabase,
  cleanExpiredRecords
};

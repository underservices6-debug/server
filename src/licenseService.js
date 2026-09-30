const crypto = require('crypto');
const { getDb, runImmediateTransaction } = require('./db');

const CHARSET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ';

function generateRandomKeyString() {
  const bytes = crypto.randomBytes(16);
  let key = '';
  for (let i = 0; i < 16; i++) {
    key += CHARSET[bytes[i] % CHARSET.length];
  }
  return `${key.slice(0, 4)}-${key.slice(4, 8)}-${key.slice(8, 12)}-${key.slice(12, 16)}`;
}

function hashKey(key) {
  const normalized = key.trim().toUpperCase();
  return crypto.createHash('sha256').update(normalized).digest('hex');
}

function maskKey(fullKey) {
  return fullKey;
}

function generateKeys({ count = 1, prefix = '', user_note = '', duration_seconds = 86400 }, actor = 'admin', ip = null) {
  const validCount = Math.min(Math.max(1, parseInt(count, 10) || 1), 100);
  const cleanPrefix = prefix ? prefix.trim().toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 8) : '';
  const cleanNote = user_note ? String(user_note).trim().slice(0, 100) : '';
  const parsedDuration = parseInt(duration_seconds, 10);
  const durationVal = (parsedDuration === -1 || parsedDuration > 0) ? parsedDuration : 86400;
  const db = getDb();

  const generatedKeys = [];
  const insertStmt = db.prepare(`
    INSERT INTO licenses (key_hash, masked_key, user_note, status, duration_seconds)
    VALUES (?, ?, ?, 'UNUSED', ?)
  `);
  const auditStmt = db.prepare(`
    INSERT INTO audit_logs (event_type, license_id, actor, ip_address, details)
    VALUES ('KEY_GENERATED', ?, ?, ?, ?)
  `);

  runImmediateTransaction(() => {
    for (let i = 0; i < validCount; i++) {
      const randomSegment = generateRandomKeyString();
      const rawKey = cleanPrefix ? `${cleanPrefix}-${randomSegment}` : randomSegment;
      const keyHash = hashKey(rawKey);

      const info = insertStmt.run(keyHash, rawKey, cleanNote || null, durationVal);
      auditStmt.run(info.lastInsertRowid, actor, ip, JSON.stringify({ masked_key: rawKey, user_note: cleanNote, duration_seconds: durationVal }));
      generatedKeys.push(rawKey);
    }
  });

  return generatedKeys;
}

function activateLicense({ key, device_id }, clientIp = null) {
  if (!key || !device_id) {
    const err = new Error('Invalid or unusable activation key.');
    err.statusCode = 400;
    throw err;
  }

  const keyHash = hashKey(key);
  const deviceId = String(device_id).trim().toLowerCase();

  return runImmediateTransaction((db) => {
    const existing = db.prepare('SELECT * FROM licenses WHERE key_hash = ?').get(keyHash);
    if (!existing) {
      const err = new Error('Invalid or unusable activation key.');
      err.statusCode = 400;
      throw err;
    }

    const now = new Date();
    const activatedAt = now.toISOString();
    const isLifetime = existing.duration_seconds === -1;
    let expiresAt = null;
    let remainingSeconds = 86400;

    if (isLifetime) {
      // 100 years in future for lifetime keys to keep sqlite date filters valid
      expiresAt = new Date(now.getTime() + 100 * 365.25 * 86400 * 1000).toISOString();
      remainingSeconds = 3153600000;
    } else {
      const duration = existing.duration_seconds > 0 ? existing.duration_seconds : 86400;
      expiresAt = new Date(now.getTime() + duration * 1000).toISOString();
      remainingSeconds = duration;
    }

    // handle initial unused key activation
    if (existing.status === 'UNUSED') {
      const updateStmt = db.prepare(`
        UPDATE licenses
        SET status = 'ACTIVE',
            activated_at = ?,
            expires_at = ?,
            device_id = ?,
            ip_address = ?
        WHERE id = ? AND status = 'UNUSED'
      `);

      const updateInfo = updateStmt.run(activatedAt, expiresAt, deviceId, clientIp, existing.id);
      if (updateInfo.changes !== 1) {
        const err = new Error('Invalid or unusable activation key.');
        err.statusCode = 400;
        throw err;
      }

      const sessionToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');

      db.prepare(`
        INSERT INTO client_sessions (license_id, token_hash, device_id, expires_at)
        VALUES (?, ?, ?, ?)
      `).run(existing.id, tokenHash, deviceId, expiresAt);

      db.prepare(`
        INSERT INTO audit_logs (event_type, license_id, actor, ip_address, details)
        VALUES ('KEY_ACTIVATED', ?, ?, ?, ?)
      `).run(existing.id, 'client', clientIp, JSON.stringify({ device_id: deviceId, duration_seconds: existing.duration_seconds }));

      return {
        status: 'ACTIVE',
        token: sessionToken,
        expires_at: expiresAt,
        remaining_seconds: remainingSeconds
      };
    }

    const expiryTime = existing.expires_at ? new Date(existing.expires_at).getTime() : 0;
    const currentTime = Date.now();
    const isExpired = !isLifetime && currentTime >= expiryTime;

    if (existing.status === 'REVOKED' || isExpired) {
      const err = new Error('Invalid or unusable activation key.');
      err.statusCode = 400;
      throw err;
    }

    const currentRemaining = isLifetime ? 3153600000 : Math.max(0, Math.floor((expiryTime - currentTime) / 1000));

    // handle reactivation on same device
    if (existing.status === 'ACTIVE' && existing.device_id === deviceId) {
      const sessionToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');

      db.prepare(`
        INSERT INTO client_sessions (license_id, token_hash, device_id, expires_at)
        VALUES (?, ?, ?, ?)
      `).run(existing.id, tokenHash, deviceId, existing.expires_at);

      return {
        status: 'ACTIVE',
        token: sessionToken,
        expires_at: existing.expires_at,
        remaining_seconds: currentRemaining
      };
    }

    // handle activation after admin device reset
    if (existing.status === 'ACTIVE' && existing.device_id === null) {
      db.prepare(`
        UPDATE licenses
        SET device_id = ?, ip_address = ?
        WHERE id = ?
      `).run(deviceId, clientIp, existing.id);

      const sessionToken = crypto.randomBytes(32).toString('hex');
      const tokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');

      db.prepare(`
        INSERT INTO client_sessions (license_id, token_hash, device_id, expires_at)
        VALUES (?, ?, ?, ?)
      `).run(existing.id, tokenHash, deviceId, existing.expires_at);

      db.prepare(`
        INSERT INTO audit_logs (event_type, license_id, actor, ip_address, details)
        VALUES ('DEVICE_REBOUND', ?, ?, ?, ?)
      `).run(existing.id, 'client', clientIp, JSON.stringify({ device_id: deviceId }));

      return {
        status: 'ACTIVE',
        token: sessionToken,
        expires_at: existing.expires_at,
        remaining_seconds: currentRemaining
      };
    }

    // different device or invalid state
    const err = new Error('Invalid or unusable activation key.');
    err.statusCode = 400;
    throw err;
  });
}

function validateSession({ token, device_id }) {
  if (!token || !device_id) {
    return { valid: false, error: 'License session invalid or expired.' };
  }

  const tokenHash = crypto.createHash('sha256').update(String(token).trim()).digest('hex');
  const deviceId = String(device_id).trim().toLowerCase();
  const db = getDb();

  const row = db.prepare(`
    SELECT s.id, s.revoked, s.expires_at, l.id as license_id, l.status, l.device_id, l.duration_seconds
    FROM client_sessions s
    JOIN licenses l ON s.license_id = l.id
    WHERE s.token_hash = ?
  `).get(tokenHash);

  if (!row) {
    return { valid: false, error: 'License session invalid or expired.' };
  }

  const isLifetime = row.duration_seconds === -1;
  const currentTime = Date.now();
  const expiryTime = row.expires_at ? new Date(row.expires_at).getTime() : 0;
  const remainingSeconds = isLifetime ? 3153600000 : Math.max(0, Math.floor((expiryTime - currentTime) / 1000));

  if (row.revoked !== 0 || row.status !== 'ACTIVE' || row.device_id !== deviceId || (!isLifetime && remainingSeconds <= 0)) {
    return { valid: false, error: 'License session invalid or expired.' };
  }

  return {
    valid: true,
    status: 'ACTIVE',
    expires_at: row.expires_at,
    remaining_seconds: remainingSeconds
  };
}

function revokeLicense(licenseId, actor = 'admin', ip = null) {
  const db = getDb();
  return runImmediateTransaction(() => {
    const row = db.prepare('SELECT id, status FROM licenses WHERE id = ?').get(licenseId);
    if (!row) {
      const err = new Error('License not found.');
      err.statusCode = 404;
      throw err;
    }

    const now = new Date().toISOString();
    db.prepare(`
      UPDATE licenses
      SET status = 'REVOKED', revoked_at = ?
      WHERE id = ?
    `).run(now, licenseId);

    db.prepare('UPDATE client_sessions SET revoked = 1 WHERE license_id = ?').run(licenseId);

    db.prepare(`
      INSERT INTO audit_logs (event_type, license_id, actor, ip_address, details)
      VALUES ('KEY_REVOKED', ?, ?, ?, ?)
    `).run(licenseId, actor, ip, JSON.stringify({ previous_status: row.status }));

    return { success: true, license_id: licenseId, status: 'REVOKED' };
  });
}

function resetLicenseDevice(licenseId, actor = 'admin', ip = null) {
  const db = getDb();
  return runImmediateTransaction(() => {
    const row = db.prepare('SELECT id, status, expires_at, device_id FROM licenses WHERE id = ?').get(licenseId);
    if (!row) {
      const err = new Error('License not found.');
      err.statusCode = 404;
      throw err;
    }

    if (row.status !== 'ACTIVE') {
      const err = new Error('Only active licenses can be reset.');
      err.statusCode = 400;
      throw err;
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
      const err = new Error('Expired licenses cannot be reset.');
      err.statusCode = 400;
      throw err;
    }

    db.prepare('UPDATE licenses SET device_id = NULL WHERE id = ?').run(licenseId);
    db.prepare('UPDATE client_sessions SET revoked = 1 WHERE license_id = ?').run(licenseId);

    db.prepare(`
      INSERT INTO audit_logs (event_type, license_id, actor, ip_address, details)
      VALUES ('DEVICE_RESET', ?, ?, ?, ?)
    `).run(licenseId, actor, ip, JSON.stringify({ previous_device: row.device_id }));

    return { success: true, license_id: licenseId };
  });
}

function deleteLicense(licenseId, actor = 'admin', ip = null) {
  const db = getDb();
  return runImmediateTransaction(() => {
    const row = db.prepare('SELECT id, masked_key, status, user_note FROM licenses WHERE id = ?').get(licenseId);
    if (!row) {
      const err = new Error('License not found.');
      err.statusCode = 404;
      throw err;
    }

    db.prepare('DELETE FROM client_sessions WHERE license_id = ?').run(licenseId);
    db.prepare(`
      INSERT INTO audit_logs (event_type, license_id, actor, ip_address, details)
      VALUES ('KEY_DELETED', ?, ?, ?, ?)
    `).run(licenseId, actor, ip, JSON.stringify({ masked_key: row.masked_key, user_note: row.user_note, status: row.status }));
    db.prepare('DELETE FROM licenses WHERE id = ?').run(licenseId);

    return { success: true, license_id: licenseId, deleted: true };
  });
}

function getLicenses({ status = '', search = '', page = 1, limit = 25 }) {
  const db = getDb();
  const validLimit = Math.min(Math.max(1, parseInt(limit, 10) || 25), 100);
  const validPage = Math.max(1, parseInt(page, 10) || 1);
  const offset = (validPage - 1) * validLimit;

  let whereClauses = [];
  let params = [];

  if (status) {
    if (status === 'EXPIRED') {
      whereClauses.push("status = 'ACTIVE' AND datetime(expires_at) <= datetime('now')");
    } else if (status === 'ACTIVE') {
      whereClauses.push("status = 'ACTIVE' AND datetime(expires_at) > datetime('now')");
    } else {
      whereClauses.push("status = ?");
      params.push(status);
    }
  }

  if (search) {
    whereClauses.push("(masked_key LIKE ? OR device_id LIKE ? OR user_note LIKE ?)");
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

  const totalRow = db.prepare(`SELECT COUNT(*) as count FROM licenses ${whereSql}`).get(...params);
  const rows = db.prepare(`
    SELECT id, masked_key, user_note, status, duration_seconds, device_id, ip_address, created_at, activated_at, expires_at, revoked_at,
           CASE
             WHEN status = 'ACTIVE' AND datetime(expires_at) <= datetime('now') THEN 'EXPIRED'
             ELSE status
           END as effective_status
    FROM licenses
    ${whereSql}
    ORDER BY activated_at DESC NULLS LAST, id DESC
    LIMIT ? OFFSET ?
  `).all(...params, validLimit, offset);

  // stats summary
  const allLicenses = db.prepare(`
    SELECT status, expires_at, device_id FROM licenses
  `).all();

  const stats = {
    total: allLicenses.length,
    active: 0,
    unused: 0,
    expired: 0,
    revoked: 0,
    unbound: 0,
    expiring_soon: 0
  };

  const nowTime = Date.now();
  const threeDaysFromNow = nowTime + 3 * 24 * 60 * 60 * 1000;

  for (const item of allLicenses) {
    if (item.status === 'UNUSED') {
      stats.unused++;
    } else if (item.status === 'REVOKED') {
      stats.revoked++;
    } else if (item.status === 'ACTIVE') {
      if (!item.device_id) {
        stats.unbound++;
      }
      if (item.expires_at) {
        const expTime = new Date(item.expires_at).getTime();
        if (expTime <= nowTime) {
          stats.expired++;
        } else {
          stats.active++;
          if (expTime <= threeDaysFromNow) {
            stats.expiring_soon++;
          }
        }
      } else {
        stats.active++;
      }
    }
  }

  return {
    keys: rows,
    total: totalRow.count,
    page: validPage,
    limit: validLimit,
    stats
  };
}

function getAuditLogs(limit = 50) {
  const db = getDb();
  const validLimit = Math.min(Math.max(1, parseInt(limit, 10) || 50), 200);
  return db.prepare(`
    SELECT id, event_type, license_id, actor, ip_address, details, created_at
    FROM audit_logs
    ORDER BY id DESC
    LIMIT ?
  `).all(validLimit);
}

function getUsersSummary() {
  const db = getDb();
  return db.prepare(`
    SELECT 
      COALESCE(NULLIF(TRIM(user_note), ''), 'Unassigned') as username,
      COUNT(*) as total_keys,
      SUM(CASE WHEN status = 'ACTIVE' AND (expires_at IS NULL OR datetime(expires_at) > datetime('now')) THEN 1 ELSE 0 END) as active_keys,
      SUM(CASE WHEN device_id IS NOT NULL AND status = 'ACTIVE' THEN 1 ELSE 0 END) as active_devices,
      MAX(activated_at) as last_activated,
      MAX(created_at) as last_created
    FROM licenses
    GROUP BY username
    ORDER BY active_keys DESC, total_keys DESC
  `).all();
}

function getDevicesList() {
  const db = getDb();
  return db.prepare(`
    SELECT 
      id as license_id,
      device_id,
      COALESCE(NULLIF(TRIM(user_note), ''), 'Unassigned') as username,
      masked_key,
      ip_address,
      activated_at,
      expires_at,
      status,
      CASE
        WHEN status = 'ACTIVE' AND datetime(expires_at) <= datetime('now') THEN 'EXPIRED'
        ELSE status
      END as effective_status
    FROM licenses
    WHERE device_id IS NOT NULL
    ORDER BY activated_at DESC NULLS LAST, id DESC
  `).all();
}

function getSystemInfo() {
  const db = getDb();
  const keyStats = db.prepare(`
    SELECT 
      COUNT(*) as total_keys,
      SUM(CASE WHEN status = 'ACTIVE' AND (expires_at IS NULL OR datetime(expires_at) > datetime('now')) THEN 1 ELSE 0 END) as active_licenses,
      SUM(CASE WHEN status = 'UNUSED' THEN 1 ELSE 0 END) as unused_keys
    FROM licenses
  `).get();
  const auditCount = db.prepare('SELECT COUNT(*) as total_logs FROM audit_logs').get();
  const sessionCount = db.prepare('SELECT COUNT(*) as active_sessions FROM client_sessions WHERE datetime(expires_at) > datetime(\'now\')').get();

  return {
    node_version: process.version,
    platform: process.platform,
    uptime_seconds: Math.floor(process.uptime()),
    sqlite_journal: 'WAL',
    total_keys: keyStats ? (keyStats.total_keys || 0) : 0,
    active_licenses: keyStats ? (keyStats.active_licenses || 0) : 0,
    unused_keys: keyStats ? (keyStats.unused_keys || 0) : 0,
    active_sessions: sessionCount ? (sessionCount.active_sessions || 0) : 0,
    total_audit_logs: auditCount ? (auditCount.total_logs || 0) : 0
  };
}

module.exports = {
  generateKeys,
  activateLicense,
  validateSession,
  revokeLicense,
  resetLicenseDevice,
  deleteLicense,
  getLicenses,
  getAuditLogs,
  getUsersSummary,
  getDevicesList,
  getSystemInfo,
  hashKey,
  generateRandomKeyString
};

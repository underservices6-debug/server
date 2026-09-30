const express = require('express');
const cookieParser = require('cookie-parser');
const path = require('path');
const {
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
  getSystemInfo
} = require('./licenseService');
const {
  adminLogin,
  adminChangePassword,
  adminLogout,
  requireAdminAuth,
  verifyAdminCsrf
} = require('./auth');
const { backupDatabase } = require('./db');

function createRateLimiter({ windowMs, maxRequests, message }) {
  const hits = new Map();

  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    const now = Date.now();
    const clientHits = hits.get(ip) || [];

    // filter hits within current sliding window
    const recentHits = clientHits.filter((timestamp) => now - timestamp < windowMs);

    if (recentHits.length >= maxRequests) {
      return res.status(429).json({ error: message || 'Too many requests. Please wait before retrying.' });
    }

    recentHits.push(now);
    hits.set(ip, recentHits);
    next();
  };
}

function createApp() {
  const app = express();

  app.use(express.json());
  app.use(cookieParser());

  // rate limiters
  const activateLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    maxRequests: 5,
    message: 'Too many activation attempts. Please wait 1 minute.'
  });

  const validateLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    maxRequests: 30,
    message: 'Too many validation requests.'
  });

  const loginLimiter = createRateLimiter({
    windowMs: 15 * 60 * 1000,
    maxRequests: 10,
    message: 'Too many login attempts. Please wait 15 minutes.'
  });

  // public client endpoints
  app.post('/api/v1/license/activate', activateLimiter, (req, res) => {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = activateLicense(req.body, clientIp);
      res.json(result);
    } catch (err) {
      const status = err.statusCode || 400;
      res.status(status).json({ error: err.message || 'Invalid or unusable activation key.' });
    }
  });

  app.post('/api/v1/license/validate', validateLimiter, (req, res) => {
    try {
      const result = validateSession(req.body);
      if (!result.valid) {
        return res.status(401).json(result);
      }
      res.json(result);
    } catch (err) {
      res.status(401).json({ valid: false, error: 'License session invalid or expired.' });
    }
  });

  // public admin login
  app.post('/api/v1/admin/login', loginLimiter, (req, res) => {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = adminLogin(req.body, clientIp);

      const isProduction = process.env.NODE_ENV === 'production';
      res.cookie('admin_session', result.token, {
        httpOnly: true,
        sameSite: 'strict',
        secure: isProduction,
        maxAge: 12 * 60 * 60 * 1000
      });

      res.json({
        success: true,
        username: result.username,
        must_change_password: result.must_change_password
      });
    } catch (err) {
      const status = err.statusCode || 401;
      res.status(status).json({ error: err.message || 'Login failed.' });
    }
  });

  // protected admin routes
  app.get('/api/v1/admin/me', requireAdminAuth, (req, res) => {
    res.json({
      username: req.admin.username,
      must_change_password: req.admin.must_change_password
    });
  });

  app.post('/api/v1/admin/logout', requireAdminAuth, verifyAdminCsrf, (req, res) => {
    adminLogout(req.admin.sessionToken);
    res.clearCookie('admin_session');
    res.json({ success: true });
  });

  app.post('/api/v1/admin/change-password', requireAdminAuth, verifyAdminCsrf, (req, res) => {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = adminChangePassword(req.admin.id, req.body, clientIp);
      res.json(result);
    } catch (err) {
      const status = err.statusCode || 400;
      res.status(status).json({ error: err.message });
    }
  });

  app.get('/api/v1/admin/keys', requireAdminAuth, (req, res) => {
    try {
      const { status, search, page, limit } = req.query;
      const result = getLicenses({ status, search, page, limit });
      res.json(result);
    } catch (err) {
      res.status(500).json({ error: 'Failed to retrieve licenses.' });
    }
  });

  app.post('/api/v1/admin/keys/generate', requireAdminAuth, verifyAdminCsrf, (req, res) => {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const keys = generateKeys(req.body, req.admin.username, clientIp);
      res.json({ keys });
    } catch (err) {
      res.status(400).json({ error: err.message || 'Key generation failed.' });
    }
  });

  app.post('/api/v1/admin/keys/:id/revoke', requireAdminAuth, verifyAdminCsrf, (req, res) => {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = revokeLicense(parseInt(req.params.id, 10), req.admin.username, clientIp);
      res.json(result);
    } catch (err) {
      const status = err.statusCode || 400;
      res.status(status).json({ error: err.message });
    }
  });

  app.delete('/api/v1/admin/keys/:id', requireAdminAuth, verifyAdminCsrf, (req, res) => {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = deleteLicense(parseInt(req.params.id, 10), req.admin.username, clientIp);
      res.json(result);
    } catch (err) {
      const status = err.statusCode || 400;
      res.status(status).json({ error: err.message });
    }
  });

  app.post('/api/v1/admin/keys/:id/delete', requireAdminAuth, verifyAdminCsrf, (req, res) => {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = deleteLicense(parseInt(req.params.id, 10), req.admin.username, clientIp);
      res.json(result);
    } catch (err) {
      const status = err.statusCode || 400;
      res.status(status).json({ error: err.message });
    }
  });

  app.post('/api/v1/admin/keys/:id/reset-device', requireAdminAuth, verifyAdminCsrf, (req, res) => {
    try {
      const clientIp = req.ip || req.connection.remoteAddress;
      const result = resetLicenseDevice(parseInt(req.params.id, 10), req.admin.username, clientIp);
      res.json(result);
    } catch (err) {
      const status = err.statusCode || 400;
      res.status(status).json({ error: err.message });
    }
  });

  app.get('/api/v1/admin/audit-logs', requireAdminAuth, (req, res) => {
    try {
      const logs = getAuditLogs(req.query.limit);
      res.json({ logs });
    } catch (err) {
      res.status(500).json({ error: 'Failed to retrieve audit logs.' });
    }
  });

  app.get('/api/v1/admin/users-summary', requireAdminAuth, (req, res) => {
    try {
      const users = getUsersSummary();
      res.json({ users });
    } catch (err) {
      res.status(500).json({ error: 'Failed to retrieve users summary.' });
    }
  });

  app.get('/api/v1/admin/devices', requireAdminAuth, (req, res) => {
    try {
      const devices = getDevicesList();
      res.json({ devices });
    } catch (err) {
      res.status(500).json({ error: 'Failed to retrieve devices list.' });
    }
  });

  app.get('/api/v1/admin/system-info', requireAdminAuth, (req, res) => {
    try {
      const info = getSystemInfo();
      res.json(info);
    } catch (err) {
      res.status(500).json({ error: 'Failed to retrieve system info.' });
    }
  });

  app.get('/api/v1/admin/export.csv', requireAdminAuth, (req, res) => {
    try {
      const result = getLicenses({ limit: 5000 });
      const rows = [
        ['ID', 'User', 'Key', 'HWID', 'Status', 'ActivatedAt', 'ExpiresAt']
      ];
      result.keys.forEach((k) => {
        rows.push([
          k.id,
          `"${(k.user_note || '').replace(/"/g, '""')}"`,
          `"${(k.masked_key || '').replace(/"/g, '""')}"`,
          `"${(k.device_id || 'unbound').replace(/"/g, '""')}"`,
          k.effective_status,
          k.activated_at || '',
          k.expires_at || ''
        ]);
      });
      const csv = rows.map((r) => r.join(',')).join('\r\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="keyvault_licenses_${Date.now()}.csv"`);
      res.send(csv);
    } catch (err) {
      res.status(500).json({ error: 'Failed to export CSV.' });
    }
  });

  app.post('/api/v1/admin/backup', requireAdminAuth, verifyAdminCsrf, (req, res) => {
    try {
      const filename = `backup_${Date.now()}.db`;
      const backupPath = path.join(__dirname, '..', 'data', 'backups', filename);
      const savedPath = backupDatabase(backupPath);
      res.json({ success: true, path: savedPath, filename });
    } catch (err) {
      res.status(500).json({ error: 'Backup failed: ' + err.message });
    }
  });

  // serve admin static files
  const publicDir = path.join(__dirname, '..', 'public');
  app.use(express.static(publicDir));

  // fallback to index.html for dashboard routes
  app.get(['/', '/admin', '/dashboard'], (req, res) => {
    res.sendFile(path.join(publicDir, 'index.html'));
  });

  app.get('/login', (req, res) => {
    res.sendFile(path.join(publicDir, 'login.html'));
  });

  return app;
}

module.exports = { createApp };

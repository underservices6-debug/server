const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { getDb } = require('./db');

function adminLogin({ username, password }, clientIp = null) {
  if (!username || !password) {
    const err = new Error('Username and password are required.');
    err.statusCode = 400;
    throw err;
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM admin_users WHERE username = ?').get(String(username).trim());

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    db.prepare(`
      INSERT INTO audit_logs (event_type, actor, ip_address, details)
      VALUES ('ADMIN_LOGIN_FAILED', ?, ?, ?)
    `).run(String(username || 'unknown'), clientIp, JSON.stringify({ reason: 'invalid_credentials' }));

    const err = new Error('Invalid username or password.');
    err.statusCode = 401;
    throw err;
  }

  const sessionToken = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(sessionToken).digest('hex');
  const expiresAt = new Date(Date.now() + 12 * 60 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO admin_sessions (user_id, token_hash, ip_address, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(user.id, tokenHash, clientIp, expiresAt);

  db.prepare(`
    INSERT INTO audit_logs (event_type, actor, ip_address, details)
    VALUES ('ADMIN_LOGIN_SUCCESS', ?, ?, ?)
  `).run(user.username, clientIp, JSON.stringify({ user_id: user.id }));

  return {
    token: sessionToken,
    must_change_password: Boolean(user.must_change_password),
    username: user.username
  };
}

function adminChangePassword(userId, { current_password, new_password }, clientIp = null) {
  if (!current_password || !new_password) {
    const err = new Error('Current and new passwords are required.');
    err.statusCode = 400;
    throw err;
  }

  if (String(new_password).length < 8) {
    const err = new Error('New password must be at least 8 characters.');
    err.statusCode = 400;
    throw err;
  }

  const db = getDb();
  const user = db.prepare('SELECT * FROM admin_users WHERE id = ?').get(userId);
  if (!user || !bcrypt.compareSync(current_password, user.password_hash)) {
    const err = new Error('Current password does not match.');
    err.statusCode = 401;
    throw err;
  }

  const newHash = bcrypt.hashSync(new_password, 12);
  db.prepare(`
    UPDATE admin_users
    SET password_hash = ?, must_change_password = 0
    WHERE id = ?
  `).run(newHash, userId);

  db.prepare(`
    INSERT INTO audit_logs (event_type, actor, ip_address, details)
    VALUES ('ADMIN_PASSWORD_CHANGED', ?, ?, ?)
  `).run(user.username, clientIp, JSON.stringify({ user_id: user.id }));

  return { success: true };
}

function adminLogout(token) {
  if (!token) return;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  getDb().prepare('DELETE FROM admin_sessions WHERE token_hash = ?').run(tokenHash);
}

function requireAdminAuth(req, res, next) {
  const token = req.cookies?.admin_session || (req.headers.authorization?.startsWith('Bearer ') ? req.headers.authorization.slice(7) : null);

  if (!token) {
    return res.status(401).json({ error: 'Authentication required.' });
  }

  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const db = getDb();

  const session = db.prepare(`
    SELECT s.id, s.user_id, s.expires_at, u.username, u.must_change_password
    FROM admin_sessions s
    JOIN admin_users u ON s.user_id = u.id
    WHERE s.token_hash = ?
  `).get(tokenHash);

  if (!session || new Date(session.expires_at).getTime() <= Date.now()) {
    return res.status(401).json({ error: 'Session expired or invalid.' });
  }

  req.admin = {
    id: session.user_id,
    username: session.username,
    must_change_password: Boolean(session.must_change_password),
    sessionToken: token
  };

  // enforce password change if flagged, except on password change endpoint
  if (req.admin.must_change_password && req.path !== '/api/v1/admin/change-password' && req.path !== '/api/v1/admin/logout') {
    return res.status(403).json({
      error: 'Password change required before accessing administration.',
      must_change_password: true
    });
  }

  next();
}

function verifyAdminCsrf(req, res, next) {
  // verify origin and custom header for state-changing requests
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const xRequestedWith = req.headers['x-requested-with'];
    if (xRequestedWith !== 'XMLHttpRequest') {
      return res.status(403).json({ error: 'Missing security header.' });
    }

    const origin = req.headers.origin || req.headers.referer;
    if (origin) {
      const allowedOrigin = process.env.ALLOWED_ORIGIN;
      const port = process.env.PORT || 3000;
      const localhostOrigins = [`http://localhost:${port}`, `http://127.0.0.1:${port}`];

      let isAllowed = false;
      if (allowedOrigin && origin.startsWith(allowedOrigin)) {
        isAllowed = true;
      }
      for (const lh of localhostOrigins) {
        if (origin.startsWith(lh)) {
          isAllowed = true;
          break;
        }
      }

      if (!isAllowed) {
        return res.status(403).json({ error: 'Cross-origin request blocked.' });
      }
    }
  }

  next();
}

module.exports = {
  adminLogin,
  adminChangePassword,
  adminLogout,
  requireAdminAuth,
  verifyAdminCsrf
};

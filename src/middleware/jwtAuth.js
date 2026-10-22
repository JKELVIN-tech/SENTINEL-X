'use strict';

/**
 * Sentinel X — JWT Authentication
 * ─────────────────────────────────────────────────────────────────────────────
 * Two-token system:
 *   Access token  — short-lived (15min), stateless JWT, sent in Authorization header
 *   Refresh token — long-lived (7 days), hashed + stored in DB, sent in httpOnly cookie
 *
 * Middleware:
 *   requireAuth         — validates access token, attaches req.user
 *   requireRole(roles)  — checks user role after requireAuth
 *   optionalAuth        — attaches req.user if token present, never rejects
 * ─────────────────────────────────────────────────────────────────────────────
 */

const jwt      = require('jsonwebtoken');
const bcrypt   = require('bcryptjs');
const crypto   = require('crypto');
const { AuthTokens, Users, AuditLog } = require('../db/repository');
const logger   = require('../utils/logger');

const JWT_SECRET         = process.env.JWT_SECRET          || 'sentinel-x-dev-secret';
const ACCESS_TOKEN_TTL   = process.env.ACCESS_TOKEN_TTL    || '15m';
const REFRESH_TOKEN_TTL  = parseInt(process.env.REFRESH_TOKEN_TTL_DAYS || 7);
const BCRYPT_ROUNDS      = parseInt(process.env.BCRYPT_ROUNDS || 12);

if (!process.env.JWT_SECRET) {
  const msg = 'JWT_SECRET is not set — using an insecure built-in default. ' +
    'Set JWT_SECRET in .env before exposing this server beyond localhost.';
  if (process.env.NODE_ENV === 'production') {
    logger.error(msg);
  } else {
    logger.warn(msg);
  }
}

// ──────────────────────────────────────────────
//  Token generation
// ──────────────────────────────────────────────

function signAccessToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { expiresIn: ACCESS_TOKEN_TTL, issuer: 'sentinelx' }
  );
}

function generateRefreshToken() {
  return crypto.randomBytes(48).toString('hex');
}

async function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// ──────────────────────────────────────────────
//  Auth service (used by routes)
// ──────────────────────────────────────────────
const AuthService = {
  /**
   * Register a new user
   */
  async register({ username, email, password, role = 'analyst' }) {
    if (!username || !password) throw new Error('username and password required');
    if (password.length < 8)    throw new Error('password must be at least 8 characters');

    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const user = await Users.create({ username, email, passwordHash, role });
    return user;
  },

  /**
   * Login — returns { accessToken, refreshToken, user }
   */
  async login({ username, password, userAgent, ipAddress }) {
    const user = await Users.findByUsername(username);
    if (!user || !user.is_active) throw Object.assign(new Error('Invalid credentials'), { status: 401 });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) throw Object.assign(new Error('Invalid credentials'), { status: 401 });

    const accessToken  = signAccessToken(user);
    const refreshToken = generateRefreshToken();
    const tokenHash    = await hashToken(refreshToken);

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_TTL);

    await AuthTokens.create({ userId: user.id, tokenHash, expiresAt, userAgent, ipAddress });
    await Users.updateLastLogin(user.id);

    await AuditLog.write({
      userId: user.id, action: 'login',
      resource: 'auth', ipAddress, userAgent,
    });

    logger.info(`User logged in: ${username} from ${ipAddress}`);
    return {
      accessToken,
      refreshToken,
      expiresIn: ACCESS_TOKEN_TTL,
      user: { id: user.id, username: user.username, role: user.role },
    };
  },

  /**
   * Refresh access token using a refresh token
   */
  async refresh({ refreshToken, userAgent, ipAddress }) {
    const tokenHash = await hashToken(refreshToken);
    const stored    = await AuthTokens.findByHash(tokenHash);

    if (!stored || !stored.is_active) {
      throw Object.assign(new Error('Invalid or expired refresh token'), { status: 401 });
    }

    const user        = await Users.findById(stored.user_id);
    const accessToken = signAccessToken(user);

    // Rotate refresh token
    const newRefreshToken = generateRefreshToken();
    const newHash         = await hashToken(newRefreshToken);
    const expiresAt       = new Date();
    expiresAt.setDate(expiresAt.getDate() + REFRESH_TOKEN_TTL);

    await AuthTokens.revoke(tokenHash);
    await AuthTokens.create({ userId: user.id, tokenHash: newHash, expiresAt, userAgent, ipAddress });

    return { accessToken, refreshToken: newRefreshToken, expiresIn: ACCESS_TOKEN_TTL };
  },

  /**
   * Logout — revoke the refresh token
   */
  async logout({ refreshToken }) {
    if (!refreshToken) return;
    const tokenHash = await hashToken(refreshToken);
    await AuthTokens.revoke(tokenHash);
  },

  /**
   * Change password
   */
  async changePassword({ userId, currentPassword, newPassword }) {
    if (newPassword.length < 8) throw new Error('New password must be at least 8 characters');
    const user = await Users.findById(userId);
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) throw Object.assign(new Error('Current password incorrect'), { status: 400 });

    const hash = await bcrypt.hash(newPassword, BCRYPT_ROUNDS);
    await Users.updatePassword(userId, hash);
    await AuthTokens.revokeAllForUser(userId); // invalidate all sessions
    await AuditLog.write({ userId, action: 'password_change', resource: 'auth' });
  },
};

// ──────────────────────────────────────────────
//  Express middleware
// ──────────────────────────────────────────────

/**
 * requireAuth — validates JWT access token.
 * Checks: Authorization: Bearer <token>  or  ?accessToken=<token> (dev only)
 */
async function requireAuth(req, res, next) {
  try {
    const header = req.headers['authorization'] || '';
    const devQuery = process.env.NODE_ENV !== 'production' ? req.query.accessToken : null;
    const raw = header.replace(/^Bearer\s+/i, '') || devQuery || '';

    if (!raw) return res.status(401).json({ error: 'Authentication required' });

    const payload = jwt.verify(raw, JWT_SECRET, { issuer: 'sentinelx' });

    // Attach user to request
    req.user = {
      id:       payload.sub,
      username: payload.username,
      role:     payload.role,
    };

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Access token expired', code: 'TOKEN_EXPIRED' });
    }
    return res.status(401).json({ error: 'Invalid token' });
  }
}

/**
 * requireRole(...roles) — role-based access control.
 * Must be used after requireAuth.
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied — required role: ${roles.join(' | ')}`,
      });
    }
    next();
  };
}

/**
 * optionalAuth — attaches req.user if valid token present, never rejects.
 */
async function optionalAuth(req, _res, next) {
  try {
    const header = req.headers['authorization'] || '';
    const raw    = header.replace(/^Bearer\s+/i, '');
    if (raw) {
      const payload = jwt.verify(raw, JWT_SECRET, { issuer: 'sentinelx' });
      req.user = { id: payload.sub, username: payload.username, role: payload.role };
    }
  } catch (_) {}
  next();
}

/**
 * auditMiddleware — logs every mutating API call to audit_log.
 */
function auditMiddleware(req, _res, next) {
  if (['POST','PUT','PATCH','DELETE'].includes(req.method) && req.user) {
    AuditLog.write({
      userId:     req.user.id,
      action:     `${req.method} ${req.path}`,
      resource:   req.path.split('/')[3] || req.path,
      ipAddress:  req.ip,
      userAgent:  req.headers['user-agent'],
      detail:     { body: sanitiseBody(req.body) },
    }).catch(() => {}); // fire-and-forget
  }
  next();
}

function sanitiseBody(body) {
  if (!body || typeof body !== 'object') return body;
  const safe = { ...body };
  for (const k of ['password','token','secret','key','hash']) delete safe[k];
  return safe;
}

module.exports = {
  AuthService,
  requireAuth,
  requireRole,
  optionalAuth,
  auditMiddleware,
  signAccessToken,
  hashToken,
};

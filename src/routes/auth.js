'use strict';

/**
 * Sentinel X — Auth Routes
 * POST   /api/auth/register     Create a new user (admin only)
 * POST   /api/auth/login        Login → access + refresh tokens
 * POST   /api/auth/refresh      Rotate refresh token → new access token
 * POST   /api/auth/logout       Revoke refresh token
 * GET    /api/auth/me           Current user profile
 * PATCH  /api/auth/password     Change password
 * GET    /api/auth/users        List users (admin only)
 * PATCH  /api/auth/users/:id    Update user active status (admin only)
 */

const express = require('express');
const router  = express.Router();
const { AuthService, requireAuth, requireRole } = require('../middleware/jwtAuth');
const { Users } = require('../db/repository');
const logger  = require('../utils/logger');

const REFRESH_COOKIE = 'sx_refresh';
const COOKIE_OPTS = {
  httpOnly: true,
  secure:   process.env.NODE_ENV === 'production',
  sameSite: 'strict',
  maxAge:   7 * 24 * 60 * 60 * 1000, // 7 days
  path:     '/api/auth',
};

// ── POST /api/auth/register  (admin only after first user exists)
router.post('/register', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { username, email, password, role } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const user = await AuthService.register({ username, email, password, role });
    logger.info(`New user registered: ${username} by ${req.user.username}`);
    return res.status(201).json({ message: 'User created', user });
  } catch (err) {
    if (err.message.includes('unique') || err.message.includes('duplicate')) {
      return res.status(409).json({ error: 'Username or email already exists' });
    }
    next(err);
  }
});

// ── POST /api/auth/login
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username and password required' });

    const result = await AuthService.login({
      username, password,
      userAgent:  req.headers['user-agent'],
      ipAddress:  req.ip,
    });

    // Refresh token in httpOnly cookie
    res.cookie(REFRESH_COOKIE, result.refreshToken, COOKIE_OPTS);

    return res.json({
      accessToken: result.accessToken,
      expiresIn:   result.expiresIn,
      user:        result.user,
    });
  } catch (err) {
    if (err.status === 401) return res.status(401).json({ error: err.message });
    next(err);
  }
});

// ── POST /api/auth/refresh
router.post('/refresh', async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.[REFRESH_COOKIE] || req.body?.refreshToken;
    if (!refreshToken) return res.status(401).json({ error: 'No refresh token provided' });

    const result = await AuthService.refresh({
      refreshToken,
      userAgent: req.headers['user-agent'],
      ipAddress: req.ip,
    });

    res.cookie(REFRESH_COOKIE, result.refreshToken, COOKIE_OPTS);
    return res.json({ accessToken: result.accessToken, expiresIn: result.expiresIn });
  } catch (err) {
    if (err.status === 401) return res.status(401).json({ error: err.message });
    next(err);
  }
});

// ── POST /api/auth/logout
router.post('/logout', async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.[REFRESH_COOKIE] || req.body?.refreshToken;
    await AuthService.logout({ refreshToken });
    res.clearCookie(REFRESH_COOKIE, { path: '/api/auth' });
    return res.json({ message: 'Logged out successfully' });
  } catch (err) { next(err); }
});

// ── GET /api/auth/me
router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const user = await Users.findById(req.user.id);
    if (!user) return res.status(404).json({ error: 'User not found' });
    const { password_hash: _, ...safe } = user;
    return res.json(safe);
  } catch (err) { next(err); }
});

// ── PATCH /api/auth/password
router.patch('/password', requireAuth, async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'currentPassword and newPassword required' });
    }
    await AuthService.changePassword({
      userId: req.user.id, currentPassword, newPassword,
    });
    return res.json({ message: 'Password changed. Please log in again.' });
  } catch (err) {
    if (err.status === 400) return res.status(400).json({ error: err.message });
    next(err);
  }
});

// ── GET /api/auth/users  (admin)
router.get('/users', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { limit = 50, offset = 0 } = req.query;
    const users = await Users.list({ limit: parseInt(limit), offset: parseInt(offset) });
    return res.json({ count: users.length, users });
  } catch (err) { next(err); }
});

// ── PATCH /api/auth/users/:id  (admin)
router.patch('/users/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    const { isActive } = req.body;
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'Cannot modify your own account status' });
    }
    await Users.setActive(req.params.id, isActive);
    return res.json({ message: `User ${isActive ? 'activated' : 'deactivated'}` });
  } catch (err) { next(err); }
});

module.exports = router;

'use strict';

const logger = require('../utils/logger');

/**
 * Simple API-key gate.
 * Clients must send one of:
 *   - Header:  X-API-Key: <key>
 *   - Header:  Authorization: Bearer <key>
 *   - Query:   ?apiKey=<key>   (only in development)
 */
function apiKeyAuth(req, res, next) {
  const validKey = process.env.API_KEY;

  // No key configured → warn once and allow through (dev convenience)
  if (!validKey || validKey === 'sentinelx-change-this-key-in-production') {
    if (process.env.NODE_ENV !== 'production') return next();
    return res.status(500).json({ error: 'API key not configured on server' });
  }

  const fromHeader =
    req.headers['x-api-key'] ||
    (req.headers['authorization'] || '').replace(/^Bearer\s+/i, '');
  const fromQuery =
    process.env.NODE_ENV !== 'production' ? req.query.apiKey : null;

  const provided = fromHeader || fromQuery || '';

  if (provided !== validKey) {
    logger.warn(`Auth failure — ${req.method} ${req.path} — IP: ${req.ip}`);
    return res.status(401).json({ error: 'Invalid or missing API key' });
  }

  next();
}

module.exports = { apiKeyAuth };

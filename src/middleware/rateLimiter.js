'use strict';

const rateLimit = require('express-rate-limit');
const logger    = require('../utils/logger');

const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60_000,  // 1 min
  max:      parseInt(process.env.RATE_LIMIT_MAX)       || 100,
  standardHeaders: true,
  legacyHeaders:   false,
  handler: (req, res) => {
    logger.warn(`Rate limit hit — IP: ${req.ip}  path: ${req.path}`);
    res.status(429).json({
      error: 'Too many requests — slow down',
      retryAfter: Math.ceil(limiter.windowMs / 1000),
    });
  },
});

module.exports = limiter;

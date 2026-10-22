'use strict';

/**
 * Sentinel X — Central Error Handler
 * ─────────────────────────────────────────────────────────────────────────────
 * Must be mounted last (`app.use(errorHandler)`), after every route.
 * Normalises thrown/`next(err)`-passed errors into a consistent JSON shape
 * and makes sure nothing ever crashes the process from inside a request.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const logger = require('../utils/logger');

// Map well-known error shapes to HTTP status codes
function resolveStatus(err) {
  if (err.status || err.statusCode) return err.status || err.statusCode;
  if (err.name === 'ValidationError') return 400;
  if (err.name === 'UnauthorizedError' || err.name === 'JsonWebTokenError') return 401;
  if (err.name === 'TokenExpiredError') return 401;
  if (err.code === 'ENOENT') return 404;
  if (err.code === '23505') return 409; // Postgres unique_violation
  if (err.code === '23503') return 409; // Postgres foreign_key_violation
  return 500;
}

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, _next) {
  const status = resolveStatus(err);
  const isServerError = status >= 500;

  if (isServerError) {
    logger.error(`${req.method} ${req.path} → ${status}: ${err.message}`, { stack: err.stack });
  } else {
    logger.warn(`${req.method} ${req.path} → ${status}: ${err.message}`);
  }

  if (res.headersSent) return; // delegate to Express's default handler

  const body = {
    error: isServerError
      ? 'Internal server error'
      : (err.publicMessage || err.message || 'Request failed'),
  };

  // Only leak internals in non-production environments
  if (process.env.NODE_ENV !== 'production') {
    body.detail = err.message;
    if (isServerError) body.stack = err.stack;
  }

  res.status(status).json(body);
}

module.exports = errorHandler;

'use strict';

/**
 * Sentinel X — Database Connection Pool
 * ─────────────────────────────────────────────────────────────────────────────
 * Wraps pg.Pool with:
 *   • Lazy connection (pool created on first use, not at import time)
 *   • Health check + automatic reconnect
 *   • Query helper with structured error logging
 *   • Transaction helper
 *   • Graceful shutdown
 * ─────────────────────────────────────────────────────────────────────────────
 */

const { Pool } = require('pg');
const logger   = require('../utils/logger');

let pool = null;

// ── Build connection config from env
function getConfig() {
  // Support both DATABASE_URL (Heroku-style) and individual vars
  if (process.env.DATABASE_URL) {
    return {
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
      max:             parseInt(process.env.DB_POOL_MAX)     || 10,
      idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT) || 30_000,
      connectionTimeoutMillis: parseInt(process.env.DB_CONN_TIMEOUT) || 5_000,
    };
  }

  return {
    host:     process.env.DB_HOST     || '127.0.0.1',
    port:     parseInt(process.env.DB_PORT) || 5432,
    database: process.env.DB_NAME     || 'sentinelx',
    user:     process.env.DB_USER     || 'sentinelx',
    password: process.env.DB_PASSWORD || 'sentinelx',
    ssl:      process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false,
    max:             parseInt(process.env.DB_POOL_MAX)     || 10,
    idleTimeoutMillis: parseInt(process.env.DB_IDLE_TIMEOUT) || 30_000,
    connectionTimeoutMillis: parseInt(process.env.DB_CONN_TIMEOUT) || 5_000,
    application_name: 'sentinelx',
  };
}

// ── Initialise pool (idempotent)
function getPool() {
  if (pool) return pool;

  const config = getConfig();
  pool = new Pool(config);

  pool.on('connect', client => {
    logger.info(`DB: new client connected (total: ${pool.totalCount})`);
    // Set default timezone for all connections
    client.query("SET timezone = 'UTC'").catch(() => {});
  });

  pool.on('error', (err) => {
    logger.error(`DB pool error: ${err.message}`);
  });

  pool.on('remove', () => {
    logger.info(`DB: client removed (idle: ${pool.idleCount})`);
  });

  return pool;
}

// ──────────────────────────────────────────────
//  Query helper
//  query(sql, params?) → { rows, rowCount, fields }
// ──────────────────────────────────────────────
async function query(sql, params = []) {
  const p     = getPool();
  const start = Date.now();
  try {
    const result = await p.query(sql, params);
    const ms     = Date.now() - start;
    if (ms > 500) logger.warn(`Slow query (${ms}ms): ${sql.slice(0, 80)}`);
    return result;
  } catch (err) {
    logger.error(`DB query error: ${err.message} | SQL: ${sql.slice(0, 120)}`);
    throw err;
  }
}

// ──────────────────────────────────────────────
//  Transaction helper
//  transaction(async (client) => { ... })
// ──────────────────────────────────────────────
async function transaction(fn) {
  const p      = getPool();
  const client = await p.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK');
    logger.error(`DB transaction rolled back: ${err.message}`);
    throw err;
  } finally {
    client.release();
  }
}

// ──────────────────────────────────────────────
//  Health check
// ──────────────────────────────────────────────
async function ping() {
  try {
    const { rows } = await query('SELECT NOW() AS now, current_database() AS db, version() AS version');
    return {
      ok:      true,
      db:      rows[0].db,
      time:    rows[0].now,
      version: rows[0].version.split(' ').slice(0, 2).join(' '),
      pool: {
        total:   pool?.totalCount  || 0,
        idle:    pool?.idleCount   || 0,
        waiting: pool?.waitingCount|| 0,
      },
    };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

// ──────────────────────────────────────────────
//  Graceful shutdown
// ──────────────────────────────────────────────
async function close() {
  if (pool) {
    await pool.end();
    pool = null;
    logger.info('DB pool closed');
  }
}

// ── Convenience wrappers
const db = {
  query,
  transaction,
  ping,
  close,
  getPool,
  // Quick helpers
  /** Returns first row or null */
  async one(sql, params = []) {
    const { rows } = await query(sql, params);
    return rows[0] || null;
  },
  /** Returns all rows */
  async all(sql, params = []) {
    const { rows } = await query(sql, params);
    return rows;
  },
  /** Inserts a row and returns it (requires RETURNING *) */
  async insert(sql, params = []) {
    const { rows } = await query(sql, params);
    return rows[0] || null;
  },
  /** Returns count as integer */
  async count(sql, params = []) {
    const { rows } = await query(sql, params);
    return parseInt(rows[0]?.count || rows[0]?.['count(*)'] || 0);
  },
};

module.exports = db;

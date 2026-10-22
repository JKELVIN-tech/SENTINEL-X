'use strict';

const winston = require('winston');
const path    = require('path');
const fs      = require('fs');

const LOG_DIR = process.env.LOG_DIR || './logs';
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

const { combine, timestamp, printf, colorize, errors } = winston.format;

const consoleFmt = printf(({ level, message, timestamp, stack }) => {
  const base = `${timestamp}  [${level.toUpperCase().padEnd(5)}]  ${message}`;
  return stack ? `${base}\n${stack}` : base;
});

const fileFmt = printf(({ level, message, timestamp, stack, ...meta }) => {
  const base = `${timestamp} [${level.toUpperCase()}] ${message}`;
  const extra = Object.keys(meta).length ? ' ' + JSON.stringify(meta) : '';
  return stack ? `${base}\n${stack}${extra}` : `${base}${extra}`;
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: combine(timestamp({ format: 'HH:mm:ss' }), errors({ stack: true })),
  transports: [
    new winston.transports.Console({
      format: combine(colorize(), consoleFmt),
    }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, 'sentinel.log'),
      format: fileFmt,
      maxsize: 10 * 1024 * 1024,   // 10 MB
      maxFiles: 5,
      tailable: true,
    }),
    new winston.transports.File({
      filename: path.join(LOG_DIR, 'error.log'),
      level: 'error',
      format: fileFmt,
      maxsize: 5 * 1024 * 1024,
      maxFiles: 3,
    }),
  ],
});

module.exports = logger;

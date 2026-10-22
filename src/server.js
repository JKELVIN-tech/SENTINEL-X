'use strict';

require('dotenv').config();
const express      = require('express');
const cors         = require('cors');
const helmet       = require('helmet');
const http         = require('http');
const cookieParser = require('cookie-parser');
const { WebSocketServer } = require('ws');
const path         = require('path');

const logger       = require('./utils/logger');
const { apiKeyAuth } = require('./middleware/auth');
const rateLimiter  = require('./middleware/rateLimiter');
const errorHandler = require('./middleware/errorHandler');

// Routes
const nmapRoutes      = require('./routes/nmap');
const scanRoutes      = require('./routes/scans');
const systemRoutes    = require('./routes/system');
const hashRoutes      = require('./routes/hash');
const wordlistRoutes  = require('./routes/wordlists');
const aiRoutes        = require('./routes/ai');
const authRoutes      = require('./routes/auth');
const engagementRoutes= require('./routes/engagements');
const reconRoutes     = require('./routes/recon');

// WebSocket broadcast registry (scan jobs push updates here)
const wsClients = new Set();
global.wsClients = wsClients;

// ──────────────────────────────────────────────
//  App bootstrap
// ──────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '127.0.0.1';

// ── Security middleware
app.use(helmet({
  contentSecurityPolicy: false,  // disabled so dashboard HTML loads cleanly
}));
// NOTE: the `cors` package matches array entries literally, so
// 'http://localhost:*' never actually matches a real origin like
// 'http://localhost:5173' — use a matcher function instead so every
// localhost/127.0.0.1 port is allowed, plus whatever is listed in
// CORS_EXTRA_ORIGINS (comma-separated) for LAN/remote dashboards.
const extraOrigins = (process.env.CORS_EXTRA_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);
const LOCAL_ORIGIN_RE = /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;

app.use(cors({
  origin(origin, callback) {
    // No Origin header (curl, server-to-server, same-origin) → allow
    if (!origin) return callback(null, true);
    if (LOCAL_ORIGIN_RE.test(origin) || extraOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error(`CORS: origin not allowed — ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
}));

// ── Body parsing
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// ── Static dashboard (optional — serves the HTML frontend)
app.use(express.static(path.join(__dirname, '../public')));

// ── Global rate limiter
app.use('/api', rateLimiter);

// ── API key auth on all /api routes
app.use('/api', apiKeyAuth);

// ── Mount routes
app.use('/api/nmap',        nmapRoutes);
app.use('/api/scans',      scanRoutes);
app.use('/api/system',     systemRoutes);
app.use('/api/hash',       hashRoutes);
app.use('/api/wordlists',  wordlistRoutes);
app.use('/api/ai',         aiRoutes);
app.use('/api/auth',       authRoutes);
app.use('/api/engagements',engagementRoutes);
app.use('/api/recon',      reconRoutes);

// ── Health check (no auth required)
app.get('/health', (_req, res) => {
  res.json({
    status: 'online',
    platform: 'Sentinel X',
    version: '2.0.0',
    uptime: Math.floor(process.uptime()),
    timestamp: new Date().toISOString(),
  });
});

// ── 404 fallback
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found', path: req.path });
});

// ── Error handler (must be last)
app.use(errorHandler);

// ──────────────────────────────────────────────
//  HTTP + WebSocket server
// ──────────────────────────────────────────────
const server = http.createServer(app);

const wss = new WebSocketServer({ server, path: '/ws' });
wss.on('connection', (ws, req) => {
  wsClients.add(ws);
  logger.info(`WebSocket client connected — ${req.socket.remoteAddress}`);

  ws.send(JSON.stringify({
    type: 'connected',
    message: 'Sentinel X WebSocket ready',
    timestamp: new Date().toISOString(),
  }));

  ws.on('close', () => {
    wsClients.delete(ws);
    logger.info('WebSocket client disconnected');
  });

  ws.on('error', (err) => {
    logger.error(`WebSocket error: ${err.message}`);
    wsClients.delete(ws);
  });
});

// Broadcast helper attached to app so routes can use it
app.broadcast = (data) => {
  const payload = JSON.stringify(data);
  for (const client of wsClients) {
    if (client.readyState === 1 /* OPEN */) {
      client.send(payload);
    }
  }
};
global.broadcast = app.broadcast;

// ── Boot persistence bridge (gracefully degrades if DB is offline)
const bridge = require('./db/bridge');
bridge.init();

server.listen(PORT, HOST, () => {
  logger.info(`╔══════════════════════════════════════════╗`);
  logger.info(`║         SENTINEL X v2.0 — ARMED          ║`);
  logger.info(`╠══════════════════════════════════════════╣`);
  logger.info(`║  HTTP  →  http://${HOST}:${PORT}         ║`);
  logger.info(`║  WS    →  ws://${HOST}:${PORT}/ws        ║`);
  logger.info(`║  Env   →  ${process.env.NODE_ENV}                    ║`);
  logger.info(`╚══════════════════════════════════════════╝`);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  logger.warn('SIGTERM received — shutting down gracefully');
  server.close(() => process.exit(0));
});
process.on('SIGINT', () => {
  logger.warn('SIGINT received — shutting down gracefully');
  server.close(() => process.exit(0));
});

module.exports = { app, server };

'use strict';

/**
 * Sentinel X — Built-in TCP Connect Port Scanner
 * ─────────────────────────────────────────────────────────────────────────────
 * A pure Node.js fallback that needs no external binary, no admin/root
 * privileges, and works identically on Windows, macOS and Linux. It only
 * does a TCP connect scan (no SYN/stealth scans — those genuinely need raw
 * sockets and a tool like nmap), but that's enough for a quick reachability
 * and open-port check, and it's what keeps Sentinel X fully usable on a
 * fresh Windows box before/without installing Nmap.
 *
 * Concurrency-limited, with an optional banner grab (reads whatever the
 * service sends first, e.g. an SSH or SMTP banner).
 * ─────────────────────────────────────────────────────────────────────────────
 */

const net = require('net');
const dns = require('dns').promises;
const { v4: uuid } = require('uuid');
const logger = require('../utils/logger');

const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 587, 631,
  993, 995, 1723, 3000, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 27017,
];

const WELL_KNOWN_SERVICES = {
  21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns', 80: 'http',
  110: 'pop3', 111: 'rpcbind', 135: 'msrpc', 139: 'netbios-ssn', 143: 'imap',
  443: 'https', 445: 'microsoft-ds', 587: 'smtp-submission', 631: 'ipp',
  993: 'imaps', 995: 'pop3s', 1723: 'pptp', 3000: 'dev-http', 3306: 'mysql',
  3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8000: 'http-alt',
  8080: 'http-proxy', 8443: 'https-alt', 9000: 'http-alt', 27017: 'mongodb',
};

const MAX_PORTS_PER_SCAN = 10_000;
const DEFAULT_CONCURRENCY = 200;
const DEFAULT_TIMEOUT_MS = 1500;

function broadcast(data) {
  if (typeof global.broadcast === 'function') global.broadcast(data);
}

// ── In-memory job store (mirrors nmapEngine's shape so the UI/API feel consistent)
const jobs = new Map();

function sanitiseTarget(raw = '') {
  const clean = String(raw).trim().replace(/[;&|`$(){}[\]\\'"<>\s]/g, '');
  if (!clean) throw new Error('Target is required');
  if (clean.length > 256) throw new Error('Target string too long');
  return clean;
}

/**
 * parsePortSpec("22,80,1000-1010,443") → [22, 80, 1000, ..., 1010, 443]
 * De-duplicated, sorted, capped at MAX_PORTS_PER_SCAN.
 */
function parsePortSpec(spec) {
  if (!spec || spec === 'common') return [...COMMON_PORTS];
  if (spec === 'all') return rangeArray(1, 65535);

  const ports = new Set();
  for (const part of String(spec).split(',').map(s => s.trim()).filter(Boolean)) {
    const rangeMatch = part.match(/^(\d{1,5})-(\d{1,5})$/);
    if (rangeMatch) {
      const [, a, b] = rangeMatch;
      for (const p of rangeArray(parseInt(a), parseInt(b))) ports.add(p);
      continue;
    }
    if (/^\d{1,5}$/.test(part)) {
      ports.add(parseInt(part));
      continue;
    }
    // silently ignore malformed tokens rather than failing the whole scan
    logger.warn(`portScanner: ignoring invalid port token "${part}"`);
  }

  const result = [...ports].filter(p => p >= 1 && p <= 65535).sort((a, b) => a - b);
  if (result.length > MAX_PORTS_PER_SCAN) {
    throw new Error(`Too many ports requested (${result.length}). Max is ${MAX_PORTS_PER_SCAN} per scan.`);
  }
  return result;
}

function rangeArray(start, end) {
  if (start > end) [start, end] = [end, start];
  const out = [];
  for (let i = start; i <= end; i++) out.push(i);
  return out;
}

/**
 * Probe a single host:port with a raw TCP connect. Optionally grabs
 * whatever bytes the service sends within a short window after connecting.
 */
function probePort(host, port, { timeoutMs = DEFAULT_TIMEOUT_MS, grabBanner = false } = {}) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let settled = false;
    let banner = '';

    const finish = (state, extra = {}) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ port, state, service: WELL_KNOWN_SERVICES[port] || null, banner: banner || null, ...extra });
    };

    socket.setTimeout(timeoutMs);

    socket.once('connect', () => {
      if (!grabBanner) return finish('open');
      // Give the service a brief window to speak first (SSH/FTP/SMTP do).
      const bannerTimer = setTimeout(() => finish('open'), Math.min(800, timeoutMs));
      socket.once('data', chunk => {
        clearTimeout(bannerTimer);
        banner = chunk.toString('utf8', 0, 256).replace(/[\r\n]+/g, ' ').trim();
        finish('open');
      });
    });

    socket.once('timeout', () => finish('filtered'));
    socket.once('error', err => {
      if (err.code === 'ECONNREFUSED') return finish('closed');
      finish('filtered', { error: err.code });
    });

    socket.connect(port, host);
  });
}

/**
 * Run probes with bounded concurrency so we don't fork thousands of
 * sockets at once (which would just look like a SYN flood and get
 * rate-limited or blocked by the target or local OS).
 */
async function runPool(items, worker, concurrency) {
  const results = new Array(items.length);
  let next = 0;

  async function runner() {
    while (true) {
      const i = next++;
      if (i >= items.length) return;
      results[i] = await worker(items[i], i);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, items.length) }, runner);
  await Promise.all(workers);
  return results;
}

/**
 * startScan({ target, ports, concurrency, timeoutMs, grabBanner, label })
 * Runs async in the background, broadcasting progress over WebSocket —
 * same event-naming convention as nmapEngine so the frontend can reuse it.
 */
function startScan({ target, ports = 'common', concurrency = DEFAULT_CONCURRENCY, timeoutMs = DEFAULT_TIMEOUT_MS, grabBanner = false, label = '' } = {}) {
  const safeTarget = sanitiseTarget(target);
  const portList = parsePortSpec(ports);
  if (!portList.length) throw new Error('No valid ports to scan');

  const safeConcurrency = Math.min(Math.max(parseInt(concurrency) || DEFAULT_CONCURRENCY, 1), 500);
  const safeTimeout = Math.min(Math.max(parseInt(timeoutMs) || DEFAULT_TIMEOUT_MS, 200), 10_000);

  const jobId = uuid();
  const job = {
    id: jobId,
    label: label || safeTarget,
    target: safeTarget,
    totalPorts: portList.length,
    status: 'running',
    createdAt: new Date().toISOString(),
    startedAt: new Date().toISOString(),
    completedAt: null,
    scanned: 0,
    openPorts: [],
    results: null,
    error: null,
  };
  jobs.set(jobId, job);

  logger.info(`[portscan:${jobId}] Starting — target: ${safeTarget}  ports: ${portList.length}  concurrency: ${safeConcurrency}`);
  broadcast({ type: 'portscan_started', jobId, target: safeTarget, totalPorts: portList.length });

  (async () => {
    try {
      const resolved = await dns.lookup(safeTarget).catch(() => null);
      const host = resolved?.address || safeTarget;

      let lastUpdate = Date.now();
      const perPort = await runPool(portList, async port => {
        const result = await probePort(host, port, { timeoutMs: safeTimeout, grabBanner });
        job.scanned++;

        if (result.state === 'open') {
          job.openPorts.push(result);
          broadcast({ type: 'portscan_open', jobId, ...result });
        }

        const now = Date.now();
        if (now - lastUpdate > 1000) {
          lastUpdate = now;
          broadcast({
            type: 'portscan_progress', jobId,
            scanned: job.scanned, total: portList.length,
            openCount: job.openPorts.length,
          });
        }
        return result;
      }, safeConcurrency);

      job.status = 'complete';
      job.completedAt = new Date().toISOString();
      job.results = {
        host, resolvedFrom: safeTarget,
        totalScanned: perPort.length,
        openCount: job.openPorts.length,
        open: job.openPorts.sort((a, b) => a.port - b.port),
      };

      logger.info(`[portscan:${jobId}] Done — ${job.openPorts.length}/${portList.length} open`);
      broadcast({ type: 'portscan_complete', jobId, status: job.status, results: job.results });
    } catch (err) {
      job.status = 'error';
      job.error = err.message;
      job.completedAt = new Date().toISOString();
      logger.error(`[portscan:${jobId}] Error: ${err.message}`);
      broadcast({ type: 'portscan_error', jobId, error: err.message });
    }
  })();

  return { jobId, status: job.status, totalPorts: portList.length };
}

function getJob(jobId) {
  return jobs.get(jobId) || null;
}

function listJobs() {
  return [...jobs.values()].map(({ openPorts, ...j }) => ({ ...j, openCount: openPorts.length }));
}

function deleteJob(jobId) {
  const existed = jobs.delete(jobId);
  return { ok: existed };
}

module.exports = {
  startScan,
  getJob,
  listJobs,
  deleteJob,
  parsePortSpec,
  COMMON_PORTS,
};

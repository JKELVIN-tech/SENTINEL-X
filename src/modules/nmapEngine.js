'use strict';

/**
 * Sentinel X — NMAP Engine Module
 * ─────────────────────────────────────────────────────────────────────────────
 * Wraps the system nmap binary. Supports:
 *   • Arbitrary flag composition from the UI builder
 *   • Real-time stdout streaming over WebSocket
 *   • XML output parsing into structured JSON
 *   • Job queue (max N concurrent scans)
 *   • Per-job cancellation
 * ─────────────────────────────────────────────────────────────────────────────
 */

const { spawn }  = require('child_process');
const path       = require('path');
const fs         = require('fs');
const { v4: uuid } = require('uuid');
const xml2js     = require('xml2js');
const logger     = require('../utils/logger');
const { resolveBinary, NMAP_COMMON_PATHS } = require('../utils/binLocator');

// ── Config
const { bin: NMAP_BIN, source: NMAP_BIN_SOURCE } = resolveBinary('nmap', {
  envVar: 'NMAP_BINARY',
  commonPaths: NMAP_COMMON_PATHS,
});
logger.info(`NmapEngine: using binary "${NMAP_BIN}" (resolved via ${NMAP_BIN_SOURCE})`);

const OUTPUT_DIR    = process.env.NMAP_OUTPUT_DIR  || './reports/nmap';
const MAX_JOBS      = parseInt(process.env.NMAP_MAX_CONCURRENT) || 3;
const TIMEOUT_MS    = parseInt(process.env.NMAP_TIMEOUT_MS)     || 300_000; // 5 min

// Ensure output directory exists
if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR, { recursive: true });

// ── In-memory job store  { jobId → JobRecord }
const jobs = new Map();
let activeCount = 0;

// ──────────────────────────────────────────────
//  Allowed flags whitelist (security gate)
//  Only flags in this set will be forwarded to nmap.
// ──────────────────────────────────────────────
const ALLOWED_FLAGS = new Set([
  // Scan types
  '-sS', '-sT', '-sU', '-sN', '-sF', '-sX', '-sA', '-sW', '-sM',
  '-sV', '-sC', '-O', '-A',
  // Timing
  '-T0', '-T1', '-T2', '-T3', '-T4', '-T5',
  // Host discovery
  '-Pn', '-PE', '-PP', '-PS', '-PA', '-PU', '-n', '-R',
  // Misc
  '-v', '-vv', '--open', '--reason', '--traceroute', '-6',
  // Evasion
  '-f', '--badsum',
  // Output (we add -oX ourselves, but allow these for reference)
  '-oN', '-oG', '-oA',
]);

// Flags that accept a value (whitelist of safe ones)
const VALUE_FLAGS = new Set([
  '--script', '-p', '--exclude', '-e', '--min-rate', '--max-rate',
  '--max-retries', '--host-timeout', '--data-length',
  '-D', '-S', '--spoof-mac', '--ttl', '--source-port',
  '--script-args',
]);

// ──────────────────────────────────────────────
//  Flag sanitiser
// ──────────────────────────────────────────────
function sanitiseFlags(rawFlags = []) {
  const safe = [];

  for (let i = 0; i < rawFlags.length; i++) {
    const flag = rawFlags[i];

    // Boolean flags
    if (ALLOWED_FLAGS.has(flag)) {
      safe.push(flag);
      continue;
    }

    // Value flags  e.g. ['--script', 'vuln']
    if (VALUE_FLAGS.has(flag)) {
      const val = rawFlags[i + 1];
      if (val && !val.startsWith('-')) {
        // Strip shell metacharacters from the value
        const cleanVal = val.replace(/[;&|`$(){}[\]\\'"]/g, '');
        safe.push(flag, cleanVal);
        i++; // skip the consumed value
      }
      continue;
    }

    // -p shorthand attached: -p80,443
    if (flag.startsWith('-p')) {
      const portPart = flag.slice(2).replace(/[^0-9,\-]/g, '');
      if (portPart) safe.push(`-p${portPart}`);
      continue;
    }

    // Timing shorthand -T0…-T5
    if (/^-T[0-5]$/.test(flag)) {
      safe.push(flag);
      continue;
    }

    logger.warn(`NmapEngine: dropping unsupported flag → ${flag}`);
  }

  return safe;
}

// ──────────────────────────────────────────────
//  Target sanitiser  (prevent command injection)
// ──────────────────────────────────────────────
function sanitiseTarget(raw = '') {
  // Allow: IPv4, IPv4/CIDR, IPv4 ranges (192.168.1.1-254), hostnames, domains
  const clean = raw.trim().replace(/[;&|`$(){}[\]\\'"<>]/g, '');
  if (!clean) throw new Error('Target is required');
  if (clean.length > 256) throw new Error('Target string too long');
  return clean;
}

// ──────────────────────────────────────────────
//  XML → JSON parser
// ──────────────────────────────────────────────
async function parseNmapXml(xmlPath) {
  try {
    const xml  = fs.readFileSync(xmlPath, 'utf8');
    const raw  = await xml2js.parseStringPromise(xml, { explicitArray: false });
    const root = raw?.nmaprun;
    if (!root) return null;

    const hostsRaw = Array.isArray(root.host) ? root.host
                   : root.host ? [root.host] : [];

    const hosts = hostsRaw.map(h => {
      // Status
      const status = h.status?.['$']?.state || 'unknown';

      // Addresses
      const addrsRaw = Array.isArray(h.address) ? h.address : [h.address];
      const addresses = addrsRaw.filter(Boolean).map(a => ({
        addr:     a['$']?.addr,
        addrtype: a['$']?.addrtype,
        vendor:   a['$']?.vendor,
      }));
      const ip = addresses.find(a => a.addrtype === 'ipv4')?.addr
              || addresses[0]?.addr;

      // Hostnames
      const hnRaw  = h.hostnames?.hostname;
      const hnames = hnRaw
        ? (Array.isArray(hnRaw) ? hnRaw : [hnRaw]).map(n => n['$']?.name)
        : [];

      // Ports
      const portsRaw = h.ports?.port;
      const ports = portsRaw
        ? (Array.isArray(portsRaw) ? portsRaw : [portsRaw]).map(p => ({
            protocol: p['$']?.protocol,
            portid:   parseInt(p['$']?.portid),
            state:    p.state?.['$']?.state,
            reason:   p.state?.['$']?.reason,
            service:  {
              name:    p.service?.['$']?.name,
              product: p.service?.['$']?.product,
              version: p.service?.['$']?.version,
              ostype:  p.service?.['$']?.ostype,
              extrainfo: p.service?.['$']?.extrainfo,
            },
            scripts: (() => {
              const sc = p.script;
              if (!sc) return [];
              return (Array.isArray(sc) ? sc : [sc]).map(s => ({
                id:     s['$']?.id,
                output: s['$']?.output,
              }));
            })(),
          }))
        : [];

      // OS detection
      const osMatches = h.os?.osmatch;
      const os = osMatches
        ? (Array.isArray(osMatches) ? osMatches : [osMatches])
            .map(o => ({
              name:      o['$']?.name,
              accuracy:  parseInt(o['$']?.accuracy),
              osfamily:  o.osclass?.['$']?.osfamily,
              osgen:     o.osclass?.['$']?.osgen,
            }))
            .sort((a, b) => b.accuracy - a.accuracy)
        : [];

      // Scripts (host-level)
      const hostScripts = h.hostscript?.script;
      const scripts = hostScripts
        ? (Array.isArray(hostScripts) ? hostScripts : [hostScripts])
            .map(s => ({ id: s['$']?.id, output: s['$']?.output }))
        : [];

      return {
        ip,
        status,
        hostnames: hnames.filter(Boolean),
        addresses,
        ports:     ports.filter(p => p.state === 'open'),
        allPorts:  ports,
        os,
        scripts,
        openPortCount: ports.filter(p => p.state === 'open').length,
      };
    });

    return {
      scanner:       root['$']?.scanner,
      args:          root['$']?.args,
      startTime:     root['$']?.start,
      version:       root['$']?.version,
      hostsTotal:    parseInt(root.runstats?.hosts?.['$']?.total   || 0),
      hostsUp:       parseInt(root.runstats?.hosts?.['$']?.up      || 0),
      hostsDown:     parseInt(root.runstats?.hosts?.['$']?.down    || 0),
      elapsed:       root.runstats?.finished?.['$']?.elapsed,
      summary:       root.runstats?.finished?.['$']?.summary,
      hosts,
    };
  } catch (err) {
    logger.error(`XML parse error: ${err.message}`);
    return null;
  }
}

// ──────────────────────────────────────────────
//  Core scan executor
// ──────────────────────────────────────────────
function executeScan(jobId) {
  const job = jobs.get(jobId);
  if (!job) return;

  job.status    = 'running';
  job.startedAt = new Date().toISOString();
  activeCount++;

  const xmlOut  = path.join(OUTPUT_DIR, `${jobId}.xml`);
  const normOut = path.join(OUTPUT_DIR, `${jobId}.txt`);

  // Build final argv
  const argv = [
    ...job.safeFlags,
    `-p${job.portRange}`,
    '-oX', xmlOut,
    '-oN', normOut,
    '--stats-every', '5s',
    job.target,
  ];

  logger.info(`[${jobId}] Launching: nmap ${argv.join(' ')}`);
  broadcast({ type: 'scan_started', jobId, target: job.target, args: argv });

  const proc = spawn(NMAP_BIN, argv, { stdio: ['ignore', 'pipe', 'pipe'] });
  job.pid     = proc.pid;
  job.process = proc;

  // ── stdout — stream lines to WebSocket
  let stdoutBuf = '';
  proc.stdout.on('data', chunk => {
    stdoutBuf += chunk.toString();
    const lines = stdoutBuf.split('\n');
    stdoutBuf   = lines.pop(); // keep incomplete line

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      job.output.push(trimmed);
      broadcast({ type: 'scan_output', jobId, line: trimmed });
    }
  });

  // ── stderr
  let stderrBuf = '';
  proc.stderr.on('data', chunk => {
    stderrBuf += chunk.toString();
  });

  // ── Timeout watchdog
  const timer = setTimeout(() => {
    if (job.status === 'running') {
      logger.warn(`[${jobId}] Scan timed out after ${TIMEOUT_MS}ms — killing`);
      proc.kill('SIGKILL');
      job.status = 'timeout';
    }
  }, TIMEOUT_MS);

  // ── Close / completion
  proc.on('close', async (code, signal) => {
    clearTimeout(timer);
    activeCount = Math.max(0, activeCount - 1);

    job.exitCode    = code;
    job.signal      = signal;
    job.completedAt = new Date().toISOString();

    if (stderrBuf.trim()) {
      logger.warn(`[${jobId}] stderr: ${stderrBuf.trim()}`);
      job.stderr = stderrBuf.trim();
    }

    if (job.status !== 'cancelled' && job.status !== 'timeout') {
      job.status = code === 0 ? 'complete' : 'error';
    }

    // Parse XML results
    if (fs.existsSync(xmlOut)) {
      job.results  = await parseNmapXml(xmlOut);
      job.xmlPath  = xmlOut;
      job.normPath = normOut;
    }

    logger.info(`[${jobId}] Finished — status: ${job.status}  exit: ${code}`);
    broadcast({ type: 'scan_complete', jobId, status: job.status, results: job.results });

    // Drain queue
    drainQueue();
  });

  proc.on('error', err => {
    clearTimeout(timer);
    activeCount = Math.max(0, activeCount - 1);
    job.status  = 'error';
    job.error   = err.message;
    logger.error(`[${jobId}] Process error: ${err.message}`);
    broadcast({ type: 'scan_error', jobId, error: err.message });
    drainQueue();
  });
}

// ──────────────────────────────────────────────
//  Queue drain
// ──────────────────────────────────────────────
function drainQueue() {
  if (activeCount >= MAX_JOBS) return;
  for (const [, job] of jobs) {
    if (job.status === 'queued') {
      executeScan(job.id);
      return;
    }
  }
}

// ──────────────────────────────────────────────
//  Broadcast helper (uses global set from server.js)
// ──────────────────────────────────────────────
function broadcast(data) {
  if (typeof global.broadcast === 'function') {
    global.broadcast(data);
  }
}

// ──────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────

/**
 * startScan({ target, flags, portRange, label })
 * Returns { jobId, status }
 */
function startScan({ target, flags = [], portRange = '1-1000', label = '' }) {
  // Validate / sanitise
  const safeTarget = sanitiseTarget(target);
  const safeFlags  = sanitiseFlags(
    Array.isArray(flags) ? flags : flags.split(/\s+/).filter(Boolean)
  );
  const safePorts  = portRange.replace(/[^0-9,\-]/g, '') || '1-1000';

  const jobId = uuid();
  const job   = {
    id:          jobId,
    label:       label || safeTarget,
    target:      safeTarget,
    safeFlags,
    portRange:   safePorts,
    status:      'queued',
    createdAt:   new Date().toISOString(),
    startedAt:   null,
    completedAt: null,
    pid:         null,
    exitCode:    null,
    signal:      null,
    output:      [],
    stderr:      '',
    error:       null,
    results:     null,
    xmlPath:     null,
    normPath:    null,
  };

  jobs.set(jobId, job);
  logger.info(`[${jobId}] Queued scan → target: ${safeTarget}  flags: ${safeFlags.join(' ')}`);
  broadcast({ type: 'scan_queued', jobId, target: safeTarget, queueDepth: activeCount });

  // Start immediately or enqueue
  if (activeCount < MAX_JOBS) {
    executeScan(jobId);
  }

  return { jobId, status: job.status };
}

/**
 * cancelScan(jobId)
 */
function cancelScan(jobId) {
  const job = jobs.get(jobId);
  if (!job) return { ok: false, error: 'Job not found' };
  if (job.status === 'complete' || job.status === 'cancelled') {
    return { ok: false, error: `Job already ${job.status}` };
  }
  if (job.process) {
    job.process.kill('SIGTERM');
    setTimeout(() => {
      if (job.status === 'running') job.process.kill('SIGKILL');
    }, 3000);
  }
  job.status = 'cancelled';
  logger.info(`[${jobId}] Cancelled by user`);
  broadcast({ type: 'scan_cancelled', jobId });
  drainQueue();
  return { ok: true };
}

/**
 * getJob(jobId) → job record (without the process handle)
 */
function getJob(jobId) {
  const job = jobs.get(jobId);
  if (!job) return null;
  const { process: _p, ...safe } = job;
  return safe;
}

/**
 * listJobs() → array of all job summaries
 */
function listJobs() {
  return [...jobs.values()].map(({ process: _p, output: _o, ...j }) => j);
}

/**
 * deleteJob(jobId) — cancel if running, then remove from store
 */
function deleteJob(jobId) {
  const job = jobs.get(jobId);
  if (!job) return { ok: false, error: 'Not found' };
  if (job.status === 'running') cancelScan(jobId);
  // Clean up report files
  [job.xmlPath, job.normPath].filter(Boolean).forEach(f => {
    try { fs.unlinkSync(f); } catch (_) {}
  });
  jobs.delete(jobId);
  return { ok: true };
}

/**
 * getJobOutput(jobId) → raw stdout lines array
 */
function getJobOutput(jobId) {
  return jobs.get(jobId)?.output || null;
}

/**
 * checkNmap() — verify binary exists + version
 */
function checkNmap() {
  return new Promise((resolve) => {
    const proc = spawn(NMAP_BIN, ['--version'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    proc.stdout.on('data', d => (out += d));
    proc.on('close', code => {
      if (code === 0) {
        const version = out.match(/Nmap version ([\d.]+)/)?.[1] || 'unknown';
        resolve({ available: true, binary: NMAP_BIN, version });
      } else {
        resolve({ available: false, binary: NMAP_BIN, error: 'nmap exited with non-zero' });
      }
    });
    proc.on('error', err => {
      const hint = err.code === 'ENOENT'
        ? (require('../utils/binLocator').IS_WINDOWS
            ? 'Nmap not found. Install it from https://nmap.org/download.html#windows, ' +
              'then either add it to PATH or set NMAP_BINARY in .env to the full path ' +
              '(e.g. C:\\Program Files (x86)\\Nmap\\nmap.exe).'
            : 'Nmap not found. Install it (e.g. `sudo apt install nmap` or `brew install nmap`) ' +
              'or set NMAP_BINARY in .env to its full path.')
        : err.message;
      resolve({ available: false, binary: NMAP_BIN, error: hint });
    });
  });
}

module.exports = {
  startScan,
  cancelScan,
  getJob,
  listJobs,
  deleteJob,
  getJobOutput,
  checkNmap,
  parseNmapXml,
};

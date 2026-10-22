'use strict';

/**
 * Sentinel X — NMAP API Routes
 * ─────────────────────────────────────────────────────────────────────────────
 * POST   /api/nmap/scan          Start a new scan
 * GET    /api/nmap/scan/:id      Get job status + results
 * GET    /api/nmap/scan/:id/output  Raw stdout lines
 * DELETE /api/nmap/scan/:id      Cancel / delete a job
 * GET    /api/nmap/jobs          List all jobs
 * GET    /api/nmap/status        NMAP binary health check
 * POST   /api/nmap/validate      Validate + preview a command without running it
 * GET    /api/nmap/scan/:id/download/:fmt  Download report (xml|txt)
 * ─────────────────────────────────────────────────────────────────────────────
 */

const express = require('express');
const fs      = require('fs');
const path    = require('path');
const router  = express.Router();
const logger  = require('../utils/logger');
const nmap    = require('../modules/nmapEngine');

// ─────────────────────────────────────────────
//  POST /api/nmap/scan
//  Body: { target, flags[], portRange, label }
// ─────────────────────────────────────────────
router.post('/scan', async (req, res, next) => {
  try {
    const { target, flags = [], portRange = '1-1000', label } = req.body;

    if (!target) {
      return res.status(400).json({ error: 'target is required' });
    }

    const result = nmap.startScan({ target, flags, portRange, label });

    logger.info(`Scan queued — jobId: ${result.jobId}  target: ${target}`);
    return res.status(202).json({
      message:   'Scan queued',
      jobId:     result.jobId,
      status:    result.status,
      target,
      portRange,
      flags,
      links: {
        status:   `/api/nmap/scan/${result.jobId}`,
        output:   `/api/nmap/scan/${result.jobId}/output`,
        cancel:   `/api/nmap/scan/${result.jobId}`,
      },
    });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────────
//  GET /api/nmap/scan/:id
// ─────────────────────────────────────────────
router.get('/scan/:id', (req, res) => {
  const job = nmap.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  // Strip large output array from status endpoint (use /output for that)
  const { output: _o, ...summary } = job;
  return res.json(summary);
});

// ─────────────────────────────────────────────
//  GET /api/nmap/scan/:id/output
// ─────────────────────────────────────────────
router.get('/scan/:id/output', (req, res) => {
  const output = nmap.getJobOutput(req.params.id);
  if (output === null) return res.status(404).json({ error: 'Job not found' });

  const since = parseInt(req.query.since) || 0;  // pagination: lines after index N
  return res.json({
    total:  output.length,
    since,
    lines:  output.slice(since),
  });
});

// ─────────────────────────────────────────────
//  DELETE /api/nmap/scan/:id   — cancel or delete
// ─────────────────────────────────────────────
router.delete('/scan/:id', (req, res) => {
  const job = nmap.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  const action = req.query.action || 'cancel';

  if (action === 'delete') {
    const r = nmap.deleteJob(req.params.id);
    return res.json(r);
  }

  const r = nmap.cancelScan(req.params.id);
  return r.ok ? res.json({ message: 'Scan cancelled', jobId: req.params.id })
              : res.status(400).json(r);
});

// ─────────────────────────────────────────────
//  GET /api/nmap/jobs
// ─────────────────────────────────────────────
router.get('/jobs', (req, res) => {
  const jobs  = nmap.listJobs();
  const { status, limit = 50, offset = 0 } = req.query;

  let filtered = status ? jobs.filter(j => j.status === status) : jobs;
  filtered = filtered
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(parseInt(offset), parseInt(offset) + parseInt(limit));

  return res.json({ total: jobs.length, count: filtered.length, jobs: filtered });
});

// ─────────────────────────────────────────────
//  GET /api/nmap/status   — NMAP binary check
// ─────────────────────────────────────────────
router.get('/status', async (req, res, next) => {
  try {
    const info = await nmap.checkNmap();
    return res.json({
      ...info,
      activeScans: nmap.listJobs().filter(j => j.status === 'running').length,
      queuedScans: nmap.listJobs().filter(j => j.status === 'queued').length,
    });
  } catch (err) {
    next(err);
  }
});

// ─────────────────────────────────────────────
//  POST /api/nmap/validate
//  Preview the sanitised command without running it
// ─────────────────────────────────────────────
router.post('/validate', (req, res) => {
  try {
    const { target = '', flags = [], portRange = '1-1000' } = req.body;

    // Reuse internal sanitisers — import private helpers via a thin wrapper
    // (We expose a validate helper on the engine module)
    const { sanitiseFlags, sanitiseTarget } = requireHelpers();
    const safeTarget = sanitiseTarget(target);
    const safeFlags  = sanitiseFlags(
      Array.isArray(flags) ? flags : flags.split(/\s+/).filter(Boolean)
    );
    const safePorts  = portRange.replace(/[^0-9,\-]/g, '') || '1-1000';
    const argv       = [...safeFlags, `-p${safePorts}`, safeTarget];
    const command    = `nmap ${argv.join(' ')}`;

    return res.json({
      valid:   true,
      command,
      safeFlags,
      target:  safeTarget,
      ports:   safePorts,
    });
  } catch (err) {
    return res.status(400).json({ valid: false, error: err.message });
  }
});

// ─────────────────────────────────────────────
//  GET /api/nmap/scan/:id/download/:fmt
//  fmt = xml | txt
// ─────────────────────────────────────────────
router.get('/scan/:id/download/:fmt', (req, res) => {
  const job = nmap.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  if (job.status !== 'complete') {
    return res.status(400).json({ error: 'Scan not yet complete' });
  }

  const fmt  = req.params.fmt.toLowerCase();
  const file = fmt === 'xml' ? job.xmlPath : job.normPath;

  if (!file || !fs.existsSync(file)) {
    return res.status(404).json({ error: 'Report file not found' });
  }

  const mime = fmt === 'xml' ? 'application/xml' : 'text/plain';
  res.setHeader('Content-Type', mime);
  res.setHeader('Content-Disposition',
    `attachment; filename="sentinelx_scan_${req.params.id}.${fmt}"`);
  fs.createReadStream(file).pipe(res);
});

// ─────────────────────────────────────────────
//  Internal helper — expose private sanitisers
//  from nmapEngine without making them public
// ─────────────────────────────────────────────
function requireHelpers() {
  // We inline lightweight versions here so the engine keeps them private
  const ALLOWED = new Set([
    '-sS','-sT','-sU','-sN','-sF','-sX','-sA','-sW','-sM',
    '-sV','-sC','-O','-A',
    '-T0','-T1','-T2','-T3','-T4','-T5',
    '-Pn','-PE','-PP','-PS','-PA','-PU','-n','-R',
    '-v','-vv','--open','--reason','--traceroute','-6',
    '-f','--badsum',
  ]);
  const VALUE = new Set([
    '--script','-p','--exclude','-e','--min-rate','--max-rate',
    '--max-retries','--host-timeout','--data-length',
    '-D','-S','--spoof-mac','--ttl','--source-port','--script-args',
  ]);
  function sanitiseFlags(raw = []) {
    const safe = [];
    for (let i = 0; i < raw.length; i++) {
      const f = raw[i];
      if (ALLOWED.has(f))  { safe.push(f); continue; }
      if (VALUE.has(f)) {
        const v = raw[i+1];
        if (v && !v.startsWith('-')) {
          safe.push(f, v.replace(/[;&|`$(){}[\]\\'"]/g, ''));
          i++;
        }
        continue;
      }
      if (/^-T[0-5]$/.test(f)) { safe.push(f); continue; }
      if (f.startsWith('-p')) {
        const p = f.slice(2).replace(/[^0-9,\-]/g,'');
        if (p) safe.push(`-p${p}`);
      }
    }
    return safe;
  }
  function sanitiseTarget(raw = '') {
    const c = raw.trim().replace(/[;&|`$(){}[\]\\'"<>]/g,'');
    if (!c) throw new Error('Target is required');
    if (c.length > 256) throw new Error('Target too long');
    return c;
  }
  return { sanitiseFlags, sanitiseTarget };
}

module.exports = router;

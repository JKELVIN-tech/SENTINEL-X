'use strict';

/**
 * Sentinel X — Recon Tools Routes
 * ─────────────────────────────────────────────────────────────────────────────
 * Built-in, no-external-binary tools — these work out of the box on any OS
 * (including a fresh Windows install with no Nmap/hashcat yet installed).
 *
 * POST   /api/recon/portscan             Start a TCP connect port scan
 * GET    /api/recon/portscan/:id         Job status + results
 * GET    /api/recon/portscan/jobs        List port-scan jobs
 * DELETE /api/recon/portscan/:id         Remove a job record
 *
 * POST   /api/recon/ssl                  Inspect a host's TLS certificate
 * POST   /api/recon/headers              Audit a URL's security headers
 * ─────────────────────────────────────────────────────────────────────────────
 */

const express = require('express');
const router = express.Router();
const logger = require('../utils/logger');
const portScanner = require('../modules/portScanner');
const sslChecker = require('../modules/sslChecker');
const headerAudit = require('../modules/headerAudit');

// ── POST /api/recon/portscan
router.post('/portscan', (req, res, next) => {
  try {
    const { target, ports = 'common', concurrency, timeoutMs, grabBanner = false, label } = req.body;
    if (!target) return res.status(400).json({ error: 'target is required' });

    const result = portScanner.startScan({ target, ports, concurrency, timeoutMs, grabBanner, label });
    logger.info(`Port scan queued — jobId: ${result.jobId}  target: ${target}`);
    return res.status(202).json({
      message: 'Port scan started',
      ...result,
      links: { status: `/api/recon/portscan/${result.jobId}` },
    });
  } catch (err) {
    if (err.message.includes('required') || err.message.includes('Too many')) {
      return res.status(400).json({ error: err.message });
    }
    next(err);
  }
});

// ── GET /api/recon/portscan/jobs
router.get('/portscan/jobs', (req, res) => {
  const jobs = portScanner.listJobs()
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  res.json({ count: jobs.length, jobs });
});

// ── GET /api/recon/portscan/:id
router.get('/portscan/:id', (req, res) => {
  const job = portScanner.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });
  res.json(job);
});

// ── DELETE /api/recon/portscan/:id
router.delete('/portscan/:id', (req, res) => {
  const r = portScanner.deleteJob(req.params.id);
  return r.ok ? res.json({ message: 'Deleted' }) : res.status(404).json({ error: 'Not found' });
});

// ── POST /api/recon/ssl   Body: { host, port }
router.post('/ssl', async (req, res, next) => {
  try {
    const { host, port = 443 } = req.body;
    if (!host) return res.status(400).json({ error: 'host is required' });
    const result = await sslChecker.checkCertificate(host, port);
    return res.json(result);
  } catch (err) {
    if (err.message.includes('required') || err.message.includes('too long')) {
      return res.status(400).json({ error: err.message });
    }
    next(err);
  }
});

// ── POST /api/recon/headers   Body: { url }
router.post('/headers', async (req, res, next) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: 'url is required' });
    const result = await headerAudit.auditUrl(url);
    return res.json(result);
  } catch (err) {
    if (err.message.includes('Invalid URL') || err.message.includes('only')) {
      return res.status(400).json({ error: err.message });
    }
    next(err);
  }
});

module.exports = router;

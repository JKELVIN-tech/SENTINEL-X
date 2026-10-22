'use strict';

/**
 * Sentinel X — Hash Cracker API Routes
 * ─────────────────────────────────────────────────────────────────────────────
 * POST   /api/hash/crack            Start a cracking job
 * GET    /api/hash/crack/:id        Job status + results
 * DELETE /api/hash/crack/:id        Cancel / delete job
 * GET    /api/hash/jobs             List all crack jobs
 * POST   /api/hash/identify         Identify hash type(s) without cracking
 * POST   /api/hash/compute          Compute hash of a plaintext (utility)
 * GET    /api/hash/wordlists        List available wordlists
 * GET    /api/hash/types            List supported hash types
 * GET    /api/hash/status           Hashcat binary availability
 * ─────────────────────────────────────────────────────────────────────────────
 */

const express  = require('express');
const router   = express.Router();
const logger   = require('../utils/logger');
const cracker  = require('../modules/hashCracker');
const { identifyHash, allTypes } = require('../modules/hashIdentifier');

// ─────────────────────────────────────────────
//  POST /api/hash/crack
// ─────────────────────────────────────────────
router.post('/crack', (req, res, next) => {
  try {
    const {
      hashes,           // string[] — required
      hashType = 'auto',
      mode     = 'dictionary',  // dictionary | bruteforce | hashcat
      wordlistPath,
      bruteOpts = {},
      rules     = [],
      hashcatOpts = {},
      label,
    } = req.body;

    if (!hashes || !Array.isArray(hashes) || hashes.length === 0) {
      return res.status(400).json({ error: 'hashes[] array is required' });
    }
    if (!['dictionary','bruteforce','hashcat'].includes(mode)) {
      return res.status(400).json({ error: 'mode must be dictionary | bruteforce | hashcat' });
    }

    const result = cracker.startCrack({ hashes, hashType, mode, wordlistPath, bruteOpts, rules, hashcatOpts, label });

    logger.info(`Crack job queued — jobId: ${result.jobId}  hashes: ${hashes.length}  mode: ${mode}`);
    return res.status(202).json({
      message:      'Crack job queued',
      jobId:        result.jobId,
      status:       result.status,
      hashType:     result.hashType,
      autoDetected: result.autoDetected,
      mode,
      links: {
        status: `/api/hash/crack/${result.jobId}`,
        cancel: `/api/hash/crack/${result.jobId}`,
      },
    });
  } catch (err) {
    // Surface validation errors as 400
    if (err.message.includes('required') || err.message.includes('valid')) {
      return res.status(400).json({ error: err.message });
    }
    next(err);
  }
});

// ─────────────────────────────────────────────
//  GET /api/hash/crack/:id
// ─────────────────────────────────────────────
router.get('/crack/:id', (req, res) => {
  const job = cracker.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'Job not found' });

  // Compute elapsed time
  const elapsed = job.startedAt
    ? ((job.completedAt
        ? new Date(job.completedAt)
        : new Date()
       ).getTime() - new Date(job.startedAt).getTime()) / 1000
    : null;

  return res.json({ ...job, elapsed: elapsed ? elapsed.toFixed(1) + 's' : null });
});

// ─────────────────────────────────────────────
//  DELETE /api/hash/crack/:id
// ─────────────────────────────────────────────
router.delete('/crack/:id', (req, res) => {
  const action = req.query.action || 'cancel';
  if (action === 'delete') {
    const r = cracker.deleteJob(req.params.id);
    return r.ok ? res.json({ message: 'Deleted' }) : res.status(404).json(r);
  }
  const r = cracker.cancelCrack(req.params.id);
  return r.ok ? res.json({ message: 'Cancelled', jobId: req.params.id })
              : res.status(400).json(r);
});

// ─────────────────────────────────────────────
//  GET /api/hash/jobs
// ─────────────────────────────────────────────
router.get('/jobs', (req, res) => {
  const jobs   = cracker.listJobs();
  const { status, limit = 50, offset = 0 } = req.query;
  const filtered = (status ? jobs.filter(j => j.status === status) : jobs)
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(parseInt(offset), parseInt(offset) + parseInt(limit));
  return res.json({ total: jobs.length, count: filtered.length, jobs: filtered });
});

// ─────────────────────────────────────────────
//  POST /api/hash/identify
//  Body: { hash } or { hashes[] }
// ─────────────────────────────────────────────
router.post('/identify', (req, res) => {
  const { hash, hashes } = req.body;
  const targets = hashes || (hash ? [hash] : []);

  if (!targets.length) {
    return res.status(400).json({ error: 'hash or hashes[] required' });
  }

  const results = targets.map(h => ({
    hash:       h.trim(),
    candidates: identifyHash(h.trim()),
  }));

  return res.json({ results });
});

// ─────────────────────────────────────────────
//  POST /api/hash/compute
//  Utility: compute the hash of a given plaintext
//  Body: { plaintext, algorithms[] }
// ─────────────────────────────────────────────
router.post('/compute', (req, res) => {
  const { plaintext, algorithms = ['md5', 'sha1', 'sha256', 'sha512', 'ntlm'] } = req.body;

  if (!plaintext && plaintext !== '') {
    return res.status(400).json({ error: 'plaintext is required' });
  }
  if (plaintext.length > 1024) {
    return res.status(400).json({ error: 'plaintext too long (max 1024 chars)' });
  }

  const results = {};
  for (const algo of algorithms) {
    results[algo] = cracker.computeHash(plaintext, algo);
  }

  return res.json({ plaintext, hashes: results });
});

// ─────────────────────────────────────────────
//  GET /api/hash/wordlists
// ─────────────────────────────────────────────
router.get('/wordlists', (req, res) => {
  const lists = cracker.listWordlists();
  return res.json({ count: lists.length, wordlists: lists });
});

// ─────────────────────────────────────────────
//  GET /api/hash/types
// ─────────────────────────────────────────────
router.get('/types', (_req, res) => {
  return res.json({ types: allTypes() });
});

// ─────────────────────────────────────────────
//  GET /api/hash/status
// ─────────────────────────────────────────────
router.get('/status', async (req, res, next) => {
  try {
    const hashcat    = await cracker.checkHashcat();
    const jobs       = cracker.listJobs();
    const wordlists  = cracker.listWordlists();
    return res.json({
      hashcat,
      wordlistsFound: wordlists.length,
      activeJobs:  jobs.filter(j => j.status === 'running').length,
      queuedJobs:  jobs.filter(j => j.status === 'queued').length,
      totalJobs:   jobs.length,
    });
  } catch (err) { next(err); }
});

module.exports = router;

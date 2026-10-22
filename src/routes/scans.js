'use strict';

/**
 * Sentinel X — Scan History Routes
 * GET  /api/scans          List all completed scans with summaries
 * GET  /api/scans/:id      Get full scan result
 * DELETE /api/scans/:id    Delete scan record + files
 */

const express = require('express');
const router  = express.Router();
const nmap    = require('../modules/nmapEngine');

// List completed scans
router.get('/', (req, res) => {
  const all = nmap.listJobs();
  const done = all.filter(j => j.status === 'complete');

  const summaries = done.map(j => ({
    jobId:       j.id,
    label:       j.label,
    target:      j.target,
    status:      j.status,
    createdAt:   j.createdAt,
    completedAt: j.completedAt,
    hostsUp:     j.results?.hostsUp     || 0,
    hostsTotal:  j.results?.hostsTotal  || 0,
    openPorts:   j.results?.hosts?.reduce((n, h) => n + h.openPortCount, 0) || 0,
    elapsed:     j.results?.elapsed,
  }));

  res.json({ count: summaries.length, scans: summaries });
});

// Full scan result
router.get('/:id', (req, res) => {
  const job = nmap.getJob(req.params.id);
  if (!job) return res.status(404).json({ error: 'Scan not found' });
  const { output: _o, ...safe } = job;
  res.json(safe);
});

// Delete scan
router.delete('/:id', (req, res) => {
  const r = nmap.deleteJob(req.params.id);
  return r.ok ? res.json({ message: 'Deleted', jobId: req.params.id })
              : res.status(404).json(r);
});

module.exports = router;

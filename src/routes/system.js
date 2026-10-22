'use strict';

/**
 * Sentinel X — System Routes
 * GET /api/system/info     Platform info + nmap status
 * GET /api/system/stats    Live runtime stats
 */

const express = require('express');
const os      = require('os');
const router  = express.Router();
const nmap    = require('../modules/nmapEngine');
const logger  = require('../utils/logger');

router.get('/info', async (req, res, next) => {
  try {
    const nmapStatus = await nmap.checkNmap();
    res.json({
      platform: 'Sentinel X',
      version:  '2.0.0',
      node:     process.version,
      os:       `${os.type()} ${os.release()}`,
      arch:     os.arch(),
      uptime:   Math.floor(process.uptime()),
      nmap:     nmapStatus,
    });
  } catch (err) { next(err); }
});

router.get('/stats', (req, res) => {
  const jobs  = nmap.listJobs();
  const mem   = process.memoryUsage();
  res.json({
    jobs: {
      total:     jobs.length,
      running:   jobs.filter(j => j.status === 'running').length,
      queued:    jobs.filter(j => j.status === 'queued').length,
      complete:  jobs.filter(j => j.status === 'complete').length,
      error:     jobs.filter(j => j.status === 'error').length,
      cancelled: jobs.filter(j => j.status === 'cancelled').length,
    },
    memory: {
      rss:      (mem.rss / 1024 / 1024).toFixed(1) + ' MB',
      heap:     (mem.heapUsed / 1024 / 1024).toFixed(1) + ' MB',
    },
    uptime: Math.floor(process.uptime()),
    load:   os.loadavg(),
  });
});

module.exports = router;

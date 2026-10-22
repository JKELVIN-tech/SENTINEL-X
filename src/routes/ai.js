'use strict';

/**
 * Sentinel X — AI Analyst Routes
 * ─────────────────────────────────────────────────────────────────────────────
 * POST   /api/ai/session              Create a new analyst session
 * DELETE /api/ai/session/:id          Delete a session
 * PATCH  /api/ai/session/:id/context  Update session scan context
 * GET    /api/ai/sessions             List active sessions
 *
 * POST   /api/ai/chat                 Single-turn or multi-turn chat (JSON)
 * POST   /api/ai/chat/stream          Streaming chat (SSE)
 *
 * POST   /api/ai/report               Generate full pentest report
 * POST   /api/ai/cve                  Deep-dive CVE explanation
 * POST   /api/ai/attack-chain         Build attack chain from findings
 * POST   /api/ai/recommend            Command recommendations
 *
 * GET    /api/ai/status               API + session health
 * ─────────────────────────────────────────────────────────────────────────────
 */

const express = require('express');
const router  = express.Router();
const logger  = require('../utils/logger');
const ai      = require('../modules/aiAnalyst');
const nmap    = require('../modules/nmapEngine');
const cracker = require('../modules/hashCracker');

// ──────────────────────────────────────────────
//  Context builder — auto-populate from live data
// ──────────────────────────────────────────────
function buildLiveContext(extra = {}) {
  // Pull latest completed scan
  const scans     = nmap.listJobs().filter(j => j.status === 'complete');
  const lastScan  = scans.sort((a, b) => new Date(b.completedAt) - new Date(a.completedAt))[0];
  const results   = lastScan?.results;

  // Pull cracked hashes
  const crackJobs = cracker.listJobs().filter(j => j.status === 'complete');
  const crackedHashes = crackJobs.flatMap(j =>
    Object.entries(j.cracked || {}).map(([hash, plaintext]) => ({
      hash, plaintext, type: j.hashType,
    }))
  );

  // Build vulnerability list from scan results
  const vulnerabilities = [];
  if (results?.hosts) {
    for (const host of results.hosts) {
      for (const port of (host.ports || [])) {
        for (const script of (port.scripts || [])) {
          if (script.output?.toLowerCase().includes('vulnerable') ||
              script.output?.toLowerCase().includes('cve')) {
            vulnerabilities.push({
              host:     host.ip,
              port:     port.portid,
              service:  port.service?.name,
              cve:      (script.output.match(/CVE-\d{4}-\d+/i) || [])[0] || null,
              name:     script.id,
              severity: 'high',
              cvss:     null,
              status:   'open',
            });
          }
        }
      }
    }
  }

  return {
    target:           lastScan?.target           || extra.target    || 'Unknown',
    hostsUp:          results?.hostsUp           || extra.hostsUp   || 0,
    hostsTotal:       results?.hostsTotal        || extra.hostsTotal|| 0,
    openPorts:        results?.hosts?.reduce((n, h) => n + h.openPortCount, 0) || extra.openPorts || 0,
    scanDuration:     results?.elapsed ? `${results.elapsed}s` : null,
    vulnerabilities:  vulnerabilities.length ? vulnerabilities : (extra.vulnerabilities || []),
    crackedHashes,
    engagement:       extra.engagement || 'Internal penetration test',
    ...extra,
  };
}

// ──────────────────────────────────────────────
//  Session routes
// ──────────────────────────────────────────────

// POST /api/ai/session
router.post('/session', (req, res) => {
  const context   = buildLiveContext(req.body.context || {});
  const sessionId = ai.createSession(context);
  logger.info(`AI session created via API: ${sessionId}`);
  return res.status(201).json({ sessionId, context, message: 'Session created' });
});

// DELETE /api/ai/session/:id
router.delete('/session/:id', (req, res) => {
  const existed = ai.deleteSession(req.params.id);
  return existed
    ? res.json({ message: 'Session deleted', sessionId: req.params.id })
    : res.status(404).json({ error: 'Session not found' });
});

// PATCH /api/ai/session/:id/context
router.patch('/session/:id/context', (req, res) => {
  const updated = ai.updateSessionContext(req.params.id, req.body);
  return updated
    ? res.json({ message: 'Context updated', sessionId: req.params.id })
    : res.status(404).json({ error: 'Session not found' });
});

// GET /api/ai/sessions
router.get('/sessions', (_req, res) => {
  return res.json({ sessions: ai.listSessions() });
});

// ──────────────────────────────────────────────
//  Chat — JSON (non-streaming)
// ──────────────────────────────────────────────
router.post('/chat', async (req, res, next) => {
  try {
    const { message, sessionId, context, maxTokens } = req.body;

    if (!message || typeof message !== 'string') {
      return res.status(400).json({ error: 'message (string) is required' });
    }

    // Auto-inject live context if no session provided
    let sid = sessionId;
    if (!sid) {
      const liveCtx = buildLiveContext(context || {});
      sid = ai.createSession(liveCtx);
    }

    const result = await ai.chat(sid, message, { maxTokens });
    return res.json(result);
  } catch (err) {
    if (err.message.includes('API key')) return res.status(503).json({ error: err.message });
    next(err);
  }
});

// ──────────────────────────────────────────────
//  Chat — SSE streaming
// ──────────────────────────────────────────────
router.post('/chat/stream', (req, res) => {
  const { message, sessionId, context, maxTokens } = req.body;

  if (!message || typeof message !== 'string') {
    return res.status(400).json({ error: 'message (string) is required' });
  }

  let sid = sessionId;
  if (!sid) {
    const liveCtx = buildLiveContext(context || {});
    sid = ai.createSession(liveCtx);
  }

  logger.info(`AI stream request — session: ${sid}`);
  ai.chatStream(sid, message, res, { maxTokens });
});

// ──────────────────────────────────────────────
//  Report generation
// ──────────────────────────────────────────────
router.post('/report', async (req, res, next) => {
  try {
    const { format = 'markdown', context } = req.body;

    if (!['markdown', 'executive', 'technical'].includes(format)) {
      return res.status(400).json({ error: 'format must be markdown | executive | technical' });
    }

    const liveCtx = buildLiveContext(context || {});
    logger.info(`Generating ${format} report for: ${liveCtx.target}`);

    const report = await ai.generateReport(liveCtx, format);
    return res.json({ format, target: liveCtx.target, report });
  } catch (err) {
    if (err.message.includes('API key')) return res.status(503).json({ error: err.message });
    next(err);
  }
});

// ──────────────────────────────────────────────
//  CVE deep-dive
// ──────────────────────────────────────────────
router.post('/cve', async (req, res, next) => {
  try {
    const { cve, context } = req.body;

    if (!cve || typeof cve !== 'string') {
      return res.status(400).json({ error: 'cve (string) is required e.g. CVE-2021-44228' });
    }
    // Validate CVE format
    if (!/^CVE-\d{4}-\d{1,7}$/i.test(cve.trim())) {
      return res.status(400).json({ error: 'Invalid CVE format. Use CVE-YYYY-NNNNN' });
    }

    const liveCtx = buildLiveContext(context || {});
    logger.info(`CVE analysis requested: ${cve}`);

    const analysis = await ai.explainCVE(cve.toUpperCase(), liveCtx);
    return res.json({ cve: cve.toUpperCase(), analysis });
  } catch (err) {
    if (err.message.includes('API key')) return res.status(503).json({ error: err.message });
    next(err);
  }
});

// ──────────────────────────────────────────────
//  Attack chain
// ──────────────────────────────────────────────
router.post('/attack-chain', async (req, res, next) => {
  try {
    const { context } = req.body;
    const liveCtx = buildLiveContext(context || {});

    if (!liveCtx.vulnerabilities.length && !liveCtx.crackedHashes.length) {
      return res.status(400).json({
        error: 'No vulnerabilities or cracked credentials found. Run a scan first.',
      });
    }

    logger.info(`Attack chain requested for: ${liveCtx.target}`);
    const chain = await ai.buildAttackChain(liveCtx);
    return res.json({ target: liveCtx.target, attackChain: chain });
  } catch (err) {
    if (err.message.includes('API key')) return res.status(503).json({ error: err.message });
    next(err);
  }
});

// ──────────────────────────────────────────────
//  Command recommendations
// ──────────────────────────────────────────────
router.post('/recommend', async (req, res, next) => {
  try {
    const { task, context } = req.body;
    const validTasks = ['nmap', 'hashcat', 'payload', 'wordlist'];

    if (!task || !validTasks.includes(task)) {
      return res.status(400).json({ error: `task must be one of: ${validTasks.join(', ')}` });
    }

    const liveCtx = buildLiveContext(context || {});
    logger.info(`Command recommendation requested: ${task}`);

    const recommendations = await ai.recommendCommands(task, liveCtx);
    return res.json({ task, recommendations });
  } catch (err) {
    if (err.message.includes('API key')) return res.status(503).json({ error: err.message });
    next(err);
  }
});

// ──────────────────────────────────────────────
//  Status
// ──────────────────────────────────────────────
router.get('/status', (_req, res) => {
  const status = ai.getStatus();
  const live   = buildLiveContext();
  return res.json({
    ...status,
    liveContext: {
      target:         live.target,
      hostsUp:        live.hostsUp,
      openPorts:      live.openPorts,
      vulnsFound:     live.vulnerabilities.length,
      hashescracked:  live.crackedHashes.length,
    },
  });
});

module.exports = router;

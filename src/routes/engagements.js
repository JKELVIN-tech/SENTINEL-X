'use strict';

/**
 * Sentinel X — Engagements Routes
 * GET    /api/engagements            List engagements
 * POST   /api/engagements            Create engagement
 * GET    /api/engagements/:id        Get engagement + stats
 * PATCH  /api/engagements/:id        Update engagement
 * DELETE /api/engagements/:id        Delete engagement (admin)
 * GET    /api/engagements/:id/stats  Live stats aggregation
 * GET    /api/engagements/:id/hosts  Discovered hosts
 * GET    /api/engagements/:id/vulns  Vulnerabilities
 */

const express = require('express');
const router  = express.Router();
const { requireAuth, requireRole } = require('../middleware/jwtAuth');
const { Engagements, Vulnerabilities, Hosts } = require('../db/repository');
const logger  = require('../utils/logger');

// GET /api/engagements
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const { status, limit = 20, offset = 0 } = req.query;
    const ownerId = req.user.role !== 'admin' ? req.user.id : req.query.ownerId;
    const list = await Engagements.list({ status, ownerId, limit: parseInt(limit), offset: parseInt(offset) });
    return res.json({ count: list.length, engagements: list });
  } catch (err) { next(err); }
});

// POST /api/engagements
router.post('/', requireAuth, async (req, res, next) => {
  try {
    const { name, description, target, scope } = req.body;
    if (!name || !target) return res.status(400).json({ error: 'name and target are required' });

    const engagement = await Engagements.create({
      name, description, target, scope,
      ownerId: req.user.id,
    });
    logger.info(`Engagement created: ${name} by ${req.user.username}`);
    return res.status(201).json(engagement);
  } catch (err) { next(err); }
});

// GET /api/engagements/:id
router.get('/:id', requireAuth, async (req, res, next) => {
  try {
    const engagement = await Engagements.findById(req.params.id);
    if (!engagement) return res.status(404).json({ error: 'Engagement not found' });
    const stats = await Engagements.stats(req.params.id);
    return res.json({ ...engagement, stats });
  } catch (err) { next(err); }
});

// PATCH /api/engagements/:id
router.patch('/:id', requireAuth, async (req, res, next) => {
  try {
    const { name, description, target, scope, status } = req.body;
    const engagement = await Engagements.update(req.params.id, { name, description, target, scope, status });
    if (!engagement) return res.status(404).json({ error: 'Engagement not found' });
    return res.json(engagement);
  } catch (err) { next(err); }
});

// DELETE /api/engagements/:id  (admin only)
router.delete('/:id', requireAuth, requireRole('admin'), async (req, res, next) => {
  try {
    await Engagements.delete(req.params.id);
    return res.json({ message: 'Engagement deleted' });
  } catch (err) { next(err); }
});

// GET /api/engagements/:id/stats
router.get('/:id/stats', requireAuth, async (req, res, next) => {
  try {
    const stats = await Engagements.stats(req.params.id);
    if (!stats) return res.status(404).json({ error: 'Engagement not found' });
    return res.json(stats);
  } catch (err) { next(err); }
});

// GET /api/engagements/:id/hosts
router.get('/:id/hosts', requireAuth, async (req, res, next) => {
  try {
    const { limit = 100, offset = 0 } = req.query;
    const hosts = await Hosts.listByEngagement(req.params.id, { limit: parseInt(limit), offset: parseInt(offset) });
    return res.json({ count: hosts.length, hosts });
  } catch (err) { next(err); }
});

// GET /api/engagements/:id/vulns
router.get('/:id/vulns', requireAuth, async (req, res, next) => {
  try {
    const { severity, status, limit = 100, offset = 0 } = req.query;
    const vulns = await Vulnerabilities.listByEngagement(
      req.params.id, { severity, status, limit: parseInt(limit), offset: parseInt(offset) }
    );
    return res.json({ count: vulns.length, vulnerabilities: vulns });
  } catch (err) { next(err); }
});

module.exports = router;

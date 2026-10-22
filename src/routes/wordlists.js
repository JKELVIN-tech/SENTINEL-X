'use strict';

/**
 * Sentinel X — Wordlist Manager Routes
 * ─────────────────────────────────────────────────────────────────────────────
 * GET    /api/wordlists              List all wordlists
 * GET    /api/wordlists/mutations    List available mutation rules
 * GET    /api/wordlists/preview      Preview a wordlist file
 * GET    /api/wordlists/search       Search inside a wordlist
 * POST   /api/wordlists/generate     Generate custom wordlist
 * POST   /api/wordlists/merge        Merge multiple wordlists
 * DELETE /api/wordlists/:name        Delete a local wordlist
 * ─────────────────────────────────────────────────────────────────────────────
 */

const express = require('express');
const router  = express.Router();
const fs      = require('fs');
const logger  = require('../utils/logger');
const wlm     = require('../modules/wordlistManager');

// GET /api/wordlists
router.get('/', async (req, res, next) => {
  try {
    const { category, source } = req.query;
    const lists = await wlm.listWordlists({ category, source });
    return res.json({ count: lists.length, wordlists: lists });
  } catch (err) { next(err); }
});

// GET /api/wordlists/mutations
router.get('/mutations', (_req, res) => {
  res.json({ mutations: wlm.listMutations() });
});

// GET /api/wordlists/preview?path=...&head=50&tail=10
router.get('/preview', async (req, res, next) => {
  try {
    const { path: filePath, head = 50, tail = 0 } = req.query;
    if (!filePath) return res.status(400).json({ error: 'path query param required' });

    // Security: only allow reading known wordlist paths or local dir
    const safe = await wlm.previewWordlist(filePath, {
      head: Math.min(parseInt(head) || 50, 200),
      tail: Math.min(parseInt(tail) || 0,  200),
    });
    return res.json(safe);
  } catch (err) {
    if (err.message.includes('not found')) return res.status(404).json({ error: err.message });
    next(err);
  }
});

// GET /api/wordlists/search?path=...&term=...&limit=100
router.get('/search', async (req, res, next) => {
  try {
    const { path: filePath, term, limit = 100, caseSensitive = 'false' } = req.query;
    if (!filePath) return res.status(400).json({ error: 'path query param required' });
    if (!term)     return res.status(400).json({ error: 'term query param required' });

    const result = await wlm.searchWordlist(filePath, term, {
      limit:         Math.min(parseInt(limit) || 100, 500),
      caseSensitive: caseSensitive === 'true',
    });
    return res.json(result);
  } catch (err) {
    if (err.message.includes('not found')) return res.status(404).json({ error: err.message });
    next(err);
  }
});

// POST /api/wordlists/generate
router.post('/generate', async (req, res, next) => {
  try {
    const { baseWords, mutations = [], outputName, minLen = 1, maxLen = 64 } = req.body;

    if (!baseWords || !Array.isArray(baseWords) || !baseWords.length) {
      return res.status(400).json({ error: 'baseWords[] array required' });
    }
    if (baseWords.length > 10_000) {
      return res.status(400).json({ error: 'baseWords[] max 10,000 entries' });
    }

    logger.info(`Generating wordlist — base: ${baseWords.length} words, mutations: ${mutations.join(',')}`);
    const result = await wlm.generateWordlist({ baseWords, mutations, outputName, minLen, maxLen });

    return res.status(201).json({
      message: 'Wordlist generated',
      ...result,
      links: { preview: `/api/wordlists/preview?path=${encodeURIComponent(result.path)}` },
    });
  } catch (err) { next(err); }
});

// POST /api/wordlists/merge
router.post('/merge', async (req, res, next) => {
  try {
    const { sources, outputName, deduplicate = true } = req.body;

    if (!sources || !Array.isArray(sources) || !sources.length) {
      return res.status(400).json({ error: 'sources[] array of file paths required' });
    }

    // Validate all sources exist
    const missing = sources.filter(s => !fs.existsSync(s));
    if (missing.length) {
      return res.status(400).json({ error: `Sources not found: ${missing.join(', ')}` });
    }

    logger.info(`Merging ${sources.length} wordlists → ${outputName || 'merged'}`);
    const result = await wlm.mergeWordlists({ sources, outputName, deduplicate });

    return res.status(201).json({
      message: 'Wordlists merged',
      ...result,
    });
  } catch (err) { next(err); }
});

// DELETE /api/wordlists/:name
router.delete('/:name', (req, res) => {
  const r = wlm.deleteWordlist(req.params.name);
  return r.ok
    ? res.json({ message: `Deleted ${req.params.name}` })
    : res.status(404).json(r);
});

module.exports = router;

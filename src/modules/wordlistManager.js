'use strict';

/**
 * Sentinel X — Wordlist Manager
 * ─────────────────────────────────────────────────────────────────────────────
 * Features:
 *   • Enumerate system wordlists (Kali / SecLists paths)
 *   • Generate custom wordlists with mutation rules
 *   • Merge + deduplicate wordlists
 *   • Count lines efficiently (streaming)
 *   • Search inside a wordlist
 *   • Preview first/last N lines
 * ─────────────────────────────────────────────────────────────────────────────
 */

const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const { v4: uuid } = require('uuid');
const logger   = require('../utils/logger');

const WORDLISTS_DIR  = process.env.WORDLISTS_DIR || './wordlists';
const REPORTS_DIR    = process.env.REPORTS_DIR   || './reports';
const MAX_PREVIEW    = 200;
const MAX_GENERATE   = 5_000_000; // safety cap for generators

// Ensure dirs exist
[WORDLISTS_DIR, REPORTS_DIR].forEach(d => {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
});

// ──────────────────────────────────────────────
//  Known Kali / SecLists paths
// ──────────────────────────────────────────────
const KNOWN_WORDLISTS = [
  // Passwords
  { name: 'rockyou.txt',           path: '/usr/share/wordlists/rockyou.txt',                                              category: 'passwords',   source: 'kali'     },
  { name: 'fasttrack.txt',         path: '/usr/share/wordlists/fasttrack.txt',                                            category: 'passwords',   source: 'kali'     },
  { name: 'darkweb2017-top10k.txt',path: '/usr/share/seclists/Passwords/darkweb2017-top10000.txt',                        category: 'passwords',   source: 'seclists' },
  { name: '10m-passwords-top1m.txt',path:'/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',category:'passwords',source:'seclists'},
  { name: 'probable-v2-top12k.txt',path: '/usr/share/seclists/Passwords/Leaked-Databases/probable-v2-top12000.txt',       category: 'passwords',   source: 'seclists' },
  // Usernames
  { name: 'usernames-shortlist.txt',path: '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',                   category: 'usernames',   source: 'seclists' },
  { name: 'names.txt',              path: '/usr/share/seclists/Usernames/Names/names.txt',                                category: 'usernames',   source: 'seclists' },
  { name: 'xato-usernames-top1m.txt',path:'/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt',             category: 'usernames',   source: 'seclists' },
  // Directories / Web
  { name: 'directory-list-2.3-medium.txt', path: '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',         category: 'directories', source: 'kali'     },
  { name: 'raft-large-directories.txt',     path: '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt',category: 'directories', source: 'seclists' },
  { name: 'common.txt',                     path: '/usr/share/seclists/Discovery/Web-Content/common.txt',                 category: 'directories', source: 'seclists' },
  // Subdomains
  { name: 'subdomains-top1m-5000.txt', path: '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',        category: 'subdomains',  source: 'seclists' },
  // Fuzzing
  { name: 'fuzz.txt',                  path: '/usr/share/seclists/Fuzzing/fuzz.txt',                                     category: 'fuzzing',     source: 'seclists' },
];

// ──────────────────────────────────────────────
//  Mutation engine
// ──────────────────────────────────────────────
const MUTATIONS = {
  leet: w => w
    .replace(/a/gi, '4').replace(/e/gi, '3').replace(/i/gi, '1')
    .replace(/o/gi, '0').replace(/s/gi, '5').replace(/t/gi, '7'),

  capitalize: w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase(),

  upperCase: w => w.toUpperCase(),

  reverse: w => w.split('').reverse().join(''),

  appendYears: w => {
    const out = [];
    for (let y = 2018; y <= 2025; y++) out.push(w + y, w + String(y).slice(2));
    return out;
  },

  appendSymbols: w => ['!','@','#','$','!!','123','!@#','@123'].map(s => w + s),

  prependNumbers: w => ['1','2','123','1234'].map(n => n + w),

  doubleWord: w => w + w,

  camelCase: w => {
    const parts = w.split(/[\s_-]/);
    return parts[0].toLowerCase() + parts.slice(1).map(p => p.charAt(0).toUpperCase() + p.slice(1)).join('');
  },
};

function applyMutations(word, mutationIds = []) {
  const results = new Set([word]);
  for (const id of mutationIds) {
    const fn = MUTATIONS[id];
    if (!fn) continue;
    for (const base of [...results]) {
      const out = fn(base);
      if (Array.isArray(out)) out.forEach(o => results.add(o));
      else results.add(out);
    }
  }
  return [...results];
}

// ──────────────────────────────────────────────
//  Efficient line counter
// ──────────────────────────────────────────────
function countLines(filePath) {
  return new Promise((resolve, reject) => {
    let count = 0;
    const stream = fs.createReadStream(filePath);
    stream.on('data', chunk => {
      for (let i = 0; i < chunk.length; i++) {
        if (chunk[i] === 10) count++; // newline byte
      }
    });
    stream.on('end', () => resolve(count));
    stream.on('error', reject);
  });
}

// ──────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────

/**
 * listWordlists({ category, source, includeLocal })
 * Returns metadata for all discovered wordlists.
 */
async function listWordlists({ category, source, includeLocal = true } = {}) {
  const results = [];

  // Known system wordlists
  for (const wl of KNOWN_WORDLISTS) {
    if (category && wl.category !== category) continue;
    if (source   && wl.source   !== source)   continue;

    if (fs.existsSync(wl.path)) {
      const stat   = fs.statSync(wl.path);
      let lineCount = null;
      try { lineCount = await countLines(wl.path); } catch (_) {}
      results.push({
        ...wl,
        exists:    true,
        sizeMB:    (stat.size / 1024 / 1024).toFixed(2),
        sizeBytes: stat.size,
        lines:     lineCount,
      });
    } else {
      results.push({ ...wl, exists: false, sizeMB: null, sizeBytes: null, lines: null });
    }
  }

  // Local wordlists
  if (includeLocal && fs.existsSync(WORDLISTS_DIR)) {
    for (const f of fs.readdirSync(WORDLISTS_DIR)) {
      if (!f.endsWith('.txt') && !f.endsWith('.lst')) continue;
      const full = path.join(WORDLISTS_DIR, f);
      if (!fs.statSync(full).isFile()) continue;
      const stat    = fs.statSync(full);
      let lineCount = null;
      try { lineCount = await countLines(full); } catch (_) {}
      results.push({
        name:      f,
        path:      full,
        category:  'custom',
        source:    'local',
        exists:    true,
        sizeMB:    (stat.size / 1024 / 1024).toFixed(2),
        sizeBytes: stat.size,
        lines:     lineCount,
      });
    }
  }

  return results;
}

/**
 * previewWordlist(filePath, { head, tail })
 * Returns first/last N lines without loading entire file.
 */
async function previewWordlist(filePath, { head = 50, tail = 0 } = {}) {
  if (!fs.existsSync(filePath)) throw new Error('Wordlist file not found');

  const headLines = [];
  const tailBuf   = [];
  const limit     = Math.min(head, MAX_PREVIEW);

  const rl = readline.createInterface({ input: fs.createReadStream(filePath), crlfDelay: Infinity });
  let total = 0;

  for await (const line of rl) {
    total++;
    if (headLines.length < limit) headLines.push(line);
    if (tail > 0) {
      tailBuf.push(line);
      if (tailBuf.length > tail) tailBuf.shift();
    }
  }

  return { total, head: headLines, tail: tailBuf };
}

/**
 * generateWordlist({ baseWords[], mutations[], outputName, minLen, maxLen })
 * Returns { path, lines }
 */
async function generateWordlist({ baseWords = [], mutations = [], outputName, minLen = 1, maxLen = 64 }) {
  if (!baseWords.length) throw new Error('baseWords[] required');

  const name   = (outputName || `custom_${Date.now()}`).replace(/[^a-z0-9_-]/gi, '_') + '.txt';
  const outPath = path.join(WORDLISTS_DIR, name);
  const stream  = fs.createWriteStream(outPath);

  const seen  = new Set();
  let   count = 0;

  for (const word of baseWords) {
    if (!word || typeof word !== 'string') continue;
    const variants = applyMutations(word.trim(), mutations);
    for (const v of variants) {
      if (v.length < minLen || v.length > maxLen) continue;
      if (seen.has(v)) continue;
      seen.add(v);
      stream.write(v + '\n');
      count++;
      if (count >= MAX_GENERATE) break;
    }
    if (count >= MAX_GENERATE) break;
  }

  await new Promise((resolve, reject) => {
    stream.end();
    stream.on('finish', resolve);
    stream.on('error', reject);
  });

  logger.info(`Generated wordlist: ${outPath} (${count} entries)`);
  return { path: outPath, name, lines: count };
}

/**
 * mergeWordlists({ sources[], outputName, deduplicate })
 */
async function mergeWordlists({ sources = [], outputName, deduplicate = true }) {
  if (!sources.length) throw new Error('sources[] required');

  const name    = (outputName || `merged_${Date.now()}`).replace(/[^a-z0-9_-]/gi, '_') + '.txt';
  const outPath = path.join(WORDLISTS_DIR, name);
  const out     = fs.createWriteStream(outPath);
  const seen    = deduplicate ? new Set() : null;
  let   count   = 0;

  for (const src of sources) {
    if (!fs.existsSync(src)) {
      logger.warn(`mergeWordlists: skipping missing file ${src}`);
      continue;
    }
    const rl = readline.createInterface({ input: fs.createReadStream(src), crlfDelay: Infinity });
    for await (const line of rl) {
      const w = line.trim();
      if (!w) continue;
      if (seen) {
        if (seen.has(w)) continue;
        seen.add(w);
      }
      out.write(w + '\n');
      count++;
    }
  }

  await new Promise((resolve, reject) => {
    out.end();
    out.on('finish', resolve);
    out.on('error', reject);
  });

  logger.info(`Merged wordlist: ${outPath} (${count} entries from ${sources.length} sources)`);
  return { path: outPath, name, lines: count };
}

/**
 * searchWordlist(filePath, term, { limit, caseSensitive })
 */
async function searchWordlist(filePath, term, { limit = 100, caseSensitive = false } = {}) {
  if (!fs.existsSync(filePath)) throw new Error('Wordlist not found');

  const results = [];
  const search  = caseSensitive ? term : term.toLowerCase();
  const rl      = readline.createInterface({ input: fs.createReadStream(filePath), crlfDelay: Infinity });

  for await (const line of rl) {
    const w = line.trim();
    if (!w) continue;
    const check = caseSensitive ? w : w.toLowerCase();
    if (check.includes(search)) {
      results.push(w);
      if (results.length >= limit) break;
    }
  }

  rl.close();
  return { term, found: results.length, results };
}

/**
 * deleteWordlist(filename)  — only deletes from local WORDLISTS_DIR
 */
function deleteWordlist(filename) {
  // Prevent path traversal
  const safe = path.basename(filename);
  const full = path.join(WORDLISTS_DIR, safe);
  if (!fs.existsSync(full)) return { ok: false, error: 'Not found' };
  fs.unlinkSync(full);
  return { ok: true };
}

/** Available mutation IDs for the API */
function listMutations() {
  return Object.keys(MUTATIONS).map(id => ({
    id,
    description: {
      leet:          'Replace letters with numbers (a→4, e→3, i→1, o→0, s→5, t→7)',
      capitalize:    'Capitalize first letter',
      upperCase:     'ALL CAPS',
      reverse:       'Reverse the word',
      appendYears:   'Append years 2018–2025 (and 2-digit variants)',
      appendSymbols: 'Append common symbols and number suffixes',
      prependNumbers:'Prepend 1, 2, 123, 1234',
      doubleWord:    'Duplicate the word (passwordpassword)',
      camelCase:     'Convert to camelCase',
    }[id] || id,
  }));
}

module.exports = {
  listWordlists,
  previewWordlist,
  generateWordlist,
  mergeWordlists,
  searchWordlist,
  deleteWordlist,
  listMutations,
};

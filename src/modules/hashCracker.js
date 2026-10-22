'use strict';

/**
 * Sentinel X — Hash Cracker Engine
 * ─────────────────────────────────────────────────────────────────────────────
 * Supports three attack modes:
 *
 *  1. DICTIONARY  — Pure Node.js crypto, no external dependency.
 *                   Streams wordlist file line-by-line for low memory usage.
 *                   Handles MD5, SHA-1, SHA-256, SHA-512, NTLM natively.
 *
 *  2. BRUTE-FORCE — Node.js mask-based generator for short passwords.
 *                   Charset: lowercase | uppercase | digits | symbols | custom.
 *
 *  3. HASHCAT     — Delegates to system hashcat binary when available.
 *                   Full GPU acceleration, all modes, rule support.
 *                   Streams hashcat stdout for real-time progress.
 *
 * All jobs tracked in memory with WebSocket broadcast on every event.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const crypto   = require('crypto');
const fs       = require('fs');
const path     = require('path');
const readline = require('readline');
const { spawn }  = require('child_process');
const { v4: uuid } = require('uuid');
const logger     = require('../utils/logger');
const { md4 }    = require('../utils/md4');
const { identifyHash, hashcatModeFor } = require('./hashIdentifier');
const { resolveBinary, HASHCAT_COMMON_PATHS, IS_WINDOWS } = require('../utils/binLocator');

// ── Config
const { bin: HASHCAT_BIN, source: HASHCAT_BIN_SOURCE } = resolveBinary('hashcat', {
  envVar: 'HASHCAT_BINARY',
  commonPaths: HASHCAT_COMMON_PATHS,
});
logger.info(`HashCracker: using hashcat binary "${HASHCAT_BIN}" (resolved via ${HASHCAT_BIN_SOURCE})`);

const WORDLISTS_DIR = process.env.WORDLISTS_DIR    || './wordlists';
const REPORTS_DIR   = process.env.REPORTS_DIR      || './reports';
const MAX_JOBS      = 2;

// ── Job store
const jobs      = new Map();
let activeCount = 0;

// ── Charsets for brute-force
const CHARSETS = {
  lower:   'abcdefghijklmnopqrstuvwxyz',
  upper:   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits:  '0123456789',
  symbols: '!@#$%^&*()-_=+[]{}|;:,.<>?',
  hex:     '0123456789abcdef',
};

// ──────────────────────────────────────────────
//  Native hash computation
// ──────────────────────────────────────────────

/**
 * Compute hash of a plaintext candidate.
 * Supports: md5, sha1, sha256, sha512, ntlm, sha224, sha384
 */
function computeHash(plaintext, algorithm) {
  const algo = algorithm.toLowerCase().replace(/-/g, '');

  if (algo === 'ntlm') {
    // NTLM = MD4 of UTF-16LE encoded password
    // Use pure-JS MD4 — Node 22+ dropped MD4 from OpenSSL
    return md4(Buffer.from(plaintext, 'utf16le'));
  }

  // Map common aliases
  const algoMap = {
    md5: 'md5', sha1: 'sha1',
    sha256: 'sha256', sha224: 'sha224',
    sha384: 'sha384', sha512: 'sha512',
    sha3256: 'sha3-256', sha3512: 'sha3-512',
    sha3224: 'sha3-224', sha3384: 'sha3-384',
    ripemd160: 'ripemd160', whirlpool: 'whirlpool',
    blake2b512: 'blake2b512', blake2s256: 'blake2s256',
  };

  const mapped = algoMap[algo] || algo;
  try {
    return crypto.createHash(mapped).update(plaintext, 'utf8').digest('hex');
  } catch (_) {
    return null;
  }
}

// ──────────────────────────────────────────────
//  Broadcast helper
// ──────────────────────────────────────────────
function broadcast(data) {
  if (typeof global.broadcast === 'function') global.broadcast(data);
}

// ──────────────────────────────────────────────
//  Dictionary attack (pure Node.js)
// ──────────────────────────────────────────────
async function runDictionary(job) {
  const { hashes, hashType: algorithm, wordlistPath } = job;

  if (!fs.existsSync(wordlistPath)) {
    throw new Error(`Wordlist not found: ${wordlistPath}`);
  }

  const remaining  = new Map(hashes.map(h => [h.toLowerCase(), h]));
  const cracked    = new Map();
  let   tested     = 0;
  let   lastUpdate = Date.now();

  const rl = readline.createInterface({
    input:     fs.createReadStream(wordlistPath),
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    if (job.status === 'cancelled') break;

    const word = line.trim();
    if (!word) continue;

    tested++;
    const digest = computeHash(word, algorithm);
    if (digest === null) continue;

    if (remaining.has(digest)) {
      const originalHash = remaining.get(digest);
      cracked.set(originalHash, word);
      remaining.delete(digest);

      job.cracked   = Object.fromEntries(cracked);
      job.crackedCount = cracked.size;

      logger.info(`[${job.id}] CRACKED: ${originalHash} → "${word}"`);
      broadcast({ type: 'hash_cracked', jobId: job.id, hash: originalHash, plaintext: word });

      if (remaining.size === 0) break; // all cracked
    }

    // Progress update every 2s
    const now = Date.now();
    if (now - lastUpdate >= 2000) {
      const elapsed = (now - new Date(job.startedAt).getTime()) / 1000;
      const hps     = elapsed > 0 ? Math.round(tested / elapsed) : 0;

      job.tested   = tested;
      job.hashRate = hps;
      lastUpdate   = now;

      broadcast({
        type: 'hash_progress',
        jobId:      job.id,
        tested,
        hashRate:   hps,
        crackedCount: cracked.size,
        totalHashes:  hashes.length,
      });
    }
  }

  job.tested     = tested;
  job.cracked    = Object.fromEntries(cracked);
  job.crackedCount = cracked.size;
  job.remaining  = [...remaining.keys()];
}

// ──────────────────────────────────────────────
//  Brute-force attack (Node.js mask generator)
// ──────────────────────────────────────────────
async function runBruteForce(job) {
  const { hashes, hashType: algorithm, bruteOpts = {} } = job;
  const {
    minLen    = 1,
    maxLen    = 6,
    charsets  = ['lower', 'digits'],
    customChars = '',
  } = bruteOpts;

  // Build charset
  let charset = charsets.reduce((acc, c) => acc + (CHARSETS[c] || ''), '');
  if (customChars) charset += customChars;
  charset = [...new Set(charset.split(''))].join(''); // deduplicate chars

  if (!charset) throw new Error('No charset specified for brute-force');

  // Total keyspace across all lengths — lets us show ETA/remaining in
  // progress updates instead of just a raw "tested" counter.
  let totalCandidates = 0;
  for (let len = minLen; len <= maxLen; len++) totalCandidates += Math.pow(charset.length, len);
  job.totalCandidates = totalCandidates;

  const remaining = new Map(hashes.map(h => [h.toLowerCase(), h]));
  const cracked   = new Map();
  let   tested    = 0;
  let   lastUpdate = Date.now();

  // Iterative mask generator — avoids deep recursion
  function* maskGenerator(len) {
    const indices = new Array(len).fill(0);
    const base    = charset.length;
    while (true) {
      yield indices.map(i => charset[i]).join('');
      // Increment
      let pos = len - 1;
      while (pos >= 0) {
        indices[pos]++;
        if (indices[pos] < base) break;
        indices[pos] = 0;
        pos--;
      }
      if (pos < 0) return; // exhausted
    }
  }

  outer:
  for (let len = minLen; len <= maxLen; len++) {
    if (job.status === 'cancelled') break;
    logger.info(`[${job.id}] Brute-force: trying length ${len} (charset size: ${charset.length})`);
    broadcast({ type: 'hash_log', jobId: job.id, message: `Trying length ${len}...` });

    for (const candidate of maskGenerator(len)) {
      if (job.status === 'cancelled') break outer;

      tested++;
      const digest = computeHash(candidate, algorithm);
      if (digest && remaining.has(digest)) {
        const orig = remaining.get(digest);
        cracked.set(orig, candidate);
        remaining.delete(digest);
        job.cracked      = Object.fromEntries(cracked);
        job.crackedCount = cracked.size;
        logger.info(`[${job.id}] CRACKED: ${orig} → "${candidate}"`);
        broadcast({ type: 'hash_cracked', jobId: job.id, hash: orig, plaintext: candidate });
        if (remaining.size === 0) break outer;
      }

      // Throttled progress
      const now = Date.now();
      if (now - lastUpdate >= 1500) {
        const hps = Math.round(tested / ((now - new Date(job.startedAt).getTime()) / 1000));
        const remainingCandidates = Math.max(0, totalCandidates - tested);
        const etaSeconds = hps > 0 ? Math.round(remainingCandidates / hps) : null;
        job.tested   = tested;
        job.hashRate = hps;
        job.etaSeconds = etaSeconds;
        lastUpdate   = now;
        broadcast({
          type: 'hash_progress', jobId: job.id, tested, hashRate: hps,
          crackedCount: cracked.size, totalCandidates, etaSeconds,
        });
      }
    }
  }

  job.tested     = tested;
  job.cracked    = Object.fromEntries(cracked);
  job.crackedCount = cracked.size;
  job.remaining  = [...remaining.keys()];
}

// ──────────────────────────────────────────────
//  Hashcat integration
// ──────────────────────────────────────────────
function runHashcat(job) {
  return new Promise((resolve, reject) => {
    const { hashes, hashType, wordlistPath, rules = [], hashcatOpts = {} } = job;

    // Write hashes to temp file
    const hashFile = path.join(REPORTS_DIR, `hash_${job.id}.txt`);
    const potFile  = path.join(REPORTS_DIR, `hash_${job.id}.pot`);
    fs.writeFileSync(hashFile, hashes.join('\n') + '\n');

    // Determine hashcat mode
    const mode = hashcatOpts.mode || hashcatModeFor(hashType) || 0;

    const argv = [
      '--quiet',
      '-m', String(mode),
      '-a', String(hashcatOpts.attackMode || 0),  // 0=dict, 3=brute
      '--potfile-path', potFile,
      '--status',
      '--status-timer', '3',
      hashFile,
    ];

    if (wordlistPath && fs.existsSync(wordlistPath)) argv.push(wordlistPath);
    if (rules.length) rules.forEach(r => argv.push('-r', r));

    logger.info(`[${job.id}] hashcat ${argv.join(' ')}`);
    broadcast({ type: 'hash_log', jobId: job.id, message: `Launching hashcat mode ${mode}` });

    const proc = spawn(HASHCAT_BIN, argv, { stdio: ['ignore', 'pipe', 'pipe'] });
    job.process = proc;

    let buf = '';
    proc.stdout.on('data', chunk => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop();
      for (const line of lines) {
        const t = line.trim();
        if (!t) continue;
        job.output = job.output || [];
        job.output.push(t);

        // Parse cracked lines: hash:plaintext
        const crackedMatch = t.match(/^([a-f0-9*$]+.+?):(.+)$/i);
        if (crackedMatch) {
          const [, hash, plain] = crackedMatch;
          job.cracked    = job.cracked || {};
          job.cracked[hash.toLowerCase()] = plain;
          job.crackedCount = Object.keys(job.cracked).length;
          broadcast({ type: 'hash_cracked', jobId: job.id, hash, plaintext: plain });
        }

        // Parse progress from status lines
        const progressMatch = t.match(/Progress\.+:\s*([\d/]+)/);
        if (progressMatch) {
          const [tested, total] = progressMatch[1].split('/').map(Number);
          job.tested = tested;
          broadcast({ type: 'hash_progress', jobId: job.id, tested, total, crackedCount: job.crackedCount || 0 });
        }

        broadcast({ type: 'hash_output', jobId: job.id, line: t });
      }
    });

    proc.stderr.on('data', chunk => {
      const msg = chunk.toString().trim();
      if (msg) logger.warn(`[${job.id}] hashcat stderr: ${msg}`);
    });

    proc.on('close', code => {
      // Parse pot file for final results
      if (fs.existsSync(potFile)) {
        const lines = fs.readFileSync(potFile, 'utf8').trim().split('\n').filter(Boolean);
        job.cracked = job.cracked || {};
        for (const line of lines) {
          const colonIdx = line.lastIndexOf(':');
          if (colonIdx !== -1) {
            const hash  = line.slice(0, colonIdx).toLowerCase();
            const plain = line.slice(colonIdx + 1);
            job.cracked[hash] = plain;
          }
        }
        job.crackedCount = Object.keys(job.cracked).length;
        // Cleanup temp files
        try { fs.unlinkSync(hashFile); fs.unlinkSync(potFile); } catch (_) {}
      }
      resolve(code);
    });

    proc.on('error', reject);
  });
}

// ──────────────────────────────────────────────
//  Job executor
// ──────────────────────────────────────────────
async function executeJob(jobId) {
  const job = jobs.get(jobId);
  if (!job) return;

  job.status    = 'running';
  job.startedAt = new Date().toISOString();
  activeCount++;

  broadcast({ type: 'crack_started', jobId, hashes: job.hashes, mode: job.mode });
  logger.info(`[${jobId}] Starting ${job.mode} attack on ${job.hashes.length} hash(es) — algo: ${job.hashType}`);

  try {
    switch (job.mode) {
      case 'dictionary':
        await runDictionary(job);
        break;
      case 'bruteforce':
        await runBruteForce(job);
        break;
      case 'hashcat':
        await runHashcat(job);
        break;
      default:
        throw new Error(`Unknown mode: ${job.mode}`);
    }

    job.status      = job.status === 'cancelled' ? 'cancelled' : 'complete';
    job.completedAt = new Date().toISOString();
    const elapsed   = ((Date.now() - new Date(job.startedAt).getTime()) / 1000).toFixed(1);

    logger.info(`[${jobId}] Done — ${job.crackedCount}/${job.hashes.length} cracked in ${elapsed}s`);
    broadcast({
      type:         'crack_complete',
      jobId,
      status:       job.status,
      crackedCount: job.crackedCount,
      totalHashes:  job.hashes.length,
      cracked:      job.cracked,
      elapsed,
    });
  } catch (err) {
    job.status    = 'error';
    job.error     = err.message;
    job.completedAt = new Date().toISOString();
    logger.error(`[${jobId}] Error: ${err.message}`);
    broadcast({ type: 'crack_error', jobId, error: err.message });
  } finally {
    activeCount = Math.max(0, activeCount - 1);
    drainQueue();
  }
}

function drainQueue() {
  if (activeCount >= MAX_JOBS) return;
  for (const [, job] of jobs) {
    if (job.status === 'queued') {
      executeJob(job.id);
      return;
    }
  }
}

// ──────────────────────────────────────────────
//  Public API
// ──────────────────────────────────────────────

/**
 * startCrack({ hashes[], hashType, mode, wordlistPath, bruteOpts, rules, hashcatOpts, label })
 */
function startCrack(opts) {
  const {
    hashes      = [],
    hashType    = 'auto',
    mode        = 'dictionary',
    wordlistPath,
    bruteOpts   = {},
    rules       = [],
    hashcatOpts = {},
    label       = '',
  } = opts;

  if (!hashes.length) throw new Error('At least one hash is required');

  // Sanitise hashes
  const cleanHashes = hashes
    .map(h => h.trim())
    .filter(h => h.length >= 8 && /^[\x20-\x7E]+$/.test(h));

  if (!cleanHashes.length) throw new Error('No valid hashes provided');

  // Auto-detect hash type if needed
  let resolvedType = hashType;
  let autoDetected = [];
  if (hashType === 'auto' || !hashType) {
    autoDetected = identifyHash(cleanHashes[0]);
    resolvedType = autoDetected[0]?.id || 'md5';
  }

  // Resolve wordlist path
  let resolvedWordlist = wordlistPath;
  if (!resolvedWordlist && mode === 'dictionary') {
    // Try default rockyou location on Kali
    const defaults = [
      '/usr/share/wordlists/rockyou.txt',
      '/usr/share/wordlists/rockyou.txt.gz',
      path.join(WORDLISTS_DIR, 'rockyou.txt'),
    ];
    resolvedWordlist = defaults.find(p => fs.existsSync(p)) || defaults[0];
  }

  const jobId = uuid();
  const job   = {
    id:           jobId,
    label:        label || `${mode} / ${resolvedType}`,
    hashes:       cleanHashes,
    hashType:     resolvedType,
    autoDetected,
    mode,
    wordlistPath: resolvedWordlist,
    bruteOpts,
    rules,
    hashcatOpts,
    status:       'queued',
    createdAt:    new Date().toISOString(),
    startedAt:    null,
    completedAt:  null,
    tested:       0,
    hashRate:     0,
    cracked:      {},
    crackedCount: 0,
    remaining:    cleanHashes.slice(),
    output:       [],
    error:        null,
    process:      null,
  };

  jobs.set(jobId, job);
  logger.info(`[${jobId}] Queued crack — ${cleanHashes.length} hashes, mode: ${mode}, type: ${resolvedType}`);
  broadcast({ type: 'crack_queued', jobId, hashes: cleanHashes.length, mode, hashType: resolvedType });

  if (activeCount < MAX_JOBS) executeJob(jobId);

  return { jobId, status: 'queued', hashType: resolvedType, autoDetected };
}

function cancelCrack(jobId) {
  const job = jobs.get(jobId);
  if (!job) return { ok: false, error: 'Not found' };
  if (['complete','cancelled','error'].includes(job.status)) {
    return { ok: false, error: `Job already ${job.status}` };
  }
  job.status = 'cancelled';
  if (job.process) {
    try { job.process.kill('SIGTERM'); } catch (_) {}
  }
  logger.info(`[${jobId}] Cancelled`);
  broadcast({ type: 'crack_cancelled', jobId });
  drainQueue();
  return { ok: true };
}

function getJob(jobId) {
  const job = jobs.get(jobId);
  if (!job) return null;
  const { process: _p, ...safe } = job;
  return safe;
}

function listJobs() {
  return [...jobs.values()].map(({ process: _p, output: _o, ...j }) => j);
}

function deleteJob(jobId) {
  const job = jobs.get(jobId);
  if (!job) return { ok: false, error: 'Not found' };
  if (job.status === 'running') cancelCrack(jobId);
  jobs.delete(jobId);
  return { ok: true };
}

/** Check if hashcat binary is available */
function checkHashcat() {
  return new Promise(resolve => {
    const proc = spawn(HASHCAT_BIN, ['--version'], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    proc.stdout.on('data', d => (out += d));
    proc.on('close', code => {
      resolve({ available: code === 0, binary: HASHCAT_BIN, version: out.trim() || null });
    });
    proc.on('error', err => {
      const hint = err.code === 'ENOENT'
        ? (IS_WINDOWS
            ? 'hashcat not found. Download it from https://hashcat.net/hashcat/ and set ' +
              'HASHCAT_BINARY in .env to the full .exe path, or add its folder to PATH. ' +
              'Note: dictionary and brute-force modes work without hashcat.'
            : 'hashcat not found. Install it or set HASHCAT_BINARY in .env to its full path. ' +
              'Note: dictionary and brute-force modes work without hashcat.')
        : err.message;
      resolve({ available: false, binary: HASHCAT_BIN, version: null, error: hint });
    });
  });
}

/** List available wordlists from the wordlists directory */
function listWordlists() {
  const known = [
    '/usr/share/wordlists/rockyou.txt',
    '/usr/share/wordlists/fasttrack.txt',
    '/usr/share/seclists/Passwords/darkweb2017-top10000.txt',
    '/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt',
    '/usr/share/seclists/Usernames/top-usernames-shortlist.txt',
  ];

  const results = [];
  // Check known Kali paths
  for (const p of known) {
    if (fs.existsSync(p)) {
      const stat = fs.statSync(p);
      results.push({
        path:    p,
        name:    path.basename(p),
        sizeMB:  (stat.size / 1024 / 1024).toFixed(1),
        source:  'system',
      });
    }
  }

  // Check local wordlists dir
  if (fs.existsSync(WORDLISTS_DIR)) {
    for (const f of fs.readdirSync(WORDLISTS_DIR)) {
      const full = path.join(WORDLISTS_DIR, f);
      if (fs.statSync(full).isFile()) {
        const stat = fs.statSync(full);
        results.push({
          path:    full,
          name:    f,
          sizeMB:  (stat.size / 1024 / 1024).toFixed(1),
          source:  'local',
        });
      }
    }
  }

  return results;
}

module.exports = {
  startCrack,
  cancelCrack,
  getJob,
  listJobs,
  deleteJob,
  checkHashcat,
  listWordlists,
  computeHash,
};

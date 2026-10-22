#!/usr/bin/env node
'use strict';

/**
 * Sentinel X — Cross-platform setup script
 * ─────────────────────────────────────────────────────────────────────────────
 * Replaces the old bash-only setup.sh for anyone not on a Debian/Ubuntu box
 * (Windows, macOS, other Linux distros, WSL). Pure Node.js, no external deps,
 * so it can run before `npm install` has happened.
 *
 * Run:  node scripts/setup.js
 *   or: npm run setup
 * ─────────────────────────────────────────────────────────────────────────────
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const IS_WINDOWS = process.platform === 'win32';

const c = {
  green: s => `\x1b[32m${s}\x1b[0m`,
  cyan: s => `\x1b[36m${s}\x1b[0m`,
  yellow: s => `\x1b[33m${s}\x1b[0m`,
  red: s => `\x1b[31m${s}\x1b[0m`,
  bold: s => `\x1b[1m${s}\x1b[0m`,
};
const ok = m => console.log(`  ${c.green('✔')}  ${m}`);
const info = m => console.log(`  ${c.cyan('→')}  ${m}`);
const warn = m => console.log(`  ${c.yellow('⚠')}  ${m}`);
const hr = () => console.log(c.cyan('  ────────────────────────────────────────'));

console.log(c.cyan(`
  ╔══════════════════════════════════════════╗
  ║     SENTINEL X — CROSS-PLATFORM SETUP    ║
  ╚══════════════════════════════════════════╝
`));

info(`Platform: ${process.platform} (${os_arch()})`);
info(`Working directory: ${ROOT}`);
hr();

function os_arch() {
  return require('os').arch();
}

// ── Step 1: Node version check
const [major] = process.versions.node.split('.').map(Number);
if (major < 18) {
  console.log(c.red(`  ✘  Node.js ${process.versions.node} detected — Sentinel X needs Node 18+.`));
  console.log(`     Download: https://nodejs.org/`);
  process.exit(1);
}
ok(`Node.js ${process.versions.node}`);
hr();

// ── Step 2: .env file
const envPath = path.join(ROOT, '.env');
const envExamplePath = path.join(ROOT, '.env.example');

function randomHex(bytes) {
  return crypto.randomBytes(bytes).toString('hex');
}

if (!fs.existsSync(envPath)) {
  if (!fs.existsSync(envExamplePath)) {
    console.log(c.red('  ✘  .env.example not found — cannot bootstrap .env'));
    process.exit(1);
  }
  let content = fs.readFileSync(envExamplePath, 'utf8');
  content = content
    .replace('API_KEY=CHANGE_ME_run_openssl_rand_hex_24', `API_KEY=${randomHex(24)}`)
    .replace('JWT_SECRET=CHANGE_ME_run_openssl_rand_hex_32', `JWT_SECRET=${randomHex(32)}`);
  fs.writeFileSync(envPath, content);
  ok('.env created from .env.example with fresh secrets');
} else {
  // Still patch any leftover placeholder secrets
  let content = fs.readFileSync(envPath, 'utf8');
  let changed = false;
  if (content.includes('CHANGE_ME_run_openssl_rand_hex_24')) {
    content = content.replace('CHANGE_ME_run_openssl_rand_hex_24', randomHex(24));
    changed = true;
  }
  if (content.includes('CHANGE_ME_run_openssl_rand_hex_32')) {
    content = content.replace('CHANGE_ME_run_openssl_rand_hex_32', randomHex(32));
    changed = true;
  }
  if (changed) {
    fs.writeFileSync(envPath, content);
    ok('.env already existed — replaced leftover placeholder secrets');
  } else {
    ok('.env already exists (keeping existing values)');
  }
}

require('dotenv').config({ path: envPath });
hr();

// ── Step 3: directories
const dirs = ['logs', 'reports/nmap', 'reports/hash', 'wordlists'];
for (const d of dirs) {
  const full = path.join(ROOT, d);
  if (!fs.existsSync(full)) fs.mkdirSync(full, { recursive: true });
}
ok(`Directories ready: ${dirs.join(', ')}`);
hr();

// ── Step 4: npm install (only if node_modules missing)
const nodeModules = path.join(ROOT, 'node_modules');
if (!fs.existsSync(nodeModules)) {
  info('Installing npm packages (this may take a minute)...');
  const npmCmd = IS_WINDOWS ? 'npm.cmd' : 'npm';
  const res = spawnSync(npmCmd, ['install'], { cwd: ROOT, stdio: 'inherit' });
  if (res.status !== 0) {
    console.log(c.red('  ✘  npm install failed — see output above'));
    process.exit(1);
  }
  ok('npm packages installed');
} else {
  ok('node_modules already present — skipping npm install');
}
hr();

// ── Step 5: detect nmap / hashcat
function detect(name) {
  const whichCmd = IS_WINDOWS ? 'where' : 'which';
  try {
    const out = execFileSync(whichCmd, [name], { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString().split(/\r?\n/)[0].trim();
    return out || null;
  } catch (_) {
    return null;
  }
}

const nmapPath = detect('nmap');
if (nmapPath) {
  ok(`nmap found: ${nmapPath}`);
} else {
  warn('nmap not found on PATH.');
  if (IS_WINDOWS) {
    console.log(`     Install from https://nmap.org/download.html#windows, then either`);
    console.log(`     add it to PATH or set NMAP_BINARY in .env to its full .exe path.`);
  } else {
    console.log(`     Install it (e.g. \`sudo apt install nmap\` or \`brew install nmap\`)`);
    console.log(`     or set NMAP_BINARY in .env to its full path.`);
  }
}

const hashcatPath = detect('hashcat');
if (hashcatPath) {
  ok(`hashcat found: ${hashcatPath}`);
} else {
  warn('hashcat not found on PATH (optional — dictionary/brute-force modes work without it).');
}
hr();

// ── Step 6: database
info('Checking PostgreSQL connection...');
(async () => {
  let pgOk = false;
  try {
    // Loaded lazily — only exists once npm install has completed.
    const { Pool } = require(path.join(nodeModules, 'pg'));
    const pool = new Pool({
      host: process.env.DB_HOST || '127.0.0.1',
      port: parseInt(process.env.DB_PORT) || 5432,
      database: process.env.DB_NAME || 'sentinelx',
      user: process.env.DB_USER || 'sentinelx',
      password: process.env.DB_PASSWORD || 'sentinelx',
      connectionTimeoutMillis: 4000,
    });
    await pool.query('SELECT 1');
    await pool.end();
    pgOk = true;
    ok('Connected to PostgreSQL with the configured credentials');
  } catch (err) {
    warn(`Could not connect to PostgreSQL: ${err.message}`);
    printDbInstructions();
  }
  hr();

  // ── Step 7: migrations
  if (pgOk) {
    info('Running database migrations...');
    const res = spawnSync(process.execPath, [path.join(ROOT, 'src', 'db', 'migrate.js')], {
      cwd: ROOT, stdio: 'inherit',
    });
    if (res.status === 0) ok('Migrations complete');
    else warn('Migrations failed — see output above. You can retry with: npm run db:migrate');
  } else {
    warn('Skipping migrations — fix the DB connection above, then run: npm run db:migrate');
  }
  hr();
  printSummary();
})();

function printDbInstructions() {
  const { DB_HOST = '127.0.0.1', DB_PORT = '5432', DB_NAME = 'sentinelx', DB_USER = 'sentinelx', DB_PASSWORD = 'sentinelx' } = process.env;
  console.log('');
  console.log(c.bold('  To create the database and user, run (requires PostgreSQL installed):'));
  console.log('');
  if (IS_WINDOWS) {
    console.log(c.cyan(`    psql -U postgres -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';"`));
    console.log(c.cyan(`    psql -U postgres -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"`));
    console.log('');
    console.log('    (psql ships with the PostgreSQL Windows installer — if "psql" is not');
    console.log('     recognized, use the full path, e.g.');
    console.log('     "C:\\Program Files\\PostgreSQL\\16\\bin\\psql.exe", or add that folder to PATH.)');
    console.log('');
    console.log('    Don\'t have PostgreSQL yet? Get it from https://www.postgresql.org/download/windows/');
    console.log('    or run it in Docker:');
    console.log(c.cyan(`      docker run -d --name sentinelx-db -e POSTGRES_USER=${DB_USER} -e POSTGRES_PASSWORD=${DB_PASSWORD} -e POSTGRES_DB=${DB_NAME} -p ${DB_PORT}:5432 postgres:16`));
  } else {
    console.log(c.cyan(`    sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASSWORD}';"`));
    console.log(c.cyan(`    sudo -u postgres psql -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"`));
    console.log('');
    console.log('    Or run it in Docker:');
    console.log(c.cyan(`      docker run -d --name sentinelx-db -e POSTGRES_USER=${DB_USER} -e POSTGRES_PASSWORD=${DB_PASSWORD} -e POSTGRES_DB=${DB_NAME} -p ${DB_PORT}:5432 postgres:16`));
  }
  console.log('');
  console.log(`    Connection target: ${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}`);
  console.log(`    Then re-run: npm run setup   (or: npm run db:migrate)`);
}

function printSummary() {
  const apiKey = (process.env.API_KEY || 'see .env');
  console.log(c.green(c.bold('  ══════════════════════════════════════════')));
  console.log(c.green(c.bold('   Sentinel X ready!')));
  console.log(c.green(c.bold('  ══════════════════════════════════════════')));
  console.log('');
  console.log(`  Start:         ${c.cyan('npm start')}   (or  npm run dev  for auto-reload)`);
  console.log(`  Dashboard:     ${c.cyan('http://127.0.0.1:3000')}`);
  console.log(`  Default login: ${c.yellow('admin / SentinelX@admin')}`);
  console.log(`  API Key:       ${c.yellow(apiKey)}`);
  console.log('');
  console.log('  Troubleshoot:');
  console.log(`    DB migration:   ${c.cyan('npm run db:migrate')}`);
  console.log(`    Health check:   ${c.cyan('curl http://127.0.0.1:3000/health')}   (or open it in a browser)`);
  console.log(`    Logs:           ${c.cyan('logs/sentinel.log')}`);
  console.log('');
  console.log(c.yellow('  ⚠  Change the admin password on first login!'));
  console.log('');
}

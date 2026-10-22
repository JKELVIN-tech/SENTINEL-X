'use strict';

/**
 * Sentinel X — Cross-platform binary locator
 * ─────────────────────────────────────────────────────────────────────────────
 * Resolves the path to an external tool (nmap, hashcat, ...) so the rest of
 * the app doesn't need to care whether it's running on Linux, macOS or
 * Windows. Resolution order:
 *
 *   1. Explicit env var (NMAP_BINARY, HASHCAT_BINARY, ...) if it points to
 *      an existing file.
 *   2. `where <name>` (Windows) / `which <name>` (everything else) — picks
 *      it up if it's already on PATH, including a Windows .exe/.cmd shim.
 *   3. A short list of common install locations per platform.
 *   4. The bare command name, so Node's own PATH lookup gets a final try
 *      when the process actually spawns it.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const IS_WINDOWS = process.platform === 'win32';

function tryWhich(name) {
  try {
    const cmd = IS_WINDOWS ? 'where' : 'which';
    const out = execFileSync(cmd, [name], { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString('utf8')
      .split(/\r?\n/)
      .map(l => l.trim())
      .filter(Boolean);
    return out[0] || null;
  } catch (_) {
    return null;
  }
}

/**
 * resolveBinary(name, { envVar, commonPaths })
 * → { bin, source }  (source: 'env' | 'path' | 'known-location' | 'bare')
 */
function resolveBinary(name, { envVar, commonPaths = [] } = {}) {
  const fromEnv = envVar && process.env[envVar];
  if (fromEnv && fs.existsSync(fromEnv)) {
    return { bin: fromEnv, source: 'env' };
  }
  if (fromEnv && fromEnv !== name) {
    // User set it explicitly but the path doesn't exist yet — still honour
    // it (e.g. container builds the file after boot), but note the issue.
    return { bin: fromEnv, source: 'env-unverified' };
  }

  const exeName = IS_WINDOWS && !name.toLowerCase().endsWith('.exe') ? `${name}.exe` : name;

  const found = tryWhich(name) || tryWhich(exeName);
  if (found) return { bin: found, source: 'path' };

  for (const candidate of commonPaths) {
    const expanded = candidate.replace('%ProgramFiles%', process.env['ProgramFiles'] || 'C:\\Program Files')
      .replace('%ProgramFiles(x86)%', process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)');
    if (fs.existsSync(expanded)) return { bin: expanded, source: 'known-location' };
  }

  return { bin: name, source: 'bare' };
}

const NMAP_COMMON_PATHS = [
  '/usr/bin/nmap',
  '/usr/local/bin/nmap',
  '/opt/homebrew/bin/nmap',
  '%ProgramFiles%\\Nmap\\nmap.exe',
  '%ProgramFiles(x86)%\\Nmap\\nmap.exe',
];

const HASHCAT_COMMON_PATHS = [
  '/usr/bin/hashcat',
  '/usr/local/bin/hashcat',
  '/opt/homebrew/bin/hashcat',
  '%ProgramFiles%\\hashcat\\hashcat.exe',
];

module.exports = {
  IS_WINDOWS,
  resolveBinary,
  NMAP_COMMON_PATHS,
  HASHCAT_COMMON_PATHS,
};

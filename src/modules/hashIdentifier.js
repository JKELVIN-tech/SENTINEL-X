'use strict';

/**
 * Sentinel X — Hash Identifier
 * Detects hash type from length + character set + format patterns.
 * Returns an ordered array of candidate types (most likely first).
 */

const HASH_SIGNATURES = [
  // ── Fixed-length hex hashes
  { id: 'md5',        name: 'MD5',        len: 32,  regex: /^[a-f0-9]{32}$/i,                  hashcatMode: 0    },
  { id: 'sha1',       name: 'SHA-1',      len: 40,  regex: /^[a-f0-9]{40}$/i,                  hashcatMode: 100  },
  { id: 'sha224',     name: 'SHA-224',    len: 56,  regex: /^[a-f0-9]{56}$/i,                  hashcatMode: 1300 },
  { id: 'sha256',     name: 'SHA-256',    len: 64,  regex: /^[a-f0-9]{64}$/i,                  hashcatMode: 1400 },
  { id: 'sha384',     name: 'SHA-384',    len: 96,  regex: /^[a-f0-9]{96}$/i,                  hashcatMode: 10800},
  { id: 'sha512',     name: 'SHA-512',    len: 128, regex: /^[a-f0-9]{128}$/i,                 hashcatMode: 1700 },
  { id: 'sha3_256',   name: 'SHA3-256',   len: 64,  regex: /^[a-f0-9]{64}$/i,                  hashcatMode: 17400},
  { id: 'sha3_512',   name: 'SHA3-512',   len: 128, regex: /^[a-f0-9]{128}$/i,                 hashcatMode: 17600},

  // ── NTLM / Windows
  { id: 'ntlm',       name: 'NTLM',       len: 32,  regex: /^[a-f0-9]{32}$/i,                  hashcatMode: 1000 },
  { id: 'lm',         name: 'LM',         len: 32,  regex: /^[a-f0-9]{32}$/i,                  hashcatMode: 3000 },
  { id: 'mscachev2',  name: 'MSCacheV2',  len: null,regex: /^\$DCC2\$\d+#.+#[a-f0-9]{32}$/i,  hashcatMode: 2100 },

  // ── bcrypt
  { id: 'bcrypt',     name: 'bcrypt',     len: null,regex: /^\$2[ayb]\$\d{2}\$.{52,}$/,          hashcatMode: 3200 },

  // ── MD5 variants
  { id: 'md5crypt',   name: 'md5crypt',   len: null,regex: /^\$1\$.{1,8}\$.{22}$/,             hashcatMode: 500  },
  { id: 'md5apr1',    name: 'MD5(APR)',   len: null,regex: /^\$apr1\$.{1,8}\$.{22}$/,          hashcatMode: 1600 },

  // ── SHA-crypt (Linux shadow)
  { id: 'sha256crypt',name: 'SHA-256crypt',len:null, regex: /^\$5\$(rounds=\d+\$)?.{1,16}\$.{20,}$/,hashcatMode:7400},
  { id: 'sha512crypt',name: 'SHA-512crypt',len:null, regex: /^\$6\$(rounds=\d+\$)?.{1,16}\$.{20,}$/,hashcatMode:1800},

  // ── MySQL
  { id: 'mysql323',   name: 'MySQL3.23',  len: 16,  regex: /^[a-f0-9]{16}$/i,                  hashcatMode: 200  },
  { id: 'mysql41',    name: 'MySQL4.1',   len: 41,  regex: /^\*[a-f0-9]{40}$/i,                hashcatMode: 300  },

  // ── WPA
  { id: 'wpa',        name: 'WPA-PBKDF2', len: null,regex: /^[a-f0-9]{64}$/i,                  hashcatMode: 2500 },

  // ── CRC32
  { id: 'crc32',      name: 'CRC32',      len: 8,   regex: /^[a-f0-9]{8}$/i,                   hashcatMode: 11500},

  // ── RIPEMD
  { id: 'ripemd160',  name: 'RIPEMD-160', len: 40,  regex: /^[a-f0-9]{40}$/i,                  hashcatMode: 6000 },

  // ── Whirlpool
  { id: 'whirlpool',  name: 'Whirlpool',  len: 128, regex: /^[a-f0-9]{128}$/i,                 hashcatMode: 6100 },

  // ── Django
  { id: 'django_md5',    name: 'Django MD5',    len: null, regex: /^md5\$\w+\$[a-f0-9]{32}$/,    hashcatMode: 3800 },
  { id: 'django_sha1',   name: 'Django SHA-1',  len: null, regex: /^sha1\$\w+\$[a-f0-9]{40}$/,   hashcatMode: 124  },
  { id: 'django_sha256', name: 'Django SHA-256', len: null,regex: /^pbkdf2_sha256\$\d+\$.+\$.+$/, hashcatMode: 10000},

  // ── Cisco / network
  { id: 'cisco_type7',  name: 'Cisco Type 7', len: null, regex: /^[0-9]{2}[a-f0-9]+$/i,         hashcatMode: null },
  { id: 'cisco_md5',    name: 'Cisco MD5',    len: null, regex: /^\$1\$[a-zA-Z0-9./]{1,8}\$.+/, hashcatMode: 500  },
];

/**
 * identifyHash(hash) → Array<{ id, name, hashcatMode, confidence }>
 */
function identifyHash(raw) {
  const hash    = raw.trim();
  const matches = [];

  for (const sig of HASH_SIGNATURES) {
    if (!sig.regex.test(hash)) continue;
    // Confidence scoring
    let confidence = 50;
    if (sig.len !== null && hash.length === sig.len) confidence += 30;
    if (sig.regex.toString().includes('\\$')) confidence += 15; // format prefix → more specific
    matches.push({ id: sig.id, name: sig.name, hashcatMode: sig.hashcatMode, confidence });
  }

  // Deduplicate by id, keep highest confidence
  const seen = new Map();
  for (const m of matches) {
    if (!seen.has(m.id) || seen.get(m.id).confidence < m.confidence) {
      seen.set(m.id, m);
    }
  }

  return [...seen.values()].sort((a, b) => b.confidence - a.confidence);
}

/**
 * hashcatModeFor(typeId) → number | null
 */
function hashcatModeFor(typeId) {
  return HASH_SIGNATURES.find(s => s.id === typeId)?.hashcatMode ?? null;
}

/**
 * allTypes() — return full signature list for UI dropdowns
 */
function allTypes() {
  const seen = new Set();
  return HASH_SIGNATURES.filter(s => {
    if (seen.has(s.id)) return false;
    seen.add(s.id);
    return true;
  }).map(({ id, name, hashcatMode }) => ({ id, name, hashcatMode }));
}

module.exports = { identifyHash, hashcatModeFor, allTypes };

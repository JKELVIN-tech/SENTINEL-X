'use strict';

/**
 * Sentinel X — Repository Layer
 * ─────────────────────────────────────────────────────────────────────────────
 * Centralises all SQL queries. Modules call these functions instead of
 * touching the DB directly. Each section maps to one table / domain.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const db = require('./pool');

// ══════════════════════════════════════════════
//  USERS
// ══════════════════════════════════════════════
const Users = {
  findById: (id) =>
    db.one('SELECT * FROM users WHERE id = $1', [id]),

  findByUsername: (username) =>
    db.one('SELECT * FROM users WHERE username = $1', [username]),

  findByEmail: (email) =>
    db.one('SELECT * FROM users WHERE email = $1', [email]),

  create: ({ username, email, passwordHash, role = 'analyst' }) =>
    db.insert(
      `INSERT INTO users (username, email, password_hash, role)
       VALUES ($1, $2, $3, $4)
       RETURNING id, username, email, role, is_active, created_at`,
      [username, email, passwordHash, role]
    ),

  updateLastLogin: (id) =>
    db.query('UPDATE users SET last_login = NOW() WHERE id = $1', [id]),

  updatePassword: (id, passwordHash) =>
    db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [passwordHash, id]),

  setActive: (id, isActive) =>
    db.query('UPDATE users SET is_active = $1 WHERE id = $2', [isActive, id]),

  list: ({ limit = 50, offset = 0 } = {}) =>
    db.all(
      `SELECT id, username, email, role, is_active, last_login, created_at
       FROM users ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
      [limit, offset]
    ),
};

// ══════════════════════════════════════════════
//  AUTH TOKENS
// ══════════════════════════════════════════════
const AuthTokens = {
  create: ({ userId, tokenHash, expiresAt, userAgent, ipAddress }) =>
    db.insert(
      `INSERT INTO auth_tokens (user_id, token_hash, expires_at, user_agent, ip_address)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [userId, tokenHash, expiresAt, userAgent, ipAddress]
    ),

  findByHash: (tokenHash) =>
    db.one(
      `SELECT t.*, u.username, u.role, u.is_active
       FROM auth_tokens t
       JOIN users u ON u.id = t.user_id
       WHERE t.token_hash = $1 AND t.revoked = false AND t.expires_at > NOW()`,
      [tokenHash]
    ),

  revoke: (tokenHash) =>
    db.query('UPDATE auth_tokens SET revoked = true WHERE token_hash = $1', [tokenHash]),

  revokeAllForUser: (userId) =>
    db.query('UPDATE auth_tokens SET revoked = true WHERE user_id = $1', [userId]),

  purgeExpired: () =>
    db.query('DELETE FROM auth_tokens WHERE expires_at < NOW() OR revoked = true'),
};

// ══════════════════════════════════════════════
//  ENGAGEMENTS
// ══════════════════════════════════════════════
const Engagements = {
  findById: (id) =>
    db.one('SELECT * FROM engagements WHERE id = $1', [id]),

  create: ({ name, description, target, scope = [], ownerId }) =>
    db.insert(
      `INSERT INTO engagements (name, description, target, scope, owner_id, started_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       RETURNING *`,
      [name, description || null, target, JSON.stringify(scope), ownerId || null]
    ),

  update: (id, { name, description, target, scope, status }) =>
    db.one(
      `UPDATE engagements
       SET name        = COALESCE($2, name),
           description = COALESCE($3, description),
           target      = COALESCE($4, target),
           scope       = COALESCE($5, scope),
           status      = COALESCE($6, status),
           ended_at    = CASE WHEN $6 = 'complete' THEN NOW() ELSE ended_at END
       WHERE id = $1
       RETURNING *`,
      [id, name, description, target, scope ? JSON.stringify(scope) : null, status]
    ),

  list: ({ status, ownerId, limit = 50, offset = 0 } = {}) =>
    db.all(
      `SELECT e.*, u.username AS owner_name,
              (SELECT COUNT(*) FROM scan_jobs    WHERE engagement_id = e.id) AS scan_count,
              (SELECT COUNT(*) FROM vulnerabilities WHERE engagement_id = e.id) AS vuln_count,
              (SELECT COUNT(*) FROM hashes        WHERE engagement_id = e.id AND cracked = true) AS cracked_count
       FROM engagements e
       LEFT JOIN users u ON u.id = e.owner_id
       WHERE ($1::text IS NULL OR e.status = $1)
         AND ($2::uuid IS NULL OR e.owner_id = $2)
       ORDER BY e.created_at DESC
       LIMIT $3 OFFSET $4`,
      [status || null, ownerId || null, limit, offset]
    ),

  stats: (id) =>
    db.one(
      `SELECT
         (SELECT COUNT(*) FROM scan_jobs       WHERE engagement_id = $1) AS total_scans,
         (SELECT COUNT(*) FROM scan_jobs       WHERE engagement_id = $1 AND status = 'complete') AS complete_scans,
         (SELECT COUNT(*) FROM hosts           WHERE engagement_id = $1) AS hosts_found,
         (SELECT COUNT(*) FROM ports           WHERE host_id IN (SELECT id FROM hosts WHERE engagement_id = $1)) AS open_ports,
         (SELECT COUNT(*) FROM vulnerabilities WHERE engagement_id = $1) AS total_vulns,
         (SELECT COUNT(*) FROM vulnerabilities WHERE engagement_id = $1 AND severity = 'critical') AS critical_vulns,
         (SELECT COUNT(*) FROM vulnerabilities WHERE engagement_id = $1 AND severity = 'high') AS high_vulns,
         (SELECT COUNT(*) FROM hashes         WHERE engagement_id = $1) AS total_hashes,
         (SELECT COUNT(*) FROM hashes         WHERE engagement_id = $1 AND cracked = true) AS cracked_hashes`,
      [id]
    ),

  delete: (id) =>
    db.query('DELETE FROM engagements WHERE id = $1', [id]),
};

// ══════════════════════════════════════════════
//  SCAN JOBS
// ══════════════════════════════════════════════
const ScanJobs = {
  findById: (id) =>
    db.one('SELECT * FROM scan_jobs WHERE id = $1', [id]),

  create: ({ id, engagementId, label, target, flags, portRange, createdBy }) =>
    db.insert(
      `INSERT INTO scan_jobs
         (id, engagement_id, label, target, flags, port_range, status, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, 'queued', $7)
       RETURNING *`,
      [id, engagementId || null, label || target, target,
       flags, portRange, createdBy || null]
    ),

  updateStatus: (id, status, extra = {}) => {
    const fields = ['status = $2'];
    const vals   = [id, status];
    let   idx    = 3;

    if (status === 'running')  { fields.push(`started_at = NOW()`); }
    if (status === 'complete' || status === 'error' || status === 'cancelled') {
      fields.push(`completed_at = NOW()`);
    }
    if (extra.pid       !== undefined) { fields.push(`pid = $${idx++}`);        vals.push(extra.pid); }
    if (extra.exitCode  !== undefined) { fields.push(`exit_code = $${idx++}`);  vals.push(extra.exitCode); }
    if (extra.errorMsg  !== undefined) { fields.push(`error_msg = $${idx++}`);  vals.push(extra.errorMsg); }
    if (extra.stderr    !== undefined) { fields.push(`stderr = $${idx++}`);     vals.push(extra.stderr); }
    if (extra.xmlPath   !== undefined) { fields.push(`xml_path = $${idx++}`);   vals.push(extra.xmlPath); }
    if (extra.normPath  !== undefined) { fields.push(`norm_path = $${idx++}`);  vals.push(extra.normPath); }

    return db.query(`UPDATE scan_jobs SET ${fields.join(', ')} WHERE id = $1`, vals);
  },

  saveResults: (id, results) =>
    db.query(
      `UPDATE scan_jobs SET
         results      = $2,
         hosts_up     = $3,
         hosts_total  = $4,
         open_ports   = $5,
         elapsed_secs = $6,
         nmap_version = $7
       WHERE id = $1`,
      [
        id,
        JSON.stringify(results),
        results.hostsUp     || 0,
        results.hostsTotal  || 0,
        results.hosts?.reduce((n, h) => n + h.openPortCount, 0) || 0,
        parseFloat(results.elapsed) || null,
        results.version     || null,
      ]
    ),

  list: ({ engagementId, status, limit = 50, offset = 0 } = {}) =>
    db.all(
      `SELECT id, engagement_id, label, target, flags, port_range, status,
              hosts_up, hosts_total, open_ports, elapsed_secs,
              queued_at, started_at, completed_at
       FROM scan_jobs
       WHERE ($1::uuid IS NULL OR engagement_id = $1)
         AND ($2::text IS NULL OR status = $2)
       ORDER BY queued_at DESC
       LIMIT $3 OFFSET $4`,
      [engagementId || null, status || null, limit, offset]
    ),

  delete: (id) =>
    db.query('DELETE FROM scan_jobs WHERE id = $1', [id]),
};

// ══════════════════════════════════════════════
//  HOSTS
// ══════════════════════════════════════════════
const Hosts = {
  findById: (id) =>
    db.one('SELECT * FROM hosts WHERE id = $1', [id]),

  findByIp: (engagementId, ip) =>
    db.one('SELECT * FROM hosts WHERE engagement_id = $1 AND ip_address = $2', [engagementId, ip]),

  upsert: ({ engagementId, scanJobId, ip, hostname, mac, vendor, osName, osAccuracy, osFamily, openPortCount, rawData }) =>
    db.insert(
      `INSERT INTO hosts
         (engagement_id, scan_job_id, ip_address, hostname, mac_address, vendor,
          os_name, os_accuracy, os_family, open_port_count, raw_data, last_seen)
       VALUES ($1, $2, $3::inet, $4, $5::macaddr, $6, $7, $8, $9, $10, $11, NOW())
       ON CONFLICT (engagement_id, ip_address)
       DO UPDATE SET
         scan_job_id    = EXCLUDED.scan_job_id,
         hostname       = COALESCE(EXCLUDED.hostname, hosts.hostname),
         mac_address    = COALESCE(EXCLUDED.mac_address, hosts.mac_address),
         vendor         = COALESCE(EXCLUDED.vendor, hosts.vendor),
         os_name        = COALESCE(EXCLUDED.os_name, hosts.os_name),
         os_accuracy    = COALESCE(EXCLUDED.os_accuracy, hosts.os_accuracy),
         os_family      = COALESCE(EXCLUDED.os_family, hosts.os_family),
         open_port_count= EXCLUDED.open_port_count,
         raw_data       = EXCLUDED.raw_data,
         last_seen      = NOW()
       RETURNING *`,
      [engagementId, scanJobId || null, ip,
       hostname || null, mac || null, vendor || null,
       osName || null, osAccuracy || null, osFamily || null,
       openPortCount || 0, JSON.stringify(rawData || {})]
    ),

  listByEngagement: (engagementId, { limit = 100, offset = 0 } = {}) =>
    db.all(
      `SELECT h.*,
         (SELECT json_agg(p ORDER BY p.port_number)
          FROM ports p WHERE p.host_id = h.id) AS ports
       FROM hosts h
       WHERE h.engagement_id = $1
       ORDER BY h.ip_address
       LIMIT $2 OFFSET $3`,
      [engagementId, limit, offset]
    ),
};

// ══════════════════════════════════════════════
//  PORTS
// ══════════════════════════════════════════════
const Ports = {
  upsert: ({ hostId, scanJobId, portNumber, protocol, state, serviceName, product, version, extraInfo, cpe, scripts }) =>
    db.insert(
      `INSERT INTO ports
         (host_id, scan_job_id, port_number, protocol, state,
          service_name, product, version, extra_info, cpe, scripts)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
       ON CONFLICT (host_id, port_number, protocol)
       DO UPDATE SET
         scan_job_id  = EXCLUDED.scan_job_id,
         state        = EXCLUDED.state,
         service_name = COALESCE(EXCLUDED.service_name, ports.service_name),
         product      = COALESCE(EXCLUDED.product,      ports.product),
         version      = COALESCE(EXCLUDED.version,      ports.version),
         extra_info   = COALESCE(EXCLUDED.extra_info,   ports.extra_info),
         scripts      = EXCLUDED.scripts,
         discovered_at= ports.discovered_at
       RETURNING *`,
      [hostId, scanJobId || null, portNumber, protocol || 'tcp', state || 'open',
       serviceName || null, product || null, version || null,
       extraInfo || null, cpe || null, JSON.stringify(scripts || [])]
    ),

  listByHost: (hostId) =>
    db.all('SELECT * FROM ports WHERE host_id = $1 ORDER BY port_number', [hostId]),
};

// ══════════════════════════════════════════════
//  VULNERABILITIES
// ══════════════════════════════════════════════
const Vulnerabilities = {
  findById: (id) =>
    db.one('SELECT * FROM vulnerabilities WHERE id = $1', [id]),

  create: ({ engagementId, hostId, portId, scanJobId, cve, name, description, severity, cvssScore, cvssVector, evidence, remediation, refs }) =>
    db.insert(
      `INSERT INTO vulnerabilities
         (engagement_id, host_id, port_id, scan_job_id, cve, name, description,
          severity, cvss_score, cvss_vector, evidence, remediation, "references")
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
       RETURNING *`,
      [engagementId, hostId || null, portId || null, scanJobId || null,
       cve || null, name, description || null, severity || 'info',
       cvssScore || null, cvssVector || null,
       evidence || null, remediation || null, JSON.stringify(refs || [])]
    ),

  updateStatus: (id, status, { remediation, verifiedBy } = {}) =>
    db.query(
      `UPDATE vulnerabilities
       SET status      = $2,
           remediation = COALESCE($3, remediation),
           verified_by = COALESCE($4, verified_by)
       WHERE id = $1`,
      [id, status, remediation || null, verifiedBy || null]
    ),

  listByEngagement: (engagementId, { severity, status, limit = 100, offset = 0 } = {}) =>
    db.all(
      `SELECT v.*, h.ip_address, h.hostname, p.port_number, p.service_name
       FROM vulnerabilities v
       LEFT JOIN hosts h ON h.id = v.host_id
       LEFT JOIN ports p ON p.id = v.port_id
       WHERE v.engagement_id = $1
         AND ($2::text IS NULL OR v.severity = $2)
         AND ($3::text IS NULL OR v.status   = $3)
       ORDER BY
         CASE v.severity
           WHEN 'critical' THEN 1 WHEN 'high' THEN 2
           WHEN 'medium'   THEN 3 WHEN 'low'  THEN 4 ELSE 5
         END,
         v.discovered_at DESC
       LIMIT $4 OFFSET $5`,
      [engagementId, severity || null, status || null, limit, offset]
    ),

  delete: (id) =>
    db.query('DELETE FROM vulnerabilities WHERE id = $1', [id]),
};

// ══════════════════════════════════════════════
//  CRACK JOBS
// ══════════════════════════════════════════════
const CrackJobs = {
  findById: (id) =>
    db.one('SELECT * FROM crack_jobs WHERE id = $1', [id]),

  create: ({ id, engagementId, label, hashType, mode, wordlistPath, totalHashes, createdBy }) =>
    db.insert(
      `INSERT INTO crack_jobs
         (id, engagement_id, label, hash_type, mode, wordlist_path, total_hashes, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING *`,
      [id, engagementId || null, label || null, hashType, mode,
       wordlistPath || null, totalHashes || 0, createdBy || null]
    ),

  updateStatus: (id, status, { crackedCount, testedCount, hashRate, errorMsg } = {}) =>
    db.query(
      `UPDATE crack_jobs
       SET status        = $2,
           cracked_count = COALESCE($3, cracked_count),
           tested_count  = COALESCE($4, tested_count),
           hash_rate     = COALESCE($5, hash_rate),
           error_msg     = COALESCE($6, error_msg),
           started_at    = CASE WHEN $2 = 'running'  AND started_at IS NULL THEN NOW() ELSE started_at END,
           completed_at  = CASE WHEN $2 IN ('complete','error','cancelled')   THEN NOW() ELSE completed_at END
       WHERE id = $1`,
      [id, status, crackedCount ?? null, testedCount ?? null, hashRate ?? null, errorMsg || null]
    ),

  list: ({ engagementId, status, limit = 50, offset = 0 } = {}) =>
    db.all(
      `SELECT id, engagement_id, label, hash_type, mode, status,
              total_hashes, cracked_count, tested_count, hash_rate,
              queued_at, started_at, completed_at
       FROM crack_jobs
       WHERE ($1::uuid IS NULL OR engagement_id = $1)
         AND ($2::text IS NULL OR status = $2)
       ORDER BY queued_at DESC
       LIMIT $3 OFFSET $4`,
      [engagementId || null, status || null, limit, offset]
    ),
};

// ══════════════════════════════════════════════
//  HASHES
// ══════════════════════════════════════════════
const Hashes = {
  bulkInsert: async (crackJobId, engagementId, hashList) => {
    if (!hashList.length) return 0;
    const values = hashList.map((h, i) => {
      const base = i * 4;
      return `($${base+1}, $${base+2}, $${base+3}, $${base+4})`;
    }).join(', ');
    const params = hashList.flatMap(h => [crackJobId, engagementId || null, h.hash, h.type]);
    const { rowCount } = await db.query(
      `INSERT INTO hashes (crack_job_id, engagement_id, hash_value, hash_type)
       VALUES ${values}
       ON CONFLICT (engagement_id, hash_value) WHERE engagement_id IS NOT NULL DO NOTHING`,
      params
    );
    return rowCount;
  },

  markCracked: (crackJobId, hashValue, plaintext) =>
    db.query(
      `UPDATE hashes
       SET cracked = true, plaintext = $3, cracked_at = NOW()
       WHERE crack_job_id = $1 AND hash_value = $2`,
      [crackJobId, hashValue, plaintext]
    ),

  listByJob: (crackJobId) =>
    db.all(
      'SELECT * FROM hashes WHERE crack_job_id = $1 ORDER BY cracked DESC, added_at',
      [crackJobId]
    ),

  crackedByEngagement: (engagementId) =>
    db.all(
      `SELECT hash_value, hash_type, plaintext, username, host_ip, cracked_at
       FROM hashes
       WHERE engagement_id = $1 AND cracked = true
       ORDER BY cracked_at DESC`,
      [engagementId]
    ),

  findByValue: (hashValue) =>
    db.one(
      'SELECT * FROM hashes WHERE hash_value = $1 AND cracked = true LIMIT 1',
      [hashValue]
    ),
};

// ══════════════════════════════════════════════
//  AI SESSIONS
// ══════════════════════════════════════════════
const AiSessions = {
  findById: (id) =>
    db.one('SELECT * FROM ai_sessions WHERE id = $1', [id]),

  create: ({ id, engagementId, userId, context }) =>
    db.insert(
      `INSERT INTO ai_sessions (id, engagement_id, user_id, context)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [id, engagementId || null, userId || null, JSON.stringify(context || {})]
    ),

  updateHistory: (id, history, { inputTokens, outputTokens } = {}) =>
    db.query(
      `UPDATE ai_sessions
       SET history       = $2,
           message_count = $3,
           input_tokens  = input_tokens  + $4,
           output_tokens = output_tokens + $5,
           last_used     = NOW(),
           expires_at    = NOW() + INTERVAL '4 hours'
       WHERE id = $1`,
      [id, JSON.stringify(history), history.length,
       inputTokens || 0, outputTokens || 0]
    ),

  updateContext: (id, context) =>
    db.query(
      'UPDATE ai_sessions SET context = $2, last_used = NOW() WHERE id = $1',
      [id, JSON.stringify(context)]
    ),

  purgeExpired: () =>
    db.query('DELETE FROM ai_sessions WHERE expires_at < NOW()'),

  list: (engagementId) =>
    db.all(
      `SELECT id, engagement_id, user_id, message_count,
              input_tokens, output_tokens, created_at, last_used, expires_at
       FROM ai_sessions
       WHERE ($1::uuid IS NULL OR engagement_id = $1)
         AND expires_at > NOW()
       ORDER BY last_used DESC`,
      [engagementId || null]
    ),
};

// ══════════════════════════════════════════════
//  REPORTS
// ══════════════════════════════════════════════
const Reports = {
  create: ({ engagementId, title, format, content, aiGenerated, tokenCount, filePath, createdBy }) =>
    db.insert(
      `INSERT INTO reports
         (engagement_id, title, format, content, ai_generated, token_count, file_path, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
       RETURNING id, engagement_id, title, format, ai_generated, created_at`,
      [engagementId || null, title, format || 'markdown', content,
       aiGenerated || false, tokenCount || 0, filePath || null, createdBy || null]
    ),

  findById: (id) =>
    db.one('SELECT * FROM reports WHERE id = $1', [id]),

  listByEngagement: (engagementId) =>
    db.all(
      `SELECT id, title, format, ai_generated, token_count, created_at
       FROM reports WHERE engagement_id = $1 ORDER BY created_at DESC`,
      [engagementId]
    ),

  delete: (id) =>
    db.query('DELETE FROM reports WHERE id = $1', [id]),
};

// ══════════════════════════════════════════════
//  AUDIT LOG
// ══════════════════════════════════════════════
const AuditLog = {
  write: ({ userId, action, resource, resourceId, detail, ipAddress, userAgent }) =>
    db.query(
      `INSERT INTO audit_log
         (user_id, action, resource, resource_id, detail, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId || null, action, resource || null, resourceId || null,
       detail ? JSON.stringify(detail) : null, ipAddress || null, userAgent || null]
    ),

  list: ({ userId, action, resource, limit = 100, offset = 0 } = {}) =>
    db.all(
      `SELECT a.*, u.username
       FROM audit_log a
       LEFT JOIN users u ON u.id = a.user_id
       WHERE ($1::uuid IS NULL OR a.user_id   = $1)
         AND ($2::text IS NULL OR a.action    = $2)
         AND ($3::text IS NULL OR a.resource  = $3)
       ORDER BY a.occurred_at DESC
       LIMIT $4 OFFSET $5`,
      [userId || null, action || null, resource || null, limit, offset]
    ),
};

// ══════════════════════════════════════════════
//  WORDLISTS
// ══════════════════════════════════════════════
const WordlistsRepo = {
  list: ({ category } = {}) =>
    db.all(
      `SELECT * FROM wordlists
       WHERE ($1::text IS NULL OR category = $1)
       ORDER BY is_system DESC, name`,
      [category || null]
    ),

  upsert: ({ name, filePath, category, source, lineCount, sizeBytes }) =>
    db.insert(
      `INSERT INTO wordlists (name, file_path, category, source, line_count, size_bytes)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (name) DO UPDATE SET
         file_path  = EXCLUDED.file_path,
         line_count = COALESCE(EXCLUDED.line_count, wordlists.line_count),
         size_bytes = COALESCE(EXCLUDED.size_bytes, wordlists.size_bytes),
         last_used  = NOW()
       RETURNING *`,
      [name, filePath, category || 'custom', source || 'local', lineCount || null, sizeBytes || null]
    ),

  touchLastUsed: (name) =>
    db.query('UPDATE wordlists SET last_used = NOW() WHERE name = $1', [name]),

  delete: (name) =>
    db.query('DELETE FROM wordlists WHERE name = $1 AND is_system = false', [name]),
};

module.exports = {
  Users,
  AuthTokens,
  Engagements,
  ScanJobs,
  Hosts,
  Ports,
  Vulnerabilities,
  CrackJobs,
  Hashes,
  AiSessions,
  Reports,
  AuditLog,
  WordlistsRepo,
};

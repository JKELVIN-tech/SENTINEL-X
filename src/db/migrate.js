'use strict';

/**
 * Sentinel X — Database Migration Runner
 * ─────────────────────────────────────────────────────────────────────────────
 * Runs migrations in order. Each migration is idempotent.
 * Tracks applied migrations in the `migrations` table.
 * Run: node src/db/migrate.js
 * ─────────────────────────────────────────────────────────────────────────────
 */

const db     = require('./pool');
const logger = require('../utils/logger');

// ──────────────────────────────────────────────
//  Migration definitions
//  Each has: id (sortable), name, sql
// ──────────────────────────────────────────────
const MIGRATIONS = [

  // ── 001 — Migrations tracker (must be first)
  {
    id: '001',
    name: 'create_migrations_table',
    sql: `
      CREATE TABLE IF NOT EXISTS migrations (
        id          SERIAL      PRIMARY KEY,
        name        TEXT        NOT NULL UNIQUE,
        applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `,
  },

  // ── 002 — Users + sessions (JWT auth)
  {
    id: '002',
    name: 'create_users_table',
    sql: `
      CREATE TABLE IF NOT EXISTS users (
        id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        username      TEXT        NOT NULL UNIQUE,
        email         TEXT        UNIQUE,
        password_hash TEXT        NOT NULL,
        role          TEXT        NOT NULL DEFAULT 'analyst'
                                  CHECK (role IN ('admin','analyst','viewer')),
        is_active     BOOLEAN     NOT NULL DEFAULT true,
        last_login    TIMESTAMPTZ,
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);

      -- Default admin user (password: SentinelX@admin — change immediately)
      INSERT INTO users (username, email, password_hash, role)
      VALUES (
        'admin',
        'admin@sentinelx.local',
        '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iGJy',
        'admin'
      )
      ON CONFLICT (username) DO NOTHING;
    `,
  },

  // ── 003 — Auth tokens (refresh token store)
  {
    id: '003',
    name: 'create_auth_tokens_table',
    sql: `
      CREATE TABLE IF NOT EXISTS auth_tokens (
        id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id     UUID        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        token_hash  TEXT        NOT NULL UNIQUE,
        expires_at  TIMESTAMPTZ NOT NULL,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        revoked     BOOLEAN     NOT NULL DEFAULT false,
        user_agent  TEXT,
        ip_address  INET
      );

      CREATE INDEX IF NOT EXISTS idx_auth_tokens_user    ON auth_tokens(user_id);
      CREATE INDEX IF NOT EXISTS idx_auth_tokens_hash    ON auth_tokens(token_hash);
      CREATE INDEX IF NOT EXISTS idx_auth_tokens_expires ON auth_tokens(expires_at);
    `,
  },

  // ── 004 — Engagements (top-level container for a pentest)
  {
    id: '004',
    name: 'create_engagements_table',
    sql: `
      CREATE TABLE IF NOT EXISTS engagements (
        id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        name        TEXT        NOT NULL,
        description TEXT,
        target      TEXT        NOT NULL,
        scope       JSONB       NOT NULL DEFAULT '[]',
        status      TEXT        NOT NULL DEFAULT 'active'
                                CHECK (status IN ('active','paused','complete','archived')),
        owner_id    UUID        REFERENCES users(id) ON DELETE SET NULL,
        started_at  TIMESTAMPTZ,
        ended_at    TIMESTAMPTZ,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_engagements_status  ON engagements(status);
      CREATE INDEX IF NOT EXISTS idx_engagements_owner   ON engagements(owner_id);
      CREATE INDEX IF NOT EXISTS idx_engagements_target  ON engagements(target);
    `,
  },

  // ── 005 — NMAP scan jobs
  {
    id: '005',
    name: 'create_scan_jobs_table',
    sql: `
      CREATE TABLE IF NOT EXISTS scan_jobs (
        id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        engagement_id   UUID        REFERENCES engagements(id) ON DELETE SET NULL,
        label           TEXT,
        target          TEXT        NOT NULL,
        flags           TEXT[]      NOT NULL DEFAULT '{}',
        port_range      TEXT        NOT NULL DEFAULT '1-1000',
        status          TEXT        NOT NULL DEFAULT 'queued'
                                    CHECK (status IN ('queued','running','complete','error','cancelled','timeout')),
        pid             INTEGER,
        exit_code       INTEGER,
        nmap_version    TEXT,
        xml_path        TEXT,
        norm_path       TEXT,
        results         JSONB,
        stderr          TEXT,
        error_msg       TEXT,
        hosts_up        INTEGER     DEFAULT 0,
        hosts_total     INTEGER     DEFAULT 0,
        open_ports      INTEGER     DEFAULT 0,
        elapsed_secs    NUMERIC(10,2),
        queued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        started_at      TIMESTAMPTZ,
        completed_at    TIMESTAMPTZ,
        created_by      UUID        REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE INDEX IF NOT EXISTS idx_scan_jobs_status        ON scan_jobs(status);
      CREATE INDEX IF NOT EXISTS idx_scan_jobs_engagement    ON scan_jobs(engagement_id);
      CREATE INDEX IF NOT EXISTS idx_scan_jobs_target        ON scan_jobs(target);
      CREATE INDEX IF NOT EXISTS idx_scan_jobs_queued_at     ON scan_jobs(queued_at DESC);
    `,
  },

  // ── 006 — Discovered hosts
  {
    id: '006',
    name: 'create_hosts_table',
    sql: `
      CREATE TABLE IF NOT EXISTS hosts (
        id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        engagement_id   UUID        REFERENCES engagements(id) ON DELETE CASCADE,
        scan_job_id     UUID        REFERENCES scan_jobs(id)   ON DELETE SET NULL,
        ip_address      INET        NOT NULL,
        hostname        TEXT,
        mac_address     MACADDR,
        vendor          TEXT,
        os_name         TEXT,
        os_accuracy     INTEGER,
        os_family       TEXT,
        status          TEXT        NOT NULL DEFAULT 'up',
        open_port_count INTEGER     DEFAULT 0,
        raw_data        JSONB,
        first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (engagement_id, ip_address)
      );

      CREATE INDEX IF NOT EXISTS idx_hosts_engagement ON hosts(engagement_id);
      CREATE INDEX IF NOT EXISTS idx_hosts_ip         ON hosts(ip_address);
      CREATE INDEX IF NOT EXISTS idx_hosts_scan       ON hosts(scan_job_id);
    `,
  },

  // ── 007 — Open ports
  {
    id: '007',
    name: 'create_ports_table',
    sql: `
      CREATE TABLE IF NOT EXISTS ports (
        id            UUID    PRIMARY KEY DEFAULT gen_random_uuid(),
        host_id       UUID    NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
        scan_job_id   UUID    REFERENCES scan_jobs(id) ON DELETE SET NULL,
        port_number   INTEGER NOT NULL,
        protocol      TEXT    NOT NULL DEFAULT 'tcp',
        state         TEXT    NOT NULL DEFAULT 'open',
        service_name  TEXT,
        product       TEXT,
        version       TEXT,
        extra_info    TEXT,
        cpe           TEXT,
        scripts       JSONB   DEFAULT '[]',
        discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (host_id, port_number, protocol)
      );

      CREATE INDEX IF NOT EXISTS idx_ports_host       ON ports(host_id);
      CREATE INDEX IF NOT EXISTS idx_ports_port       ON ports(port_number);
      CREATE INDEX IF NOT EXISTS idx_ports_service    ON ports(service_name);
    `,
  },

  // ── 008 — Vulnerabilities
  {
    id: '008',
    name: 'create_vulnerabilities_table',
    sql: `
      CREATE TABLE IF NOT EXISTS vulnerabilities (
        id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        engagement_id   UUID        REFERENCES engagements(id) ON DELETE CASCADE,
        host_id         UUID        REFERENCES hosts(id)       ON DELETE CASCADE,
        port_id         UUID        REFERENCES ports(id)       ON DELETE SET NULL,
        scan_job_id     UUID        REFERENCES scan_jobs(id)   ON DELETE SET NULL,
        cve             TEXT,
        name            TEXT        NOT NULL,
        description     TEXT,
        severity        TEXT        NOT NULL DEFAULT 'info'
                                    CHECK (severity IN ('critical','high','medium','low','info')),
        cvss_score      NUMERIC(4,1),
        cvss_vector     TEXT,
        status          TEXT        NOT NULL DEFAULT 'open'
                                    CHECK (status IN ('open','in_review','patched','false_positive','accepted')),
        evidence        TEXT,
        remediation     TEXT,
        references      JSONB       DEFAULT '[]',
        discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        verified_by     UUID        REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE INDEX IF NOT EXISTS idx_vulns_engagement ON vulnerabilities(engagement_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_host       ON vulnerabilities(host_id);
      CREATE INDEX IF NOT EXISTS idx_vulns_cve        ON vulnerabilities(cve);
      CREATE INDEX IF NOT EXISTS idx_vulns_severity   ON vulnerabilities(severity);
      CREATE INDEX IF NOT EXISTS idx_vulns_status     ON vulnerabilities(status);
    `,
  },

  // ── 009 — Hash crack jobs
  {
    id: '009',
    name: 'create_crack_jobs_table',
    sql: `
      CREATE TABLE IF NOT EXISTS crack_jobs (
        id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        engagement_id   UUID        REFERENCES engagements(id) ON DELETE SET NULL,
        label           TEXT,
        hash_type       TEXT        NOT NULL,
        mode            TEXT        NOT NULL DEFAULT 'dictionary'
                                    CHECK (mode IN ('dictionary','bruteforce','hashcat')),
        wordlist_path   TEXT,
        status          TEXT        NOT NULL DEFAULT 'queued'
                                    CHECK (status IN ('queued','running','complete','error','cancelled')),
        total_hashes    INTEGER     NOT NULL DEFAULT 0,
        cracked_count   INTEGER     NOT NULL DEFAULT 0,
        tested_count    BIGINT      NOT NULL DEFAULT 0,
        hash_rate       INTEGER     DEFAULT 0,
        error_msg       TEXT,
        queued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        started_at      TIMESTAMPTZ,
        completed_at    TIMESTAMPTZ,
        created_by      UUID        REFERENCES users(id) ON DELETE SET NULL
      );

      CREATE INDEX IF NOT EXISTS idx_crack_jobs_status     ON crack_jobs(status);
      CREATE INDEX IF NOT EXISTS idx_crack_jobs_engagement ON crack_jobs(engagement_id);
    `,
  },

  // ── 010 — Individual hashes + cracked results
  {
    id: '010',
    name: 'create_hashes_table',
    sql: `
      CREATE TABLE IF NOT EXISTS hashes (
        id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        crack_job_id  UUID        NOT NULL REFERENCES crack_jobs(id) ON DELETE CASCADE,
        engagement_id UUID        REFERENCES engagements(id) ON DELETE SET NULL,
        hash_value    TEXT        NOT NULL,
        hash_type     TEXT        NOT NULL,
        plaintext     TEXT,
        cracked       BOOLEAN     NOT NULL DEFAULT false,
        source        TEXT,
        host_ip       INET,
        username      TEXT,
        cracked_at    TIMESTAMPTZ,
        added_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_hashes_crack_job    ON hashes(crack_job_id);
      CREATE INDEX IF NOT EXISTS idx_hashes_engagement   ON hashes(engagement_id);
      CREATE INDEX IF NOT EXISTS idx_hashes_cracked      ON hashes(cracked);
      CREATE INDEX IF NOT EXISTS idx_hashes_value        ON hashes(hash_value);
      -- Dedup index: same hash per engagement
      CREATE UNIQUE INDEX IF NOT EXISTS idx_hashes_unique
        ON hashes(engagement_id, hash_value)
        WHERE engagement_id IS NOT NULL;
    `,
  },

  // ── 011 — AI analyst sessions + conversation history
  {
    id: '011',
    name: 'create_ai_sessions_table',
    sql: `
      CREATE TABLE IF NOT EXISTS ai_sessions (
        id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        engagement_id   UUID        REFERENCES engagements(id) ON DELETE SET NULL,
        user_id         UUID        REFERENCES users(id)       ON DELETE SET NULL,
        context         JSONB       NOT NULL DEFAULT '{}',
        history         JSONB       NOT NULL DEFAULT '[]',
        input_tokens    INTEGER     NOT NULL DEFAULT 0,
        output_tokens   INTEGER     NOT NULL DEFAULT 0,
        message_count   INTEGER     NOT NULL DEFAULT 0,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_used       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at      TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '4 hours')
      );

      CREATE INDEX IF NOT EXISTS idx_ai_sessions_engagement ON ai_sessions(engagement_id);
      CREATE INDEX IF NOT EXISTS idx_ai_sessions_user       ON ai_sessions(user_id);
      CREATE INDEX IF NOT EXISTS idx_ai_sessions_expires    ON ai_sessions(expires_at);
    `,
  },

  // ── 012 — Generated reports
  {
    id: '012',
    name: 'create_reports_table',
    sql: `
      CREATE TABLE IF NOT EXISTS reports (
        id              UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        engagement_id   UUID        REFERENCES engagements(id) ON DELETE SET NULL,
        title           TEXT        NOT NULL,
        format          TEXT        NOT NULL DEFAULT 'markdown'
                                    CHECK (format IN ('markdown','executive','technical','html','pdf')),
        content         TEXT        NOT NULL,
        ai_generated    BOOLEAN     NOT NULL DEFAULT false,
        token_count     INTEGER     DEFAULT 0,
        file_path       TEXT,
        created_by      UUID        REFERENCES users(id) ON DELETE SET NULL,
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_reports_engagement ON reports(engagement_id);
      CREATE INDEX IF NOT EXISTS idx_reports_format     ON reports(format);
    `,
  },

  // ── 013 — Audit log
  {
    id: '013',
    name: 'create_audit_log_table',
    sql: `
      CREATE TABLE IF NOT EXISTS audit_log (
        id          BIGSERIAL   PRIMARY KEY,
        user_id     UUID        REFERENCES users(id) ON DELETE SET NULL,
        action      TEXT        NOT NULL,
        resource    TEXT,
        resource_id TEXT,
        detail      JSONB,
        ip_address  INET,
        user_agent  TEXT,
        occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );

      CREATE INDEX IF NOT EXISTS idx_audit_user     ON audit_log(user_id);
      CREATE INDEX IF NOT EXISTS idx_audit_action   ON audit_log(action);
      CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_log(resource, resource_id);
      CREATE INDEX IF NOT EXISTS idx_audit_time     ON audit_log(occurred_at DESC);
    `,
  },

  // ── 014 — Wordlists registry
  {
    id: '014',
    name: 'create_wordlists_table',
    sql: `
      CREATE TABLE IF NOT EXISTS wordlists (
        id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
        name        TEXT        NOT NULL UNIQUE,
        file_path   TEXT        NOT NULL UNIQUE,
        category    TEXT        NOT NULL DEFAULT 'passwords'
                                CHECK (category IN ('passwords','usernames','directories','subdomains','fuzzing','custom')),
        source      TEXT        NOT NULL DEFAULT 'local',
        line_count  BIGINT,
        size_bytes  BIGINT,
        is_system   BOOLEAN     NOT NULL DEFAULT false,
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_used   TIMESTAMPTZ
      );

      CREATE INDEX IF NOT EXISTS idx_wordlists_category ON wordlists(category);

      -- Seed known Kali / SecLists paths
      INSERT INTO wordlists (name, file_path, category, source, is_system) VALUES
        ('rockyou.txt',            '/usr/share/wordlists/rockyou.txt',                                                         'passwords',   'kali',     true),
        ('fasttrack.txt',          '/usr/share/wordlists/fasttrack.txt',                                                       'passwords',   'kali',     true),
        ('darkweb2017-top10k.txt', '/usr/share/seclists/Passwords/darkweb2017-top10000.txt',                                   'passwords',   'seclists', true),
        ('usernames-shortlist.txt','/usr/share/seclists/Usernames/top-usernames-shortlist.txt',                                'usernames',   'seclists', true),
        ('directory-list-2.3.txt', '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',                            'directories', 'kali',     true),
        ('raft-large-dirs.txt',    '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt',                    'directories', 'seclists', true),
        ('subdomains-5000.txt',    '/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt',                       'subdomains',  'seclists', true),
        ('common.txt',             '/usr/share/seclists/Discovery/Web-Content/common.txt',                                    'directories', 'seclists', true)
      ON CONFLICT (name) DO NOTHING;
    `,
  },

  // ── 015 — updated_at trigger function (shared)
  {
    id: '015',
    name: 'create_updated_at_trigger',
    sql: `
      CREATE OR REPLACE FUNCTION set_updated_at()
      RETURNS TRIGGER AS $$
      BEGIN
        NEW.updated_at = NOW();
        RETURN NEW;
      END;
      $$ LANGUAGE plpgsql;

      -- Attach to tables that have updated_at
      DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_users_updated_at') THEN
          CREATE TRIGGER trg_users_updated_at
            BEFORE UPDATE ON users
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_engagements_updated_at') THEN
          CREATE TRIGGER trg_engagements_updated_at
            BEFORE UPDATE ON engagements
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'trg_vulns_updated_at') THEN
          CREATE TRIGGER trg_vulns_updated_at
            BEFORE UPDATE ON vulnerabilities
            FOR EACH ROW EXECUTE FUNCTION set_updated_at();
        END IF;
      END $$;
    `,
  },

];

// ──────────────────────────────────────────────
//  Migration runner
// ──────────────────────────────────────────────
async function migrate() {
  logger.info('Running migrations...');

  // Ensure migrations table exists first (migration 001)
  await db.query(MIGRATIONS[0].sql);

  let applied = 0;
  let skipped = 0;

  for (const m of MIGRATIONS) {
    const existing = await db.one(
      'SELECT id FROM migrations WHERE name = $1',
      [m.name]
    );

    if (existing) {
      skipped++;
      continue;
    }

    try {
      await db.transaction(async (client) => {
        await client.query(m.sql);
        await client.query(
          'INSERT INTO migrations (name) VALUES ($1) ON CONFLICT DO NOTHING',
          [m.name]
        );
      });
      logger.info(`  ✔  [${m.id}] ${m.name}`);
      applied++;
    } catch (err) {
      logger.error(`  ✘  [${m.id}] ${m.name}: ${err.message}`);
      throw err;
    }
  }

  logger.info(`Migrations done — applied: ${applied}, skipped: ${skipped}`);
  return { applied, skipped };
}

// ── Run directly: node src/db/migrate.js
if (require.main === module) {
  require('dotenv').config();
  migrate()
    .then(({ applied, skipped }) => {
      console.log(`\n  Migrations complete — ${applied} applied, ${skipped} already up to date.\n`);
      process.exit(0);
    })
    .catch(err => {
      console.error('\n  Migration failed:', err.message, '\n');
      process.exit(1);
    });
}

module.exports = { migrate, MIGRATIONS };

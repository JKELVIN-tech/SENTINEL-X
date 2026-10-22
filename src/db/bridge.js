'use strict';

/**
 * Sentinel X — Persistence Bridge
 * ─────────────────────────────────────────────────────────────────────────────
 * Sits between the in-memory engines (nmapEngine, hashCracker) and PostgreSQL.
 * Listens to WebSocket broadcast events and persists results without modifying
 * the engine modules themselves — zero coupling.
 *
 * Usage: call bridge.init() once at server startup.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const logger  = require('../utils/logger');
const { ScanJobs, Hosts, Ports, Vulnerabilities, CrackJobs, Hashes } = require('../db/repository');

// DB availability flag — bridge degrades gracefully if DB is offline
let dbAvailable = false;

async function checkDb() {
  try {
    const db = require('./pool');
    const r  = await db.ping();
    dbAvailable = r.ok;
    if (!r.ok) logger.warn(`Persistence bridge: DB unavailable — ${r.error}`);
    else       logger.info(`Persistence bridge: DB connected (${r.version})`);
  } catch (_) {
    dbAvailable = false;
  }
  return dbAvailable;
}

// ──────────────────────────────────────────────
//  NMAP scan result → DB
// ──────────────────────────────────────────────
async function persistScanJob(job) {
  if (!dbAvailable) return;
  try {
    await ScanJobs.create({
      id:           job.id,
      engagementId: job.engagementId || null,
      label:        job.label,
      target:       job.target,
      flags:        job.safeFlags,
      portRange:    job.portRange,
      createdBy:    job.createdBy || null,
    });
  } catch (err) {
    // Row may already exist if server restarted — ignore
    if (!err.message.includes('duplicate') && !err.message.includes('unique')) {
      logger.warn(`persistScanJob: ${err.message}`);
    }
  }
}

async function persistScanStatus(jobId, status, extra = {}) {
  if (!dbAvailable) return;
  try {
    await ScanJobs.updateStatus(jobId, status, extra);
  } catch (err) {
    logger.warn(`persistScanStatus: ${err.message}`);
  }
}

async function persistScanResults(jobId, engagementId, results) {
  if (!dbAvailable || !results) return;
  try {
    await ScanJobs.saveResults(jobId, results);

    if (!engagementId || !results.hosts) return;

    // Persist each host + ports
    for (const host of results.hosts) {
      const os      = host.os?.[0] || {};
      const dbHost  = await Hosts.upsert({
        engagementId,
        scanJobId:    jobId,
        ip:           host.ip,
        hostname:     host.hostnames?.[0] || null,
        mac:          host.addresses?.find(a => a.addrtype === 'mac')?.addr || null,
        vendor:       host.addresses?.find(a => a.addrtype === 'mac')?.vendor || null,
        osName:       os.name        || null,
        osAccuracy:   os.accuracy    || null,
        osFamily:     os.osfamily    || null,
        openPortCount: host.openPortCount || 0,
        rawData:       host,
      });

      // Persist open ports
      for (const port of (host.ports || [])) {
        const dbPort = await Ports.upsert({
          hostId:      dbHost.id,
          scanJobId:   jobId,
          portNumber:  port.portid,
          protocol:    port.protocol || 'tcp',
          state:       port.state,
          serviceName: port.service?.name    || null,
          product:     port.service?.product || null,
          version:     port.service?.version || null,
          extraInfo:   port.service?.extrainfo || null,
          scripts:     port.scripts || [],
        });

        // Auto-detect vulnerabilities from NSE script output
        for (const script of (port.scripts || [])) {
          if (!script.output) continue;
          const out = script.output.toLowerCase();
          if (!out.includes('vulnerable') && !out.includes('cve')) continue;

          const cveMatch = script.output.match(/CVE-\d{4}-\d+/i);
          await Vulnerabilities.create({
            engagementId,
            hostId:    dbHost.id,
            portId:    dbPort?.id || null,
            scanJobId: jobId,
            cve:       cveMatch?.[0]?.toUpperCase() || null,
            name:      script.id,
            description: script.output.slice(0, 2000),
            severity:  guessSeverity(script.output),
            evidence:  script.output,
          });
        }
      }
    }
  } catch (err) {
    logger.error(`persistScanResults: ${err.message}`);
  }
}

// ──────────────────────────────────────────────
//  Hash crack result → DB
// ──────────────────────────────────────────────
async function persistCrackJob(job) {
  if (!dbAvailable) return;
  try {
    await CrackJobs.create({
      id:           job.id,
      engagementId: job.engagementId || null,
      label:        job.label,
      hashType:     job.hashType,
      mode:         job.mode,
      wordlistPath: job.wordlistPath || null,
      totalHashes:  job.hashes.length,
      createdBy:    job.createdBy || null,
    });

    // Persist hashes
    await Hashes.bulkInsert(
      job.id,
      job.engagementId || null,
      job.hashes.map(h => ({ hash: h, type: job.hashType }))
    );
  } catch (err) {
    if (!err.message.includes('duplicate') && !err.message.includes('unique')) {
      logger.warn(`persistCrackJob: ${err.message}`);
    }
  }
}

async function persistCrackedHash(jobId, hashValue, plaintext) {
  if (!dbAvailable) return;
  try {
    await Hashes.markCracked(jobId, hashValue, plaintext);
  } catch (err) {
    logger.warn(`persistCrackedHash: ${err.message}`);
  }
}

async function persistCrackStatus(jobId, status, stats = {}) {
  if (!dbAvailable) return;
  try {
    await CrackJobs.updateStatus(jobId, status, stats);
  } catch (err) {
    logger.warn(`persistCrackStatus: ${err.message}`);
  }
}

// ──────────────────────────────────────────────
//  Severity heuristic from NSE output
// ──────────────────────────────────────────────
function guessSeverity(output) {
  const o = output.toLowerCase();
  if (o.includes('critical') || o.includes('cvss: 9') || o.includes('cvss: 10')) return 'critical';
  if (o.includes('high')     || o.includes('cvss: 7') || o.includes('cvss: 8'))  return 'high';
  if (o.includes('medium')   || o.includes('cvss: 4') || o.includes('cvss: 5') || o.includes('cvss: 6')) return 'medium';
  if (o.includes('low')      || o.includes('cvss: 1') || o.includes('cvss: 2') || o.includes('cvss: 3')) return 'low';
  return 'medium'; // default for confirmed vulns
}

// ──────────────────────────────────────────────
//  WebSocket event interceptor
//  Patches the global broadcast function to also
//  persist relevant events to the DB.
// ──────────────────────────────────────────────
function init() {
  checkDb().then(ok => {
    if (!ok) {
      logger.warn('Persistence bridge running in degraded mode (no DB) — all data in-memory only');
    }
  });

  // Wrap global broadcast
  const originalBroadcast = global.broadcast;
  global.broadcast = async function patchedBroadcast(data) {
    // Call original first (WebSocket delivery)
    if (originalBroadcast) originalBroadcast(data);

    if (!dbAvailable) return;

    // Intercept relevant events
    try {
      switch (data.type) {

        // ── NMAP
        case 'scan_queued':
          // Job data only available from engine — fetched via nmapEngine.getJob
          break;

        case 'scan_started': {
          await persistScanStatus(data.jobId, 'running', { pid: data.pid });
          break;
        }

        case 'scan_complete': {
          await persistScanStatus(data.jobId, data.status);
          if (data.results && data.engagementId) {
            await persistScanResults(data.jobId, data.engagementId, data.results);
          }
          break;
        }

        case 'scan_error': {
          await persistScanStatus(data.jobId, 'error', { errorMsg: data.error });
          break;
        }

        case 'scan_cancelled': {
          await persistScanStatus(data.jobId, 'cancelled');
          break;
        }

        // ── Hash cracker
        case 'crack_started': {
          await persistCrackStatus(data.jobId, 'running');
          break;
        }

        case 'hash_cracked': {
          await persistCrackedHash(data.jobId, data.hash, data.plaintext);
          break;
        }

        case 'crack_complete': {
          await persistCrackStatus(data.jobId, 'complete', {
            crackedCount: data.crackedCount,
            testedCount:  data.testedCount,
          });
          break;
        }

        case 'crack_error': {
          await persistCrackStatus(data.jobId, 'error', { errorMsg: data.error });
          break;
        }

        case 'crack_cancelled': {
          await persistCrackStatus(data.jobId, 'cancelled');
          break;
        }
      }
    } catch (err) {
      logger.error(`Bridge persist error [${data.type}]: ${err.message}`);
    }
  };

  // Schedule periodic cleanup
  setInterval(async () => {
    if (!dbAvailable) return;
    try {
      const db = require('./pool');
      await db.query('DELETE FROM auth_tokens WHERE expires_at < NOW() OR revoked = true');
      await db.query('DELETE FROM ai_sessions  WHERE expires_at < NOW()');
    } catch (_) {}
  }, 60 * 60 * 1000); // every hour

  logger.info('Persistence bridge initialized');
  return { persistScanJob, persistCrackJob };
}

module.exports = {
  init,
  checkDb,
  persistScanJob,
  persistScanResults,
  persistScanStatus,
  persistCrackJob,
  persistCrackedHash,
  persistCrackStatus,
  get available() { return dbAvailable; },
};

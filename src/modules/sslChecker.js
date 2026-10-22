'use strict';

/**
 * Sentinel X — TLS/SSL Inspector
 * ─────────────────────────────────────────────────────────────────────────────
 * Connects to host:port with TLS, pulls the certificate chain, negotiated
 * protocol version and cipher, and flags common misconfigurations:
 *   • Expired or soon-to-expire certificate
 *   • Self-signed / untrusted chain
 *   • Hostname mismatch
 *   • Outdated protocol (TLS 1.0 / 1.1 / SSLv3)
 * Pure Node `tls` module — no external binary required.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const tls = require('tls');
const logger = require('../utils/logger');

const WEAK_PROTOCOLS = new Set(['SSLv3', 'TLSv1', 'TLSv1.1']);
const DEFAULT_TIMEOUT_MS = 8000;

function sanitiseHost(raw = '') {
  const clean = String(raw).trim().replace(/[;&|`$(){}[\]\\'"<>\s]/g, '').replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  if (!clean) throw new Error('Host is required');
  if (clean.length > 256) throw new Error('Host string too long');
  return clean;
}

/**
 * checkCertificate(host, port)
 * → { ok, host, port, protocol, cipher, certificate, issues[] }
 */
function checkCertificate(host, port = 443, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  const safeHost = sanitiseHost(host);
  const safePort = Math.min(Math.max(parseInt(port) || 443, 1), 65535);

  return new Promise((resolve) => {
    const issues = [];
    let settled = false;

    const socket = tls.connect({
      host: safeHost,
      port: safePort,
      servername: safeHost,       // SNI
      rejectUnauthorized: false,  // we want to *see* bad certs, not throw on them
      timeout: timeoutMs,
    }, () => {
      if (settled) return;
      settled = true;

      const cert = socket.getPeerCertificate(true);
      const protocol = socket.getProtocol();
      const cipher = socket.getCipher();
      const authorized = socket.authorized;
      const authError = socket.authorizationError;

      if (!cert || Object.keys(cert).length === 0) {
        issues.push('No certificate presented by server');
      } else {
        const now = Date.now();
        const validFrom = new Date(cert.valid_from).getTime();
        const validTo = new Date(cert.valid_to).getTime();
        const daysLeft = Math.floor((validTo - now) / 86_400_000);

        if (now > validTo) issues.push(`Certificate expired ${Math.abs(daysLeft)} day(s) ago`);
        else if (now < validFrom) issues.push('Certificate is not yet valid');
        else if (daysLeft <= 14) issues.push(`Certificate expires in ${daysLeft} day(s)`);

        if (!authorized) {
          issues.push(`Chain not trusted: ${authError || 'unknown reason'}`);
        }
        if (cert.issuer && cert.subject &&
            cert.issuer.CN === cert.subject.CN &&
            JSON.stringify(cert.issuer) === JSON.stringify(cert.subject)) {
          issues.push('Certificate appears self-signed');
        }

        const altNames = (cert.subjectaltname || '')
          .split(',').map(s => s.trim().replace(/^DNS:/, ''));
        const namesToCheck = [cert.subject?.CN, ...altNames].filter(Boolean);
        const hostMatches = namesToCheck.some(n => matchesHostname(n, safeHost));
        if (!hostMatches) {
          issues.push(`Hostname "${safeHost}" does not match certificate names (${namesToCheck.join(', ') || 'none'})`);
        }
      }

      if (protocol && WEAK_PROTOCOLS.has(protocol)) {
        issues.push(`Outdated protocol negotiated: ${protocol}`);
      }

      resolve({
        ok: true,
        host: safeHost,
        port: safePort,
        protocol,
        cipher: cipher ? { name: cipher.name, version: cipher.version } : null,
        certificate: cert && Object.keys(cert).length ? {
          subject: cert.subject,
          issuer: cert.issuer,
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          serialNumber: cert.serialNumber,
          fingerprint256: cert.fingerprint256,
          altNames: (cert.subjectaltname || '').split(',').map(s => s.trim()).filter(Boolean),
        } : null,
        authorized,
        issues,
        grade: issues.length === 0 ? 'good' : (issues.some(i => /expired|not trusted|does not match/i.test(i)) ? 'poor' : 'warning'),
      });
      socket.end();
    });

    socket.on('timeout', () => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve({ ok: false, host: safeHost, port: safePort, error: 'Connection timed out' });
    });

    socket.on('error', err => {
      if (settled) return;
      settled = true;
      logger.warn(`sslChecker: ${safeHost}:${safePort} → ${err.message}`);
      resolve({ ok: false, host: safeHost, port: safePort, error: err.message });
    });
  });
}

function matchesHostname(pattern, host) {
  if (!pattern) return false;
  const p = pattern.toLowerCase();
  const h = host.toLowerCase();
  if (p === h) return true;
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".example.com"
    return h.endsWith(suffix) && h.split('.').length === p.split('.').length;
  }
  return false;
}

module.exports = { checkCertificate };

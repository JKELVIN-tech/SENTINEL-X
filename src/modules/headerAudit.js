'use strict';

/**
 * Sentinel X — HTTP Security Header Audit
 * ─────────────────────────────────────────────────────────────────────────────
 * Makes a single GET request to a URL and checks the response for common
 * security headers (HSTS, CSP, X-Frame-Options, etc.), flagging missing or
 * weak configuration. Pure Node `http`/`https` — no external binary.
 * ─────────────────────────────────────────────────────────────────────────────
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const logger = require('../utils/logger');

const DEFAULT_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 5;

const CHECKS = [
  {
    header: 'strict-transport-security',
    name: 'HSTS',
    severity: 'high',
    httpsOnly: true,
    advice: 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains to force HTTPS.',
  },
  {
    header: 'content-security-policy',
    name: 'Content-Security-Policy',
    severity: 'high',
    advice: 'Add a Content-Security-Policy to mitigate XSS and data-injection attacks.',
  },
  {
    header: 'x-frame-options',
    name: 'X-Frame-Options',
    severity: 'medium',
    advice: 'Add X-Frame-Options: DENY or SAMEORIGIN (or frame-ancestors in CSP) to prevent clickjacking.',
  },
  {
    header: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    severity: 'medium',
    advice: 'Add X-Content-Type-Options: nosniff to stop MIME-type sniffing.',
  },
  {
    header: 'referrer-policy',
    name: 'Referrer-Policy',
    severity: 'low',
    advice: 'Add a Referrer-Policy (e.g. strict-origin-when-cross-origin) to limit referrer leakage.',
  },
  {
    header: 'permissions-policy',
    name: 'Permissions-Policy',
    severity: 'low',
    advice: 'Add a Permissions-Policy to restrict powerful browser features (camera, geolocation, etc.).',
  },
];

function fetchHeaders(targetUrl, redirectsLeft = MAX_REDIRECTS, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch (_) {
      return reject(new Error('Invalid URL'));
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return reject(new Error('Only http:// and https:// URLs are supported'));
    }

    const client = parsed.protocol === 'https:' ? https : http;
    const req = client.request(parsed, {
      method: 'GET',
      timeout: timeoutMs,
      headers: { 'User-Agent': 'SentinelX-HeaderAudit/1.0' },
      rejectUnauthorized: false, // we report TLS issues separately via sslChecker
    }, res => {
      res.resume(); // discard body, we only care about headers/status
      const { statusCode, headers } = res;

      if ([301, 302, 303, 307, 308].includes(statusCode) && headers.location && redirectsLeft > 0) {
        const nextUrl = new URL(headers.location, parsed).toString();
        return resolve(fetchHeaders(nextUrl, redirectsLeft - 1, { timeoutMs }));
      }

      resolve({ finalUrl: parsed.toString(), statusCode, headers, protocol: parsed.protocol });
    });

    req.on('timeout', () => { req.destroy(new Error('Request timed out')); });
    req.on('error', reject);
    req.end();
  });
}

/**
 * auditUrl(url) → { url, finalUrl, statusCode, findings[], score }
 */
async function auditUrl(targetUrl, opts = {}) {
  if (!/^https?:\/\//i.test(targetUrl)) targetUrl = `https://${targetUrl}`;

  const { finalUrl, statusCode, headers, protocol } = await fetchHeaders(targetUrl, MAX_REDIRECTS, opts);

  const findings = [];
  for (const check of CHECKS) {
    if (check.httpsOnly && protocol !== 'https:') continue;
    const present = Object.prototype.hasOwnProperty.call(headers, check.header);
    findings.push({
      name: check.name,
      header: check.header,
      present,
      value: present ? headers[check.header] : null,
      severity: present ? 'ok' : check.severity,
      advice: present ? null : check.advice,
    });
  }

  // Server/X-Powered-By fingerprinting leak (informational, not a hard fail)
  if (headers['server']) {
    findings.push({
      name: 'Server banner',
      header: 'server',
      present: true,
      value: headers['server'],
      severity: 'info',
      advice: 'Consider suppressing or genericizing the Server header to reduce fingerprinting.',
    });
  }
  if (headers['x-powered-by']) {
    findings.push({
      name: 'X-Powered-By banner',
      header: 'x-powered-by',
      present: true,
      value: headers['x-powered-by'],
      severity: 'low',
      advice: 'Remove X-Powered-By to avoid revealing the backend framework/version.',
    });
  }

  const missingHigh = findings.filter(f => !f.present && f.severity === 'high').length;
  const missingMedium = findings.filter(f => !f.present && f.severity === 'medium').length;
  const score = Math.max(0, 100 - missingHigh * 25 - missingMedium * 10 -
    findings.filter(f => !f.present && f.severity === 'low').length * 5);

  logger.info(`headerAudit: ${finalUrl} → score ${score}/100 (${statusCode})`);

  return { url: targetUrl, finalUrl, statusCode, findings, score };
}

module.exports = { auditUrl };

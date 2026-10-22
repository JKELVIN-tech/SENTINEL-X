'use strict';

/**
 * Sentinel X — AI Analyst Module
 * ─────────────────────────────────────────────────────────────────────────────
 * Powered by Anthropic Claude (claude-sonnet-4-5).
 *
 * Capabilities:
 *   • Contextual analysis  — inject live scan/vuln/hash data into every prompt
 *   • Streaming responses  — Server-Sent Events streamed to the client
 *   • Conversation memory  — per-session multi-turn history
 *   • Structured reports   — JSON-schema guided pentest report generation
 *   • CVE lookup           — deep-dive explanation + exploit path + remediation
 *   • Attack chain builder — map vulnerabilities into a kill chain
 *   • Command advisor      — recommend NMAP / hashcat / payload commands
 * ─────────────────────────────────────────────────────────────────────────────
 */

const https    = require('https');
const { v4: uuid } = require('uuid');
const logger   = require('../utils/logger');

const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const MODEL             = 'claude-sonnet-4-5';
const MAX_TOKENS        = 4096;
const API_HOST          = 'api.anthropic.com';
const API_PATH          = '/v1/messages';

// ── Session store  { sessionId → { history[], context, createdAt, lastUsed } }
const sessions = new Map();
const SESSION_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours

// ──────────────────────────────────────────────
//  System prompt builder
//  Injects live platform data so Claude has full
//  awareness of the current engagement state.
// ──────────────────────────────────────────────
function buildSystemPrompt(context = {}) {
  const {
    target        = 'Not set',
    hostsUp       = 0,
    hostsTotal    = 0,
    openPorts     = 0,
    vulnerabilities = [],
    crackedHashes = [],
    scanDuration  = null,
    engagement    = 'Internal pentest',
  } = context;

  const vulnSummary = vulnerabilities.length
    ? vulnerabilities.map(v =>
        `  • ${v.cve || 'N/A'} — ${v.name} on ${v.host} [${v.severity}] CVSS:${v.cvss || '?'} (${v.status || 'open'})`
      ).join('\n')
    : '  None found yet.';

  const hashSummary = crackedHashes.length
    ? crackedHashes.map(h => `  • ${h.hash} → "${h.plaintext}" (${h.type || 'unknown'})`).join('\n')
    : '  None cracked yet.';

  return `You are the Sentinel X AI Analyst — an expert offensive security engineer and penetration tester embedded in the Sentinel X platform.

ENGAGEMENT CONTEXT
──────────────────
Engagement type : ${engagement}
Target scope    : ${target}
Hosts up/total  : ${hostsUp} / ${hostsTotal}
Open ports      : ${openPorts}
Scan duration   : ${scanDuration || 'N/A'}

VULNERABILITIES DETECTED
────────────────────────
${vulnSummary}

CRACKED CREDENTIALS
───────────────────
${hashSummary}

YOUR ROLE
─────────
You assist a professional penetration tester with:
  - Analysing scan results and identifying attack paths
  - Explaining CVEs, exploits, and their real-world impact
  - Recommending NMAP flags, payloads, hashcat rules, wordlist strategies
  - Generating professional pentest reports (executive + technical)
  - Building attack chains / kill-chain narratives from findings
  - Suggesting remediation steps for every vulnerability found

RULES
─────
  - Be concise and technical. Avoid filler sentences.
  - Always assume authorized testing on owned/permitted infrastructure.
  - When generating commands, include exact flags and explain each one.
  - Format code blocks with language tags.
  - When writing reports, use structured markdown with clear sections.
  - Severity ratings follow CVSS v3.1 scale.`;
}

// ──────────────────────────────────────────────
//  Low-level Anthropic API call (non-streaming)
// ──────────────────────────────────────────────
function callAnthropic(messages, systemPrompt, opts = {}) {
  return new Promise((resolve, reject) => {
    if (!ANTHROPIC_API_KEY) {
      return reject(new Error('ANTHROPIC_API_KEY not configured in .env'));
    }

    const body = JSON.stringify({
      model:      MODEL,
      max_tokens: opts.maxTokens || MAX_TOKENS,
      system:     systemPrompt,
      messages,
    });

    const options = {
      hostname: API_HOST,
      path:     API_PATH,
      method:   'POST',
      headers: {
        'Content-Type':      'application/json',
        'x-api-key':         ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Length':    Buffer.byteLength(body),
      },
    };

    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) return reject(new Error(parsed.error.message || JSON.stringify(parsed.error)));
          resolve(parsed);
        } catch (e) {
          reject(new Error(`JSON parse error: ${e.message} — raw: ${data.slice(0, 200)}`));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(120_000, () => {
      req.destroy(new Error('Anthropic API request timed out'));
    });
    req.write(body);
    req.end();
  });
}

// ──────────────────────────────────────────────
//  Streaming API call — writes SSE to Express res
// ──────────────────────────────────────────────
function streamAnthropic(messages, systemPrompt, opts = {}, onChunk, onDone, onError) {
  if (!ANTHROPIC_API_KEY) {
    return onError(new Error('ANTHROPIC_API_KEY not configured in .env'));
  }

  const body = JSON.stringify({
    model:      MODEL,
    max_tokens: opts.maxTokens || MAX_TOKENS,
    system:     systemPrompt,
    messages,
    stream:     true,
  });

  const options = {
    hostname: API_HOST,
    path:     API_PATH,
    method:   'POST',
    headers: {
      'Content-Type':      'application/json',
      'x-api-key':         ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
      'Content-Length':    Buffer.byteLength(body),
    },
  };

  let fullText  = '';
  let inputTok  = 0;
  let outputTok = 0;

  const req = https.request(options, res => {
    let buf = '';
    res.on('data', chunk => {
      buf += chunk.toString();
      const lines = buf.split('\n');
      buf = lines.pop(); // keep incomplete

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        const raw = line.slice(6).trim();
        if (raw === '[DONE]') continue;

        try {
          const evt = JSON.parse(raw);

          if (evt.type === 'content_block_delta' && evt.delta?.type === 'text_delta') {
            const text = evt.delta.text || '';
            fullText += text;
            onChunk(text);
          }

          if (evt.type === 'message_start' && evt.message?.usage) {
            inputTok = evt.message.usage.input_tokens || 0;
          }

          if (evt.type === 'message_delta' && evt.usage) {
            outputTok = evt.usage.output_tokens || 0;
          }

          if (evt.type === 'message_stop') {
            onDone(fullText, { inputTokens: inputTok, outputTokens: outputTok });
          }
        } catch (_) {
          // ignore malformed SSE lines
        }
      }
    });

    res.on('error', onError);
  });

  req.on('error', onError);
  req.setTimeout(180_000, () => req.destroy(new Error('Stream timeout')));
  req.write(body);
  req.end();
}

// ──────────────────────────────────────────────
//  Session management
// ──────────────────────────────────────────────
function createSession(context = {}) {
  const sessionId = uuid();
  sessions.set(sessionId, {
    id:        sessionId,
    history:   [],
    context,
    createdAt: new Date().toISOString(),
    lastUsed:  Date.now(),
    tokens:    { input: 0, output: 0 },
  });
  logger.info(`AI session created: ${sessionId}`);
  return sessionId;
}

function getSession(sessionId) {
  return sessions.get(sessionId) || null;
}

function updateSessionContext(sessionId, context) {
  const s = sessions.get(sessionId);
  if (!s) return false;
  s.context  = { ...s.context, ...context };
  s.lastUsed = Date.now();
  return true;
}

function deleteSession(sessionId) {
  const existed = sessions.has(sessionId);
  sessions.delete(sessionId);
  return existed;
}

function listSessions() {
  return [...sessions.values()].map(({ history: _h, ...s }) => ({
    ...s,
    messageCount: sessions.get(s.id)?.history?.length || 0,
  }));
}

// Purge expired sessions every 30 minutes
setInterval(() => {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [id, s] of sessions) {
    if (s.lastUsed < cutoff) {
      sessions.delete(id);
      logger.info(`AI session expired: ${id}`);
    }
  }
}, 30 * 60 * 1000);

// ──────────────────────────────────────────────
//  Core chat — non-streaming
// ──────────────────────────────────────────────
async function chat(sessionId, userMessage, opts = {}) {
  let session = sessions.get(sessionId);
  if (!session) {
    // Auto-create ephemeral session
    const newId = createSession(opts.context || {});
    session = sessions.get(newId);
    sessionId = newId;
  }

  session.history.push({ role: 'user', content: userMessage });
  session.lastUsed = Date.now();

  const systemPrompt = buildSystemPrompt(session.context);

  try {
    const response = await callAnthropic(session.history, systemPrompt, opts);
    const reply    = response.content?.[0]?.text || '';
    const usage    = response.usage || {};

    session.history.push({ role: 'assistant', content: reply });
    session.tokens.input  += usage.input_tokens  || 0;
    session.tokens.output += usage.output_tokens || 0;

    logger.info(`AI chat [${sessionId}] — in:${usage.input_tokens} out:${usage.output_tokens}`);
    return { sessionId, reply, usage, historyLength: session.history.length };
  } catch (err) {
    // Roll back the user message on failure
    session.history.pop();
    throw err;
  }
}

// ──────────────────────────────────────────────
//  Streaming chat — pipes chunks to Express res
// ──────────────────────────────────────────────
function chatStream(sessionId, userMessage, res, opts = {}) {
  let session = sessions.get(sessionId);
  if (!session) {
    const newId = createSession(opts.context || {});
    session = sessions.get(newId);
    sessionId = newId;
  }

  session.history.push({ role: 'user', content: userMessage });
  session.lastUsed = Date.now();

  const systemPrompt = buildSystemPrompt(session.context);

  // SSE headers
  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('X-Session-Id',  sessionId);
  res.flushHeaders();

  // Send session id first so client can store it
  res.write(`data: ${JSON.stringify({ type: 'session', sessionId })}\n\n`);

  streamAnthropic(
    session.history,
    systemPrompt,
    opts,
    // onChunk
    (text) => {
      res.write(`data: ${JSON.stringify({ type: 'chunk', text })}\n\n`);
    },
    // onDone
    (fullText, usage) => {
      session.history.push({ role: 'assistant', content: fullText });
      session.tokens.input  += usage.inputTokens  || 0;
      session.tokens.output += usage.outputTokens || 0;
      logger.info(`AI stream [${sessionId}] done — in:${usage.inputTokens} out:${usage.outputTokens}`);
      res.write(`data: ${JSON.stringify({ type: 'done', usage, historyLength: session.history.length })}\n\n`);
      res.end();
    },
    // onError
    (err) => {
      logger.error(`AI stream error [${sessionId}]: ${err.message}`);
      session.history.pop(); // rollback
      res.write(`data: ${JSON.stringify({ type: 'error', error: err.message })}\n\n`);
      res.end();
    }
  );
}

// ──────────────────────────────────────────────
//  Specialised analysts
// ──────────────────────────────────────────────

/**
 * generateReport(context, format)
 * Generates a full professional pentest report.
 * format: 'markdown' | 'executive' | 'technical'
 */
async function generateReport(context, format = 'markdown') {
  const prompts = {
    markdown: `Generate a complete professional penetration testing report in Markdown for the engagement described in your context.

Structure:
# Penetration Test Report
## Executive Summary
## Scope & Methodology
## Findings Overview (table: CVE, name, severity, host, CVSS, status)
## Detailed Findings
### [For each vuln: description, impact, proof of concept, remediation]
## Attack Chain Narrative
## Compromised Credentials
## Recommendations (prioritised)
## Conclusion

Use proper markdown tables, code blocks, and headers. Be thorough and professional.`,

    executive: `Write an executive summary (max 400 words) for a non-technical audience.
Cover: what was tested, key findings, business risk, top 3 priorities, overall risk rating.
No jargon. Plain language. Suitable for C-suite.`,

    technical: `Write a detailed technical findings section for each vulnerability in the context.
For each: exact CVE, affected component, attack vector, proof-of-concept steps, 
evidence/output, CVSS breakdown, specific remediation with version/config details.
Include exact commands a defender would run to patch each issue.`,
  };

  const prompt = prompts[format] || prompts.markdown;

  // Use a fresh session with the engagement context
  const sessionId = createSession(context);
  const result    = await chat(sessionId, prompt, { maxTokens: 4096 });
  deleteSession(sessionId);
  return result.reply;
}

/**
 * explainCVE(cveId, context)
 * Deep-dive on a specific CVE.
 */
async function explainCVE(cveId, context = {}) {
  const sessionId = createSession(context);
  const prompt = `Provide a comprehensive analysis of ${cveId}:

1. **Vulnerability Description** — what it is, root cause
2. **Affected Versions** — exact version ranges
3. **Attack Vector** — how it is exploited (step by step)
4. **Real-World Impact** — what an attacker achieves
5. **Proof of Concept** — safe lab demonstration commands
6. **Detection** — IOCs, log signatures, IDS rules
7. **Remediation** — patches, config changes, workarounds
8. **Hashcat/NMAP** — relevant scanning or cracking commands if applicable

Be precise. Include actual commands and version numbers.`;

  const result = await chat(sessionId, prompt, { maxTokens: 2048 });
  deleteSession(sessionId);
  return result.reply;
}

/**
 * buildAttackChain(context)
 * Maps vulnerabilities into a logical kill chain.
 */
async function buildAttackChain(context = {}) {
  const sessionId = createSession(context);
  const prompt = `Based on the vulnerabilities and cracked credentials in this engagement, build a detailed attack chain narrative.

Structure it as a kill chain:
1. **Initial Recon** — what was discovered and how
2. **Initial Access** — which vuln provides entry and how
3. **Execution** — what runs post-exploitation
4. **Privilege Escalation** — path to root/SYSTEM using findings
5. **Lateral Movement** — how to pivot across the network using cracked creds and open ports
6. **Persistence** — how an attacker would maintain access
7. **Impact** — what data/systems are at risk

For each step, reference specific IPs, CVEs, and credentials from the context.
Include exact commands for each phase.`;

  const result = await chat(sessionId, prompt, { maxTokens: 2048 });
  deleteSession(sessionId);
  return result.reply;
}

/**
 * recommendCommands(task, context)
 * task: 'nmap' | 'hashcat' | 'payload' | 'wordlist'
 */
async function recommendCommands(task, context = {}) {
  const taskPrompts = {
    nmap: `Based on the current scan results and targets, recommend the optimal NMAP commands for deeper enumeration.
Include: version detection, vulnerability scripts, OS fingerprinting, evasion if needed.
Explain every flag used. Provide 3 command variants: quick, thorough, stealth.`,

    hashcat: `Based on the NTLM hashes and targets found, recommend the best hashcat attack strategy.
Include: mode selection, rule files, wordlist order, mask attack for residuals.
Provide exact hashcat commands with all flags explained.`,

    payload: `Based on the vulnerabilities found, recommend the most effective payloads for each exploitable host.
For each: target IP, vulnerability, payload type, exact msfvenom or manual command, listener setup.`,

    wordlist: `Based on the organisation name, domain, and usernames discovered, recommend a targeted wordlist strategy.
Include: base words to use, mutation rules, wordlist order, custom rule file content for hashcat.`,
  };

  const prompt = taskPrompts[task] || `Provide expert recommendations for: ${task}`;
  const sessionId = createSession(context);
  const result    = await chat(sessionId, prompt, { maxTokens: 2048 });
  deleteSession(sessionId);
  return result.reply;
}

// ──────────────────────────────────────────────
//  Status check
// ──────────────────────────────────────────────
function getStatus() {
  return {
    configured:    !!ANTHROPIC_API_KEY,
    model:         MODEL,
    maxTokens:     MAX_TOKENS,
    activeSessions: sessions.size,
    sessionTtlHrs: SESSION_TTL_MS / 3_600_000,
  };
}

module.exports = {
  // Session management
  createSession,
  getSession,
  updateSessionContext,
  deleteSession,
  listSessions,
  // Chat
  chat,
  chatStream,
  // Specialised
  generateReport,
  explainCVE,
  buildAttackChain,
  recommendCommands,
  // Util
  getStatus,
  buildSystemPrompt,
};

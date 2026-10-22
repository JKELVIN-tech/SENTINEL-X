#!/usr/bin/env node
/**
 * Sentinel X — Full API Test Suite
 * Run: node src/test.js
 * Server must be running: npm start
 */
'use strict';

const BASE = 'http://127.0.0.1:3000';
let API_KEY = '';
try {
  const env = require('fs').readFileSync('.env', 'utf8');
  API_KEY   = env.match(/^API_KEY=(.+)$/m)?.[1]?.trim() || '';
} catch (_) {}

const H = { 'Content-Type': 'application/json', 'X-API-Key': API_KEY };
const req = async (method, path, body) => {
  const r = await fetch(`${BASE}${path}`, { method, headers: H, body: body ? JSON.stringify(body) : undefined });
  return { status: r.status, json: await r.json().catch(() => ({})) };
};

const pass = m => console.log(`  \x1b[32m✔\x1b[0m  ${m}`);
const fail = m => console.log(`  \x1b[31m✘\x1b[0m  ${m}`);
const info = m => console.log(`  \x1b[36m→\x1b[0m  ${m}`);
const head = m => console.log(`\n  \x1b[1m\x1b[33m${m}\x1b[0m`);
const wait = ms => new Promise(r => setTimeout(r, ms));

async function pollJob(path, maxWaitSec = 30) {
  for (let i = 0; i < maxWaitSec; i++) {
    await wait(1000);
    const r = await req('GET', path);
    const s = r.json.status;
    process.stdout.write(`\r     status: ${s}              `);
    if (['complete','error','cancelled','timeout'].includes(s)) {
      process.stdout.write('\n');
      return r.json;
    }
  }
  process.stdout.write('\n');
  return null;
}

async function run() {
  console.log('\n\x1b[1m  ╔══════════════════════════════════╗\x1b[0m');
  console.log('\x1b[1m  ║   SENTINEL X — API TEST SUITE    ║\x1b[0m');
  console.log('\x1b[1m  ╚══════════════════════════════════╝\x1b[0m');

  // ── SYSTEM
  head('SYSTEM');
  let r = await req('GET', '/health');
  r.status === 200 ? pass(`Health OK — uptime: ${r.json.uptime}s`) : fail(`Health: ${r.status}`);

  r = await req('GET', '/api/system/info');
  r.status === 200 ? pass(`System info — NMAP: ${r.json.nmap?.version || 'N/A'}`) : fail(`System info: ${r.status}`);

  r = await req('GET', '/api/system/stats');
  r.status === 200 ? pass(`Stats OK — heap: ${r.json.memory?.heap}`) : fail(`Stats: ${r.status}`);

  // ── NMAP
  head('NMAP ENGINE');
  r = await req('GET', '/api/nmap/status');
  r.status === 200 ? pass(`NMAP ${r.json.available ? 'available' : 'NOT FOUND'} — v${r.json.version}`) : fail(`NMAP status: ${r.status}`);

  r = await req('POST', '/api/nmap/validate', { target:'127.0.0.1', flags:['-sV','-T4'], portRange:'80,443' });
  r.json.valid ? pass(`Validate OK → ${r.json.command}`) : fail(`Validate: ${JSON.stringify(r.json)}`);

  r = await req('POST', '/api/nmap/scan', { target:'127.0.0.1', flags:['-sV','-T4','-Pn'], portRange:'22,80,443,3000', label:'Test scan' });
  if (r.status === 202) {
    pass(`Scan queued — jobId: ${r.json.jobId}`);
    const done = await pollJob(`/api/nmap/scan/${r.json.jobId}`, 45);
    done?.status === 'complete'
      ? pass(`Scan complete — ${done.results?.hostsUp || 0} host(s) up`)
      : fail(`Scan ended: ${done?.status}`);
    const out = await req('GET', `/api/nmap/scan/${r.json.jobId}/output`);
    out.status === 200 ? pass(`Output endpoint OK — ${out.json.total} lines`) : fail(`Output: ${out.status}`);
  } else {
    fail(`Scan start failed — ${JSON.stringify(r.json)}`);
  }

  r = await req('GET', '/api/nmap/jobs?limit=5');
  r.status === 200 ? pass(`Jobs list OK — ${r.json.total} total`) : fail(`Jobs: ${r.status}`);

  // ── HASH IDENTIFIER
  head('HASH IDENTIFIER');
  r = await req('POST', '/api/hash/identify', { hash: '5f4dcc3b5aa765d61d8327deb882cf99' });
  if (r.status === 200 && r.json.results?.length) {
    const top = r.json.results[0].candidates[0];
    pass(`Identify MD5 → top: ${top?.name} (confidence: ${top?.confidence})`);
  } else fail(`Identify failed: ${r.status}`);

  r = await req('POST', '/api/hash/identify', { hashes: [
    '5f4dcc3b5aa765d61d8327deb882cf99',
    'aaf4c61ddcc5e8a2dabede0f3b482cd9947e6564',
    '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p72Lu8WHXHkaS8/OGtOIa',
  ]});
  r.status === 200 ? pass(`Multi-hash identify OK — ${r.json.results.length} results`) : fail(`Multi-identify: ${r.status}`);

  // ── HASH COMPUTE
  head('HASH COMPUTE');
  r = await req('POST', '/api/hash/compute', { plaintext: 'password', algorithms: ['md5','sha1','sha256','ntlm'] });
  if (r.status === 200) {
    pass(`Compute OK`);
    console.log(`       MD5  → ${r.json.hashes.md5}`);
    console.log(`       SHA1 → ${r.json.hashes.sha1}`);
    console.log(`       NTLM → ${r.json.hashes.ntlm}`);
  } else fail(`Compute: ${r.status}`);

  // ── HASH CRACKER — dictionary
  head('HASH CRACKER (dictionary)');
  const testHashes = [
    '5f4dcc3b5aa765d61d8327deb882cf99',  // password
    'e10adc3949ba59abbe56e057f20f883e',  // 123456
    '098f6bcd4621d373cade4e832627b4f6',  // test
  ];
  r = await req('POST', '/api/hash/crack', { hashes: testHashes, hashType: 'md5', mode: 'dictionary', label: 'Dict test' });
  if (r.status === 202) {
    pass(`Crack queued — jobId: ${r.json.jobId}  type: ${r.json.hashType}`);
    const done = await pollJob(`/api/hash/crack/${r.json.jobId}`, 60);
    const crackedCount = Object.keys(done?.cracked || {}).length;
    crackedCount > 0
      ? pass(`Cracked ${crackedCount}/${testHashes.length}: ${JSON.stringify(done.cracked)}`)
      : fail(`0 cracked — rockyou.txt may not be installed`);
  } else fail(`Crack start: ${JSON.stringify(r.json)}`);

  // ── HASH CRACKER — brute-force
  head('HASH CRACKER (brute-force)');
  info('Cracking MD5("abc") with brute-force len 1-3...');
  r = await req('POST', '/api/hash/crack', {
    hashes:    ['900150983cd24fb0d6963f7d28e17f72'],
    hashType:  'md5',
    mode:      'bruteforce',
    bruteOpts: { minLen: 1, maxLen: 3, charsets: ['lower'] },
    label:     'BF test',
  });
  if (r.status === 202) {
    const done = await pollJob(`/api/hash/crack/${r.json.jobId}`, 30);
    done?.cracked?.['900150983cd24fb0d6963f7d28e17f72'] === 'abc'
      ? pass(`Brute-force cracked → "abc" ✓`)
      : fail(`BF result: ${JSON.stringify(done?.cracked)}`);
  } else fail(`BF start: ${r.status}`);

  r = await req('GET', '/api/hash/status');
  r.status === 200 ? pass(`Hashcat binary: ${r.json.hashcat?.available ? 'found' : 'not found'}`) : fail(`Hash status: ${r.status}`);

  r = await req('GET', '/api/hash/types');
  r.status === 200 ? pass(`Hash types: ${r.json.types.length} supported`) : fail(`Types: ${r.status}`);

  // ── WORDLISTS
  head('WORDLIST MANAGER');
  r = await req('GET', '/api/wordlists');
  r.status === 200
    ? pass(`Wordlists: ${r.json.count} known, ${r.json.wordlists.filter(w => w.exists).length} present on disk`)
    : fail(`Wordlists: ${r.status}`);

  r = await req('GET', '/api/wordlists/mutations');
  r.status === 200 ? pass(`Mutations: ${r.json.mutations.map(m => m.id).join(', ')}`) : fail(`Mutations: ${r.status}`);

  r = await req('POST', '/api/wordlists/generate', {
    baseWords:  ['admin', 'password', 'sentinel', 'kali'],
    mutations:  ['leet', 'appendYears', 'appendSymbols', 'capitalize'],
    outputName: 'sentinelx_test',
  });
  if (r.status === 201) {
    pass(`Generated: ${r.json.name} — ${r.json.lines} entries`);

    const prev = await req('GET', `/api/wordlists/preview?path=${encodeURIComponent(r.json.path)}&head=5`);
    prev.status === 200
      ? pass(`Preview OK — sample: [${prev.json.head.join(', ')}]`)
      : fail(`Preview: ${prev.status}`);

    const srch = await req('GET', `/api/wordlists/search?path=${encodeURIComponent(r.json.path)}&term=admin&limit=5`);
    srch.status === 200
      ? pass(`Search "admin" → ${srch.json.found} matches`)
      : fail(`Search: ${srch.status}`);

    await req('DELETE', `/api/wordlists/sentinelx_test.txt`);
    pass(`Cleanup: test wordlist deleted`);
  } else fail(`Generate: ${JSON.stringify(r.json)}`);

  // ── SUMMARY
  console.log('\n  \x1b[1m\x1b[32m══════════════════════════════════════\x1b[0m');
  console.log('  \x1b[1m\x1b[32m   All tests complete — Sentinel X v2\x1b[0m');
  console.log('  \x1b[1m\x1b[32m══════════════════════════════════════\x1b[0m\n');
}

run().catch(err => {
  console.error('\n  \x1b[31mFatal:', err.message, '\x1b[0m\n');
  process.exit(1);
});

// ── AI ANALYST (appended by build step)
async function runAITests() {
  const head = m => console.log(`\n  \x1b[1m\x1b[33m${m}\x1b[0m`);
  const pass = m => console.log(`  \x1b[32m✔\x1b[0m  ${m}`);
  const fail = m => console.log(`  \x1b[31m✘\x1b[0m  ${m}`);
  const wait = ms => new Promise(r => setTimeout(r, ms));
  const BASE = 'http://127.0.0.1:3000';
  let API_KEY = '';
  try { API_KEY = require('fs').readFileSync('.env','utf8').match(/^API_KEY=(.+)$/m)?.[1]?.trim()||''; } catch(_){}
  const H = { 'Content-Type':'application/json','X-API-Key':API_KEY };
  const req = async (m,p,b) => {
    const r = await fetch(`${BASE}${p}`,{method:m,headers:H,body:b?JSON.stringify(b):undefined});
    return {status:r.status,json:await r.json().catch(()=>({}))};
  };

  head('AI ANALYST');

  // Status
  let r = await req('GET','/api/ai/status');
  r.status===200
    ? pass(`AI status — configured:${r.json.configured} model:${r.json.model} sessions:${r.json.activeSessions}`)
    : fail(`AI status: ${r.status}`);

  if (!r.json.configured) {
    console.log('  \x1b[33m  ⚠  ANTHROPIC_API_KEY not set — skipping live AI tests\x1b[0m');
    console.log('     Set it in .env: ANTHROPIC_API_KEY=sk-ant-...\n');
    return;
  }

  // Create session
  r = await req('POST','/api/ai/session',{
    context:{
      target:'192.168.1.0/24', hostsUp:47, openPorts:312,
      vulnerabilities:[
        {cve:'CVE-2021-44228',name:'Log4Shell',host:'192.168.1.12',severity:'critical',cvss:'10.0',status:'open'},
        {cve:'CVE-2017-0144', name:'EternalBlue',host:'192.168.1.5',severity:'critical',cvss:'9.8',status:'open'},
      ],
      crackedHashes:[{hash:'5f4dcc3b5aa765d61d8327deb882cf99',plaintext:'password',type:'md5'}],
    }
  });
  const sessionId = r.json.sessionId;
  r.status===201 ? pass(`Session created: ${sessionId}`) : fail(`Session: ${r.status}`);

  // Chat (non-streaming)
  r = await req('POST','/api/ai/chat',{
    sessionId,
    message:'What is the highest priority vulnerability in this engagement and why?',
  });
  if (r.status===200 && r.json.reply) {
    pass(`Chat OK — ${r.json.reply.length} chars, ${r.json.usage?.output_tokens} tokens`);
    console.log(`\n  \x1b[35m  AI: ${r.json.reply.slice(0,200)}...\x1b[0m\n`);
  } else fail(`Chat: ${r.status} — ${JSON.stringify(r.json).slice(0,100)}`);

  // Multi-turn follow-up
  r = await req('POST','/api/ai/chat',{
    sessionId,
    message:'Give me the exact NMAP command to verify the EternalBlue vulnerability.',
  });
  r.status===200 ? pass(`Multi-turn follow-up OK — history: ${r.json.historyLength} msgs`)
                 : fail(`Follow-up: ${r.status}`);

  // CVE analysis
  r = await req('POST','/api/ai/cve',{cve:'CVE-2021-44228'});
  r.status===200 && r.json.analysis
    ? pass(`CVE analysis OK — ${r.json.analysis.length} chars`)
    : fail(`CVE: ${r.status}`);

  // Command recommendation
  r = await req('POST','/api/ai/recommend',{task:'nmap'});
  r.status===200 && r.json.recommendations
    ? pass(`NMAP recommendations OK — ${r.json.recommendations.length} chars`)
    : fail(`Recommend: ${r.status}`);

  // Attack chain
  r = await req('POST','/api/ai/attack-chain',{
    context:{
      target:'192.168.1.0/24',hostsUp:47,openPorts:312,
      vulnerabilities:[
        {cve:'CVE-2021-44228',name:'Log4Shell',host:'192.168.1.12',severity:'critical',cvss:'10.0',status:'open'},
        {cve:'CVE-2017-0144',name:'EternalBlue',host:'192.168.1.5',severity:'critical',cvss:'9.8',status:'open'},
      ],
      crackedHashes:[{hash:'8846f7eaee8fb117ad06bdd830b7586c',plaintext:'password',type:'ntlm'}],
    }
  });
  r.status===200 && r.json.attackChain
    ? pass(`Attack chain OK — ${r.json.attackChain.length} chars`)
    : fail(`Attack chain: ${r.status}`);

  // Report generation (executive)
  r = await req('POST','/api/ai/report',{
    format:'executive',
    context:{
      target:'192.168.1.0/24',hostsUp:47,openPorts:312,
      vulnerabilities:[
        {cve:'CVE-2021-44228',name:'Log4Shell',host:'192.168.1.12',severity:'critical',cvss:'10.0',status:'open'},
      ],
    }
  });
  r.status===200 && r.json.report
    ? pass(`Executive report OK — ${r.json.report.length} chars`)
    : fail(`Report: ${r.status}`);

  // Context update
  r = await req('PATCH',`/api/ai/session/${sessionId}/context`,{hostsUp:50,newHost:'192.168.1.99'});
  r.status===200 ? pass('Context update OK') : fail(`Context update: ${r.status}`);

  // Sessions list
  r = await req('GET','/api/ai/sessions');
  r.status===200 ? pass(`Sessions list: ${r.json.sessions.length} active`) : fail(`Sessions: ${r.status}`);

  // Delete session
  r = await req('DELETE',`/api/ai/session/${sessionId}`);
  r.status===200 ? pass(`Session deleted: ${sessionId}`) : fail(`Delete: ${r.status}`);
}

// Run AI tests if called directly
if (require.main === module) {
  runAITests().catch(console.error);
}
module.exports = { runAITests };

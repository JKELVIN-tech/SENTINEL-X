/**
 * Sentinel X — Application Controller
 * Owns navigation, global state, and wires all modules together.
 */
'use strict';

const App = (() => {
  // ── Global state
  const state = {
    user:            null,
    currentSection:  'dashboard',
    activeEngagement:null,
    wsConnected:     false,
    nmapJobId:       null,
    crackJobId:      null,
    aiSessionId:     null,
    scanPollInt:     null,
    crackPollInt:    null,
  };

  // ── Section registry — keyed by section id
  const _sections = {};

  function register(id, mod) {
    _sections[id] = mod;
  }

  // ── Navigation
  function nav(id) {
    state.currentSection = id;

    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    const navEl = document.querySelector(`[data-nav="${id}"]`);
    if (navEl) navEl.classList.add('active');

    document.querySelectorAll('.section').forEach(s => s.classList.remove('active'));
    const sec = document.getElementById(`sec-${id}`);
    if (sec) sec.classList.add('active');

    _sections[id]?.onEnter?.();
  }

  // ── Live feed terminal
  const liveFeed = {
    get el() { return document.getElementById('live-feed'); },
    add(src, cls, msg, mc = '') {
      if (!this.el) return;
      const now  = new Date().toTimeString().slice(0, 8);
      const line = document.createElement('div');
      line.className = 'tl';
      line.innerHTML =
        `<span class="tt">[${now}]</span>` +
        `<span class="ts ${cls}">${src}</span>` +
        `<span class="tm ${mc}">${msg}</span>`;
      this.el.appendChild(line);
      this.el.scrollTop = this.el.scrollHeight;
      while (this.el.children.length > 500) this.el.firstChild.remove();
    },
    clear() { if (this.el) this.el.innerHTML = ''; },
  };

  // ── Stat counters
  function updateStats(data = {}) {
    Object.entries(data).forEach(([k, v]) => {
      const el = document.getElementById(`stat-${k}`);
      if (el) el.textContent = v;
    });
  }

  // ── Scan UI state machine
  function updateScanUI(status, results) {
    const btn  = document.getElementById('scan-execute-btn');
    const prog = document.getElementById('scan-progress-row');
    const fill = document.getElementById('scan-prog-fill');
    const pct  = document.getElementById('scan-prog-pct');

    if (status === 'running') {
      if (btn)  { btn.disabled = true; btn.textContent = '⏳  SCANNING…'; }
      if (prog) prog.style.display = 'flex';
      let p = 0;
      clearInterval(state.scanPollInt);
      state.scanPollInt = setInterval(() => {
        p = Math.min(p + Math.random() * 3, 92);
        if (fill) fill.style.width = p + '%';
        if (pct)  pct.textContent  = Math.round(p) + '%';
      }, 800);
    } else {
      clearInterval(state.scanPollInt);
      if (btn) { btn.disabled = false; btn.textContent = '▶  EXECUTE SCAN'; }
      if (fill && status === 'complete') fill.style.width = '100%';
      if (pct  && status === 'complete') pct.textContent  = '100%';
      setTimeout(() => { if (prog) prog.style.display = 'none'; }, 1500);
      if (results) _sections['nmap']?.renderResults?.(results);
    }
  }

  // ── WebSocket wiring
  function wireWebSocket() {
    WS.on('ws:connected', () => {
      state.wsConnected = true;
      const dot = document.getElementById('ws-dot');
      const txt = document.getElementById('ws-status');
      if (dot) dot.classList.add('connected');
      if (txt) txt.textContent = 'LIVE';
      liveFeed.add('SYS', 'sys', 'WebSocket connected — real-time feed active.', 'ok');
    });

    WS.on('ws:disconnected', () => {
      state.wsConnected = false;
      const dot = document.getElementById('ws-dot');
      const txt = document.getElementById('ws-status');
      if (dot) dot.classList.remove('connected');
      if (txt) txt.textContent = 'RECONNECTING';
      liveFeed.add('SYS', 'sys', 'WebSocket disconnected — reconnecting…', 'warn');
    });

    WS.on('scan_queued',   d => liveFeed.add('NMAP','nmap',`Scan queued — target: ${d.target}`,'info'));
    WS.on('scan_started',  d => { liveFeed.add('NMAP','nmap',`Scan started — PID ${d.pid||'?'}`,'info'); updateScanUI('running'); });
    WS.on('scan_output',   d => { if (d.jobId === state.nmapJobId) liveFeed.add('NMAP','nmap', d.line); });
    WS.on('scan_complete', d => {
      liveFeed.add('NMAP','nmap',`Scan complete — ${d.results?.hostsUp||0} hosts up`,'ok');
      updateScanUI('complete', d.results);
      if (d.results) updateStats({
        hosts: d.results.hostsUp || 0,
        ports: d.results.hosts?.reduce((n,h)=>n+h.openPortCount,0)||0,
      });
      clearInterval(state.scanPollInt);
    });
    WS.on('scan_error',    d => { liveFeed.add('NMAP','nmap',`Scan error: ${d.error}`,'warn'); updateScanUI('error'); clearInterval(state.scanPollInt); });
    WS.on('scan_cancelled',d => { liveFeed.add('NMAP','nmap','Scan cancelled','warn'); updateScanUI('cancelled'); clearInterval(state.scanPollInt); });

    WS.on('crack_started', d => liveFeed.add('HASH','hash',`Cracking started — ${d.hashes} hash(es)`,'info'));
    WS.on('hash_cracked',  d => {
      liveFeed.add('HASH','hash',`CRACKED: ${d.hash.slice(0,16)}… → "${d.plaintext}"`,'warn');
      _sections['hash']?.onCracked?.(d);
    });
    WS.on('hash_progress', d => _sections['hash']?.onProgress?.(d));
    WS.on('crack_complete',d => {
      liveFeed.add('HASH','hash',`Cracking complete — ${d.crackedCount}/${d.totalHashes} cracked`,'ok');
      _sections['hash']?.onComplete?.(d);
      clearInterval(state.crackPollInt);
      updateStats({ cracked: d.crackedCount || 0 });
    });
    WS.on('crack_error',   d => { liveFeed.add('HASH','hash',`Crack error: ${d.error}`,'warn'); clearInterval(state.crackPollInt); });
  }

  // ── Boot sequence
  async function boot() {
    if (API.isAuthed()) {
      try {
        state.user = await API.Auth.me();
        showApp();
      } catch (_) { showLogin(); }
    } else {
      showLogin();
    }
    window.addEventListener('sx:logout', () => { state.user = null; showLogin(); });
  }

  function showLogin() {
    document.getElementById('login-screen').style.display = 'flex';
    document.getElementById('app-shell').style.display    = 'none';
  }

  function showApp() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('app-shell').style.display    = 'grid';
    const uEl = document.getElementById('header-username');
    if (uEl) uEl.textContent = state.user?.username || 'user';
    wireWebSocket();
    loadDashboard();
    nav('dashboard');
  }

  async function loadDashboard() {
    try {
      const [nmapStatus, hashStatus, aiStatus] = await Promise.allSettled([
        API.Nmap.status(),
        API.Hash.status(),
        API.AI.status(),
      ]);
      if (nmapStatus.status === 'fulfilled') {
        const s = nmapStatus.value;
        liveFeed.add('SYS','sys', s.available ? `NMAP v${s.version} ready` : 'NMAP not found', s.available ? 'ok' : 'warn');
      }
      if (hashStatus.status === 'fulfilled') {
        liveFeed.add('HASH','hash', `Hash cracker ready — wordlists: ${hashStatus.value.wordlistsFound}`, 'ok');
      }
      if (aiStatus.status === 'fulfilled') {
        const s = aiStatus.value;
        liveFeed.add('AI','ai', s.configured ? `AI Analyst connected — ${s.model}` : 'AI Analyst offline (no API key)', s.configured ? 'ok' : 'warn');
      }
      const jobs = await API.Nmap.listJobs({ limit: 5 });
      const last = jobs.jobs?.filter(j => j.status === 'complete')[0];
      if (last) updateStats({ hosts: last.hosts_up || 0, ports: last.open_ports || 0 });
      const crack = await API.Hash.listJobs();
      const cracked = crack.jobs?.reduce((n,j) => n + (j.cracked_count || j.crackedCount || 0), 0) || 0;
      updateStats({ cracked });
    } catch (err) { console.warn('Dashboard:', err.message); }
  }

  // Public interface — sections exposed via _sections for modules.js
  return { boot, nav, register, state, liveFeed, updateStats, updateScanUI, showApp,
           get sections() { return _sections; } };
})();

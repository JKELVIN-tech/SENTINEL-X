/**
 * Sentinel X — Section Modules
 * Each section registers itself with App and handles
 * its own rendering, API calls, and WebSocket events.
 */
'use strict';

// ══════════════════════════════════════════════
//  NMAP MODULE
// ══════════════════════════════════════════════
App.register('nmap', {
  async onEnter() {
    await this.loadStatus();
    this.buildCmd();
  },

  async loadStatus() {
    try {
      const s = await API.Nmap.status();
      html('#nmap-binary-status',
        s.available
          ? `<span style="color:#00ff88">● NMAP v${s.version} ready</span>`
          : `<span style="color:#ff4757">✘ nmap not found at ${s.binary}</span>`
      );
    } catch (_) {}
  },

  buildCmd() {
    const target    = document.getElementById('nm-target')?.value    || 'TARGET';
    const ports     = document.getElementById('nm-ports')?.value     || '1-1000';
    const scanType  = document.getElementById('nm-type')?.value      || '-sS';
    const timing    = document.getElementById('nm-timing')?.value    || '-T3';
    const outputFmt = document.getElementById('nm-output')?.value    || '';

    const flags = [scanType, timing];
    document.querySelectorAll('#nmap-flags-grid .cbi.on[data-flag]').forEach(el => {
      const f = el.dataset.flag;
      if (f && !flags.includes(f)) flags.push(f);
    });
    if (outputFmt) flags.push(outputFmt);

    const portArg = ports && ports !== '-' ? `-p${ports}` : '';
    const cmd = `nmap ${[...flags, portArg, target].filter(Boolean).join(' ')}`;

    html('#nmap-cmd-preview', `<span style="color:#c471ed">nmap</span> <span style="color:#ffa502">${flags.join(' ')}</span> ${portArg ? `<span style="color:#00d4ff">${portArg}</span>` : ''} <span style="color:#ff4757">${target}</span>`);

    // Update header target display
    const hdrTarget = document.getElementById('header-target');
    if (hdrTarget) hdrTarget.textContent = target;

    return { target, flags, portRange: ports, cmd };
  },

  async executeScan() {
    const { target, flags, portRange } = this.buildCmd();
    if (!target || target === 'TARGET') { Toast.error('Enter a target IP/CIDR first'); return; }

    try {
      // Validate first
      const v = await API.Nmap.validateCmd({ target, flags, portRange });
      if (!v.valid) { Toast.error(`Invalid command: ${v.error}`); return; }

      const job = await API.Nmap.startScan({ target, flags, portRange, label: `Scan ${target}` });
      App.state.nmapJobId = job.jobId;
      Toast.info(`Scan queued — job ${job.jobId.slice(0,8)}…`);
      App.updateScanUI('running');

    } catch (err) {
      Toast.error(`Scan failed: ${err.message}`);
      App.updateScanUI('error');
    }
  },

  async cancelScan() {
    if (!App.state.nmapJobId) return;
    try {
      await API.Nmap.cancelScan(App.state.nmapJobId);
      Toast.warn('Scan cancelled');
    } catch (err) { Toast.error(err.message); }
  },

  async copyCmd() {
    const { cmd } = this.buildCmd();
    await navigator.clipboard.writeText(cmd).catch(() => {});
    Toast.success('Command copied to clipboard');
  },

  async loadJobs() {
    try {
      const { jobs } = await API.Nmap.listJobs({ limit: 20 });
      const rows = jobs.map(j => [
        Fmt.mono(j.id.slice(0,8) + '…'),
        j.label || j.target,
        Fmt.status(j.status),
        j.hosts_up ?? '—',
        j.open_ports ?? '—',
        Fmt.ts(j.queued_at),
        `<button onclick="Modules.nmap.viewJob('${j.id}')"
          style="font-family:var(--mono);font-size:9px;padding:2px 8px;
          border:1px solid #1a3a50;background:none;color:#4a7a96;cursor:pointer;border-radius:2px">
          VIEW</button>
         ${j.status==='complete'?`<a href="${API.Nmap.downloadUrl(j.id,'xml')}"
          style="font-family:var(--mono);font-size:9px;padding:2px 8px;margin-left:4px;
          border:1px solid #1a3a50;color:#4a7a96;text-decoration:none;border-radius:2px">XML</a>`:''}`,
      ]);
      html('#nmap-jobs-table', buildTable(
        ['Job ID','Label','Status','Hosts','Ports','Queued','Actions'], rows
      ));
    } catch (err) { Toast.error(err.message); }
  },

  async viewJob(id) {
    try {
      const job = await API.Nmap.getJob(id);
      const hosts = job.results?.hosts || [];
      const hostRows = hosts.map(h => [
        `<span style="font-family:var(--mono);color:#00d4ff">${h.ip}</span>`,
        h.hostnames?.[0] || '—',
        h.os?.[0]?.name  || '—',
        h.openPortCount  || 0,
        h.os?.[0]?.accuracy ? h.os[0].accuracy + '%' : '—',
      ]);
      Modal.open(`Scan Results — ${job.target}`,
        `<div style="margin-bottom:12px;font-family:var(--mono);font-size:11px;color:#4a7a96">
          Status: ${job.status} &nbsp;|&nbsp; Hosts up: ${job.results?.hostsUp||0} &nbsp;|&nbsp;
          Elapsed: ${job.results?.elapsed||'?'}s
        </div>` + buildTable(['IP','Hostname','OS','Open Ports','OS Accuracy'], hostRows),
        [{ label:'CLOSE', close:true }]
      );
    } catch (err) { Toast.error(err.message); }
  },

  renderResults(results) {
    const hostsEl = document.getElementById('nmap-results-hosts');
    if (!hostsEl || !results?.hosts) return;
    const rows = results.hosts.map(h => [
      `<span style="font-family:var(--mono);color:#00d4ff">${h.ip}</span>`,
      h.hostnames?.[0] || '—',
      h.os?.[0]?.name  || '—',
      h.openPortCount  || 0,
    ]);
    hostsEl.innerHTML = buildTable(['IP','Hostname','OS','Open Ports'], rows);
    hostsEl.parentElement?.style && (hostsEl.parentElement.style.display = '');
  },
});

// ══════════════════════════════════════════════
//  HASH MODULE
// ══════════════════════════════════════════════
App.register('hash', {
  _crackedResults: {},
  _jobId:          null,

  async onEnter() {
    await this.loadStatus();
  },

  async loadStatus() {
    try {
      const s = await API.Hash.status();
      html('#hash-status-bar',
        `<span style="color:#4a7a96;font-family:var(--mono);font-size:10px">
          Hashcat: <span style="color:${s.hashcat?.available?'#00ff88':'#ff4757'}">
          ${s.hashcat?.available ? '● '+s.hashcat.version : '✘ not found'}</span>
          &nbsp;|&nbsp; Wordlists: <span style="color:#00d4ff">${s.wordlistsFound}</span>
          &nbsp;|&nbsp; Active jobs: <span style="color:#ffa502">${s.activeJobs}</span>
        </span>`
      );
    } catch (_) {}
  },

  async identify() {
    const raw = document.getElementById('hash-input')?.value?.trim();
    if (!raw) { Toast.warn('Paste at least one hash'); return; }
    const hashes = raw.split('\n').map(h => h.trim()).filter(Boolean);
    try {
      const r = await API.Hash.identify({ hashes });
      const rows = r.results.map(res => {
        const top = res.candidates[0];
        return [
          `<span style="font-family:var(--mono);font-size:10px;color:#4a7a96">${res.hash.slice(0,24)}…</span>`,
          top ? `${top.name}` : '—',
          top ? `${top.confidence}%` : '—',
          top?.hashcatMode ?? '—',
        ];
      });
      html('#hash-identify-results', buildTable(['Hash','Type','Confidence','Hashcat Mode'], rows));
    } catch (err) { Toast.error(err.message); }
  },

  async compute() {
    const plaintext = document.getElementById('hash-plaintext')?.value;
    if (!plaintext && plaintext !== '') { Toast.warn('Enter plaintext'); return; }
    try {
      const r = await API.Hash.compute({ plaintext, algorithms: ['md5','sha1','sha256','sha512','ntlm'] });
      const rows = Object.entries(r.hashes).map(([algo, hash]) => [
        algo.toUpperCase(),
        `<span style="font-family:var(--mono);font-size:10px;color:#00d4ff;word-break:break-all">${hash||'—'}</span>`,
      ]);
      html('#hash-compute-results', buildTable(['Algorithm','Hash'], rows));
    } catch (err) { Toast.error(err.message); }
  },

  async startCrack() {
    const raw  = document.getElementById('hash-input')?.value?.trim();
    const type = document.getElementById('hash-type-sel')?.value || 'auto';
    const mode = document.getElementById('hash-mode-sel')?.value || 'dictionary';
    if (!raw) { Toast.warn('Paste at least one hash'); return; }

    const hashes = raw.split('\n').map(h => h.trim()).filter(Boolean);
    const minLen = parseInt(document.getElementById('bf-min-len')?.value) || 1;
    const maxLen = parseInt(document.getElementById('bf-max-len')?.value) || 6;
    const charsets = [...document.querySelectorAll('.charset-cb:checked')].map(c => c.value);

    try {
      const r = await API.Hash.crack({
        hashes, hashType: type, mode,
        bruteOpts: { minLen, maxLen, charsets: charsets.length ? charsets : ['lower','digits'] },
      });
      this._jobId = r.jobId;
      App.state.crackJobId = r.jobId;
      Toast.info(`Crack job started — type: ${r.hashType}, mode: ${mode}`);

      // Show progress UI
      const progRow = document.getElementById('crack-progress-row');
      if (progRow) progRow.style.display = 'flex';

    } catch (err) { Toast.error(`Crack failed: ${err.message}`); }
  },

  async stopCrack() {
    if (!this._jobId) return;
    try {
      await API.Hash.cancelJob(this._jobId);
      Toast.warn('Cracking stopped');
    } catch (err) { Toast.error(err.message); }
  },

  onProgress(d) {
    const fill  = document.getElementById('crack-prog-fill');
    const speed = document.getElementById('crack-speed');
    const pct   = document.getElementById('crack-pct-text');
    if (fill && d.total) fill.style.width = Math.round((d.tested/d.total)*100) + '%';
    if (speed) speed.textContent = Fmt.hps(d.hashRate);
    if (pct && d.total) pct.textContent = Math.round((d.tested/d.total)*100) + '%';
  },

  onCracked(d) {
    this._crackedResults[d.hash] = d.plaintext;
    this._renderResults();
    // Update stat
    const n = Object.keys(this._crackedResults).length;
    App.updateStats({ cracked: n });
  },

  onComplete(d) {
    this._crackedResults = { ...this._crackedResults, ...(d.cracked || {}) };
    this._renderResults();
    Toast.success(`Cracking done — ${d.crackedCount}/${d.totalHashes} cracked in ${d.elapsed}`);
    const progRow = document.getElementById('crack-progress-row');
    if (progRow) setTimeout(() => progRow.style.display = 'none', 2000);
  },

  _renderResults() {
    const entries = Object.entries(this._crackedResults);
    if (!entries.length) return;
    const rows = entries.map(([hash, plain]) => [
      `<span style="font-family:var(--mono);font-size:10px;color:#4a7a96">${hash.slice(0,20)}…</span>`,
      `<span style="font-family:var(--mono);color:#ff4757;font-weight:700">${plain}</span>`,
    ]);
    html('#crack-results-table', buildTable(['Hash','Plaintext'], rows));
  },

  async loadHistory() {
    try {
      const { jobs } = await API.Hash.listJobs();
      const rows = jobs.slice(0,15).map(j => [
        Fmt.mono(j.id?.slice(0,8) + '…'),
        j.label || j.hash_type,
        j.mode,
        Fmt.status(j.status),
        `${j.crackedCount || j.cracked_count || 0} / ${j.totalHashes || j.total_hashes || 0}`,
        Fmt.ts(j.queued_at || j.createdAt),
      ]);
      html('#crack-history-table', buildTable(['ID','Label','Mode','Status','Cracked','Time'], rows));
    } catch (err) { console.warn(err); }
  },
});

// ══════════════════════════════════════════════
//  WORDLIST MODULE
// ══════════════════════════════════════════════
App.register('wordlist', {
  async onEnter() {
    await this.loadLists();
    await this.loadMutations();
  },

  async loadLists(category) {
    try {
      const { wordlists } = await API.Wordlists.list(category ? { category } : {});
      const rows = wordlists.map(w => [
        `<span style="color:${w.exists?'#c8e6f5':'#4a7a96'}">${w.name}</span>`,
        `<span style="font-family:var(--mono);font-size:10px;color:#00d4ff">${w.category}</span>`,
        w.lines ? w.lines.toLocaleString() : '—',
        `<span style="color:#ffa502">${w.sizeMB ? w.sizeMB+' MB' : '—'}</span>`,
        w.source,
        w.exists
          ? `<button onclick="Modules.wordlist.preview('${w.path}','${w.name}')"
              style="font-family:var(--mono);font-size:9px;padding:2px 8px;border:1px solid #1a3a50;
              background:none;color:#4a7a96;cursor:pointer;border-radius:2px">PREVIEW</button>`
          : `<span style="font-family:var(--mono);font-size:9px;color:#ff4757">NOT INSTALLED</span>`,
      ]);
      html('#wordlist-table', buildTable(['Name','Category','Entries','Size','Source',''], rows));
    } catch (err) { Toast.error(err.message); }
  },

  async loadMutations() {
    try {
      const { mutations } = await API.Wordlists.mutations();
      const container = document.getElementById('mutation-checkboxes');
      if (!container) return;
      container.innerHTML = mutations.map(m =>
        `<label class="cbi" style="cursor:pointer;display:flex;align-items:center;gap:5px;
          padding:3px 9px;border:1px solid #1a3a50;border-radius:2px;font-size:11px;
          font-family:var(--mono);color:#4a7a96;transition:.15s"
          onmouseover="this.style.borderColor='#4a7a96';this.style.color='#c8e6f5'"
          onmouseout="this.style.borderColor='#1a3a50';this.style.color='#4a7a96'">
          <input type="checkbox" value="${m.id}" class="mutation-cb" style="display:none">
          <div style="width:5px;height:5px;border-radius:50%;background:#1a3a50;flex-shrink:0"></div>
          ${m.id}
        </label>`
      ).join('');
      // Wire checkbox styling
      container.querySelectorAll('.mutation-cb').forEach(cb => {
        cb.addEventListener('change', () => {
          const lbl = cb.closest('label');
          if (cb.checked) {
            lbl.style.borderColor = '#00d4ff';
            lbl.style.color       = '#00d4ff';
            lbl.querySelector('div').style.background = '#00d4ff';
          } else {
            lbl.style.borderColor = '#1a3a50';
            lbl.style.color       = '#4a7a96';
            lbl.querySelector('div').style.background = '#1a3a50';
          }
        });
      });
    } catch (_) {}
  },

  async preview(path, name) {
    try {
      const r = await API.Wordlists.preview(path, 50);
      Modal.open(`Preview — ${name}`,
        `<div style="font-family:var(--mono);font-size:11px;color:#4a7a96;margin-bottom:10px">
          ${r.total?.toLocaleString()} total entries
        </div>
        <div style="background:#050a0e;border:1px solid #1a3a50;border-radius:3px;padding:12px;
          font-family:var(--mono);font-size:11px;max-height:300px;overflow-y:auto;line-height:1.8">
          ${r.head.join('<br>')}
        </div>`,
        [{ label: 'CLOSE', close: true }]
      );
    } catch (err) { Toast.error(err.message); }
  },

  async generate() {
    const raw = document.getElementById('wl-base-words')?.value?.trim();
    if (!raw) { Toast.warn('Enter at least one base word'); return; }

    const baseWords = raw.split('\n').map(w => w.trim()).filter(Boolean);
    const mutations = [...document.querySelectorAll('.mutation-cb:checked')].map(c => c.value);
    const outputName = document.getElementById('wl-output-name')?.value?.trim() || null;

    try {
      const btn = document.getElementById('wl-generate-btn');
      if (btn) { btn.disabled = true; btn.textContent = '⏳ GENERATING…'; }

      const r = await API.Wordlists.generate({ baseWords, mutations, outputName });
      Toast.success(`Generated ${r.lines.toLocaleString()} entries → ${r.name}`);
      await this.loadLists();

      if (btn) { btn.disabled = false; btn.textContent = '≡  GENERATE WORDLIST'; }
    } catch (err) {
      Toast.error(err.message);
      const btn = document.getElementById('wl-generate-btn');
      if (btn) { btn.disabled = false; btn.textContent = '≡  GENERATE WORDLIST'; }
    }
  },

  async search() {
    const path = document.getElementById('wl-search-path')?.value?.trim();
    const term = document.getElementById('wl-search-term')?.value?.trim();
    if (!path || !term) { Toast.warn('Select a wordlist and enter a search term'); return; }
    try {
      const r = await API.Wordlists.search(path, term);
      Modal.open(`Search: "${term}" in ${path.split('/').pop()}`,
        `<div style="font-family:var(--mono);font-size:11px;color:#4a7a96;margin-bottom:10px">
          ${r.found} results found
        </div>
        <div style="background:#050a0e;border:1px solid #1a3a50;border-radius:3px;padding:12px;
          font-family:var(--mono);font-size:11px;max-height:300px;overflow-y:auto;line-height:1.8;
          color:#00ff88">
          ${r.results.join('<br>') || 'No matches'}
        </div>`,
        [{ label: 'CLOSE', close: true }]
      );
    } catch (err) { Toast.error(err.message); }
  },
});

// ══════════════════════════════════════════════
//  AI MODULE
// ══════════════════════════════════════════════
App.register('ai', {
  _stopStream: null,

  async onEnter() {
    try {
      const s = await API.AI.status();
      const bar = document.getElementById('ai-status-bar');
      if (bar) bar.innerHTML = s.configured
        ? `<span style="color:#00ff88;font-family:var(--mono);font-size:10px">● ${s.model} connected</span>
           <span style="color:#4a7a96;font-family:var(--mono);font-size:10px;margin-left:12px">
             Sessions: ${s.activeSessions}</span>`
        : `<span style="color:#ff4757;font-family:var(--mono);font-size:10px">
             ✘ ANTHROPIC_API_KEY not set in .env</span>`;

      if (!App.state.aiSessionId) await this.createSession();
    } catch (_) {}
  },

  async createSession() {
    try {
      const r = await API.AI.createSession({});
      App.state.aiSessionId = r.sessionId;
      App.liveFeed.add('AI', 'ai', `AI session created: ${r.sessionId.slice(0,8)}…`, 'ok');
    } catch (_) {}
  },

  async sendMessage() {
    const input = document.getElementById('ai-input');
    const msg   = input?.value?.trim();
    if (!msg) return;
    if (input) input.value = '';

    this._appendMessage('user', msg);
    this._showLoading();

    if (this._stopStream) this._stopStream();

    let   fullText = '';
    const loadEl   = document.getElementById('ai-loading-msg');

    this._stopStream = API.AI.chatStream(
      App.state.aiSessionId, msg,
      // onChunk
      (text) => {
        fullText += text;
        if (loadEl) loadEl.innerHTML = this._renderAIText(fullText) + '<span class="ai-cursor">▌</span>';
      },
      // onDone
      (evt) => {
        if (loadEl) {
          loadEl.id = '';
          loadEl.innerHTML = this._renderAIText(fullText);
        }
        this._stopStream = null;
        const chat = document.getElementById('ai-chat');
        if (chat) chat.scrollTop = chat.scrollHeight;
      },
      // onError
      (err) => {
        if (loadEl) loadEl.innerHTML = `<span style="color:#ff4757">Error: ${err.message}</span>`;
        this._stopStream = null;
      }
    );
  },

  _appendMessage(role, text) {
    const chat = document.getElementById('ai-chat');
    if (!chat) return;
    const div = document.createElement('div');
    div.className = 'ai-msg';
    div.innerHTML = `
      <div class="sender ${role}">${role === 'ai' ? '✦ SENTINEL AI' : 'YOU'}</div>
      <div class="body ${role === 'ai' ? 'ai-body' : ''}">${role === 'ai' ? this._renderAIText(text) : text}</div>`;
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
  },

  _showLoading() {
    const chat = document.getElementById('ai-chat');
    if (!chat) return;
    const div = document.createElement('div');
    div.className = 'ai-msg';
    div.innerHTML = `
      <div class="sender ai">✦ SENTINEL AI</div>
      <div class="body ai-body" id="ai-loading-msg">
        <div class="ai-loading">
          <div class="ai-dot"></div><div class="ai-dot"></div><div class="ai-dot"></div>
        </div>
      </div>`;
    chat.appendChild(div);
    chat.scrollTop = chat.scrollHeight;
  },

  _renderAIText(text) {
    return text
      .replace(/```(\w*)\n?([\s\S]*?)```/g,
        (_, lang, code) => `<pre style="background:#050a0e;border:1px solid #1a3a50;
          border-radius:3px;padding:10px 12px;overflow-x:auto;font-family:var(--mono);
          font-size:11px;color:#00ff88;margin:8px 0;line-height:1.6">${escHtml(code.trim())}</pre>`)
      .replace(/`([^`]+)`/g,
        (_, c) => `<code style="background:#0d1e2e;padding:1px 5px;border-radius:2px;
          font-family:var(--mono);font-size:11px;color:#00d4ff">${escHtml(c)}</code>`)
      .replace(/\*\*(.+?)\*\*/g, '<strong style="color:#c8e6f5">$1</strong>')
      .replace(/^#{1,3} (.+)$/gm,
        (_, t) => `<div style="font-weight:700;color:#00d4ff;margin:10px 0 4px;letter-spacing:.5px">${t}</div>`)
      .replace(/^- (.+)$/gm, '<div style="padding-left:12px">• $1</div>')
      .replace(/\n\n/g, '<br><br>')
      .replace(/\n/g,   '<br>');
  },

  quickPrompt(text) {
    const input = document.getElementById('ai-input');
    if (input) { input.value = text; this.sendMessage(); }
  },

  async generateReport(format = 'executive') {
    const btn = document.getElementById(`report-${format}-btn`);
    if (btn) { btn.disabled = true; btn.textContent = '⏳ GENERATING…'; }

    try {
      const r = await API.AI.report({ format });
      Modal.open(`${format.toUpperCase()} REPORT`,
        `<div style="font-family:'Rajdhani',sans-serif;font-size:13px;line-height:1.8;
          max-height:500px;overflow-y:auto;white-space:pre-wrap;color:#c8e6f5">
          ${this._renderAIText(r.report)}
        </div>`,
        [
          { label: 'COPY', onClick: () => navigator.clipboard.writeText(r.report), close: false },
          { label: 'CLOSE' },
        ]
      );
    } catch (err) { Toast.error(err.message); }

    if (btn) { btn.disabled = false; btn.textContent = format === 'executive' ? '📋 EXECUTIVE' : '🔧 TECHNICAL'; }
  },

  async analyzeCVE() {
    const cve = document.getElementById('cve-input')?.value?.trim();
    if (!cve) { Toast.warn('Enter a CVE ID (e.g. CVE-2021-44228)'); return; }
    const btn = document.getElementById('cve-analyze-btn');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ ANALYZING…'; }
    try {
      const r = await API.AI.cve({ cve });
      this._appendMessage('user', `Analyze ${cve}`);
      this._appendMessage('ai', r.analysis);
    } catch (err) { Toast.error(err.message); }
    if (btn) { btn.disabled = false; btn.textContent = 'ANALYZE CVE'; }
  },

  async buildAttackChain() {
    const btn = document.getElementById('attack-chain-btn');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ BUILDING…'; }
    try {
      const r = await API.AI.attackChain({});
      this._appendMessage('user', 'Build attack chain from current findings');
      this._appendMessage('ai', r.attackChain);
    } catch (err) { Toast.error(err.message); }
    if (btn) { btn.disabled = false; btn.textContent = '⛓ ATTACK CHAIN'; }
  },

  clearChat() {
    html('#ai-chat', '');
    this.createSession();
  },
});

// Modules proxy defined in index.html script block; nothing needed here.

// ── Escape HTML helper
function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

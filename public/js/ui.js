/**
 * Sentinel X — UI Utilities
 */
'use strict';

// ── Toast notifications
const Toast = (() => {
  let container;
  function getContainer() {
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.style.cssText = `
        position:fixed;top:16px;right:16px;z-index:9999;
        display:flex;flex-direction:column;gap:8px;pointer-events:none;`;
      document.body.appendChild(container);
    }
    return container;
  }

  function show(message, type = 'info', duration = 4000) {
    const colors = {
      info:    { bg: 'rgba(0,212,255,.12)', border: '#00d4ff', text: '#00d4ff' },
      success: { bg: 'rgba(0,255,136,.12)', border: '#00ff88', text: '#00ff88' },
      error:   { bg: 'rgba(255,71,87,.14)', border: '#ff4757', text: '#ff4757' },
      warn:    { bg: 'rgba(255,165,2,.12)', border: '#ffa502', text: '#ffa502' },
    };
    const c = colors[type] || colors.info;

    const el = document.createElement('div');
    el.style.cssText = `
      pointer-events:all;padding:10px 16px;border-radius:3px;font-family:'Share Tech Mono',monospace;
      font-size:12px;letter-spacing:.5px;max-width:360px;line-height:1.5;
      background:${c.bg};border:1px solid ${c.border};color:${c.text};
      animation:toastIn .2s ease;cursor:pointer;`;
    el.textContent = message;
    el.onclick = () => dismiss(el);

    const style = document.createElement('style');
    style.textContent = `
      @keyframes toastIn  { from{opacity:0;transform:translateX(20px)} to{opacity:1;transform:none} }
      @keyframes toastOut { from{opacity:1;transform:none} to{opacity:0;transform:translateX(20px)} }`;
    document.head.appendChild(style);

    getContainer().appendChild(el);
    if (duration > 0) setTimeout(() => dismiss(el), duration);
    return el;
  }

  function dismiss(el) {
    if (!el.parentNode) return;
    el.style.animation = 'toastOut .2s ease forwards';
    setTimeout(() => el.remove(), 200);
  }

  return {
    info:    (m, d) => show(m, 'info',    d),
    success: (m, d) => show(m, 'success', d),
    error:   (m, d) => show(m, 'error',   d),
    warn:    (m, d) => show(m, 'warn',    d),
  };
})();

// ── Modal
const Modal = (() => {
  function open(title, bodyHtml, actions = []) {
    close();
    const overlay = document.createElement('div');
    overlay.id = 'sx-modal';
    overlay.style.cssText = `
      position:fixed;inset:0;background:rgba(5,10,14,.85);z-index:8000;
      display:flex;align-items:center;justify-content:center;animation:fadeIn .15s ease;`;

    const box = document.createElement('div');
    box.style.cssText = `
      background:#0a1520;border:1px solid #1a3a50;border-radius:4px;
      width:min(600px,90vw);max-height:80vh;display:flex;flex-direction:column;
      font-family:'Rajdhani',sans-serif;`;

    const hdr = document.createElement('div');
    hdr.style.cssText = `padding:14px 18px;border-bottom:1px solid #1a3a50;
      display:flex;align-items:center;justify-content:space-between;`;
    hdr.innerHTML = `<span style="font-size:14px;font-weight:700;letter-spacing:2px;
      color:#c8e6f5;text-transform:uppercase">${title}</span>
      <button onclick="Modal.close()" style="background:none;border:none;color:#4a7a96;
      font-size:18px;cursor:pointer;line-height:1">✕</button>`;

    const body = document.createElement('div');
    body.style.cssText = 'padding:18px;overflow-y:auto;color:#c8e6f5;font-size:14px;line-height:1.6;flex:1;';
    body.innerHTML = bodyHtml;

    box.appendChild(hdr);
    box.appendChild(body);

    if (actions.length) {
      const foot = document.createElement('div');
      foot.style.cssText = 'padding:12px 18px;border-top:1px solid #1a3a50;display:flex;gap:8px;justify-content:flex-end;';
      actions.forEach(a => {
        const btn = document.createElement('button');
        btn.textContent = a.label;
        btn.style.cssText = `padding:6px 16px;border-radius:2px;font-family:'Share Tech Mono',monospace;
          font-size:11px;letter-spacing:1px;cursor:pointer;border:1px solid;
          background:${a.primary ? 'rgba(0,212,255,.15)' : 'transparent'};
          border-color:${a.danger ? '#ff4757' : '#00d4ff'};
          color:${a.danger ? '#ff4757' : '#00d4ff'};`;
        btn.onclick = () => { a.onClick?.(); if (a.close !== false) close(); };
        foot.appendChild(btn);
      });
      box.appendChild(foot);
    }

    overlay.appendChild(box);
    overlay.onclick = e => { if (e.target === overlay) close(); };
    document.body.appendChild(overlay);
  }

  function close() {
    document.getElementById('sx-modal')?.remove();
  }

  return { open, close };
})();

// ── Formatters
const Fmt = {
  severity(s) {
    const map = {
      critical: { bg:'rgba(255,71,87,.2)',  border:'rgba(255,71,87,.4)',  color:'#ff4757', label:'CRITICAL' },
      high:     { bg:'rgba(255,165,2,.15)', border:'rgba(255,165,2,.35)', color:'#ffa502', label:'HIGH'     },
      medium:   { bg:'rgba(0,212,255,.1)',  border:'rgba(0,212,255,.25)', color:'#00d4ff', label:'MEDIUM'   },
      low:      { bg:'rgba(0,255,136,.08)', border:'rgba(0,255,136,.2)',  color:'#00ff88', label:'LOW'      },
      info:     { bg:'rgba(74,122,150,.15)',border:'rgba(74,122,150,.3)', color:'#4a7a96', label:'INFO'     },
    };
    const c = map[s?.toLowerCase()] || map.info;
    return `<span style="font-family:var(--mono);font-size:9px;padding:2px 7px;border-radius:2px;
      background:${c.bg};border:1px solid ${c.border};color:${c.color};letter-spacing:.5px;
      font-weight:700">${c.label}</span>`;
  },

  status(s) {
    const map = {
      running:   '#00d4ff', queued: '#ffa502', complete: '#00ff88',
      error:     '#ff4757', cancelled: '#4a7a96', timeout: '#ff4757',
      open:      '#ff4757', patched: '#00ff88', in_review: '#ffa502',
    };
    const col = map[s?.toLowerCase()] || '#4a7a96';
    return `<span style="font-family:var(--mono);font-size:10px;color:${col}">${(s||'').toUpperCase()}</span>`;
  },

  elapsed(ms) {
    if (!ms && ms !== 0) return '—';
    const s = Math.floor(ms / 1000);
    if (s < 60)   return `${s}s`;
    if (s < 3600) return `${Math.floor(s/60)}m ${s%60}s`;
    return `${Math.floor(s/3600)}h ${Math.floor((s%3600)/60)}m`;
  },

  bytes(b) {
    if (!b) return '0 B';
    const u = ['B','KB','MB','GB'];
    let i = 0;
    while (b >= 1024 && i < u.length - 1) { b /= 1024; i++; }
    return `${b.toFixed(1)} ${u[i]}`;
  },

  ts(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    return d.toLocaleTimeString('en-GB', { hour12:false }) + ' ' +
           d.toLocaleDateString('en-GB', { day:'2-digit', month:'short' });
  },

  hps(n) {
    if (!n) return '0 H/s';
    if (n >= 1e9) return `${(n/1e9).toFixed(1)} GH/s`;
    if (n >= 1e6) return `${(n/1e6).toFixed(1)} MH/s`;
    if (n >= 1e3) return `${(n/1e3).toFixed(0)} KH/s`;
    return `${n} H/s`;
  },

  mono(t) {
    return `<span style="font-family:var(--mono);font-size:11px;color:#4a7a96">${t}</span>`;
  },
};

// ── Progress bar
function progressBar(pct, color = '#00d4ff') {
  return `<div style="height:3px;background:#0d1e2e;border-radius:2px;overflow:hidden;flex:1">
    <div style="height:100%;width:${Math.min(100,pct||0)}%;background:${color};border-radius:2px;transition:width .4s"></div>
  </div>`;
}

// ── Table builder
function buildTable(headers, rows, opts = {}) {
  const ths = headers.map(h =>
    `<th style="padding:8px 12px;font-family:var(--mono);font-size:9px;color:#4a7a96;
      letter-spacing:1px;text-transform:uppercase;border-bottom:1px solid #1a3a50;
      text-align:left;white-space:nowrap">${h}</th>`
  ).join('');

  const trs = rows.map(cells => {
    const tds = cells.map(c =>
      `<td style="padding:7px 12px;border-bottom:1px solid rgba(26,58,80,.35);
        font-size:13px;${opts.monoAll ? 'font-family:var(--mono);font-size:11px;' : ''}">${c}</td>`
    ).join('');
    return `<tr style="transition:.1s" onmouseover="this.style.background='rgba(0,212,255,.02)'"
      onmouseout="this.style.background=''">${tds}</tr>`;
  }).join('');

  return `<table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr>${ths}</tr></thead>
    <tbody>${trs || `<tr><td colspan="${headers.length}" style="padding:20px 12px;text-align:center;
      font-family:var(--mono);font-size:11px;color:#4a7a96">No data</td></tr>`}</tbody>
  </table>`;
}

// ── DOM
function el(selector) { return document.querySelector(selector); }
function els(selector) { return [...document.querySelectorAll(selector)]; }
function html(selector, content) {
  const e = typeof selector === 'string' ? el(selector) : selector;
  if (e) e.innerHTML = content;
}
function show(selector) { const e = el(selector); if (e) e.style.display = ''; }
function hide(selector) { const e = el(selector); if (e) e.style.display = 'none'; }
function toggle(selector, condition) {
  const e = typeof selector === 'string' ? el(selector) : selector;
  if (e) e.style.display = condition ? '' : 'none';
}

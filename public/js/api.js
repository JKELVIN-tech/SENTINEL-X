/**
 * Sentinel X — API Client
 * Handles JWT auth, auto-refresh, and all endpoint calls.
 */
'use strict';

const API = (() => {
  const BASE = window.location.origin;
  let   accessToken = sessionStorage.getItem('sx_access_token') || '';

  // ── Token management
  const setToken  = t => { accessToken = t; sessionStorage.setItem('sx_access_token', t); };
  const clearToken= () => { accessToken = ''; sessionStorage.removeItem('sx_access_token'); };
  const getToken  = () => accessToken;
  const isAuthed  = () => !!accessToken;

  // ── Core request
  async function request(method, path, body, retry = true) {
    const headers = { 'Content-Type': 'application/json' };
    if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`;

    const opts = { method, headers };
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(`${BASE}${path}`, opts);

    // Auto-refresh on 401 TOKEN_EXPIRED
    if (res.status === 401 && retry) {
      const json = await res.json().catch(() => ({}));
      if (json.code === 'TOKEN_EXPIRED') {
        const refreshed = await tryRefresh();
        if (refreshed) return request(method, path, body, false);
      }
      clearToken();
      window.dispatchEvent(new Event('sx:logout'));
      throw Object.assign(new Error('Session expired'), { status: 401 });
    }

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw Object.assign(new Error(err.error || 'Request failed'), { status: res.status, data: err });
    }

    return res.json();
  }

  async function tryRefresh() {
    try {
      const res = await fetch(`${BASE}/api/auth/refresh`, {
        method: 'POST', credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) return false;
      const data = await res.json();
      setToken(data.accessToken);
      return true;
    } catch (_) { return false; }
  }

  // ── Auth
  const Auth = {
    async login(username, password) {
      const data = await request('POST', '/api/auth/login', { username, password });
      setToken(data.accessToken);
      return data;
    },
    async logout() {
      await request('POST', '/api/auth/logout').catch(() => {});
      clearToken();
    },
    me:              () => request('GET',   '/api/auth/me'),
    changePassword:  (b) => request('PATCH', '/api/auth/password', b),
    listUsers:       () => request('GET',   '/api/auth/users'),
    registerUser:    (b) => request('POST',  '/api/auth/register', b),
  };

  // ── System
  const System = {
    health:  () => fetch(`${BASE}/health`).then(r => r.json()),
    info:    () => request('GET', '/api/system/info'),
    stats:   () => request('GET', '/api/system/stats'),
  };

  // ── NMAP
  const Nmap = {
    startScan:    (b)  => request('POST',   '/api/nmap/scan', b),
    getJob:       (id) => request('GET',    `/api/nmap/scan/${id}`),
    getOutput:    (id, since = 0) => request('GET', `/api/nmap/scan/${id}/output?since=${since}`),
    cancelScan:   (id) => request('DELETE', `/api/nmap/scan/${id}`),
    deleteJob:    (id) => request('DELETE', `/api/nmap/scan/${id}?action=delete`),
    listJobs:     (q)  => request('GET',    `/api/nmap/jobs?${new URLSearchParams(q||{})}`),
    validateCmd:  (b)  => request('POST',   '/api/nmap/validate', b),
    status:       ()   => request('GET',    '/api/nmap/status'),
    downloadUrl:  (id, fmt) => `${BASE}/api/nmap/scan/${id}/download/${fmt}?accessToken=${accessToken}`,
  };

  // ── Hash
  const Hash = {
    crack:      (b)  => request('POST',   '/api/hash/crack', b),
    getJob:     (id) => request('GET',    `/api/hash/crack/${id}`),
    cancelJob:  (id) => request('DELETE', `/api/hash/crack/${id}`),
    listJobs:   ()   => request('GET',    '/api/hash/jobs'),
    identify:   (b)  => request('POST',   '/api/hash/identify', b),
    compute:    (b)  => request('POST',   '/api/hash/compute', b),
    wordlists:  ()   => request('GET',    '/api/hash/wordlists'),
    types:      ()   => request('GET',    '/api/hash/types'),
    status:     ()   => request('GET',    '/api/hash/status'),
  };

  // ── Wordlists
  const Wordlists = {
    list:      (q)  => request('GET',    `/api/wordlists?${new URLSearchParams(q||{})}`),
    mutations: ()   => request('GET',    '/api/wordlists/mutations'),
    preview:   (path, head=50) => request('GET', `/api/wordlists/preview?path=${encodeURIComponent(path)}&head=${head}`),
    search:    (path, term)    => request('GET', `/api/wordlists/search?path=${encodeURIComponent(path)}&term=${encodeURIComponent(term)}`),
    generate:  (b)  => request('POST',   '/api/wordlists/generate', b),
    merge:     (b)  => request('POST',   '/api/wordlists/merge', b),
    delete:    (name) => request('DELETE', `/api/wordlists/${encodeURIComponent(name)}`),
  };

  // ── AI
  const AI = {
    createSession:  (b)  => request('POST',  '/api/ai/session', b),
    deleteSession:  (id) => request('DELETE', `/api/ai/session/${id}`),
    updateContext:  (id, b) => request('PATCH', `/api/ai/session/${id}/context`, b),
    listSessions:   ()   => request('GET',   '/api/ai/sessions'),
    chat:           (b)  => request('POST',  '/api/ai/chat', b),
    report:         (b)  => request('POST',  '/api/ai/report', b),
    cve:            (b)  => request('POST',  '/api/ai/cve', b),
    attackChain:    (b)  => request('POST',  '/api/ai/attack-chain', b),
    recommend:      (b)  => request('POST',  '/api/ai/recommend', b),
    status:         ()   => request('GET',   '/api/ai/status'),

    // Streaming chat — returns cleanup fn
    chatStream(sessionId, message, onChunk, onDone, onError) {
      const ctrl = new AbortController();
      fetch(`${BASE}/api/ai/chat/stream`, {
        method: 'POST',
        headers: {
          'Content-Type':  'application/json',
          'Authorization': `Bearer ${accessToken}`,
        },
        body:   JSON.stringify({ sessionId, message }),
        signal: ctrl.signal,
      }).then(async res => {
        const reader = res.body.getReader();
        const dec    = new TextDecoder();
        let   buf    = '';
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          buf += dec.decode(value, { stream: true });
          const lines = buf.split('\n');
          buf = lines.pop();
          for (const line of lines) {
            if (!line.startsWith('data: ')) continue;
            try {
              const evt = JSON.parse(line.slice(6));
              if (evt.type === 'chunk') onChunk(evt.text);
              if (evt.type === 'done')  onDone(evt);
              if (evt.type === 'error') onError(new Error(evt.error));
            } catch (_) {}
          }
        }
      }).catch(err => { if (err.name !== 'AbortError') onError(err); });
      return () => ctrl.abort();
    },
  };

  // ── Engagements
  const Engagements = {
    list:    (q)  => request('GET',    `/api/engagements?${new URLSearchParams(q||{})}`),
    create:  (b)  => request('POST',   '/api/engagements', b),
    get:     (id) => request('GET',    `/api/engagements/${id}`),
    update:  (id, b) => request('PATCH', `/api/engagements/${id}`, b),
    delete:  (id) => request('DELETE', `/api/engagements/${id}`),
    stats:   (id) => request('GET',    `/api/engagements/${id}/stats`),
    hosts:   (id) => request('GET',    `/api/engagements/${id}/hosts`),
    vulns:   (id) => request('GET',    `/api/engagements/${id}/vulns`),
  };

  return { Auth, System, Nmap, Hash, Wordlists, AI, Engagements, getToken, isAuthed, clearToken };
})();

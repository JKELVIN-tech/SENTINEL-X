/**
 * Sentinel X — WebSocket Client
 * Real-time event bus. Connects to ws://host/ws and dispatches
 * typed events to registered handlers throughout the UI.
 */
'use strict';

const WS = (() => {
  let   socket      = null;
  let   reconnTimer = null;
  let   reconnDelay = 1000;
  const MAX_DELAY   = 30_000;
  const handlers    = new Map(); // type → Set<fn>
  let   connected   = false;

  function connect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const url   = `${proto}://${location.host}/ws`;

    socket = new WebSocket(url);

    socket.onopen = () => {
      connected   = true;
      reconnDelay = 1000;
      clearTimeout(reconnTimer);
      dispatch('ws:connected', {});
      console.info('[WS] Connected');
    };

    socket.onmessage = ({ data }) => {
      try {
        const evt = JSON.parse(data);
        dispatch(evt.type, evt);
        // Also dispatch a wildcard for the live feed
        dispatch('*', evt);
      } catch (_) {}
    };

    socket.onclose = () => {
      connected = false;
      dispatch('ws:disconnected', {});
      scheduleReconnect();
    };

    socket.onerror = () => {
      connected = false;
      socket.close();
    };
  }

  function scheduleReconnect() {
    clearTimeout(reconnTimer);
    reconnTimer = setTimeout(() => {
      console.info(`[WS] Reconnecting in ${reconnDelay}ms…`);
      connect();
      reconnDelay = Math.min(reconnDelay * 2, MAX_DELAY);
    }, reconnDelay);
  }

  function dispatch(type, data) {
    (handlers.get(type)  || new Set()).forEach(fn => { try { fn(data); } catch (_) {} });
  }

  function on(type, fn) {
    if (!handlers.has(type)) handlers.set(type, new Set());
    handlers.get(type).add(fn);
    return () => handlers.get(type).delete(fn); // returns unsubscribe fn
  }

  function off(type, fn) {
    handlers.get(type)?.delete(fn);
  }

  function isConnected() { return connected; }

  // Auto-connect when module loads
  connect();

  return { on, off, isConnected };
})();

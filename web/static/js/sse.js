// sse.js — Live SSE manager with auto-reconnect and exponential backoff
'use strict';

const SSEState = Object.freeze({
  DISCONNECTED: 'DISCONNECTED',
  CONNECTING:   'CONNECTING',
  CONNECTED:    'CONNECTED',
  RETRYING:     'RETRYING',
});

const SSE = (() => {
  let _state = SSEState.DISCONNECTED;
  let _es = null;
  let _retryTimer = null;
  const _handlers = {};

  const _retryBaseMs = 1000;
  const _retryMaxMs = 20000;
  let _retryMs = _retryBaseMs;

  function on(type, fn) {
    if (!_handlers[type]) _handlers[type] = [];
    _handlers[type].push(fn);
  }

  function _emit(type, data) {
    (_handlers[type] || []).forEach(fn => {
      try { fn(data); } catch (err) { console.error('SSE handler error:', type, err); }
    });
  }

  function _attachListeners(es) {
    ['open', 'error', 'alert', 'stats', 'correlation', 'status', 'notification', 'heartbeat'].forEach(type => {
      es.addEventListener(type, e => {
        try {
          const parsed = e.data ? JSON.parse(e.data) : {};
          _emit(type, parsed);
        } catch(err) {
          // If not JSON, emit raw string
          _emit(type, e.data);
        }
      });
    });
  }

  function _transitionState(target) {
    if (_state === target) return;

    _state = target;
    _emit('state_change', { state: _state });

    switch (target) {
      case SSEState.CONNECTING:
        if (_retryTimer) {
          clearTimeout(_retryTimer);
          _retryTimer = null;
        }
        if (_es) {
          _es.close();
          _es = null;
        }
        try {
          _es = new EventSource('/events');
          _attachListeners(_es);

          _es.onopen = () => {
            _transitionState(SSEState.CONNECTED);
          };
          _es.onerror = () => {
            _transitionState(SSEState.RETRYING);
          };
        } catch (e) {
          console.error('[SSE] Failed to create EventSource:', e);
          _transitionState(SSEState.RETRYING);
        }
        break;

      case SSEState.CONNECTED:
        _retryMs = _retryBaseMs;
        _emit('connected', {});
        break;

      case SSEState.RETRYING:
        _emit('disconnected', {});
        if (_es) {
          _es.close();
          _es = null;
        }
        const delay = _retryMs;
        _retryMs = Math.min(_retryMs * 1.5, _retryMaxMs);
        _retryTimer = setTimeout(() => {
          _retryTimer = null;
          _transitionState(SSEState.CONNECTING);
        }, delay);
        break;

      case SSEState.DISCONNECTED:
        if (_retryTimer) {
          clearTimeout(_retryTimer);
          _retryTimer = null;
        }
        if (_es) {
          _es.close();
          _es = null;
        }
        _retryMs = _retryBaseMs;
        break;
    }
  }

  function connect() {
    if (_state === SSEState.CONNECTING || _state === SSEState.CONNECTED) return;
    _transitionState(SSEState.CONNECTING);
  }

  function disconnect() {
    _transitionState(SSEState.DISCONNECTED);
  }

  function getState() {
    return _state;
  }

  return { on, connect, disconnect, getState, State: SSEState };
})();

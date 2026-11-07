/* Web SSH: the bearer token stays in the server session; tickets never enter URLs. */
import { Terminal } from '/static/vendor/xterm/xterm.mjs';

const panel = document.getElementById('isolate-terminal');
if (panel) {
  const terminal = new Terminal({ cursorBlink: true, convertEol: false, scrollback: 5000 });
  terminal.open(panel);
  let socket;
  let connected = false;
  const status = document.getElementById('isolate-terminal-status');
  const message = (text) => { if (status) status.textContent = text; };
  const resize = () => {
    const cols = Math.max(20, Math.min(250, Math.floor(panel.clientWidth / 9)));
    const rows = Math.max(5, Math.min(100, Math.floor(panel.clientHeight / 18)));
    terminal.resize(cols, rows);
    if (connected && socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'resize', cols, rows }));
    }
  };
  resize();
  const observer = new ResizeObserver(resize);
  observer.observe(panel);
  terminal.onData((data) => {
    if (connected && socket?.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: 'input', data }));
    }
  });
  async function connect() {
    message('Authorizing connection…');
    const response = await fetch(panel.dataset.ticketUrl || '/api/v1/connections', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': panel.dataset.csrfToken },
      body: JSON.stringify({ host_id: panel.dataset.hostId, protocol: 'webssh' }),
    });
    if (!response.ok) throw new Error('Connection authorization failed');
    const grant = await response.json();
    const endpoint = new URL(grant.websocket_url || panel.dataset.websocketUrl, window.location.href);
    if (endpoint.protocol === 'https:') endpoint.protocol = 'wss:';
    if (endpoint.protocol === 'http:') endpoint.protocol = 'ws:';
    if (window.location.protocol === 'https:' && endpoint.protocol !== 'wss:') {
      throw new Error('A secure WebSocket endpoint is required');
    }
    if (!['ws:', 'wss:'].includes(endpoint.protocol) || endpoint.search || endpoint.hash) {
      throw new Error('Invalid WebSocket endpoint');
    }
    socket = new WebSocket(endpoint);
    socket.binaryType = 'arraybuffer';
    socket.addEventListener('open', () => {
      socket.send(JSON.stringify({ ticket: grant.ticket, cols: terminal.cols, rows: terminal.rows }));
      delete grant.ticket;
    });
    socket.addEventListener('message', (event) => {
      if (event.data instanceof ArrayBuffer) {
        terminal.write(new Uint8Array(event.data));
        return;
      }
      let value;
      try { value = JSON.parse(event.data); } catch { return; }
      if (value.type === 'status') {
        connected = value.state === 'connected';
        message(connected ? 'Connected' : 'Waiting for session approval…');
        if (connected) { resize(); terminal.focus(); }
      } else if (value.type === 'error') {
        message(value.message);
      } else if (value.type === 'exit') {
        connected = false;
        message(`Session ended (${value.code})`);
      }
    });
    socket.addEventListener('error', () => message('Gateway connection failed'));
    socket.addEventListener('close', () => { connected = false; message('Session closed'); });
  }
  connect().catch((error) => message(error.message));
  window.addEventListener('pagehide', () => { observer.disconnect(); socket?.close(); terminal.dispose(); });
}

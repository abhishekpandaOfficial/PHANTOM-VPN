// ============================================================
//  PHANTOM VPN — Real-Time Monitoring API Server
//  Node.js + WebSocket — runs on your DigitalOcean droplet
//  Place at: /opt/phantom-vpn/server.js
// ============================================================

'use strict';
const http    = require('http');
const { exec, execSync } = require('child_process');
const fs      = require('fs');

// ---- Config from environment ----
const PORT           = process.env.PORT           || 7777;
const API_SECRET     = process.env.API_SECRET     || 'changeme';
const DASHBOARD_USER = process.env.DASHBOARD_USER || 'phantom';
const DASHBOARD_PASS = process.env.DASHBOARD_PASS || 'changeme';
const CORS_ORIGIN    = process.env.CORS_ORIGIN    || '*';
const TOR_CTRL_PASS  = process.env.TOR_CONTROL_PASSWORD || '';
const ROTATE_LOG     = '/var/log/phantom-rotate.log';
const FAIL2BAN_LOG   = '/var/log/fail2ban.log';
const DASHBOARD_FILE = '/opt/phantom-vpn/dashboard.html';

// ---- WebSocket (built-in, no ws module required for basic) ----
// We use a simple SSE + REST approach for max compatibility
// Clients connect via EventSource (SSE) for real-time streaming

// ---- State ----
let state = {
  vpn: { connected: false, uptime: 0, startTime: null },
  currentIP: null,
  rotations: 0,
  threats: [],
  blockedAds: 0,
  bandwidthRx: 0,
  bandwidthTx: 0,
  connectedPeers: [],
  torCircuits: 0,
  dnsQueries: 0,
  dnsBlocked: 0,
};

// ---- SSE clients list ----
const sseClients = new Set();

// ---- Broadcast to all SSE clients ----
function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach(res => {
    try { res.write(payload); } catch(e) { sseClients.delete(res); }
  });
}

// ---- Auth middleware ----
function requireAuth(req) {
  const auth = req.headers['authorization'] || '';
  if (auth.startsWith('Bearer ')) {
    return auth.slice(7) === API_SECRET;
  }
  // Basic auth
  if (auth.startsWith('Basic ')) {
    const decoded = Buffer.from(auth.slice(6), 'base64').toString();
    const [u, p] = decoded.split(':');
    return u === DASHBOARD_USER && p === DASHBOARD_PASS;
  }
  return false;
}

// ---- Helper: run shell cmd safely ----
function shell(cmd, fallback = '') {
  try { return execSync(cmd, { timeout: 5000 }).toString().trim(); }
  catch(e) { return fallback; }
}

function escapeForDoubleQuotes(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function torCtl(command) {
  const auth = escapeForDoubleQuotes(TOR_CTRL_PASS);
  return `printf 'AUTHENTICATE "${auth}"\\r\\n${command}\\r\\nQUIT\\r\\n' | nc -q1 127.0.0.1 9051 2>/dev/null`;
}

// ---- Collect WireGuard stats ----
function collectWGStats() {
  try {
    const raw = shell('wg show wg0 dump', '');
    if (!raw) { state.vpn.connected = false; return; }

    state.vpn.connected = true;
    if (!state.vpn.startTime) state.vpn.startTime = Date.now();
    state.vpn.uptime = Math.floor((Date.now() - state.vpn.startTime) / 1000);

    const lines = raw.split('\n').filter(Boolean);
    const peers = [];
    let totalRx = 0, totalTx = 0;

    lines.slice(1).forEach(line => {
      const parts = line.split('\t');
      if (parts.length >= 7) {
        const rx = parseInt(parts[5]) || 0;
        const tx = parseInt(parts[6]) || 0;
        totalRx += rx; totalTx += tx;
        peers.push({
          pubkey: parts[0].substring(0, 16) + '...',
          endpoint: parts[2] || 'N/A',
          allowedIPs: parts[3],
          lastHandshake: parseInt(parts[4]) || 0,
          rx: formatBytes(rx),
          tx: formatBytes(tx),
        });
      }
    });

    state.bandwidthRx = totalRx;
    state.bandwidthTx = totalTx;
    state.connectedPeers = peers;
  } catch(e) {
    state.vpn.connected = false;
  }
}

// ---- Collect Tor stats ----
function collectTorStats() {
  try {
    const circuits = shell(`${torCtl('GETINFO circuit-status')} | grep -Ec '^[0-9]+\\s' || echo 0`, '0');
    state.torCircuits = parseInt(circuits) || 0;

    // Get current exit IP via Tor
    exec('curl -s --socks5 127.0.0.1:9050 --max-time 8 ifconfig.me', (err, stdout) => {
      if (!err && stdout.trim()) state.currentIP = stdout.trim();
    });

    // Count rotations from log
    if (fs.existsSync(ROTATE_LOG)) {
      const lines = fs.readFileSync(ROTATE_LOG, 'utf8').split('\n').filter(Boolean);
      state.rotations = lines.length;

      // Last rotation entry
      if (lines.length > 0) {
        const last = lines[lines.length - 1];
        const match = last.match(/ROTATED_TO=(\S+)/);
        if (match) state.currentIP = match[1];
      }
    }
  } catch(e) {}
}

// ---- Collect threat events from Fail2Ban ----
function collectThreats() {
  try {
    if (!fs.existsSync(FAIL2BAN_LOG)) return;
    const lines = fs.readFileSync(FAIL2BAN_LOG, 'utf8')
      .split('\n').filter(Boolean).slice(-200);

    const threats = [];
    lines.forEach(line => {
      const banMatch   = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*Ban (\d+\.\d+\.\d+\.\d+)/);
      const unbanMatch = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*Unban (\d+\.\d+\.\d+\.\d+)/);
      const foundMatch = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*Found (\d+\.\d+\.\d+\.\d+)/);

      if (banMatch) {
        threats.push({ time: banMatch[1], ip: banMatch[2], type: 'BAN', severity: 'HIGH', msg: 'IP Banned — repeated auth failures' });
      } else if (foundMatch) {
        threats.push({ time: foundMatch[1], ip: foundMatch[2], type: 'PROBE', severity: 'MED', msg: 'Suspicious connection attempt detected' });
      }
    });

    state.threats = threats.slice(-50).reverse(); // Most recent first
  } catch(e) {}
}

// ---- Collect DNS stats from Unbound ----
function collectDNSStats() {
  try {
    const stats = shell('unbound-control stats_noreset 2>/dev/null', '');
    if (!stats) return;

    const totalMatch   = stats.match(/total\.num\.queries=(\d+)/);
    const blockedMatch = stats.match(/total\.num\.zero_ttl=(\d+)/);

    if (totalMatch)   state.dnsQueries = parseInt(totalMatch[1]);
    if (blockedMatch) state.dnsBlocked = parseInt(blockedMatch[1]);
  } catch(e) {}
}

// ---- System metrics ----
function collectSystemMetrics() {
  const cpuLine = shell("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'", '0');
  const memLine = shell("free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'", '0');
  const load    = shell('cat /proc/loadavg', '0 0 0').split(' ').slice(0,3);

  return {
    cpu:    parseFloat(cpuLine) || 0,
    mem:    parseFloat(memLine) || 0,
    load:   load,
    uptime: parseInt(shell('cat /proc/uptime', '0').split('.')[0]) || 0,
  };
}

// ---- IP Rotation via Tor NEWNYM ----
function rotateIP(callback) {
  exec(torCtl('SIGNAL NEWNYM'), () => {
    const ts = new Date().toISOString();
    fs.appendFileSync(ROTATE_LOG, `${ts} ROTATE_TRIGGERED=manual\n`);
    state.rotations++;

    setTimeout(() => {
      exec('curl -s --socks5 127.0.0.1:9050 --max-time 8 ifconfig.me', (e, stdout) => {
        if (!e && stdout.trim()) {
          state.currentIP = stdout.trim();
          broadcast('rotation', { ip: state.currentIP, time: ts, count: state.rotations });
        }
        callback(null, state.currentIP);
      });
    }, 3000);
  });
}

// ---- Format bytes ----
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024, sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ---- Route handler ----
function handleRequest(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN);
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = req.url.split('?')[0];

  // ---- SSE stream (real-time updates) ----
  if (url === '/stream') {
    if (!requireAuth(req)) {
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="PHANTOM VPN"' });
      res.end('Unauthorized');
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write(': PHANTOM VPN Stream Connected\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  // ---- Health check (no auth) ----
  if (url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', version: '2.0' }));
    return;
  }

  if (url === '/dashboard' && req.method === 'GET') {
    if (!fs.existsSync(DASHBOARD_FILE)) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Dashboard file not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(DASHBOARD_FILE, 'utf8'));
    return;
  }

  // ---- All API routes require auth ----
  if (!requireAuth(req)) {
    res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="PHANTOM VPN"' });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return;
  }

  res.setHeader('Content-Type', 'application/json');

  // ---- GET /api/status ----
  if (url === '/api/status' && req.method === 'GET') {
    const sys = collectSystemMetrics();
    res.writeHead(200);
    res.end(JSON.stringify({
      vpn:     state.vpn,
      ip:      state.currentIP,
      tor:     { circuits: state.torCircuits, rotations: state.rotations },
      network: { rx: formatBytes(state.bandwidthRx), tx: formatBytes(state.bandwidthTx) },
      dns:     { queries: state.dnsQueries, blocked: state.dnsBlocked },
      peers:   state.connectedPeers,
      system:  sys,
      threats: state.threats.slice(0, 10),
    }));
    return;
  }

  // ---- GET /api/threats ----
  if (url === '/api/threats' && req.method === 'GET') {
    res.writeHead(200);
    res.end(JSON.stringify({ threats: state.threats, total: state.threats.length }));
    return;
  }

  // ---- GET /api/stats ----
  if (url === '/api/stats' && req.method === 'GET') {
    res.writeHead(200);
    res.end(JSON.stringify({
      bandwidth: { rx: state.bandwidthRx, tx: state.bandwidthTx },
      dns: { queries: state.dnsQueries, blocked: state.dnsBlocked },
      rotations: state.rotations,
      peers: state.connectedPeers.length,
    }));
    return;
  }

  // ---- POST /api/rotate ----
  if (url === '/api/rotate' && req.method === 'POST') {
    rotateIP((err, newIP) => {
      res.writeHead(200);
      res.end(JSON.stringify({ success: true, newIP, rotations: state.rotations }));
    });
    return;
  }

  // ---- POST /api/wg/restart ----
  if (url === '/api/wg/restart' && req.method === 'POST') {
    exec('systemctl restart wg-quick@wg0', (err) => {
      res.writeHead(200);
      res.end(JSON.stringify({ success: !err, message: err ? err.message : 'WireGuard restarted' }));
    });
    return;
  }

  // ---- POST /api/tor/newcircuit ----
  if (url === '/api/tor/newcircuit' && req.method === 'POST') {
    exec(torCtl('SIGNAL NEWNYM'), (err) => {
      broadcast('circuit', { time: new Date().toISOString(), status: 'rebuilt' });
      res.writeHead(200);
      res.end(JSON.stringify({ success: !err }));
    });
    return;
  }

  // ---- GET /api/logs/rotate ----
  if (url === '/api/logs/rotate' && req.method === 'GET') {
    try {
      const lines = fs.existsSync(ROTATE_LOG)
        ? fs.readFileSync(ROTATE_LOG, 'utf8').split('\n').filter(Boolean).slice(-100).reverse()
        : [];
      res.writeHead(200);
      res.end(JSON.stringify({ logs: lines }));
    } catch(e) {
      res.writeHead(500);
      res.end(JSON.stringify({ error: e.message }));
    }
    return;
  }

  // ---- GET /api/peers ----
  if (url === '/api/peers' && req.method === 'GET') {
    res.writeHead(200);
    res.end(JSON.stringify({ peers: state.connectedPeers }));
    return;
  }

  res.writeHead(404);
  res.end(JSON.stringify({ error: 'Not found' }));
}

// ---- Main server ----
const server = http.createServer(handleRequest);
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[PHANTOM] Monitoring API running on port ${PORT}`);
  console.log(`[PHANTOM] SSE stream: http://0.0.0.0:${PORT}/stream`);
  console.log(`[PHANTOM] Health: http://0.0.0.0:${PORT}/health`);
});

// ---- Collection loop (every 5 seconds) ----
function collectAll() {
  collectWGStats();
  collectTorStats();
  collectThreats();
  collectDNSStats();

  const sys = collectSystemMetrics();

  // Broadcast live stats to all SSE clients
  broadcast('stats', {
    vpn:     state.vpn,
    ip:      state.currentIP,
    tor:     { circuits: state.torCircuits, rotations: state.rotations },
    network: { rx: formatBytes(state.bandwidthRx), tx: formatBytes(state.bandwidthTx), rxBytes: state.bandwidthRx, txBytes: state.bandwidthTx },
    dns:     { queries: state.dnsQueries, blocked: state.dnsBlocked },
    peers:   state.connectedPeers.length,
    system:  sys,
    timestamp: Date.now(),
  });

  // Broadcast new threats separately
  if (state.threats.length > 0) {
    const latest = state.threats[0];
    if (Date.now() - new Date(latest.time).getTime() < 10000) {
      broadcast('threat', latest);
    }
  }
}

setInterval(collectAll, 5000);
collectAll(); // Run immediately on start

process.on('uncaughtException', err => console.error('[PHANTOM] Error:', err.message));
process.on('SIGTERM', () => { console.log('[PHANTOM] Shutting down...'); process.exit(0); });

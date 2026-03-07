// ============================================================
//  PHANTOM VPN — Real-Time Monitoring API Server
//  Node.js + WireGuard provisioning + user portal + Razorpay
//  Place at: /opt/phantom-vpn/server.js
// ============================================================

'use strict';
const crypto = require('crypto');
const fs = require('fs');
const http = require('http');
const https = require('https');
const pathMod = require('path');
const { exec, execSync } = require('child_process');

// ---- Config from environment ----
const PORT = parseInt(process.env.PORT || '7777', 10);
const API_SECRET = process.env.API_SECRET || 'changeme';
const ADMIN_USER = (process.env.ADMIN_USER || process.env.DASHBOARD_USER || 'hello@abhishekpanda.com').trim().toLowerCase();
const LEGACY_ADMIN_PASSWORD = process.env.DASHBOARD_PASS || '';
const ADMIN_TOTP_SECRET = (process.env.ADMIN_TOTP_SECRET || '').replace(/\s+/g, '').toUpperCase();
const ADMIN_TOTP_ISSUER = process.env.ADMIN_TOTP_ISSUER || 'PHANTOM VPN';
const ADMIN_SESSION_TTL_MS = parseInt(process.env.ADMIN_SESSION_TTL_MS || String(12 * 60 * 60 * 1000), 10);
const FREE_TRIAL_HOURS = Math.max(1, parseInt(process.env.FREE_TRIAL_HOURS || '1', 10));
const FREE_TRIAL_RESET_DAYS = Math.max(1, parseInt(process.env.FREE_TRIAL_RESET_DAYS || '15', 10));
const FREE_TRIAL_SECONDS = FREE_TRIAL_HOURS * 60 * 60;
const PAYMENT_LINK = process.env.PAYMENT_LINK || `mailto:${ADMIN_USER}?subject=PHANTOM%20VPN%20Payment`;
const PLAN_PRICE_LABEL = process.env.PLAN_PRICE_LABEL || 'Payment required after trial';
const CORS_ORIGIN = process.env.CORS_ORIGIN || '*';
const TOR_CTRL_PASS = process.env.TOR_CONTROL_PASSWORD || '';
const RAZORPAY_KEY_ID = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const RAZORPAY_CURRENCY = process.env.RAZORPAY_CURRENCY || 'INR';
const RAZORPAY_PLAN_AMOUNT = Math.max(100, parseInt(process.env.RAZORPAY_PLAN_AMOUNT || '49900', 10));
const RAZORPAY_PLAN_NAME = process.env.RAZORPAY_PLAN_NAME || 'PHANTOM VPN Premium';
const RAZORPAY_PLAN_DESCRIPTION = process.env.RAZORPAY_PLAN_DESCRIPTION || 'PHANTOM VPN paid access';

const ROTATE_LOG = '/var/log/phantom-rotate.log';
const FAIL2BAN_LOG = '/var/log/fail2ban.log';
const DASHBOARD_FILE = '/opt/phantom-vpn/dashboard.html';
const LANDING_FILE = '/opt/phantom-vpn/landing.html';
const ADMIN_FILE = '/opt/phantom-vpn/admin.html';
const PORTAL_FILE = '/opt/phantom-vpn/portal.html';
const ROUTING_FILE = '/opt/phantom-vpn/routing.html';
const DOCS_FILE = '/opt/phantom-vpn/docs.html';
const BRAND_DIR = '/opt/phantom-vpn/brand';
const USERS_DB_FILE = '/opt/phantom-vpn/users.json';
const WG_CONF_FILE = '/etc/wireguard/wg0.conf';
const WG_SERVER_PUBLIC_KEY_FILE = '/etc/wireguard/server_public.key';
const WG_SUBNET = process.env.WG_SUBNET || '10.8.0.0/24';
const WG_DNS = process.env.WG_DNS || '10.8.0.1';
const WG_PUBLIC_ENDPOINT = process.env.WG_PUBLIC_ENDPOINT || '';

// ---- State ----
let state = {
  vpn: { connected: false, uptime: 0, startTime: null },
  currentIP: null,
  rotations: 0,
  threats: [],
  bandwidthRx: 0,
  bandwidthTx: 0,
  connectedPeers: [],
  torCircuits: 0,
  dnsQueries: 0,
  dnsBlocked: 0,
};

const sseClients = new Set();
const adminSessions = new Map();

function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  sseClients.forEach((res) => {
    try {
      res.write(payload);
    } catch (e) {
      sseClients.delete(res);
    }
  });
}

function shell(cmd, fallback = '') {
  try {
    return execSync(cmd, { timeout: 5000 }).toString().trim();
  } catch (e) {
    return fallback;
  }
}

function run(cmd) {
  return execSync(cmd, { timeout: 10000 }).toString().trim();
}

function json(res, status, payload, extraHeaders = {}) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    ...extraHeaders,
  });
  res.end(JSON.stringify(payload));
}

function readJsonBody(req, callback) {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk;
    if (body.length > 1_000_000) req.destroy();
  });
  req.on('end', () => {
    if (!body) return callback(null, {});
    try {
      callback(null, JSON.parse(body));
    } catch (e) {
      callback(new Error('Invalid JSON body'));
    }
  });
  req.on('error', (err) => callback(err));
}

function serveHtml(res, path, notFoundMsg) {
  if (!fs.existsSync(path)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end(notFoundMsg);
    return;
  }
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(fs.readFileSync(path, 'utf8'));
}

function mimeTypeFromPath(filePath) {
  const ext = pathMod.extname(filePath).toLowerCase();
  if (ext === '.svg') return 'image/svg+xml';
  if (ext === '.png') return 'image/png';
  if (ext === '.ico') return 'image/x-icon';
  return 'application/octet-stream';
}

function serveStaticFile(res, filePath) {
  if (!fs.existsSync(filePath)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }
  res.writeHead(200, {
    'Content-Type': mimeTypeFromPath(filePath),
    'Cache-Control': 'public, max-age=86400',
  });
  res.end(fs.readFileSync(filePath));
}

function escapeForDoubleQuotes(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function escapeRegExp(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function shQuote(value) {
  return `'${String(value).replace(/'/g, `'"'"'`)}'`;
}

function torCtl(command) {
  const auth = escapeForDoubleQuotes(TOR_CTRL_PASS);
  return `printf 'AUTHENTICATE "${auth}"\\r\\n${command}\\r\\nQUIT\\r\\n' | nc -q1 127.0.0.1 9051 2>/dev/null`;
}

function parseSubnet24(cidr) {
  const [rawIp, rawPrefix] = String(cidr).split('/');
  const prefix = parseInt(rawPrefix, 10);
  const parts = (rawIp || '').split('.').map((p) => parseInt(p, 10));
  if (prefix !== 24 || parts.length !== 4 || parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) {
    throw new Error(`Only /24 subnet is supported for provisioning (got ${cidr})`);
  }
  return { octets: parts };
}

function cleanName(name) {
  const cleaned = String(name || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9_-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  return cleaned.slice(0, 48);
}

function cleanEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function isLikelyEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

function nowIso() {
  return new Date().toISOString();
}

function addHours(isoOrMs, hours) {
  const base = typeof isoOrMs === 'number' ? isoOrMs : new Date(isoOrMs).getTime();
  return new Date(base + hours * 60 * 60 * 1000).toISOString();
}

function addDays(isoOrMs, days) {
  const base = typeof isoOrMs === 'number' ? isoOrMs : new Date(isoOrMs).getTime();
  return new Date(base + days * 24 * 60 * 60 * 1000).toISOString();
}

function toIsoOrNull(value) {
  if (!value) return null;
  const ts = new Date(value).getTime();
  return Number.isNaN(ts) ? null : new Date(ts).toISOString();
}

function makeId(name) {
  return `${name}-${Date.now().toString(36)}`;
}

function randomToken(len = 24) {
  return crypto.randomBytes(len).toString('hex');
}

function base32ToBuffer(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = String(secret || '').replace(/=+$/g, '').replace(/\s+/g, '').toUpperCase();
  let bits = '';
  for (const ch of cleaned) {
    const idx = alphabet.indexOf(ch);
    if (idx === -1) throw new Error('Invalid base32 secret');
    bits += idx.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTotp(secret, timeMs = Date.now()) {
  const key = base32ToBuffer(secret);
  const counter = Math.floor(timeMs / 30000);
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac('sha1', key).update(buf).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24)
    | ((hmac[offset + 1] & 0xff) << 16)
    | ((hmac[offset + 2] & 0xff) << 8)
    | (hmac[offset + 3] & 0xff);
  return String(code % 1000000).padStart(6, '0');
}

function verifyTotp(secret, token) {
  const input = String(token || '').trim();
  if (!/^\d{6}$/.test(input)) return false;
  for (let offset = -1; offset <= 1; offset += 1) {
    if (generateTotp(secret, Date.now() + offset * 30000) === input) return true;
  }
  return false;
}

function getAdminSetupUri() {
  if (!ADMIN_TOTP_SECRET) return null;
  return `otpauth://totp/${encodeURIComponent(`${ADMIN_TOTP_ISSUER}:${ADMIN_USER}`)}?secret=${ADMIN_TOTP_SECRET}&issuer=${encodeURIComponent(ADMIN_TOTP_ISSUER)}`;
}

function verifyAdminPassword(password) {
  if (ADMIN_TOTP_SECRET) return verifyTotp(ADMIN_TOTP_SECRET, password);
  return !!LEGACY_ADMIN_PASSWORD && password === LEGACY_ADMIN_PASSWORD;
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function createAdminSession() {
  const token = randomToken(32);
  const id = hashToken(token);
  const now = Date.now();
  const session = {
    id,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + ADMIN_SESSION_TTL_MS).toISOString(),
  };
  adminSessions.set(id, session);
  return { token, session };
}

function pruneAdminSessions() {
  const now = Date.now();
  for (const [id, session] of adminSessions.entries()) {
    if (new Date(session.expiresAt).getTime() <= now) {
      adminSessions.delete(id);
    }
  }
}

function parseBasicAuth(req) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Basic ')) return null;
  try {
    const decoded = Buffer.from(auth.slice(6), 'base64').toString();
    const idx = decoded.indexOf(':');
    if (idx === -1) return null;
    return {
      username: decoded.slice(0, idx).trim().toLowerCase(),
      password: decoded.slice(idx + 1),
    };
  } catch (e) {
    return null;
  }
}

function getAuthContext(req) {
  const auth = req.headers.authorization || '';
  if (auth.startsWith('Bearer ')) {
    const token = auth.slice(7).trim();
    if (token === API_SECRET) return { kind: 'api-secret' };
    const session = adminSessions.get(hashToken(token));
    if (session && new Date(session.expiresAt).getTime() > Date.now()) {
      return { kind: 'admin-session', session };
    }
  }

  const basic = parseBasicAuth(req);
  if (basic && basic.username === ADMIN_USER && verifyAdminPassword(basic.password)) {
    return { kind: 'admin-basic' };
  }

  return null;
}

function requireAdmin(req) {
  return getAuthContext(req);
}

function getPortalUrl(user) {
  return `/profile?user=${encodeURIComponent(user.id)}`;
}

function isRazorpayConfigured() {
  return !!(RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET);
}

function migrateUserRecord(user) {
  const createdAt = toIsoOrNull(user.createdAt) || nowIso();
  const email = cleanEmail(user.email);
  const paymentStatus = user.paymentStatus || (user.trialEndsAt ? 'trial' : 'paid');
  const trialWindowStartedAt = toIsoOrNull(user.trialWindowStartedAt)
    || toIsoOrNull(user.trialStartedAt)
    || (paymentStatus === 'paid' ? null : createdAt);
  const nextTrialEligibleAt = toIsoOrNull(user.nextTrialEligibleAt)
    || toIsoOrNull(user.trialWindowEndsAt)
    || toIsoOrNull(user.trialEndsAt)
    || (trialWindowStartedAt ? addDays(trialWindowStartedAt, FREE_TRIAL_RESET_DAYS) : null);

  return {
    id: user.id,
    name: cleanName(user.name || (email ? email.split('@')[0] : 'user')),
    email,
    note: String(user.note || '').slice(0, 200),
    publicKey: user.publicKey || '',
    address: user.address || '',
    status: user.status || 'active',
    createdAt,
    updatedAt: toIsoOrNull(user.updatedAt) || createdAt,
    createdVia: user.createdVia || 'admin',
    paymentStatus,
    paymentReference: String(user.paymentReference || '').slice(0, 200),
    paymentRequestedAt: toIsoOrNull(user.paymentRequestedAt),
    lastPaidAt: toIsoOrNull(user.lastPaidAt),
    trialStartedAt: toIsoOrNull(user.trialStartedAt) || trialWindowStartedAt,
    trialEndsAt: toIsoOrNull(user.trialEndsAt) || null,
    trialQuotaSeconds: Number.isFinite(user.trialQuotaSeconds) ? user.trialQuotaSeconds : (paymentStatus === 'paid' ? 0 : FREE_TRIAL_SECONDS),
    trialConsumedSeconds: Number.isFinite(user.trialConsumedSeconds) ? user.trialConsumedSeconds : 0,
    trialWindowStartedAt,
    trialWindowEndsAt: toIsoOrNull(user.trialWindowEndsAt) || nextTrialEligibleAt,
    nextTrialEligibleAt,
    currentSessionStartedAt: toIsoOrNull(user.currentSessionStartedAt),
    lastMeteredAt: toIsoOrNull(user.lastMeteredAt),
    lastConnectedAt: toIsoOrNull(user.lastConnectedAt),
    lastKnownEndpoint: String(user.lastKnownEndpoint || ''),
    suspendedAt: toIsoOrNull(user.suspendedAt),
    suspendedReason: user.suspendedReason || '',
    revokedAt: toIsoOrNull(user.revokedAt),
    portalToken: String(user.portalToken || randomToken(12)),
    razorpayOrderId: String(user.razorpayOrderId || ''),
    razorpayPaymentId: String(user.razorpayPaymentId || ''),
    razorpaySignature: String(user.razorpaySignature || ''),
  };
}

function loadUsersDb() {
  try {
    if (!fs.existsSync(USERS_DB_FILE)) return { users: [] };
    const parsed = JSON.parse(fs.readFileSync(USERS_DB_FILE, 'utf8'));
    const users = Array.isArray(parsed.users) ? parsed.users.map(migrateUserRecord) : [];
    return { users };
  } catch (e) {
    return { users: [] };
  }
}

function saveUsersDb(db) {
  fs.writeFileSync(USERS_DB_FILE, JSON.stringify(db, null, 2));
}

function getServerPublicKey() {
  if (process.env.WG_SERVER_PUBLIC_KEY) return process.env.WG_SERVER_PUBLIC_KEY;
  return shell(`cat ${WG_SERVER_PUBLIC_KEY_FILE}`, '');
}

function getPublicEndpoint(req) {
  if (WG_PUBLIC_ENDPOINT) return WG_PUBLIC_ENDPOINT;
  const host = (req.headers.host || '').split(':')[0];
  if (host) return `${host}:51820`;
  const ip = shell('curl -4fsS --max-time 6 ifconfig.me || curl -4fsS --max-time 6 api.ipify.org', '');
  return ip ? `${ip}:51820` : '';
}

function allocateClientIp(users) {
  const { octets } = parseSubnet24(WG_SUBNET);
  const used = new Set(users.filter((u) => u.status !== 'revoked' && u.address).map((u) => u.address));
  for (let host = 2; host <= 254; host += 1) {
    const candidate = `${octets[0]}.${octets[1]}.${octets[2]}.${host}`;
    if (!used.has(candidate) && candidate !== WG_DNS) return candidate;
  }
  throw new Error('No free client IPs left in subnet');
}

function appendPeerToWgConfig(userId, pubKey, ip) {
  const marker = `# PHANTOM_USER ${userId}`;
  const conf = fs.readFileSync(WG_CONF_FILE, 'utf8');
  if (conf.includes(marker)) return;
  const block = `\n${marker}\n[Peer]\nPublicKey = ${pubKey}\nAllowedIPs = ${ip}/32\n`;
  fs.appendFileSync(WG_CONF_FILE, block);
}

function removePeerFromWgConfig(userId) {
  const marker = `# PHANTOM_USER ${userId}`;
  const conf = fs.readFileSync(WG_CONF_FILE, 'utf8');
  if (!conf.includes(marker)) return;
  const pattern = new RegExp(`\\n?# PHANTOM_USER ${escapeRegExp(userId)}\\n\\[Peer\\]\\nPublicKey = .*?\\nAllowedIPs = .*?\\n`, 'g');
  const next = conf.replace(pattern, '\n');
  fs.writeFileSync(WG_CONF_FILE, next);
}

function assertProvisioningReady(req) {
  const serverPub = getServerPublicKey();
  const endpoint = getPublicEndpoint(req);
  if (!serverPub || !endpoint) throw new Error('unable to resolve server public key or endpoint');
  if (!fs.existsSync(WG_CONF_FILE)) throw new Error('WireGuard config not found; deploy the VPN server first');
  return { serverPub, endpoint };
}

function buildClientConfig(name, privateKey, address, serverPub, endpoint) {
  return [
    '# PHANTOM VPN — User Config',
    `# User: ${name}`,
    '',
    '[Interface]',
    `PrivateKey = ${privateKey}`,
    `Address = ${address}/24`,
    `DNS = ${WG_DNS}`,
    '',
    '[Peer]',
    `PublicKey = ${serverPub}`,
    `Endpoint = ${endpoint}`,
    'AllowedIPs = 0.0.0.0/0, ::/0',
    'PersistentKeepalive = 25',
    '',
  ].join('\n');
}

function activateUserPeer(user) {
  run(`wg set wg0 peer ${shQuote(user.publicKey)} allowed-ips ${user.address}/32`);
  appendPeerToWgConfig(user.id, user.publicKey, user.address);
}

function removeUserPeer(user) {
  shell(`wg set wg0 peer ${shQuote(user.publicKey)} remove`, '');
  if (fs.existsSync(WG_CONF_FILE)) removePeerFromWgConfig(user.id);
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

function getEffectiveTrialConsumedSeconds(user, nowMs = Date.now()) {
  let consumed = Number(user.trialConsumedSeconds || 0);
  if (user.paymentStatus === 'paid' || !user.currentSessionStartedAt || !user.lastMeteredAt) return consumed;
  const lastMeteredMs = new Date(user.lastMeteredAt).getTime();
  if (Number.isNaN(lastMeteredMs) || lastMeteredMs >= nowMs) return consumed;
  consumed += Math.floor((nowMs - lastMeteredMs) / 1000);
  return Math.min(consumed, Number(user.trialQuotaSeconds || FREE_TRIAL_SECONDS));
}

function getRemainingTrialSeconds(user, nowMs = Date.now()) {
  if (user.paymentStatus === 'paid') return null;
  const quota = Number(user.trialQuotaSeconds || FREE_TRIAL_SECONDS);
  return Math.max(0, quota - getEffectiveTrialConsumedSeconds(user, nowMs));
}

function getCurrentSessionSeconds(user, nowMs = Date.now()) {
  if (!user.currentSessionStartedAt) return 0;
  const startMs = new Date(user.currentSessionStartedAt).getTime();
  if (Number.isNaN(startMs)) return 0;
  return Math.max(0, Math.floor((nowMs - startMs) / 1000));
}

function suspendTrialUser(user, reason) {
  user.status = 'suspended';
  user.suspendedAt = nowIso();
  user.suspendedReason = reason;
  user.updatedAt = user.suspendedAt;
  user.currentSessionStartedAt = null;
  user.lastMeteredAt = null;
}

function serializeUser(user) {
  const nowMs = Date.now();
  const remainingTrialSeconds = getRemainingTrialSeconds(user, nowMs);
  const trialWindowEndsAt = user.trialWindowEndsAt || user.nextTrialEligibleAt || null;
  const windowExpired = !!(trialWindowEndsAt && new Date(trialWindowEndsAt).getTime() <= nowMs);
  const quotaExhausted = remainingTrialSeconds !== null && remainingTrialSeconds <= 0;
  let accessState = 'active';

  if (user.status === 'revoked') accessState = 'revoked';
  else if (user.paymentStatus === 'paid') accessState = 'paid_active';
  else if (user.status === 'suspended' && windowExpired) accessState = 'cooldown_wait';
  else if (user.status === 'suspended') accessState = 'payment_required';
  else if (windowExpired) accessState = 'trial_window_expired';
  else accessState = 'trial_active';

  return {
    id: user.id,
    name: user.name,
    email: user.email,
    note: user.note || '',
    address: user.address,
    status: user.status,
    accessState,
    createdVia: user.createdVia,
    paymentStatus: user.paymentStatus,
    paymentReference: user.paymentReference || '',
    paymentRequestedAt: user.paymentRequestedAt || null,
    lastPaidAt: user.lastPaidAt || null,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt || null,
    trialStartedAt: user.trialStartedAt || null,
    trialEndsAt: user.trialEndsAt || null,
    trialQuotaSeconds: user.paymentStatus === 'paid' ? null : Number(user.trialQuotaSeconds || FREE_TRIAL_SECONDS),
    trialConsumedSeconds: user.paymentStatus === 'paid' ? null : getEffectiveTrialConsumedSeconds(user, nowMs),
    remainingTrialSeconds,
    trialWindowStartedAt: user.trialWindowStartedAt || null,
    trialWindowEndsAt,
    nextTrialEligibleAt: user.nextTrialEligibleAt || null,
    trialWindowExpired: windowExpired,
    quotaExhausted,
    cooldownActive: !!(user.nextTrialEligibleAt && new Date(user.nextTrialEligibleAt).getTime() > nowMs && user.paymentStatus !== 'paid'),
    currentConnected: !!user.currentSessionStartedAt && user.status === 'active',
    currentSessionStartedAt: user.currentSessionStartedAt || null,
    currentSessionSeconds: getCurrentSessionSeconds(user, nowMs),
    lastConnectedAt: user.lastConnectedAt || null,
    lastKnownEndpoint: user.lastKnownEndpoint || '',
    suspendedAt: user.suspendedAt || null,
    suspendedReason: user.suspendedReason || '',
    revokedAt: user.revokedAt || null,
    portalUrl: getPortalUrl(user),
    razorpayEnabled: isRazorpayConfigured(),
    razorpayOrderId: user.razorpayOrderId || '',
    razorpayPaymentId: user.razorpayPaymentId || '',
  };
}

function listUsers() {
  const db = loadUsersDb();
  return db.users.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()).map(serializeUser);
}

function revokeStaleTrialRecord(user) {
  if (!user || user.status === 'revoked') return;
  if (user.status === 'active') removeUserPeer(user);
  user.status = 'revoked';
  user.revokedAt = nowIso();
  user.updatedAt = user.revokedAt;
  user.currentSessionStartedAt = null;
  user.lastMeteredAt = null;
}

function buildNewUserRecord(req, payload, source, db) {
  const email = cleanEmail(payload.email);
  const name = cleanName(payload.name || (email ? email.split('@')[0] : ''));
  const note = String(payload.note || '').slice(0, 200);

  if (!name || name.length < 3) throw new Error('name is required (min 3 chars, letters/numbers/_/-)');
  if (!email || !isLikelyEmail(email)) throw new Error('valid email is required');

  const now = nowIso();
  const accessType = source === 'public' ? 'trial' : (payload.accessType === 'trial' ? 'trial' : 'paid');
  const sameEmail = db.users
    .filter((u) => u.email === email)
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());

  const latest = sameEmail[0];
  if (source === 'public' && latest) {
    if (latest.paymentStatus === 'paid' && latest.status !== 'revoked') {
      throw new Error('a paid PHANTOM account already exists for this email');
    }
    const nextEligibleMs = latest.nextTrialEligibleAt ? new Date(latest.nextTrialEligibleAt).getTime() : 0;
    if (nextEligibleMs && nextEligibleMs > Date.now()) {
      throw new Error(`free trial is locked until ${latest.nextTrialEligibleAt}`);
    }
    revokeStaleTrialRecord(latest);
  }

  if (source !== 'public' && latest && latest.status !== 'revoked') {
    throw new Error(`active record already exists for ${email}`);
  }

  const { serverPub, endpoint } = assertProvisioningReady(req);
  const id = makeId(name);
  const address = allocateClientIp(db.users);
  const privateKey = run('wg genkey');
  const publicKey = run(`printf '%s' ${shQuote(privateKey)} | wg pubkey`);

  const isPaid = accessType === 'paid';
  const trialWindowStartedAt = isPaid ? null : now;
  const nextTrialEligibleAt = isPaid ? null : addDays(now, FREE_TRIAL_RESET_DAYS);

  const user = {
    id,
    name,
    email,
    note,
    publicKey,
    address,
    status: 'active',
    createdAt: now,
    updatedAt: now,
    createdVia: source,
    paymentStatus: isPaid ? 'paid' : 'trial',
    paymentReference: '',
    paymentRequestedAt: null,
    lastPaidAt: isPaid ? now : null,
    trialStartedAt: isPaid ? null : now,
    trialEndsAt: isPaid ? null : addHours(now, FREE_TRIAL_HOURS),
    trialQuotaSeconds: isPaid ? 0 : FREE_TRIAL_SECONDS,
    trialConsumedSeconds: 0,
    trialWindowStartedAt,
    trialWindowEndsAt: nextTrialEligibleAt,
    nextTrialEligibleAt,
    currentSessionStartedAt: null,
    lastMeteredAt: null,
    lastConnectedAt: null,
    lastKnownEndpoint: '',
    suspendedAt: null,
    suspendedReason: '',
    revokedAt: null,
    portalToken: randomToken(12),
    razorpayOrderId: '',
    razorpayPaymentId: '',
    razorpaySignature: '',
  };

  activateUserPeer(user);
  db.users.push(user);
  saveUsersDb(db);

  return {
    user: serializeUser(user),
    config: buildClientConfig(name, privateKey, address, serverPub, endpoint),
  };
}

function createUserVpnProfile(req, payload, options = {}) {
  const source = options.source || 'admin';
  const db = loadUsersDb();
  return buildNewUserRecord(req, payload, source, db);
}

function revokeUserVpnProfile(userId) {
  const db = loadUsersDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) throw new Error('user not found');
  if (user.status === 'revoked') return { user: serializeUser(user), alreadyRevoked: true };
  revokeStaleTrialRecord(user);
  saveUsersDb(db);
  return { user: serializeUser(user), alreadyRevoked: false };
}

function updateUserPayment(userId, action, reference) {
  const db = loadUsersDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) throw new Error('user not found');
  if (user.status === 'revoked') throw new Error('revoked users cannot be updated');

  const now = nowIso();
  if (reference !== undefined) user.paymentReference = String(reference || '').slice(0, 200);

  if (action === 'approve') {
    user.paymentStatus = 'paid';
    user.lastPaidAt = now;
    user.updatedAt = now;
    user.suspendedReason = '';
    user.suspendedAt = null;
    user.razorpayOrderId = user.razorpayOrderId || '';
    if (user.status === 'suspended') {
      activateUserPeer(user);
      user.status = 'active';
    }
  } else if (action === 'pending_review') {
    user.paymentStatus = 'pending_review';
    user.paymentRequestedAt = now;
    user.updatedAt = now;
  } else if (action === 'trial') {
    user.paymentStatus = 'trial';
    user.updatedAt = now;
  } else {
    throw new Error('unsupported payment action');
  }

  saveUsersDb(db);
  return serializeUser(user);
}

function requestPaymentReview(userId, reference) {
  const db = loadUsersDb();
  const user = db.users.find((u) => u.id === userId);
  if (!user) throw new Error('user not found');
  if (user.status === 'revoked') throw new Error('user is revoked');
  if (user.paymentStatus === 'paid') throw new Error('user is already marked as paid');
  user.paymentStatus = 'pending_review';
  user.paymentReference = String(reference || '').slice(0, 200);
  user.paymentRequestedAt = nowIso();
  user.updatedAt = user.paymentRequestedAt;
  saveUsersDb(db);
  return serializeUser(user);
}

function apiRequestJson(hostname, path, method, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname,
      path,
      method,
      headers: {
        ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
        ...headers,
      },
    }, (res) => {
      let raw = '';
      res.on('data', (chunk) => { raw += chunk; });
      res.on('end', () => {
        let parsed = {};
        try { parsed = raw ? JSON.parse(raw) : {}; } catch (e) {}
        if (res.statusCode < 200 || res.statusCode >= 300) {
          const errDescription = parsed && parsed.error && parsed.error.description;
          reject(new Error(errDescription || parsed.error || `HTTP ${res.statusCode}`));
          return;
        }
        resolve(parsed);
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function createRazorpayOrderForUser(userId) {
  if (!isRazorpayConfigured()) throw new Error('Razorpay is not configured yet');
  const db = loadUsersDb();
  const user = db.users.find((entry) => entry.id === userId);
  if (!user) throw new Error('user not found');
  if (user.paymentStatus === 'paid') throw new Error('user is already paid');

  const receipt = `phantom_${user.id}_${Date.now().toString(36)}`.slice(0, 40);
  const auth = Buffer.from(`${RAZORPAY_KEY_ID}:${RAZORPAY_KEY_SECRET}`).toString('base64');
  const order = await apiRequestJson(
    'api.razorpay.com',
    '/v1/orders',
    'POST',
    {
      amount: RAZORPAY_PLAN_AMOUNT,
      currency: RAZORPAY_CURRENCY,
      receipt,
      notes: {
        userId: user.id,
        email: user.email,
        plan: RAZORPAY_PLAN_NAME,
      },
    },
    { Authorization: `Basic ${auth}` },
  );

  user.razorpayOrderId = order.id || '';
  user.paymentStatus = 'pending_gateway';
  user.paymentRequestedAt = nowIso();
  user.updatedAt = user.paymentRequestedAt;
  saveUsersDb(db);

  return {
    key: RAZORPAY_KEY_ID,
    order,
    amount: RAZORPAY_PLAN_AMOUNT,
    currency: RAZORPAY_CURRENCY,
    name: RAZORPAY_PLAN_NAME,
    description: RAZORPAY_PLAN_DESCRIPTION,
    user: serializeUser(user),
  };
}

function verifyRazorpayPayment(payload) {
  if (!isRazorpayConfigured()) throw new Error('Razorpay is not configured yet');

  const userId = String(payload.userId || '');
  const orderId = String(payload.razorpay_order_id || '');
  const paymentId = String(payload.razorpay_payment_id || '');
  const signature = String(payload.razorpay_signature || '');
  if (!userId || !orderId || !paymentId || !signature) throw new Error('missing Razorpay verification fields');

  const db = loadUsersDb();
  const user = db.users.find((entry) => entry.id === userId);
  if (!user) throw new Error('user not found');
  if (user.razorpayOrderId !== orderId) throw new Error('Razorpay order mismatch');

  const expected = crypto.createHmac('sha256', RAZORPAY_KEY_SECRET).update(`${orderId}|${paymentId}`).digest('hex');
  if (expected !== signature) throw new Error('invalid Razorpay signature');

  user.razorpayPaymentId = paymentId;
  user.razorpaySignature = signature;
  user.paymentReference = paymentId;
  user.paymentStatus = 'paid';
  user.lastPaidAt = nowIso();
  user.updatedAt = user.lastPaidAt;
  user.suspendedAt = null;
  user.suspendedReason = '';
  if (user.status === 'suspended') {
    activateUserPeer(user);
    user.status = 'active';
  }
  saveUsersDb(db);

  return serializeUser(user);
}

function syncUserConnectionState(peerDetails) {
  const db = loadUsersDb();
  let changed = false;
  const nowMs = Date.now();
  const now = new Date(nowMs).toISOString();
  const peersByPublicKey = new Map(peerDetails.map((peer) => [peer.fullPublicKey, peer]));

  db.users.forEach((user) => {
    const peer = peersByPublicKey.get(user.publicKey);
    const isConnected = !!(peer && peer.lastHandshakeMs && (nowMs - peer.lastHandshakeMs < 130000));
    if (peer && peer.endpoint && peer.endpoint !== 'N/A' && peer.endpoint !== user.lastKnownEndpoint) {
      user.lastKnownEndpoint = peer.endpoint;
      changed = true;
    }

    if (user.paymentStatus !== 'paid' && user.currentSessionStartedAt && !user.lastMeteredAt) {
      user.lastMeteredAt = user.currentSessionStartedAt;
      changed = true;
    }

    if (isConnected && user.status === 'active') {
      if (!user.currentSessionStartedAt) {
        user.currentSessionStartedAt = now;
        changed = true;
      }
      user.lastConnectedAt = now;

      if (user.paymentStatus !== 'paid' && Number(user.trialQuotaSeconds || 0) > 0) {
        const lastMeteredMs = user.lastMeteredAt ? new Date(user.lastMeteredAt).getTime() : nowMs;
        const deltaSeconds = Math.max(0, Math.floor((nowMs - lastMeteredMs) / 1000));
        if (deltaSeconds > 0) {
          user.trialConsumedSeconds = Math.min(
            Number(user.trialQuotaSeconds || FREE_TRIAL_SECONDS),
            Number(user.trialConsumedSeconds || 0) + deltaSeconds,
          );
          user.lastMeteredAt = now;
          user.updatedAt = now;
          changed = true;
        } else if (!user.lastMeteredAt) {
          user.lastMeteredAt = now;
          changed = true;
        }
      }
    } else {
      if (user.currentSessionStartedAt) {
        user.currentSessionStartedAt = null;
        changed = true;
      }
      if (user.lastMeteredAt) {
        user.lastMeteredAt = null;
        changed = true;
      }
    }
  });

  if (changed) saveUsersDb(db);
}

function enforceAccessPolicies() {
  const db = loadUsersDb();
  let changed = false;
  const nowMs = Date.now();

  db.users.forEach((user) => {
    if (user.status !== 'active') return;
    if (user.paymentStatus === 'paid') return;

    const remaining = getRemainingTrialSeconds(user, nowMs);
    const windowExpired = !!(user.nextTrialEligibleAt && new Date(user.nextTrialEligibleAt).getTime() <= nowMs);
    if ((remaining !== null && remaining <= 0) || windowExpired) {
      removeUserPeer(user);
      suspendTrialUser(
        user,
        remaining !== null && remaining <= 0
          ? `Free trial quota used. Wait until ${user.nextTrialEligibleAt} for a fresh free hour or complete payment.`
          : `Free-trial window ended. Wait until ${user.nextTrialEligibleAt} for a fresh free hour or complete payment.`,
      );
      changed = true;
    }
  });

  if (changed) saveUsersDb(db);
}

function collectWGStats() {
  try {
    const raw = shell('wg show wg0 dump', '');
    if (!raw) {
      state.vpn.connected = false;
      state.connectedPeers = [];
      return;
    }

    state.vpn.connected = true;
    if (!state.vpn.startTime) state.vpn.startTime = Date.now();
    state.vpn.uptime = Math.floor((Date.now() - state.vpn.startTime) / 1000);

    const lines = raw.split('\n').filter(Boolean);
    const peers = [];
    const peerDetails = [];
    let totalRx = 0;
    let totalTx = 0;

    lines.slice(1).forEach((line) => {
      const parts = line.split('\t');
      if (parts.length >= 7) {
        const fullPublicKey = parts[0];
        const endpoint = parts[2] || 'N/A';
        const lastHandshake = parseInt(parts[4], 10) || 0;
        const lastHandshakeMs = lastHandshake > 0 ? lastHandshake * 1000 : 0;
        const rx = parseInt(parts[5], 10) || 0;
        const tx = parseInt(parts[6], 10) || 0;
        totalRx += rx;
        totalTx += tx;
        peerDetails.push({
          fullPublicKey,
          endpoint,
          lastHandshakeMs,
          allowedIPs: parts[3] || '',
          rxBytes: rx,
          txBytes: tx,
        });
        peers.push({
          pubkey: `${fullPublicKey.substring(0, 16)}...`,
          endpoint,
          allowedIPs: parts[3],
          lastHandshake,
          rx: formatBytes(rx),
          tx: formatBytes(tx),
        });
      }
    });

    state.bandwidthRx = totalRx;
    state.bandwidthTx = totalTx;
    state.connectedPeers = peers;
    syncUserConnectionState(peerDetails);
  } catch (e) {
    state.vpn.connected = false;
    state.connectedPeers = [];
  }
}

function collectTorStats() {
  try {
    const circuits = shell(`${torCtl('GETINFO circuit-status')} | grep -Ec '^[0-9]+\\s' || echo 0`, '0');
    state.torCircuits = parseInt(circuits, 10) || 0;

    exec('curl -s --socks5 127.0.0.1:9050 --max-time 8 ifconfig.me', (err, stdout) => {
      if (!err && stdout.trim()) state.currentIP = stdout.trim();
    });

    if (fs.existsSync(ROTATE_LOG)) {
      const lines = fs.readFileSync(ROTATE_LOG, 'utf8').split('\n').filter(Boolean);
      state.rotations = lines.length;
      if (lines.length > 0) {
        const last = lines[lines.length - 1];
        const match = last.match(/ROTATED_TO=(\S+)/);
        if (match) state.currentIP = match[1];
      }
    }
  } catch (e) {
    // ignore
  }
}

function collectThreats() {
  try {
    if (!fs.existsSync(FAIL2BAN_LOG)) return;
    const lines = fs.readFileSync(FAIL2BAN_LOG, 'utf8').split('\n').filter(Boolean).slice(-200);
    const threats = [];

    lines.forEach((line) => {
      const banMatch = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*Ban (\d+\.\d+\.\d+\.\d+)/);
      const foundMatch = line.match(/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*Found (\d+\.\d+\.\d+\.\d+)/);
      if (banMatch) {
        threats.push({ time: banMatch[1], ip: banMatch[2], type: 'BAN', severity: 'HIGH', msg: 'IP banned after repeated auth failures' });
      } else if (foundMatch) {
        threats.push({ time: foundMatch[1], ip: foundMatch[2], type: 'PROBE', severity: 'MED', msg: 'Suspicious connection attempt detected' });
      }
    });

    state.threats = threats.slice(-50).reverse();
  } catch (e) {
    // ignore
  }
}

function collectDNSStats() {
  try {
    const stats = shell('unbound-control stats_noreset 2>/dev/null', '');
    if (!stats) return;
    const totalMatch = stats.match(/total\.num\.queries=(\d+)/);
    const blockedMatch = stats.match(/total\.num\.zero_ttl=(\d+)/);
    if (totalMatch) state.dnsQueries = parseInt(totalMatch[1], 10);
    if (blockedMatch) state.dnsBlocked = parseInt(blockedMatch[1], 10);
  } catch (e) {
    // ignore
  }
}

function collectSystemMetrics() {
  const cpuLine = shell("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'", '0');
  const memLine = shell("free | grep Mem | awk '{printf \"%.1f\", $3/$2 * 100.0}'", '0');
  const load = shell('cat /proc/loadavg', '0 0 0').split(' ').slice(0, 3);
  return {
    cpu: parseFloat(cpuLine) || 0,
    mem: parseFloat(memLine) || 0,
    load,
    uptime: parseInt(shell('cat /proc/uptime', '0').split('.')[0], 10) || 0,
  };
}

function rotateIP(callback) {
  exec(torCtl('SIGNAL NEWNYM'), () => {
    const ts = nowIso();
    fs.appendFileSync(ROTATE_LOG, `${ts} ROTATE_TRIGGERED=manual\n`);
    state.rotations += 1;

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

function unauthorized(res) {
  json(res, 401, { error: 'Unauthorized' }, { 'WWW-Authenticate': 'Basic realm="PHANTOM VPN"' });
}

function publicConfigPayload() {
  return {
    freeTrialHours: FREE_TRIAL_HOURS,
    freeTrialSeconds: FREE_TRIAL_SECONDS,
    freeTrialResetDays: FREE_TRIAL_RESET_DAYS,
    paymentLink: PAYMENT_LINK,
    planPriceLabel: PLAN_PRICE_LABEL,
    adminUser: ADMIN_USER,
    razorpayEnabled: isRazorpayConfigured(),
    razorpayKeyId: isRazorpayConfigured() ? RAZORPAY_KEY_ID : '',
    razorpayAmount: RAZORPAY_PLAN_AMOUNT,
    razorpayCurrency: RAZORPAY_CURRENCY,
    razorpayPlanName: RAZORPAY_PLAN_NAME,
    razorpayPlanDescription: RAZORPAY_PLAN_DESCRIPTION,
  };
}

function findUserById(userId) {
  const db = loadUsersDb();
  const user = db.users.find((entry) => entry.id === userId);
  return { db, user };
}

function handleRequest(req, res) {
  res.setHeader('Access-Control-Allow-Origin', CORS_ORIGIN);
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const requestUrl = new URL(req.url, 'http://localhost');
  const path = requestUrl.pathname;

  if (path === '/favicon.ico') {
    serveStaticFile(res, `${BRAND_DIR}/favicon-32.png`);
    return;
  }

  if (path.startsWith('/brand/')) {
    const name = path.slice('/brand/'.length);
    if (!/^[a-zA-Z0-9._-]+$/.test(name)) {
      res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Invalid asset path');
      return;
    }
    serveStaticFile(res, `${BRAND_DIR}/${name}`);
    return;
  }

  if (path === '/health') {
    json(res, 200, {
      status: 'ok',
      version: '4.0',
      adminUser: ADMIN_USER,
      authMode: ADMIN_TOTP_SECRET ? 'totp-session' : 'legacy-password',
      freeTrialHours: FREE_TRIAL_HOURS,
      freeTrialResetDays: FREE_TRIAL_RESET_DAYS,
      razorpayEnabled: isRazorpayConfigured(),
    });
    return;
  }

  if (path === '/' || path === '/vpn' || path === '/landing') {
    serveHtml(res, LANDING_FILE, 'Landing page not found');
    return;
  }

  if ((path === '/profile' || path === '/portal') && req.method === 'GET') {
    serveHtml(res, PORTAL_FILE, 'User portal file not found');
    return;
  }

  if ((path === '/dashboard' || path === '/monitor') && req.method === 'GET') {
    serveHtml(res, DASHBOARD_FILE, 'Dashboard file not found');
    return;
  }

  if (path === '/admin' && req.method === 'GET') {
    serveHtml(res, ADMIN_FILE, 'Admin portal file not found');
    return;
  }

  if (path === '/routing' && req.method === 'GET') {
    serveHtml(res, ROUTING_FILE, 'Routing page not found');
    return;
  }

  if (path === '/docs' && req.method === 'GET') {
    serveHtml(res, DOCS_FILE, 'Docs page not found');
    return;
  }

  if (path === '/api/public/config' && req.method === 'GET') {
    json(res, 200, publicConfigPayload());
    return;
  }

  if (path === '/api/auth/login' && req.method === 'POST') {
    readJsonBody(req, (err, body) => {
      if (err) return json(res, 400, { error: err.message });
      const username = cleanEmail(body.username);
      const password = String(body.password || '');
      if (username !== ADMIN_USER || !verifyAdminPassword(password)) {
        json(res, 401, { error: ADMIN_TOTP_SECRET ? 'Invalid username or authenticator code' : 'Invalid credentials' });
        return;
      }
      const { token, session } = createAdminSession();
      json(res, 200, {
        success: true,
        token,
        expiresAt: session.expiresAt,
        adminUser: ADMIN_USER,
        authMode: ADMIN_TOTP_SECRET ? 'totp-session' : 'legacy-password',
      });
    });
    return;
  }

  if (path === '/api/public/trial' && req.method === 'POST') {
    readJsonBody(req, (err, body) => {
      if (err) return json(res, 400, { error: err.message });
      try {
        const out = createUserVpnProfile(req, body, { source: 'public' });
        json(res, 201, {
          success: true,
          user: out.user,
          config: out.config,
          qrText: out.config,
          portalUrl: out.user.portalUrl,
          paymentLink: PAYMENT_LINK,
          planPriceLabel: PLAN_PRICE_LABEL,
          hint: `Users get ${FREE_TRIAL_HOURS} hour free over a ${FREE_TRIAL_RESET_DAYS}-day cycle. Remaining time continues after reconnects until the quota is exhausted.`,
        });
      } catch (e) {
        json(res, 400, { error: e.message });
      }
    });
    return;
  }

  const publicUserMatch = path.match(/^\/api\/public\/users\/([a-z0-9_-]+-[a-z0-9]+)$/);
  if (publicUserMatch && req.method === 'GET') {
    const { user } = findUserById(publicUserMatch[1]);
    if (!user) return json(res, 404, { error: 'user not found' });
    json(res, 200, {
      user: serializeUser(user),
      paymentLink: PAYMENT_LINK,
      planPriceLabel: PLAN_PRICE_LABEL,
      razorpayEnabled: isRazorpayConfigured(),
      razorpayKeyId: isRazorpayConfigured() ? RAZORPAY_KEY_ID : '',
      razorpayAmount: RAZORPAY_PLAN_AMOUNT,
      razorpayCurrency: RAZORPAY_CURRENCY,
      razorpayPlanName: RAZORPAY_PLAN_NAME,
    });
    return;
  }

  const paymentRequestMatch = path.match(/^\/api\/public\/users\/([a-z0-9_-]+-[a-z0-9]+)\/payment-request$/);
  if (paymentRequestMatch && req.method === 'POST') {
    readJsonBody(req, (err, body) => {
      if (err) return json(res, 400, { error: err.message });
      try {
        const user = requestPaymentReview(paymentRequestMatch[1], body.reference);
        json(res, 200, { success: true, user, message: 'Payment submitted for admin review' });
      } catch (e) {
        json(res, 400, { error: e.message });
      }
    });
    return;
  }

  const orderMatch = path.match(/^\/api\/public\/users\/([a-z0-9_-]+-[a-z0-9]+)\/razorpay-order$/);
  if (orderMatch && req.method === 'POST') {
    readJsonBody(req, async (err) => {
      if (err) return json(res, 400, { error: err.message });
      try {
        const out = await createRazorpayOrderForUser(orderMatch[1]);
        json(res, 200, { success: true, ...out });
      } catch (e) {
        json(res, 400, { error: e.message });
      }
    });
    return;
  }

  if (path === '/api/public/payments/verify' && req.method === 'POST') {
    readJsonBody(req, (err, body) => {
      if (err) return json(res, 400, { error: err.message });
      try {
        const user = verifyRazorpayPayment(body);
        json(res, 200, { success: true, user });
      } catch (e) {
        json(res, 400, { error: e.message });
      }
    });
    return;
  }

  if (path === '/stream') {
    if (!requireAdmin(req)) {
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="PHANTOM VPN"' });
      res.end('Unauthorized');
      return;
    }
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
      'X-Accel-Buffering': 'no',
    });
    res.write(': PHANTOM VPN Stream Connected\n\n');
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  const auth = requireAdmin(req);
  if (!auth) return unauthorized(res);

  if (path === '/api/auth/session' && req.method === 'GET') {
    json(res, 200, {
      authenticated: true,
      adminUser: ADMIN_USER,
      authMode: ADMIN_TOTP_SECRET ? 'totp-session' : 'legacy-password',
    });
    return;
  }

  if (path === '/api/admin/security' && req.method === 'GET') {
    json(res, 200, {
      adminUser: ADMIN_USER,
      authMode: ADMIN_TOTP_SECRET ? 'totp-session' : 'legacy-password',
      sessionTtlHours: Math.round(ADMIN_SESSION_TTL_MS / 3600000),
      totpSetupUri: getAdminSetupUri(),
      totpSecretMasked: ADMIN_TOTP_SECRET ? `${ADMIN_TOTP_SECRET.slice(0, 4)}...${ADMIN_TOTP_SECRET.slice(-4)}` : null,
      ...publicConfigPayload(),
    });
    return;
  }

  if (path === '/api/status' && req.method === 'GET') {
    const sys = collectSystemMetrics();
    json(res, 200, {
      vpn: state.vpn,
      ip: state.currentIP,
      tor: { circuits: state.torCircuits, rotations: state.rotations },
      network: {
        rx: formatBytes(state.bandwidthRx),
        tx: formatBytes(state.bandwidthTx),
        rxBytes: state.bandwidthRx,
        txBytes: state.bandwidthTx,
      },
      dns: { queries: state.dnsQueries, blocked: state.dnsBlocked },
      peers: state.connectedPeers,
      system: sys,
      threats: state.threats.slice(0, 10),
    });
    return;
  }

  if (path === '/api/threats' && req.method === 'GET') {
    json(res, 200, { threats: state.threats, total: state.threats.length });
    return;
  }

  if (path === '/api/stats' && req.method === 'GET') {
    json(res, 200, {
      bandwidth: { rx: state.bandwidthRx, tx: state.bandwidthTx },
      dns: { queries: state.dnsQueries, blocked: state.dnsBlocked },
      rotations: state.rotations,
      peers: state.connectedPeers.length,
    });
    return;
  }

  if (path === '/api/rotate' && req.method === 'POST') {
    rotateIP((err, newIP) => {
      json(res, 200, { success: true, newIP, rotations: state.rotations });
    });
    return;
  }

  if (path === '/api/wg/restart' && req.method === 'POST') {
    exec('systemctl restart wg-quick@wg0', (err) => {
      json(res, 200, { success: !err, message: err ? err.message : 'WireGuard restarted' });
    });
    return;
  }

  if (path === '/api/tor/newcircuit' && req.method === 'POST') {
    exec(torCtl('SIGNAL NEWNYM'), (err) => {
      broadcast('circuit', { time: nowIso(), status: 'rebuilt' });
      json(res, 200, { success: !err });
    });
    return;
  }

  if (path === '/api/logs/rotate' && req.method === 'GET') {
    try {
      const lines = fs.existsSync(ROTATE_LOG)
        ? fs.readFileSync(ROTATE_LOG, 'utf8').split('\n').filter(Boolean).slice(-100).reverse()
        : [];
      json(res, 200, { logs: lines });
    } catch (e) {
      json(res, 500, { error: e.message });
    }
    return;
  }

  if (path === '/api/peers' && req.method === 'GET') {
    json(res, 200, { peers: state.connectedPeers });
    return;
  }

  if (path === '/api/admin/users' && req.method === 'GET') {
    json(res, 200, { users: listUsers() });
    return;
  }

  if (path === '/api/admin/users' && req.method === 'POST') {
    readJsonBody(req, (err, body) => {
      if (err) return json(res, 400, { error: err.message });
      try {
        const out = createUserVpnProfile(req, body, { source: 'admin' });
        json(res, 201, {
          success: true,
          user: out.user,
          config: out.config,
          qrText: out.config,
          portalUrl: out.user.portalUrl,
          hint: 'Store this config now. Private key is only returned once.',
        });
      } catch (e) {
        json(res, 400, { error: e.message });
      }
    });
    return;
  }

  const paymentAdminMatch = path.match(/^\/api\/admin\/users\/([a-z0-9_-]+-[a-z0-9]+)\/payment$/);
  if (paymentAdminMatch && req.method === 'POST') {
    readJsonBody(req, (err, body) => {
      if (err) return json(res, 400, { error: err.message });
      try {
        const user = updateUserPayment(paymentAdminMatch[1], body.action, body.reference);
        json(res, 200, { success: true, user });
      } catch (e) {
        json(res, 400, { error: e.message });
      }
    });
    return;
  }

  const revokeMatch = path.match(/^\/api\/admin\/users\/([a-z0-9_-]+-[a-z0-9]+)$/);
  if (revokeMatch && req.method === 'DELETE') {
    try {
      const out = revokeUserVpnProfile(revokeMatch[1]);
      json(res, 200, { success: true, alreadyRevoked: out.alreadyRevoked, user: out.user });
    } catch (e) {
      json(res, 404, { error: e.message });
    }
    return;
  }

  json(res, 404, { error: 'Not found' });
}

const server = http.createServer(handleRequest);
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[PHANTOM] Monitoring API running on port ${PORT}`);
  console.log(`[PHANTOM] Health: http://0.0.0.0:${PORT}/health`);
  console.log(`[PHANTOM] VPN page: http://0.0.0.0:${PORT}/vpn`);
  console.log(`[PHANTOM] Dashboard: http://0.0.0.0:${PORT}/dashboard`);
  console.log(`[PHANTOM] Admin: http://0.0.0.0:${PORT}/admin`);
  console.log(`[PHANTOM] User Profile: http://0.0.0.0:${PORT}/profile`);
  console.log(`[PHANTOM] Routing: http://0.0.0.0:${PORT}/routing`);
  console.log(`[PHANTOM] Docs: http://0.0.0.0:${PORT}/docs`);
});

function collectAll() {
  pruneAdminSessions();
  collectWGStats();
  enforceAccessPolicies();
  collectTorStats();
  collectThreats();
  collectDNSStats();

  const sys = collectSystemMetrics();
  broadcast('stats', {
    vpn: state.vpn,
    ip: state.currentIP,
    tor: { circuits: state.torCircuits, rotations: state.rotations },
    network: {
      rx: formatBytes(state.bandwidthRx),
      tx: formatBytes(state.bandwidthTx),
      rxBytes: state.bandwidthRx,
      txBytes: state.bandwidthTx,
    },
    dns: { queries: state.dnsQueries, blocked: state.dnsBlocked },
    peers: state.connectedPeers.length,
    system: sys,
    timestamp: Date.now(),
  });

  if (state.threats.length > 0) {
    const latest = state.threats[0];
    if (Date.now() - new Date(latest.time).getTime() < 10000) {
      broadcast('threat', latest);
    }
  }
}

if (!fs.existsSync(USERS_DB_FILE)) saveUsersDb({ users: [] });

setInterval(collectAll, 5000);
collectAll();

process.on('uncaughtException', (err) => console.error('[PHANTOM] Error:', err.message));
process.on('SIGTERM', () => {
  console.log('[PHANTOM] Shutting down...');
  process.exit(0);
});

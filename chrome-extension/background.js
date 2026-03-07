// ============================================================
//  PHANTOM VPN — Chrome Extension Background Service Worker
//  Polls your DigitalOcean server API for real-time data
// ============================================================

// ─── CONFIG (set these after deploying your server) ────────
let config = {
  serverUrl: '',   // e.g. http://YOUR_DROPLET_IP:7777
  apiUser:   'phantom',
  apiPass:   '',
  autoRotate: false,
  rotateInterval: 30,
  blockAds: true,
  blockTrackers: true,
  showNotifications: true,
  spoofGeo: false,
};

// ─── STATE ─────────────────────────────────────────────────
let state = {
  connected: false,
  currentIP: null,
  rotations: 0,
  threats: 0,
  dnsBlocked: 0,
  bandwidthRx: '—',
  bandwidthTx: '—',
  lastUpdate: null,
  peers: 0,
};

let rotateTimer = null;
let pollInterval = null;
let attackCount = 0;

// ─── Load config from storage ──────────────────────────────
chrome.storage.local.get(['phantom_config', 'phantom_state'], (result) => {
  if (result.phantom_config) Object.assign(config, result.phantom_config);
  if (result.phantom_state)  Object.assign(state, result.phantom_state);
  if (config.serverUrl) startPolling();
});

// ─── Listen for messages from popup ────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  switch (msg.type) {

    case 'GET_STATE':
      sendResponse({ state, config });
      break;

    case 'SAVE_CONFIG':
      Object.assign(config, msg.config);
      chrome.storage.local.set({ phantom_config: config });
      if (config.serverUrl) { stopPolling(); startPolling(); }
      sendResponse({ ok: true });
      break;

    case 'ROTATE_IP':
      rotateIP().then(r => sendResponse(r)).catch(e => sendResponse({ ok: false, error: e.message }));
      return true; // async

    case 'NEW_CIRCUIT':
      apiPost('/api/tor/newcircuit').then(r => sendResponse(r)).catch(e => sendResponse({ ok: false }));
      return true;

    case 'RESTART_WG':
      apiPost('/api/wg/restart').then(r => sendResponse(r)).catch(e => sendResponse({ ok: false }));
      return true;

    case 'FETCH_STATUS':
      fetchStatus().then(r => sendResponse(r)).catch(e => sendResponse({ ok: false }));
      return true;

    case 'TOGGLE_AUTO_ROTATE':
      config.autoRotate = msg.enabled;
      chrome.storage.local.set({ phantom_config: config });
      if (msg.enabled) startAutoRotate(); else stopAutoRotate();
      sendResponse({ ok: true });
      break;

    case 'TOGGLE_BLOCK_ADS':
      config.blockAds = msg.enabled;
      chrome.storage.local.set({ phantom_config: config });
      updateBlockingRules();
      sendResponse({ ok: true });
      break;

    case 'TOGGLE_BLOCK_TRACKERS':
      config.blockTrackers = msg.enabled;
      chrome.storage.local.set({ phantom_config: config });
      updateBlockingRules();
      sendResponse({ ok: true });
      break;

    case 'TOGGLE_NOTIFICATIONS':
      config.showNotifications = msg.enabled;
      chrome.storage.local.set({ phantom_config: config });
      sendResponse({ ok: true });
      break;

    case 'TOGGLE_SPOOF_GEO':
      config.spoofGeo = msg.enabled;
      chrome.storage.local.set({ phantom_config: config });
      sendResponse({ ok: true });
      break;
  }
});

// ─── API helpers ───────────────────────────────────────────
function authHeader() {
  return 'Basic ' + btoa(config.apiUser + ':' + config.apiPass);
}

async function apiFetch(endpoint, method = 'GET') {
  if (!config.serverUrl) throw new Error('No server configured');
  const res = await fetch(config.serverUrl + endpoint, {
    method,
    headers: { 'Authorization': authHeader() },
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) throw new Error('API error ' + res.status);
  return res.json();
}

async function apiPost(endpoint) {
  return apiFetch(endpoint, 'POST');
}

// ─── Fetch server status ───────────────────────────────────
async function fetchStatus() {
  try {
    const data = await apiFetch('/api/status');

    const wasConnected = state.connected;
    state.connected   = true;
    state.currentIP   = data.ip || null;
    state.rotations   = data.tor?.rotations || 0;
    state.dnsBlocked  = data.dns?.blocked || 0;
    state.bandwidthRx = data.network?.rx || '—';
    state.bandwidthTx = data.network?.tx || '—';
    state.peers       = data.peers || 0;
    state.lastUpdate  = Date.now();

    // Threat detection
    const newThreats = (data.threats || []).filter(t => t.type === 'BAN').length;
    if (newThreats > state.threats && config.showNotifications) {
      const diff = newThreats - state.threats;
      notifyUser('🔴 Attack Blocked!', `${diff} IP${diff > 1 ? 's' : ''} banned — ${data.threats[0]?.ip || 'unknown'}`);
    }
    state.threats = newThreats;

    if (!wasConnected && config.showNotifications) {
      notifyUser('🛡 PHANTOM Connected', 'VPN active · IP: ' + (state.currentIP || 'fetching...'));
    }

    chrome.storage.local.set({ phantom_state: state });
    updateBadge();
    return { ok: true, state };
  } catch(e) {
    if (state.connected && config.showNotifications) {
      notifyUser('⚠ PHANTOM Disconnected', 'Lost connection to VPN server');
    }
    state.connected = false;
    updateBadge();
    chrome.storage.local.set({ phantom_state: state });
    return { ok: false, error: e.message };
  }
}

// ─── Rotate IP ─────────────────────────────────────────────
async function rotateIP() {
  try {
    const data = await apiPost('/api/rotate');
    state.rotations = data.rotations || state.rotations + 1;
    if (data.newIP) state.currentIP = data.newIP;
    chrome.storage.local.set({ phantom_state: state });
    if (config.showNotifications) {
      notifyUser('⟳ IP Rotated', 'New IP: ' + (data.newIP || 'fetching...'));
    }
    return { ok: true, newIP: data.newIP };
  } catch(e) {
    return { ok: false, error: e.message };
  }
}

// ─── Badge ─────────────────────────────────────────────────
function updateBadge() {
  if (state.connected) {
    chrome.action.setBadgeBackgroundColor({ color: '#00ff9d' });
    chrome.action.setBadgeText({ text: 'ON' });
  } else {
    chrome.action.setBadgeBackgroundColor({ color: '#ff2d6b' });
    chrome.action.setBadgeText({ text: 'OFF' });
  }
}

// ─── Notification ──────────────────────────────────────────
function notifyUser(title, message) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon48.png',
    title,
    message,
  });
}

// ─── Polling ───────────────────────────────────────────────
function startPolling() {
  stopPolling();
  fetchStatus();
  pollInterval = setInterval(fetchStatus, 5000);
}

function stopPolling() {
  if (pollInterval) clearInterval(pollInterval);
}

// ─── Auto Rotate ───────────────────────────────────────────
function startAutoRotate() {
  stopAutoRotate();
  rotateTimer = setInterval(() => rotateIP(), config.rotateInterval * 1000);
}
function stopAutoRotate() {
  if (rotateTimer) clearInterval(rotateTimer);
}
if (config.autoRotate && config.serverUrl) startAutoRotate();
updateBlockingRules();

// ─── Content script attack detection ──────────────────────
// Listen for attack reports from content.js
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg.type === 'ATTACK_DETECTED') {
    attackCount++;
    if (config.showNotifications) {
      notifyUser('⚠ Browser Attack Detected', `${msg.attackType} on ${sender.url?.substring(0,60) || 'unknown page'}`);
    }
    // Log it
    chrome.storage.local.get('phantom_attacks', (r) => {
      const attacks = r.phantom_attacks || [];
      attacks.unshift({
        time: new Date().toISOString(),
        type: msg.attackType,
        url: sender.url,
        details: msg.details,
      });
      chrome.storage.local.set({ phantom_attacks: attacks.slice(0, 100) });
    });
  }
});

// ─── Blocking rules update ────────────────────────────────
function updateBlockingRules() {
  // Enable/disable declarativeNetRequest rule sets
  const updates = [];
  if (config.blockAds) {
    updates.push({ rulesetId: 'block_ads', enabled: true });
  } else {
    updates.push({ rulesetId: 'block_ads', enabled: false });
  }
  if (config.blockTrackers) {
    updates.push({ rulesetId: 'block_trackers', enabled: true });
  } else {
    updates.push({ rulesetId: 'block_trackers', enabled: false });
  }
  chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds:  updates.filter(u => u.enabled).map(u => u.rulesetId),
    disableRulesetIds: updates.filter(u => !u.enabled).map(u => u.rulesetId),
  });
}

// Alarms for reliability (service workers can sleep)
chrome.alarms.create('phantomPoll', { periodInMinutes: 0.5 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'phantomPoll' && config.serverUrl) fetchStatus();
});

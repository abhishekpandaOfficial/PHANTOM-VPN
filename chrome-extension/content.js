// ============================================================
//  PHANTOM VPN — Content Script
//  Injected into every page — detects browser-level attacks
//  and spoofs geolocation when enabled
// ============================================================

'use strict';

// ─── ATTACK DETECTION ────────────────────────────────────
const PhantomGuard = (() => {

  // Track detected attacks to avoid spam
  const detected = new Set();
  function report(type, details) {
    const key = type + details;
    if (detected.has(key)) return;
    detected.add(key);
    chrome.runtime.sendMessage({ type: 'ATTACK_DETECTED', attackType: type, details });
    injectWarningBanner(type, details);
  }

  // ── 1. Clickjacking detection ──────────────────────────
  if (window.top !== window.self) {
    // Page is inside an iframe — potential clickjacking
    const src = document.referrer || window.location.href;
    report('CLICKJACKING', 'Page embedded in iframe from: ' + src);
  }

  // ── 2. XSS via suspicious URL params ──────────────────
  const urlParams = window.location.href;
  const xssPatterns = [
    /<script/i, /javascript:/i, /onerror=/i, /onload=/i,
    /eval\(/i, /document\.cookie/i, /window\.location/i,
    /<img[^>]+onerror/i, /vbscript:/i, /data:text\/html/i,
  ];
  xssPatterns.forEach(p => {
    if (p.test(decodeURIComponent(urlParams))) {
      report('XSS_IN_URL', 'Suspicious pattern in URL: ' + p.toString());
    }
  });

  // ── 3. Malicious form action detection ─────────────────
  function checkForms() {
    document.querySelectorAll('form').forEach(form => {
      const action = form.getAttribute('action') || '';
      const origin = window.location.origin;
      if (action && !action.startsWith('/') && !action.startsWith(origin) && !action.startsWith('#')) {
        if (!action.startsWith('http')) return;
        try {
          const dest = new URL(action);
          if (dest.origin !== origin) {
            report('FORM_HIJACK', 'Form submits to external: ' + dest.origin);
          }
        } catch(e) {}
      }
    });
  }

  // ── 4. Crypto mining script detection ──────────────────
  function checkMining() {
    const scripts = document.querySelectorAll('script[src]');
    const miningDomains = ['coinhive', 'cryptoloot', 'minero.cc', 'jsecoin', 'coin-hive', 'miner.pr0gramm', 'webmine'];
    scripts.forEach(s => {
      const src = s.src.toLowerCase();
      miningDomains.forEach(d => {
        if (src.includes(d)) report('CRYPTOMINING', 'Mining script detected: ' + s.src);
      });
    });
  }

  // ── 5. Fake overlay / phishing detection ───────────────
  function checkOverlays() {
    const suspicious = document.querySelectorAll(
      'div[style*="position:fixed"], div[style*="position: fixed"]'
    );
    suspicious.forEach(el => {
      const style = el.getAttribute('style') || '';
      const hasFullscreen = (style.includes('width:100') || style.includes('width: 100')) &&
                            (style.includes('height:100') || style.includes('height: 100'));
      const hasHighZ = /z-index\s*:\s*[0-9]{4,}/.test(style);
      if (hasFullscreen && hasHighZ) {
        const hasInput = el.querySelector('input[type="password"], input[type="email"]');
        if (hasInput) report('PHISHING_OVERLAY', 'Suspicious full-screen overlay with credentials form');
      }
    });
  }

  // ── 6. Detect hidden iframes (tracking) ────────────────
  function checkHiddenIframes() {
    document.querySelectorAll('iframe').forEach(iframe => {
      const style = window.getComputedStyle(iframe);
      if (style.display === 'none' || style.visibility === 'hidden' ||
          parseInt(style.width) < 2 || parseInt(style.height) < 2) {
        const src = iframe.src || iframe.getAttribute('src') || '';
        if (src && !src.startsWith(window.location.origin)) {
          report('HIDDEN_TRACKER', 'Hidden tracking iframe: ' + src.substring(0,80));
        }
      }
    });
  }

  // ── 7. CSP violation monitoring ────────────────────────
  document.addEventListener('securitypolicyviolation', (e) => {
    report('CSP_VIOLATION', `Blocked ${e.violatedDirective} → ${e.blockedURI}`);
  });

  // ── 8. Detect canvas fingerprinting ────────────────────
  const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
  let fingerprintAttempts = 0;
  HTMLCanvasElement.prototype.toDataURL = function(...args) {
    fingerprintAttempts++;
    if (fingerprintAttempts === 3) {
      report('CANVAS_FINGERPRINT', 'Canvas fingerprinting detected on ' + window.location.hostname);
    }
    return origToDataURL.apply(this, args);
  };

  // ── 9. Detect font enumeration fingerprinting ──────────
  const origOffsetWidth = Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'offsetWidth');
  let fontProbes = 0;
  if (origOffsetWidth) {
    Object.defineProperty(HTMLElement.prototype, 'offsetWidth', {
      get: function() {
        fontProbes++;
        if (fontProbes === 50) {
          report('FONT_FINGERPRINT', 'Font enumeration fingerprinting detected');
        }
        return origOffsetWidth.get.call(this);
      }
    });
  }

  // Run checks after DOM loads
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      checkForms(); checkMining(); checkOverlays(); checkHiddenIframes();
    });
  } else {
    checkForms(); checkMining(); checkOverlays(); checkHiddenIframes();
  }

  // Re-check on DOM mutations (for dynamic pages)
  const observer = new MutationObserver(() => {
    checkForms(); checkHiddenIframes();
  });
  observer.observe(document.body || document.documentElement, {
    childList: true, subtree: true
  });

  // ── Warning Banner ─────────────────────────────────────
  function injectWarningBanner(type, details) {
    if (document.getElementById('phantom-warn')) return;
    const banner = document.createElement('div');
    banner.id = 'phantom-warn';
    banner.style.cssText = `
      position:fixed;top:0;left:0;right:0;z-index:2147483647;
      background:linear-gradient(90deg,#1a0608,#0a0010);
      border-bottom:2px solid #ff2d6b;
      padding:10px 20px;display:flex;align-items:center;
      justify-content:space-between;font-family:'JetBrains Mono',monospace;
      font-size:12px;color:#ff2d6b;box-shadow:0 2px 20px rgba(255,45,107,.4);
    `;
    banner.innerHTML = `
      <span>🛡 <strong>PHANTOM VPN:</strong> ⚠ ${type} detected — ${details.substring(0,80)}</span>
      <button onclick="this.parentElement.remove()" style="
        background:none;border:1px solid #ff2d6b;color:#ff2d6b;
        padding:3px 10px;cursor:pointer;font-family:'JetBrains Mono';font-size:10px;
      ">DISMISS</button>
    `;
    document.body?.prepend(banner) || document.documentElement.prepend(banner);
    setTimeout(() => banner?.remove(), 8000);
  }

})();

// ─── GEOLOCATION SPOOFING ────────────────────────────────
chrome.storage.local.get(['phantom_config'], (r) => {
  if (!r?.phantom_config?.spoofGeo) return;

  const FAKE = { latitude: 37.7749, longitude: -122.4194, accuracy: 20 };

  try {
    Object.defineProperty(navigator, 'geolocation', {
      value: {
        getCurrentPosition: (success) => success({ coords: FAKE, timestamp: Date.now() }),
        watchPosition: (success) => { success({ coords: FAKE, timestamp: Date.now() }); return 0; },
        clearWatch: () => {},
      },
      writable: false, configurable: false,
    });
  } catch(e) {}
});

// ─── WEBRTC IP LEAK PREVENTION ───────────────────────────
// Intercept RTCPeerConnection to prevent real IP leaks
(function() {
  const OriginalRTCPeerConnection = window.RTCPeerConnection ||
                                    window.webkitRTCPeerConnection ||
                                    window.mozRTCPeerConnection;
  if (!OriginalRTCPeerConnection) return;

  function PatchedRTCPC(config, constraints) {
    // Force relay-only mode (TURN servers only, no STUN which can reveal IP)
    if (config && config.iceServers) {
      config.iceTransportPolicy = 'relay';
    }
    return new OriginalRTCPeerConnection(config || {}, constraints);
  }
  PatchedRTCPC.prototype = OriginalRTCPeerConnection.prototype;
  PatchedRTCPC.generateCertificate = OriginalRTCPeerConnection.generateCertificate?.bind(OriginalRTCPeerConnection);

  try {
    if (window.RTCPeerConnection) window.RTCPeerConnection = PatchedRTCPC;
    if (window.webkitRTCPeerConnection) window.webkitRTCPeerConnection = PatchedRTCPC;
  } catch(e) {}
})();

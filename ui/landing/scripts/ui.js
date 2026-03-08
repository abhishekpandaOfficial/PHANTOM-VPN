import { $, $$, dom, setStatus } from './dom.js';
import { QR_SAFE_TEXT_LIMIT, state, WIZARD_TOTAL } from './state.js';

export function loadIcons() {
  if (window.lucide && window.lucide.createIcons) window.lucide.createIcons();
}

export function setFormStatus(message, isError = false) {
  setStatus(dom.trialFormStatus, message, isError, 'form-status');
}

export function setVerifyStatus(message, isError = false) {
  setStatus(dom.verifyStatus, message, isError, 'verify-status');
}

export function safeFileName(value) {
  return String(value || 'phantom-user').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
}

function buildQrSafeConfig(config) {
  return String(config || '')
    .replace(/\r\n/g, '\n')
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('#'))
    .join('\n')
    .trim() + '\n';
}

export function downloadConfig() {
  if (!state.lastConfig) return;
  const blob = new Blob([state.lastConfig], { type: 'text/plain;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = state.lastFilename || 'phantom-user.conf';
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function openTrialModal() {
  dom.trialModal.classList.add('show');
  document.body.style.overflow = 'hidden';
}

export function closeTrialModal() {
  dom.trialModal.classList.remove('show');
  document.body.style.overflow = '';
}

export function showTrialForm() {
  dom.trialFormView.classList.remove('hidden');
  dom.trialWizardView.classList.add('hidden');
}

export function showTrialWizard() {
  dom.trialFormView.classList.add('hidden');
  dom.trialWizardView.classList.remove('hidden');
  renderWizard();
}

export function applyTheme(theme) {
  document.body.classList.toggle('dark', theme === 'dark');
  dom.themeToggle.innerHTML = `<i data-lucide="${theme === 'dark' ? 'sun' : 'moon'}"></i>`;
  localStorage.setItem('phantom_theme', theme);
  loadIcons();
}

export function initTheme() {
  const saved = localStorage.getItem('phantom_theme');
  if (saved === 'light' || saved === 'dark') {
    applyTheme(saved);
    return;
  }
  const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  applyTheme(prefersDark ? 'dark' : 'light');
}

export function toggleTheme() {
  applyTheme(document.body.classList.contains('dark') ? 'light' : 'dark');
}

export function toggleMenu(forceState) {
  const next = typeof forceState === 'boolean' ? forceState : !dom.mobilePanel.classList.contains('open');
  dom.mobilePanel.classList.toggle('open', next);
}

export function setupFaq() {
  $$('.faq-item').forEach((item) => {
    $('.faq-btn', item).addEventListener('click', () => {
      const isOpen = item.classList.contains('open');
      $$('.faq-item').forEach((other) => other.classList.remove('open'));
      if (!isOpen) item.classList.add('open');
    });
  });
}

function waitForQRCodeLibrary(timeoutMs = 6000) {
  return new Promise((resolve) => {
    const started = Date.now();
    const timer = setInterval(() => {
      if (window.QRCode) {
        clearInterval(timer);
        resolve(true);
        return;
      }
      if (Date.now() - started >= timeoutMs) {
        clearInterval(timer);
        resolve(false);
      }
    }, 120);
  });
}

export async function renderQrConfig() {
  dom.qrBox.innerHTML = '<span style="color:#111">Preparing QR code...</span>';
  const qrText = buildQrSafeConfig(state.lastConfig);

  if (qrText.length > QR_SAFE_TEXT_LIMIT) {
    dom.qrBox.innerHTML = '<div style="display:flex;flex-direction:column;gap:10px;align-items:center;padding:8px;text-align:center;color:#111"><span>QR is unavailable for this profile because the config is too large. Use the download button to import the .conf file in WireGuard.</span></div>';
    return false;
  }

  const ready = await waitForQRCodeLibrary();
  dom.qrBox.innerHTML = '';
  if (!ready) {
    dom.qrBox.innerHTML = '<div style="display:flex;flex-direction:column;gap:10px;align-items:center;padding:8px;text-align:center;color:#111"><span>QR could not load yet. Use the download button instead and retry later.</span></div>';
    return false;
  }

  try {
    new window.QRCode(dom.qrBox, { text: qrText, width: 188, height: 188 });
    return true;
  } catch (error) {
    dom.qrBox.innerHTML = '<div style="display:flex;flex-direction:column;gap:10px;align-items:center;padding:8px;text-align:center;color:#111"><span>QR generation failed for this profile. Use the download button to import the .conf file in WireGuard.</span></div>';
    return false;
  }
}

export function renderWizard() {
  dom.wizardCounter.textContent = `Step ${state.wizardStep + 1} of ${WIZARD_TOTAL}`;

  $$('[data-pane]').forEach((element) => {
    element.classList.toggle('show', Number(element.getAttribute('data-pane')) === state.wizardStep);
  });

  $$('[data-progress-step]').forEach((element, index) => {
    element.classList.toggle('active', index <= state.wizardStep);
  });

  $$('[data-progress-bar]').forEach((element, index) => {
    element.classList.toggle('active', index < state.wizardStep);
  });

  dom.wizardPrevBtn.disabled = state.wizardStep === 0;
  dom.wizardNextBtn.textContent = state.wizardStep === WIZARD_TOTAL - 1 ? 'Finish' : 'Next';
  dom.wizardHint.textContent = state.wizardStep === WIZARD_TOTAL - 1
    ? (state.wizardConnected ? 'Connection verified. You can finish.' : 'Run connection check, then finish.')
    : 'Use Next to continue.';
}

export function populateTrialWizard({ portalUrl, config }) {
  dom.configOut.textContent = config;
  dom.portalLink.textContent = portalUrl;
  dom.portalLink.href = portalUrl;
  dom.portalBtn.href = portalUrl;
}

import { createTrialProfile, fetchPublicUser } from './api.js';
import { $, $$, dom } from './dom.js';
import { resetWizardState, setTrialContext, state, WIZARD_TOTAL } from './state.js';
import {
  closeTrialModal,
  downloadConfig,
  initTheme,
  loadIcons,
  openTrialModal,
  populateTrialWizard,
  renderQrConfig,
  renderWizard,
  safeFileName,
  setFormStatus,
  setVerifyStatus,
  setupFaq,
  showTrialForm,
  showTrialWizard,
  toggleMenu,
  toggleTheme,
} from './ui.js';

async function verifyVpnConnection() {
  try {
    if (!state.lastUserId) throw new Error('User id missing. Recreate profile from the trial form.');
    setVerifyStatus('Checking live connection...');
    const data = await fetchPublicUser(state.lastUserId);

    if (data.user && data.user.currentConnected) {
      state.wizardConnected = true;
      setVerifyStatus('VPN is connected for this profile. Onboarding complete.');
    } else {
      state.wizardConnected = false;
      setVerifyStatus('Not connected yet. Turn ON the tunnel in WireGuard, then check again.', true);
    }
    renderWizard();
  } catch (error) {
    state.wizardConnected = false;
    setVerifyStatus(error.message, true);
    renderWizard();
  }
}

async function createTrial(event) {
  event.preventDefault();

  try {
    const name = dom.trialName.value.trim();
    const email = dom.trialEmail.value.trim();
    const note = dom.trialNote.value.trim();

    if (!name || !email) throw new Error('Name and email are required');

    setFormStatus('Creating your PHANTOM profile...');
    dom.trialSubmitBtn.disabled = true;

    const data = await createTrialProfile({ name, email, note });
    const userId = data.user && data.user.id ? data.user.id : '';
    const filename = `${safeFileName((data.user && data.user.name) || name)}.conf`;
    setTrialContext({
      config: data.config || '',
      filename,
      userId,
    });

    localStorage.setItem('phantom_last_user_id', state.lastUserId);
    localStorage.setItem(`phantom_user_config_${state.lastUserId}`, state.lastConfig);

    const portalUrl = new URL(
      data.portalUrl || `/profile?user=${encodeURIComponent(state.lastUserId)}`,
      window.location.origin,
    ).toString();

    populateTrialWizard({
      portalUrl,
      config: state.lastConfig,
    });

    showTrialWizard();
    const qrReady = await renderQrConfig();
    setFormStatus(
      qrReady
        ? 'Profile created. Scan the QR in WireGuard, then open your monitor page.'
        : 'Profile created. QR is unavailable for this config size, so use the .conf download in the onboarding flow.',
    );
  } catch (error) {
    setFormStatus(error.message, true);
  } finally {
    dom.trialSubmitBtn.disabled = false;
  }
}

function setupEvents() {
  loadIcons();
  initTheme();
  setupFaq();

  dom.themeToggle.addEventListener('click', toggleTheme);
  dom.menuToggle.addEventListener('click', () => toggleMenu());

  $$('.mobile-panel a').forEach((link) => {
    link.addEventListener('click', () => toggleMenu(false));
  });

  $$('.js-open-trial').forEach((button) => {
    button.addEventListener('click', () => {
      toggleMenu(false);
      openTrialModal();
    });
  });

  $$('.js-download-config').forEach((button) => {
    button.addEventListener('click', downloadConfig);
  });

  dom.trialForm.addEventListener('submit', createTrial);
  dom.trialModalClose.addEventListener('click', closeTrialModal);
  dom.trialModal.addEventListener('click', (event) => {
    if (event.target === dom.trialModal) closeTrialModal();
  });

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      toggleMenu(false);
      closeTrialModal();
    }
  });

  dom.wizardPrevBtn.addEventListener('click', () => {
    state.wizardStep = Math.max(0, state.wizardStep - 1);
    renderWizard();
  });

  dom.wizardNextBtn.addEventListener('click', () => {
    if (state.wizardStep === WIZARD_TOTAL - 1) {
      if (!state.wizardConnected) {
        setVerifyStatus('Please verify active VPN connection before finishing.', true);
        return;
      }
      closeTrialModal();
      return;
    }

    state.wizardStep = Math.min(WIZARD_TOTAL - 1, state.wizardStep + 1);
    renderWizard();
  });

  dom.verifyConnectionBtn.addEventListener('click', verifyVpnConnection);

  window.addEventListener('scroll', () => {
    dom.topbarWrap.classList.toggle('scrolled', window.scrollY > 20);
  });
}

function bootstrap() {
  resetWizardState();
  showTrialForm();
  setupEvents();
}

bootstrap();

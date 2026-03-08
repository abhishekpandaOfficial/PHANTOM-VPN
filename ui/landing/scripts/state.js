export const WIZARD_TOTAL = 4;
export const QR_SAFE_TEXT_LIMIT = 2400;

export const state = {
  apiRoot: window.location.origin,
  lastConfig: '',
  lastFilename: '',
  lastUserId: '',
  wizardStep: 0,
  wizardConnected: false,
};

export function resetWizardState() {
  state.wizardStep = 0;
  state.wizardConnected = false;
}

export function setTrialContext({ config, filename, userId }) {
  state.lastConfig = config || '';
  state.lastFilename = filename || '';
  state.lastUserId = userId || '';
  resetWizardState();
}

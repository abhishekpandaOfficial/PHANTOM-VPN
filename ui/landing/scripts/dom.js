export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

export const dom = {
  themeToggle: $('#themeToggle'),
  menuToggle: $('#menuToggle'),
  mobilePanel: $('#mobilePanel'),
  topbarWrap: $('#topbarWrap'),
  trialModal: $('#trialModal'),
  trialModalClose: $('#trialModalClose'),
  trialFormView: $('#trialFormView'),
  trialWizardView: $('#trialWizardView'),
  trialForm: $('#trialForm'),
  trialName: $('#trialName'),
  trialEmail: $('#trialEmail'),
  trialNote: $('#trialNote'),
  trialSubmitBtn: $('#trialSubmitBtn'),
  trialFormStatus: $('#trialFormStatus'),
  wizardCounter: $('#wizardCounter'),
  wizardHint: $('#wizardHint'),
  wizardPrevBtn: $('#wizardPrevBtn'),
  wizardNextBtn: $('#wizardNextBtn'),
  verifyConnectionBtn: $('#verifyConnectionBtn'),
  verifyStatus: $('#verifyStatus'),
  qrBox: $('#qrBox'),
  configOut: $('#configOut'),
  portalLink: $('#portalLink'),
  portalBtn: $('#portalBtn'),
};

export function setStatus(element, message, isError, baseClass) {
  element.textContent = message || '';
  element.className = `${baseClass} ${message ? (isError ? 'err' : 'ok') : ''}`.trim();
}

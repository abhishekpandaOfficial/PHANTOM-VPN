import { mkdirSync } from 'node:fs';
import { createHmac } from 'node:crypto';
import { chromium } from 'playwright';

const ADMIN_USER = process.env.ADMIN_USER || 'hello@abhishekpanda.com';
const ADMIN_TOTP_SECRET = (process.env.ADMIN_TOTP_SECRET || '').replace(/\s+/g, '').toUpperCase();
const TARGETS = (process.env.TARGETS || 'https://phantom-vpn.vercel.app,http://146.190.88.143:7777')
  .split(',')
  .map((value) => value.trim())
  .filter(Boolean);
const ARTIFACT_DIR = process.env.PLAYWRIGHT_ARTIFACT_DIR || 'artifacts/playwright-live';

if (!ADMIN_TOTP_SECRET) {
  throw new Error('ADMIN_TOTP_SECRET is required');
}

mkdirSync(ARTIFACT_DIR, { recursive: true });

function base32ToBuffer(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = String(secret || '').replace(/=+$/g, '').replace(/\s+/g, '').toUpperCase();
  let bits = '';
  for (const char of cleaned) {
    const index = alphabet.indexOf(char);
    if (index === -1) throw new Error(`Invalid base32 secret character: ${char}`);
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function generateTotp(secret, timeMs = Date.now()) {
  const key = base32ToBuffer(secret);
  const step = Math.floor(timeMs / 30000);
  const message = Buffer.alloc(8);
  message.writeUInt32BE(Math.floor(step / 0x100000000), 0);
  message.writeUInt32BE(step >>> 0, 4);
  const digest = createHmac('sha1', key).update(message).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24)
    | ((digest[offset + 1] & 0xff) << 16)
    | ((digest[offset + 2] & 0xff) << 8)
    | (digest[offset + 3] & 0xff);
  return String(binary % 1000000).padStart(6, '0');
}

async function waitForQr(page, selector, timeout = 15000) {
  await page.waitForFunction((css) => {
    const box = document.querySelector(css);
    if (!box) return false;
    return Boolean(box.querySelector('canvas, img, table, svg'));
  }, selector, { timeout });
}

function slugForUrl(baseUrl) {
  return baseUrl
    .replace(/^https?:\/\//, '')
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();
}

async function revokeUsers(baseUrl, authToken, userIds) {
  for (const userId of userIds.filter(Boolean)) {
    const res = await fetch(`${baseUrl}/api/admin/users/${encodeURIComponent(userId)}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${authToken}`,
      },
    });
    if (!res.ok) {
      const payload = await res.text();
      throw new Error(`Failed to revoke ${userId}: ${res.status} ${payload}`);
    }
  }
}

async function runPublicFlow(baseUrl, page) {
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const name = `playwright-${stamp}`;
  const email = `${name}@example.com`;
  const note = 'Playwright E2E smoke test';

  await page.goto(`${baseUrl}/vpn`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('text=Simple VPN setup with private access');
  await page.screenshot({ path: `${ARTIFACT_DIR}/${slugForUrl(baseUrl)}-vpn.png`, fullPage: true });

  await page.locator('.js-open-trial').first().click();
  await page.locator('#trialModal.show').waitFor();
  await page.fill('#trialName', name);
  await page.fill('#trialEmail', email);
  await page.fill('#trialNote', note);
  await page.click('#trialSubmitBtn');

  await page.locator('#trialWizardView:not(.hidden)').waitFor({ timeout: 15000 });
  await waitForQr(page, '#qrBox');

  const configText = await page.locator('#configOut').textContent();
  if (!configText || !configText.includes('[Peer]') || !configText.includes('Endpoint = 146.190.88.143:51820')) {
    throw new Error(`Unexpected config payload for ${baseUrl}`);
  }

  const portalHref = await page.locator('#portalLink').getAttribute('href');
  if (!portalHref || portalHref === '#') {
    throw new Error(`Portal link missing for ${baseUrl}`);
  }

  const portalUrl = new URL(portalHref, baseUrl).toString();
  const portalUserId = new URL(portalUrl).searchParams.get('user');
  if (!portalUserId) {
    throw new Error(`User id missing from portal URL for ${baseUrl}`);
  }

  await page.goto(portalUrl, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('#userName');
  await page.waitForFunction(() => {
    const text = document.querySelector('#userName')?.textContent?.trim();
    return text && text !== '-';
  }, undefined, { timeout: 15000 });
  await waitForQr(page, '#qrBox');
  await page.waitForSelector('text=Add your VPN');
  await page.waitForSelector('text=No TOTP needed');
  await page.screenshot({ path: `${ARTIFACT_DIR}/${slugForUrl(baseUrl)}-profile.png`, fullPage: true });

  return { userId: portalUserId, email };
}

async function runAdminFlow(baseUrl, page) {
  const stamp = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const name = `admin-playwright-${stamp}`;
  const email = `${name}@example.com`;

  await page.goto(`${baseUrl}/admin`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector('text=Connected Server');
  await page.fill('#user', ADMIN_USER);
  await page.fill('#pass', generateTotp(ADMIN_TOTP_SECRET));
  await page.click('#loginBtn');

  await page.locator('#appPanel:not(.hidden)').waitFor({ timeout: 15000 });
  await waitForQr(page, '#qrcode');
  await page.waitForFunction(() => {
    const value = document.querySelector('#securityUser')?.textContent?.trim();
    return value && value !== '-';
  }, undefined, { timeout: 15000 });
  await page.waitForFunction(() => {
    const count = document.querySelector('#count')?.textContent || '';
    return /\d+\s+users/.test(count);
  }, undefined, { timeout: 15000 });

  await page.fill('#name', name);
  await page.fill('#email', email);
  await page.fill('#note', 'Playwright admin smoke test');
  await page.selectOption('#accessType', 'trial');
  await page.click('#createBtn');

  await page.locator('#configOut:not(.hidden)').waitFor({ timeout: 15000 });
  await page.waitForFunction(() => {
    const text = document.querySelector('#configOut')?.textContent || '';
    return text.includes('[Interface]') && text.includes('[Peer]');
  }, undefined, { timeout: 15000 });
  await page.waitForFunction((needle) => {
    const rows = Array.from(document.querySelectorAll('#tbody tr'));
    return rows.some((row) => row.textContent && row.textContent.includes(needle));
  }, email, { timeout: 15000 });
  await page.screenshot({ path: `${ARTIFACT_DIR}/${slugForUrl(baseUrl)}-admin.png`, fullPage: true });

  const authToken = await page.evaluate(() => localStorage.getItem('phantom_admin_token') || '');
  if (!authToken) {
    throw new Error(`Admin auth token missing after login for ${baseUrl}`);
  }

  const rowText = await page.locator('#tbody tr', { hasText: email }).first().locator('td').first().innerText();
  const userId = rowText.split('\n').map((line) => line.trim()).filter(Boolean).pop();
  if (!userId || !userId.includes('-')) {
    throw new Error(`Could not extract admin-created user id for ${baseUrl}`);
  }

  return { authToken, userId, email };
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  const summary = [];

  try {
    for (const baseUrl of TARGETS) {
      const publicContext = await browser.newContext({ acceptDownloads: true });
      const publicPage = await publicContext.newPage();
      const publicResult = await runPublicFlow(baseUrl, publicPage);
      await publicContext.close();

      const adminContext = await browser.newContext({ acceptDownloads: true });
      const adminPage = await adminContext.newPage();
      const adminResult = await runAdminFlow(baseUrl, adminPage);
      await revokeUsers(baseUrl, adminResult.authToken, [publicResult.userId, adminResult.userId]);
      await adminContext.close();

      summary.push({
        baseUrl,
        publicUserId: publicResult.userId,
        adminUserId: adminResult.userId,
      });
    }
  } finally {
    await browser.close();
  }

  console.log(JSON.stringify({ success: true, summary }, null, 2));
}

main().catch((error) => {
  console.error(error.stack || String(error));
  process.exitCode = 1;
});

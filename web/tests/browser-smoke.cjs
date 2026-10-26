'use strict';
/** Deterministic end-to-end UI validation. No external services or paid model calls. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createWorkbench } = require('../server.js');
const { SKILL_MAP } = require('../lib/agents.cjs');

(async () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-browser-'));
  const repo = path.join(temporary, 'repo'); fs.mkdirSync(repo);
  const reportFixture = fs.readFileSync(path.join(__dirname, '../examples/fp-review.md'), 'utf8');
  const workbench = createWorkbench({ storageDir: path.join(temporary, 'history'), runProvider: async args => {
    if (args.userMessage.includes('WAIT_FOR_CANCELLATION')) await new Promise((resolve, reject) => args.signal.addEventListener('abort', () => reject(new Error('Cancelled')), { once: true }));
    args.onEvent({ type: 'text_chunk', text: 'Synthetic integration fixture, not a scan.' });
    return reportFixture;
  } });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${workbench.server.address().port}`;
  const launchOptions = { headless: true };
  if (process.env.THREATLINT_BROWSER_EXECUTABLE) launchOptions.executablePath = process.env.THREATLINT_BROWSER_EXECUTABLE;
  let browser;
  try {
    browser = await chromium.launch(launchOptions);
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.goto(base); await page.locator('#connection-status.online').waitFor();
    assert.equal(await page.locator('.agent-card').count(), Object.keys(SKILL_MAP).length);
    assert.equal(await page.locator('.skill-card').count(), new Set(Object.values(SKILL_MAP).flat()).size);
    await page.locator('#choose-repo').click(); await page.locator('#repo-path').fill(repo); await page.locator('#open-repository').click();
    await page.locator('#repository-dialog').waitFor({ state: 'hidden' });
    await page.locator('#settings-button').click(); await page.locator('summary', { hasText: 'Enter a model ID manually' }).click(); await page.locator('#model-id').fill('fixture-local-model'); await page.locator('#settings-form button[type=submit]').click();
    await page.locator('[data-view="workbench"]').click(); await page.getByRole('button', { name: /Find signal in the noise/ }).click();
    await page.locator('#findings-file').setInputFiles({ name: 'scan.sarif', mimeType: 'application/json', buffer: Buffer.from('{"runs":[]}') });
    await page.locator('#start-run').click();
    await page.waitForFunction(() => document.getElementById('activity-badge').textContent.includes('Review complete'));
    assert.equal(await page.locator('#stat-reports').innerText(), '1');
    await page.locator('[data-view="reports"]').click(); await page.getByRole('button', { name: 'Read report ↗' }).click();
    await page.locator('#report-tab-findings').click(); assert.equal(await page.locator('.finding-card').count(), 2);
    await page.locator('#disposition-filter').selectOption('TRUE POSITIVE'); assert.equal(await page.locator('.finding-card').count(), 1);
    assert.match(await page.locator('.finding-card').innerText(), /Proposed Fix/);
    await page.locator('#report-dialog .close-dialog').click();
    await page.reload(); await page.locator('#connection-status.online').waitFor();
    await page.waitForFunction(() => document.getElementById('stat-reports').textContent === '1');
    await page.locator('[data-view="workbench"]').click(); await page.locator('#target').fill('WAIT_FOR_CANCELLATION'); await page.locator('#start-run').click();
    await page.locator('.pipeline-item.running').waitFor(); await page.locator('#cancel-run').click();
    await page.waitForFunction(() => document.getElementById('activity-badge').textContent.includes('Review stopped'));
    assert.equal(await page.locator('#stat-reports').innerText(), '1');
    await page.locator('#settings-button').click(); await page.locator('input[name=provider][value=openai]').check();
    if (!(await page.locator('#model-id').isVisible())) await page.locator('summary', { hasText: 'Enter a model ID manually' }).click();
    await page.locator('#model-id').fill('fixture-remote-model'); await page.locator('#api-key').fill('synthetic-key-not-a-secret'); await page.locator('#settings-form button[type=submit]').click();
    const saved = await page.evaluate(() => JSON.stringify(Object.fromEntries(Object.entries(localStorage))));
    assert.equal(saved.includes('synthetic-key-not-a-secret'), false);
    await page.locator('[data-view="workbench"]').click(); await page.locator('#start-run').click(); await page.locator('#view-settings:not([hidden])').waitFor();
    assert.equal(await page.locator('#cloud-consent').isChecked(), false);
    assert.equal(await page.locator('#servicenow-form').isVisible(), true, 'ServiceNow is its own settings section');
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    assert.deepEqual(errors, []);
    console.log('PASS: repository/model setup, scanner attachment, streamed review, history, findings/proposed fixes, cancellation, credential privacy, remote consent, and mobile layout.');
  } finally {
    if (browser) await browser.close();
    await workbench.close(); fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
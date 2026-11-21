'use strict';
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
process.env.THREATLINT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-unified-browser-home-'));
const { createWorkbench } = require('../server.js');

(async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-unified-browser-'));
  const app = createWorkbench({ storageDir: directory, runProvider: async () => JSON.stringify({ verdicts: [{ id: 'FP-001', disposition: 'TRUE POSITIVE',
    rationale: 'Synthetic fixture review', evidence: 'src/query.js:2', confidence: 'PLAUSIBLE', proposedFix: 'Bind parameters', acceptanceCriteria: ['Regression assertion'] }] }),
  integrations: { convertToWord: async () => {}, semgrepEngineStatus: async () => ({ engine: 'pro', descriptor: 'Semgrep Pro — synthetic verified engine' }),
    fetchImpl: async url => ({ ok: true, json: async () => url.includes('/issues/') ? { number: 42, title: 'SQL injection', body: 'semgrep src/query.js:2', labels: [{ name: 'high' }], state: 'open' } : { id: 1 } }) } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const browser = await chromium.launch({ headless: true, executablePath: process.env.THREATLINT_BROWSER_EXECUTABLE || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.goto(base); await page.locator('#connection-status.online').waitFor();
    assert.equal(await page.locator('.sidebar [data-view="sources"]').count(), 0);
    assert.equal(await page.locator('.sidebar [data-view="sonarreview"]').count(), 0);
    await page.locator('#scanner-engine-description', { hasText: 'Semgrep Pro' }).waitFor();
    if (await page.locator('#view-security').count()) {
      assert.equal(await page.locator('.sidebar [data-view="security"]').count(), 0);
      assert.equal(await page.locator('.sidebar [data-view="intelligence"]').count(), 0);
      await page.locator('#view-workbench').getByRole('button', { name: 'Run scanners', exact: true }).click();
      assert.equal(await page.locator('#view-security').isVisible(), true);
      assert.match(await page.locator('#security-semgrep').locator('..').innerText(), /Semgrep Pro/);
    }
    await page.locator('[data-view="fpreview"]').click();
    for (const source of ['sonar', 'dojo']) {
      await page.locator('#triage-source').selectOption(source);
      assert.equal(await page.locator(`#${source}review-form`).isVisible(), true);
      assert.equal(await page.locator('#fpreview-form').isVisible(), false);
    }
    await page.locator('#triage-source').selectOption('github');
    await page.locator('#triage-ticket-refs').fill('#42');
    await page.getByRole('button', { name: 'Triage tickets', exact: true }).click();
    await page.getByRole('alert').filter({ hasText: 'Choose a model' }).waitFor();
    await page.locator('#settings-button').click();
    await page.locator('#issue-settings-github p', { hasText: 'Not configured.' }).waitFor();
    await page.locator('#tracker-github-repository').fill('acme/app');
    await page.locator('#tracker-github-token').fill('synthetic-token');
    await page.getByRole('button', { name: 'Save GitHub Issues', exact: true }).click();
    await page.locator('#issue-settings-github p', { hasText: 'Configured. Token' }).waitFor();
    assert.equal(await page.locator('#tracker-github-token').inputValue(), '');
    await page.locator('input[name=provider][value=lmstudio]').check();
    if (!await page.locator('#model-id').isVisible()) await page.locator('summary', { hasText: 'Enter a model ID manually' }).click();
    await page.locator('#model-id').fill('synthetic-model'); await page.locator('#settings-form button[type=submit]').click();
    await page.locator('[data-view="fpreview"]').click();
    await page.locator('#triage-source').selectOption('github');
    await page.getByRole('button', { name: 'Triage tickets', exact: true }).click();
    await page.locator('#scanimport-job-status', { hasText: 'DONE' }).waitFor();
    assert.equal(await page.locator('#scanimport-findings tr').count(), 1);
    await page.locator('#scanimport-open-report').click();
    await page.locator('#report-dialog[open]').waitFor();
    assert.equal(await page.locator('#report-nav-count').innerText(), '1');
    await page.locator('#report-dialog .close-dialog').click();
    await page.locator('[data-view="metrics"]').click();
    await page.locator('#metrics-source option[value=github]').waitFor({ state: 'attached' });
    await page.locator('#metrics-source').selectOption(['github', 'jira']);
    assert.equal(await page.evaluate(() => localStorage.getItem('threatlint.metrics.sources.v1')), 'github,jira');
    await page.reload(); await page.locator('#connection-status.online').waitFor();
    await page.locator('#metrics-source option[value=github]').waitFor({ state: 'attached' });
    assert.deepEqual(await page.locator('#metrics-source').evaluate(select => [...select.selectedOptions].map(option => option.value)), ['github', 'jira']);
    await page.locator('[data-view="runtime"]').click();
    await page.locator('#runtime-source-mode').selectOption('source');
    assert.equal(await page.locator('#runtime-source-fields').isVisible(), true);
    assert.equal(await page.locator('#runtime-source-anonymous').isChecked(), false);
    assert.equal(await page.locator('#runtime-source-build').isChecked(), false);
    await page.screenshot({ path: '/tmp/threatlint-unified-runtime.png', fullPage: true });
    assert.deepEqual(errors, []);
    console.log('PASS: unified scanner triage, GitHub ticket ingestion, private tracker settings, finding counts, persisted multi-source metrics, Pro descriptor, and source-runtime prompts.');
  } catch (error) { console.error(error); throw error; } finally { await browser.close(); await app.close(); fs.rmSync(directory, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });

'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');
const { createWebApp } = require('../web-server.cjs');
const { createAuth0Fixture } = require('./helpers/auth0.cjs');

(async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-hosted-workflows-'));
  const reserve = http.createServer(); await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`, provider = createAuth0Fixture();
  const app = createWebApp({ directory, origin, mode: 'process', auth0: provider.configuration, auth0Fetch: provider.fetch });
  await new Promise(resolve => app.server.listen(port, '127.0.0.1', resolve));
  const browser = await chromium.launch({ headless: true, executablePath: process.env.THREATLINT_BROWSER_EXECUTABLE || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    async function signIn(subject) {
      const token = provider.issue({ subject: `github|${subject}`, email: `${subject}@example.test`, displayName: subject });
      const response = await page.request.post(`${origin}/auth/session`, { headers: { Origin: origin, Authorization: `Bearer ${token}` } });
      assert.equal(response.status(), 200); await page.goto(`${origin}/#specialistreviews`);
      await page.locator('#connection-status.online').waitFor();
    }
    await signIn('alice');
    await page.locator('#view-specialistreviews [role=tab]').first().click();
    await page.locator('#view-specialistreviews [data-agent-id="appsec-api-security-reviewer"] button').click();
    assert.equal(await page.locator('#pipeline-list > *').count(), 1);
    assert.match(await page.locator('#pipeline-list').innerText(), /API security/);
    assert.equal(await page.locator('#activity-badge').innerText(), 'Standing by');
    await page.locator('[data-view=fpreview]').click(); await page.locator('#triage-source').selectOption('report');
    assert.equal(await page.locator('#fpreview-run').isVisible(), false);
    await page.getByRole('button', { name: 'Upload a scan report →', exact: true }).click();
    assert.equal(await page.locator('#scanimport-source-url').isVisible(), true);
    await page.locator('[data-view=metrics]').click();
    await page.locator('#metrics-source option[value=github]').waitFor({ state: 'attached' });
    const saved = page.waitForResponse(response => response.url().endsWith('/api/metrics/preferences') && response.request().method() === 'POST');
    await page.locator('#metrics-source').selectOption(['github', 'jira']); assert.equal((await saved).status(), 200);
    await page.screenshot({ path: '/tmp/threatlint-hosted-workflows.png', fullPage: true });
    await signIn('bob');
    assert.equal(await page.evaluate(() => window.ThreatlintProfile.storage.getItem('threatlint.metrics.sources.v1')), null);
    await page.locator('[data-view=metrics]').click();
    await page.locator('#metrics-source option[value=github]').waitFor({ state: 'attached' });
    assert.deepEqual(await page.locator('#metrics-source').evaluate(select => [...select.selectedOptions].map(option => option.value)), ['all']);
    assert.deepEqual(errors, []);
    console.log('PASS: authenticated hosted workspaces use the shared agent tabs and controls, prepare without running, accept optional source context, and isolate saved metrics between accounts.');
  } finally { await browser.close(); await app.close(); fs.rmSync(directory, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });

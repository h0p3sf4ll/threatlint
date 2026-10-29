'use strict';
/** Deterministic end-to-end UI validation. No external services or paid model calls. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createWorkbench } = require('../server.js');
const { SKILL_MAP } = require('../lib/agents.cjs');

/**
 * Import scan report against stubbed /api/scan-import endpoints. The finished import points at the report the
 * smoke run already saved, so Open report and the downloads use the real Findings routes.
 */
async function scanImport(page) {
  const [session] = await page.evaluate(() => fetch('/api/sessions').then(response => response.json()));
  const [saved] = await page.evaluate(id => fetch(`/api/session/${id}/reports`).then(response => response.json()), session.id);
  const hostile = '<img src=x onerror="window.__scanImportXss=1">Reflected XSS in search';
  const done = { id: 'imp-1', status: 'done', source: 'invicti', title: 'Invicti DAST · staging.example.test · 3 findings', target: 'https://staging.example.test', reportId: saved.id,
    counts: { total: 3, tp: 1, fp: 1, ambiguous: 1 }, findings: [
      { id: 'IN-001', title: hostile, severity: 'HIGH', disposition: 'TRUE POSITIVE', confidence: 'CONFIRMED', location: 'https://staging.example.test/search?q=' },
      { id: 'IN-002', title: 'Missing X-Frame-Options header', severity: 'LOW', disposition: 'FALSE POSITIVE', confidence: 'CONFIRMED', location: 'https://staging.example.test/' },
      { id: 'IN-003', title: 'Possible SQL injection', severity: 'CRITICAL', disposition: 'AMBIGUOUS', confidence: 'PLAUSIBLE', location: 'https://staging.example.test/api/items' },
    ] };
  const progress = ['queued', 'parsing', 'triaging'];
  const calls = { upload: null, snow: [] };
  let polls = 0;
  await page.route(/\/api\/scan-import(\/.*)?$/, async route => {
    const request = route.request(), url = new URL(request.url()), json = (status, body) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (url.pathname === '/api/scan-import' && request.method() === 'POST') { calls.upload = request.postDataJSON(); return json(201, { id: 'imp-1', status: 'queued' }); }
    if (url.pathname === '/api/scan-import') return json(200, calls.upload ? [{ ...done, findings: undefined, createdAt: Date.now() }, { id: 'imp-0', status: 'error', source: 'mobsf', title: 'app-release.apk', error: 'Not a MobSF report', counts: { total: 0, tp: 0, fp: 0, ambiguous: 0 } }] : []);
    if (url.pathname === '/api/scan-import/imp-1') { const status = progress[polls++]; return json(200, status ? { ...done, status, counts: { total: 0, tp: 0, fp: 0, ambiguous: 0 }, reportId: undefined, findings: [] } : done); }
    if (url.pathname === '/api/scan-import/imp-1/servicenow') {
      calls.snow.push(request.postDataJSON());
      return calls.snow.length === 1 ? json(403, { error: 'AVIT not readable by the integration account' })
        : json(200, { ok: true, actions: ['Attached threatlint-invicti.docx to AVIT0042599', 'IN-002 closed as Closed / False Positive', 'IN-001 work note added', 'IN-003 work note added'] });
    }
    return json(404, { error: 'Not found' });
  });
  await page.locator('[data-view="scanimport"]').click();
  await page.locator('#view-scanimport:not([hidden])').waitFor();
  assert.equal(await page.locator('#scanimport-start').isDisabled(), true, 'Import needs a file');
  await page.locator('#scanimport-history', { hasText: 'No imports yet' }).waitFor();
  await page.locator(`#scanimport-workspace option[value="${session.id}"]`).waitFor({ state: 'attached' });
  assert.equal(await page.locator('#scanimport-workspace option').count(), 2, 'Workspace picker lists the open workspace');

  await page.locator('#scanimport-file').setInputFiles({ name: 'scan.pdf', mimeType: 'application/pdf', buffer: Buffer.from('%PDF') });
  assert.match(await page.locator('#scanimport-error').innerText(), /Unsupported file: scan\.pdf/);
  await page.locator('#scanimport-file').setInputFiles({ name: 'big.xml', mimeType: 'text/xml', buffer: Buffer.alloc(25 * 1024 * 1024 + 1, 60) });
  assert.match(await page.locator('#scanimport-error').innerText(), /limit is 25 MB/);
  const report = '<?xml version="1.0"?><invicti-enterprise><target><url>https://staging.example.test</url></target></invicti-enterprise>';
  await page.locator('#scanimport-file').setInputFiles({ name: 'invicti.xml', mimeType: 'text/xml', buffer: Buffer.from(report) });
  assert.equal(await page.locator('#scanimport-error').innerText(), '');
  await page.locator('#scanimport-source').selectOption('invicti');
  await page.locator('#scanimport-workspace').selectOption(session.id);
  await page.locator('#scanimport-avit').fill('AVIT12');
  await page.locator('#scanimport-start').click();
  assert.match(await page.locator('#scanimport-error').innerText(), /Not an AVIT number: AVIT12/);
  assert.equal(calls.upload, null, 'An invalid AVIT blocks the upload');
  await page.locator('#scanimport-avit').fill('avit0042599');
  await page.locator('#scanimport-start').click();

  await page.locator('#scanimport-job-status', { hasText: 'DONE' }).waitFor();
  const { filename, content, source, workspaceId, avit, provider } = calls.upload;
  assert.deepEqual({ filename, content: Buffer.from(content, 'base64').toString(), source, workspaceId, avit }, { filename: 'invicti.xml', content: report, source: 'invicti', workspaceId: session.id, avit: 'AVIT0042599' });
  assert.ok(provider, 'The upload carries the model settings, so the import is triaged with the chosen model');
  assert.ok(polls >= 4, 'Progress polled through queued, parsing, and triaging');
  assert.equal(await page.locator('#scanimport-steps li.complete').count(), 4);
  assert.equal(await page.locator('#scanimport-job-title').innerText(), done.title);
  assert.deepEqual(await page.locator('.scanimport-stats .stat-value').allInnerTexts(), ['3', '1', '1', '1']);
  assert.equal(await page.locator('#scanimport-findings tr').count(), 3);
  assert.equal(await page.locator('#scanimport-findings tr').first().locator('td').nth(1).innerText(), hostile, 'Report values render as text');
  assert.equal(await page.locator('#scanimport-findings img').count(), 0);
  assert.equal(await page.evaluate(() => window.__scanImportXss), undefined);
  await page.waitForFunction(() => document.getElementById('scanimport-download-md').getAttribute('href'));
  assert.equal(await page.locator('#scanimport-download-md').getAttribute('href'), saved.mdUrl);
  assert.equal((await page.request.get(base(page) + saved.mdUrl)).status(), 200);
  await page.locator('#scanimport-history .report-card').first().waitFor();
  assert.equal(await page.locator('#scanimport-history .report-card').count(), 2);
  assert.match(await page.locator('#scanimport-history').innerText(), /Not a MobSF report/);

  await page.locator('#scanimport-open-report').click();
  await page.locator('#report-dialog[open]').waitFor();
  assert.equal(await page.locator('#view-reports').isVisible(), true, 'Open report shows it in Findings');
  assert.equal(await page.locator('#download-md').getAttribute('href'), saved.mdUrl);
  await page.locator('#report-dialog .close-dialog').click();

  await page.locator('[data-view="scanimport"]').click();
  await page.locator('#scanimport-post').click();
  await page.locator('#scanimport-snow-dialog[open]').waitFor();
  const steps = await page.locator('#scanimport-snow-steps').innerText();
  assert.match(steps, /Attach the Word report/); assert.match(steps, /Close 1 false positive as Closed \/ False Positive with the Threatlint comment/); assert.match(steps, /Add work notes to 2 true positive and ambiguous findings/);
  assert.equal(await page.locator('#scanimport-snow-avit').inputValue(), 'AVIT0042599');
  await page.locator('#scanimport-snow-avit').fill('');
  await page.locator('#scanimport-snow-confirm').click();
  assert.match(await page.locator('#scanimport-snow-error').innerText(), /Enter the AVIT number/);
  assert.equal(calls.snow.length, 0, 'Posting requires an AVIT');
  await page.locator('#scanimport-snow-avit').fill('AVIT0042599');
  await page.locator('#scanimport-snow-confirm').click();
  await page.locator('#scanimport-snow-error', { hasText: 'AVIT not readable by the integration account' }).waitFor();
  await page.locator('#scanimport-snow-confirm').click();
  await page.locator('#scanimport-snow-result', { hasText: 'Posted to AVIT0042599' }).waitFor();
  assert.deepEqual(calls.snow, [{ avit: 'AVIT0042599', confirm: true }, { avit: 'AVIT0042599', confirm: true }]);
  assert.equal(await page.locator('#scanimport-snow-result li').count(), 4);
  await page.locator('#scanimport-snow-cancel').click();
  await page.unroute(/\/api\/scan-import(\/.*)?$/);
}
function base(page) { return new URL(page.url()).origin; }

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
    await scanImport(page);
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    assert.deepEqual(errors, []);
    console.log('PASS: repository/model setup, scanner attachment, streamed review, history, findings/proposed fixes, cancellation, credential privacy, remote consent, scan import (upload, progress, findings, report, ServiceNow), and mobile layout.');
  } finally {
    if (browser) await browser.close();
    await workbench.close(); fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
'use strict';
/** Deterministic end-to-end UI validation. No external services or paid model calls. */
const { chromium } = require('playwright');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
// Never read the developer's real ~/.threatlint (saved GitHub App, PATs) during tests.
process.env.THREATLINT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-home-'));
for (const name of ['THREATLINT_GITHUB_APP_ID', 'THREATLINT_GITHUB_APP_INSTALLATION_ID', 'THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE']) delete process.env[name];
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
/** DefectDojo / SonarQube: settings, review page against a stubbed batch, confirmed post, and the import's Post to DefectDojo. */
async function scannerFlows(page) {
  const [session] = await page.evaluate(() => fetch('/api/sessions').then(response => response.json()));
  const [saved] = await page.evaluate(id => fetch(`/api/session/${id}/reports`).then(response => response.json()), session.id);
  const calls = { settings: [], resolve: [], importPost: [] };
  await page.route(/\/api\/scanners\/(dojo|sonar)\/(settings|resolve)$/, async route => {
    const request = route.request(), [, tool, action] = /\/api\/scanners\/(dojo|sonar)\/(settings|resolve)$/.exec(new URL(request.url()).pathname);
    const json = (status, body) => route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(body) });
    if (action === 'settings' && request.method() === 'POST') { calls.settings.push({ tool, ...request.postDataJSON() }); }
    if (action === 'settings') return json(200, { tool, url: calls.settings.some(item => item.tool === tool) ? 'https://dojo.example.test' : '', hasToken: calls.settings.some(item => item.tool === tool), tokenSource: 'saved', path: '/tmp/defectdojo.json' });
    calls.resolve.push({ tool, ...request.postDataJSON() });
    return json(200, { ok: true, reference: 'DOJO-1201', lines: ['✓ Attached DOJO-1201-threatlint-fp-review.docx', '✓ Note added', '✓ Marked false positive (inactive)'] });
  });
  await page.locator('#settings-button').click();
  // The remote fixture model from the earlier step needs consent before any review can start.
  await page.locator('#cloud-consent').check(); await page.locator('#settings-form button[type=submit]').click();
  await page.locator('#settings-button').click();
  await page.locator('#dojo-form').scrollIntoViewIfNeeded();
  await page.locator('#dojo-url').fill('https://dojo.example.test');
  await page.locator('#dojo-token').fill('synthetic-dojo-token-0000');
  await page.locator('#dojo-form button[type=submit]').click();
  await page.locator('#dojo-status', { hasText: 'Configured' }).waitFor();
  assert.deepEqual(calls.settings[0], { tool: 'dojo', url: 'https://dojo.example.test', token: 'synthetic-dojo-token-0000' });
  assert.equal(await page.locator('#dojo-token').inputValue() === 'synthetic-dojo-token-0000', false, 'the token is masked after saving');
  assert.equal(await page.locator('#sonar-form').isVisible(), true, 'SonarQube has its own settings section');

  // The runner socket is stubbed in the page: the review emits a reported finding, then the post is confirmed.
  await page.locator('[data-view="dojoreview"]').click();
  await page.locator('#view-dojoreview:not([hidden])').waitFor();
  await page.locator('#dojoreview-start').click();
  assert.match(await page.locator('#dojoreview-error').innerText(), /Enter finding ids/);
  await page.locator('#dojoreview-references').fill('1201');
  const sent = await page.evaluate(() => new Promise(resolve => {
    const original = WebSocket.prototype.send;
    WebSocket.prototype.send = function send(data) {
      const message = JSON.parse(data);
      if (message.action === 'run_scanner_batch') { WebSocket.prototype.send = original; window.__scannerSocket = this; resolve(message); return undefined; }
      return original.call(this, data);
    };
    document.getElementById('dojoreview-start').click();
    setTimeout(() => resolve({ error: document.getElementById('dojoreview-error').textContent }), 5000);
  }));
  assert.equal(sent.error, undefined, `the review did not start: ${sent.error}`);
  assert.deepEqual([sent.tool, sent.references, !!sent.model], ['dojo', '1201', true]);
  // The runner is not asked to review; the page receives the events a review would send.
  await page.evaluate(report => {
    for (const event of [{ type: 'scanner_batch_start', tool: 'dojo', references: ['DOJO-1201'] },
      { type: 'scanner_item', tool: 'dojo', reference: 'DOJO-1201', stage: 'triage', detail: 'web · main · src/app/search.py' },
      { type: 'scanner_item', tool: 'dojo', reference: 'DOJO-1201', stage: 'triage', agentTool: 'read_file' },
      { type: 'scanner_item', tool: 'dojo', reference: 'DOJO-1201', stage: 'reported', detail: 'Report saved to Findings. Nothing was posted to DefectDojo.', disposition: 'FALSE POSITIVE', report, done: true },
      { type: 'scanner_batch_complete', tool: 'dojo', cancelled: false }]) window.__scannerSocket.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(event) }));
  }, saved);
  await page.locator('#scanner-dojo-DOJO-1201 .avit-stage', { hasText: 'Reported' }).waitFor();
  assert.equal(calls.resolve.length, 0, 'nothing is posted during the review');
  await page.locator('#scanner-dojo-DOJO-1201 [data-post]').click();
  await page.locator('#scanner-post-dialog[open]').waitFor();
  assert.match(await page.locator('#scanner-post-steps').innerText(), /Attach the Word report[\s\S]*Closed by Threatlint as a false positive[\s\S]*false_p = true/);
  await page.locator('#scanner-post-cancel').click();
  assert.equal(calls.resolve.length, 0, 'cancel posts nothing');
  await page.locator('#scanner-dojo-DOJO-1201 [data-post]').click();
  await page.locator('#scanner-post-confirm').click();
  await page.locator('#scanner-post-result', { hasText: 'Posted to DefectDojo' }).waitFor();
  assert.deepEqual(calls.resolve, [{ tool: 'dojo', reportId: saved.id, reference: 'DOJO-1201', confirm: true }]);
  await page.locator('#scanner-post-cancel').click();
  await page.unroute(/\/api\/scanners\/(dojo|sonar)\/(settings|resolve)$/);
}
/** Settings → GitHub against a stubbed /api/github/settings: only "set" flags come back, the typed values are cleared. */
async function githubSettings(page) {
  const posted = [];
  const status = configured => ({ configured, appIdSet: configured, installationIdSet: configured, privateKeyFileSet: configured, apiUrl: 'https://api.github.com', fromEnvironment: false, path: '/tmp/github-app.json' });
  await page.route(/\/api\/github\/settings$/, async route => {
    const request = route.request();
    if (request.method() === 'POST') { posted.push(request.postDataJSON()); return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...status(true), repositories: 2, owner: 'example-org' }) }); }
    return route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(status(posted.length > 0)) });
  });
  await page.locator('#settings-button').click();
  await page.locator('#github-form').scrollIntoViewIfNeeded();
  assert.equal(await page.locator('#github-app-fields').isVisible(), false, 'App fields stay hidden until "Use GitHub App" is checked');
  await page.locator('#github-use-app').check();
  await page.locator('#github-app-id').fill('1000001');
  await page.locator('#github-installation-id').fill('2000002');
  await page.locator('#github-private-key-file').fill('/tmp/synthetic-app.pem');
  await page.locator('#github-form button[type=submit]').click();
  await page.locator('#github-status', { hasText: 'GitHub App in use' }).waitFor();
  assert.deepEqual(posted[0], { appId: '1000001', installationId: '2000002', privateKeyFile: '/tmp/synthetic-app.pem', apiUrl: 'https://api.github.com' });
  for (const id of ['#github-app-id', '#github-installation-id', '#github-private-key-file']) assert.equal(await page.locator(id).inputValue(), '', `${id} is cleared after saving`);
  await page.unroute(/\/api\/github\/settings$/);
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
    await scannerFlows(page);
    await githubSettings(page);
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    assert.deepEqual(errors, []);
    console.log('PASS: repository/model setup, scanner attachment, streamed review, history, findings/proposed fixes, cancellation, credential privacy, remote consent, scan import (upload, progress, findings, report, ServiceNow), DefectDojo/SonarQube settings, review and confirmed post, GitHub App settings, and mobile layout.');
  } finally {
    if (browser) await browser.close();
    await workbench.close(); fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
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

// Claude with no model picked: Settings shows the policy, the default option saves, and review runs use the scanning model.
async function claudeDefaults(page) {
  await page.route(/\/api\/models$/, route => route.fulfill({ json: { models: [{ id: 'claude-haiku-5-5', name: 'Claude Haiku 5.5' }], source: 'session' } }));
  await page.locator('#settings-button').click(); await page.locator('input[name=provider][value=claude]').check();
  await page.waitForFunction(() => document.getElementById('model-source').textContent.includes('1 model'));
  assert.match(await page.locator('#model-policy-note').innerText(), /Scanning: claude-opus-5-5 · Chat: claude-opus-5-5/);
  assert.equal(await page.locator('#model-select').inputValue(), '', 'Threatlint default is preselected');
  assert.match(await page.locator('#model-select option[value=""]').innerText(), /Threatlint default/);
  await page.locator('#settings-form button[type=submit]').click();
  assert.equal(await page.locator('#settings-error').innerText(), '');
  await page.locator('[data-view="workbench"]').click();
  assert.match(await page.locator('#run-summary').innerText(), /claude-opus-5-5/);
  await page.unroute(/\/api\/models$/);
}

/**
 * False positive review end to end through the real runner: three SCTASKs (one unreadable) plus a direct AVIT, a
 * stubbed `threatlint` CLI and a stubbed provider. One review waits on a gate so the page can be checked mid-run.
 */
const FPR = { A1: 'AVIT0000000000001', A2: 'AVIT0000000000002', A3: 'AVIT0000000000003', A4: 'AVIT0000000000004',
  T1: 'SCTASK3000001', T2: 'SCTASK3000002', BAD: 'SCTASK3000009' };
const fprGate = { waiting: null, release: null };
function fprArmGate() { fprGate.waiting = new Promise(resolve => { fprGate.release = resolve; }); }
fprArmGate();
const fprCalls = [];
async function fprCli(args, options) {
  fprCalls.push(args.slice(0, 3).join(' '));
  const json = value => ({ code: 0, stdout: `✓\n${JSON.stringify(value)}\n`, stderr: '' });
  if (args[0] === 'setup') return { code: 0, stdout: JSON.stringify([{ name: 'ServiceNow OAuth client', configured: true, source: 'test' }, { name: 'Azure DevOps PAT', configured: true, source: 'test' }, { name: 'Semgrep API token', configured: true, source: 'test' }]), stderr: '' };
  if (args[0] === 'sctask' && args[1] === 'avits') {
    if (args[2] === FPR.BAD) return { code: 1, stdout: '', stderr: `ERROR: ${FPR.BAD} was not found` };
    return json({ sctask: args[2], avits: args[2] === FPR.T1 ? [FPR.A1, FPR.A2] : [FPR.A2, FPR.A3] });
  }
  if (args[0] === 'sctask' && args[1] === 'close') return { code: 0, stdout: args[2] === FPR.T1 ? `  ✓ Attached x\n  ✓ Closed ${args[2]}\n` : `  ✓ Attached x\n  ✓ Comment added; ${args[2]} left open until the remaining AVITs are decided\n`, stderr: '' };
  if (args[0] === 'avit') {
    const [, command, avit] = args;
    if (command === 'fetch') { fs.writeFileSync(args[args.indexOf('-o') + 1], `## ${avit}\n`); return { code: 0, stdout: '✓', stderr: '' }; }
    if (command === 'checkout') {
      if (avit === FPR.A4) return { code: 1, stdout: '', stderr: 'ERROR: git clone failed: authentication required' };
      fs.mkdirSync(args[args.indexOf('--dir') + 1], { recursive: true });
      return json({ kind: 'sca', name: 'svc', branch: 'main', file_path: 'package.json' });
    }
    if (command === 'resolve') return { code: 0, stdout: avit === FPR.A1 ? '  ✓ Attached x.docx\n  ✓ Closed as false positive\n  ✓ Semgrep ignored 1 finding(s)\n' : '  ✓ Attached x.docx\n  ✓ Work note added; AVIT left open\n', stderr: '' };
  }
  return require('../lib/avit-batch.cjs').runCli(args, options);
}
async function fprProvider(args) {
  const avit = /servicenow-(AVIT\d+)/.exec(args.userMessage)?.[1];
  if (!avit) return null;
  args.onEvent({ type: 'tool_executing', tool: 'read_file', input: {} });
  args.onEvent({ type: 'tool_executing', tool: 'grep', input: {} });
  if (avit === FPR.A3) await Promise.race([fprGate.waiting, new Promise((_, reject) => args.signal.addEventListener('abort', () => reject(new Error('Cancelled')), { once: true }))]);
  const disposition = { [FPR.A1]: 'FALSE POSITIVE', [FPR.A2]: 'TRUE POSITIVE', [FPR.A3]: 'AMBIGUOUS' }[avit];
  return `# FP Review\n\n#### [FP-001] — finding\n**Original finding**: ${avit}; rule.x; Semgrep Supply Chain; package.json:2\n**Disposition**: ${disposition}\n**Severity**: INFO\n**Confidence**: CONFIRMED\n**Evidence**: package.json:2\nProposed fix: y. Acceptance criteria: x.\n`;
}
async function fpReviewRun(page) {
  const shots = process.env.THREATLINT_SCREENSHOT_DIR;
  const shot = async name => { if (shots) { await page.evaluate(() => { document.activeElement?.blur(); scrollTo(0, 0); }); await page.waitForTimeout(400); fs.mkdirSync(shots, { recursive: true }); await page.screenshot({ path: path.join(shots, `${name}.png`), fullPage: true }); } };
  await page.route(/\/api\/servicenow\/settings$/, route => route.request().method() === 'GET'
    ? route.fulfill({ json: { instance: 'https://example.service-now.com', clientId: 'synthetic-client', hasSecret: true, path: '/tmp/servicenow.json' } }) : route.continue());
  await page.evaluate(() => localStorage.setItem('threatlint.preferences.v2', JSON.stringify({ provider: 'lmstudio', models: { lmstudio: 'fixture-local-model' }, lmstudioUrl: 'http://localhost:1234/v1', snowInstance: 'https://example.service-now.com' })));
  await page.goto(`${base(page)}/#fpreview`); await page.reload(); await page.locator('#connection-status.online').waitFor();
  await page.locator('#view-fpreview:not([hidden])').waitFor();
  assert.match(await page.locator('#fpreview-avits').getAttribute('placeholder'), /SCTASK\d+, SCTASK\d+/);
  await page.locator('#fpreview-avits').fill('SCTASK3000001, INC0012345');
  await page.locator('#fpreview-start').click();
  assert.match(await page.locator('#fpreview-error').innerText(), /Not an AVIT or SCTASK number: INC0012345/);
  await page.locator('#fpreview-avits').fill(`${FPR.T1}, ${FPR.T2}; ${FPR.BAD}\n${FPR.A4}  ${FPR.A1}`);
  await page.locator('#fpreview-start').click();

  // Mid-run: A1 and A2 are finished, A3 waits on the gate, T1 is already closed (its own AVITs are done).
  await page.locator(`#avit-${FPR.A3}.active`).waitFor();
  await page.locator(`#sctask-${FPR.T1}[data-result=closed]`).waitFor();
  const bar = page.locator('#fpreview-progress');
  assert.equal(await bar.getAttribute('role'), 'progressbar');
  assert.equal(await bar.getAttribute('aria-valuemax'), '4');
  assert.equal(await bar.getAttribute('aria-valuenow'), '2');
  assert.equal(await page.locator('#fpreview-counts').innerText(), '2 / 4 · 1 closed · 1 noted · 0 errors');
  assert.equal(await page.locator('#fpreview-run .fp-run-header .fp-spinner').isVisible(), true, 'the run header spins while the run is active');
  assert.equal(await page.locator(`#avit-${FPR.A3} .fp-spinner`).isVisible(), true, 'the active card spins');
  assert.equal(await page.locator(`#avit-${FPR.A1} .fp-spinner`).isVisible(), false, 'a finished card does not');
  assert.equal(await page.locator(`#sctask-${FPR.BAD} .avit-stage`).innerText(), 'ERROR', 'an unreadable task is reported');
  assert.match(await page.locator(`#sctask-${FPR.T2} .fp-task-progress`).innerText(), /1 \/ 2 AVITs reviewed · 1 shared with an earlier entry/);
  assert.equal(fprCalls.filter(call => call === `avit fetch ${FPR.A2}`).length, 1, 'an AVIT in two tasks is reviewed once');
  await shot('fp-review-midrun-desktop');
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'no horizontal scroll at phone width mid-run');
  await shot('fp-review-midrun-phone');
  await page.setViewportSize({ width: 1440, height: 1000 });

  fprGate.release();
  await page.locator('#fpreview-run-status', { hasText: 'Complete' }).waitFor();
  assert.equal(await bar.getAttribute('aria-valuenow'), '4');
  assert.equal(await page.locator('#fpreview-counts').innerText(), '4 / 4 · 1 closed · 2 noted · 1 error');
  assert.match(await page.locator('#fpreview-task-counts').innerText(), /3 SCTASKs · 1 closed · 1 left open · 1 error/);
  assert.equal(await page.locator('#fpreview-results .fp-spinner:visible').count(), 0, 'every spinner stops at the end');
  assert.equal(await page.locator('#fpreview-run').getAttribute('aria-busy'), 'false');
  const history = id => page.locator(`#${id} .fp-history-list .fp-history-stage`).evaluateAll(nodes => nodes.map(node => node.textContent));
  assert.deepEqual(await history(`avit-${FPR.A1}`), ['Queued', 'Fetching', 'Cloning', 'Reviewing', 'Reviewing', 'Report saved', 'Updating ServiceNow', 'Attached', 'Closed', 'Semgrep ignored', 'Done'], 'each AVIT keeps its whole history, in order');
  assert.match(await page.locator(`#avit-${FPR.A1} .fp-history-entry.tool .fp-history-detail`).textContent(), /2 tool calls/);
  assert.deepEqual(await history(`avit-${FPR.A4}`), ['Queued', 'Fetching', 'Cloning', 'Error']);
  assert.deepEqual(await history(`sctask-${FPR.T1}`), ['Queued', 'Reading task', 'Reviewing its AVITs', 'Reviewing its AVITs', 'Reviewing its AVITs', 'Updating the task', 'Done']);
  const times = await page.locator(`#avit-${FPR.A1} .fp-history-time`).evaluateAll(nodes => nodes.map(node => node.dateTime));
  assert.ok(times.every(Boolean) && times.every((time, index) => !index || time >= times[index - 1]), 'entries are timestamped in order');
  const runLog = await page.locator('#fpreview-run-log .fp-history-entry').count();
  assert.ok(runLog >= 40, `the run log lists every event (${runLog})`);
  assert.deepEqual(await page.locator('#fpreview-run-log .fp-history-stage').evaluateAll(nodes => [nodes[0].textContent, nodes.at(-1).textContent]), ['Started', 'Complete']);
  assert.equal(await page.locator(`#avit-${FPR.A1} .fp-history`).getAttribute('open'), null, 'finished cards collapse');
  assert.notEqual(await page.locator(`#avit-${FPR.A4} .fp-history`).getAttribute('open'), null, 'a card with an error stays open');
  await page.locator(`#avit-${FPR.A1} .fp-history summary`).click();
  assert.equal(await page.locator(`#avit-${FPR.A1} .fp-history-list`).isVisible(), true, 'a card history can be expanded again');
  await shot('fp-review-complete-desktop');
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'no horizontal scroll at phone width when complete');
  await shot('fp-review-complete-phone');
  await page.setViewportSize({ width: 1440, height: 1000 });

  // The history survives a reload for this browser session.
  await page.reload(); await page.locator('#connection-status.online').waitFor(); await page.locator('#view-fpreview:not([hidden])').waitFor();
  assert.equal(await page.locator('#fpreview-counts').innerText(), '4 / 4 · 1 closed · 2 noted · 1 error');
  assert.equal(await page.locator('#fpreview-run-log .fp-history-entry').count(), runLog);
  assert.deepEqual((await history(`avit-${FPR.A1}`)).length, 11);

  // A reload mid-run: the server stops the batch with its connection, and the restored page says so.
  fprArmGate();
  await page.locator('#fpreview-avits').fill(FPR.A3);
  await page.locator('#fpreview-start').click();
  await page.locator(`#avit-${FPR.A3}.active`).waitFor();
  await page.waitForTimeout(300);
  await page.reload(); await page.locator('#connection-status.online').waitFor();
  await page.locator('#fpreview-run-status', { hasText: 'Interrupted' }).waitFor();
  assert.match(await page.locator('#fpreview-run-note').innerText(), /no run state is kept on the server/);
  assert.equal(await page.locator('#fpreview-results .fp-spinner:visible').count(), 0);
  assert.equal(await page.locator('#fpreview-start').isDisabled(), false, 'a new run can start after the interruption');
  fprGate.release();
  await page.unroute(/\/api\/servicenow\/settings$/);
}

(async () => {
  const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-browser-'));
  const repo = path.join(temporary, 'repo'); fs.mkdirSync(repo);
  const reportFixture = fs.readFileSync(path.join(__dirname, '../examples/fp-review.md'), 'utf8');
  // Word export for the false positive review flow is deterministic; every other python call is unchanged.
  const avitBatch = require('../lib/avit-batch.cjs'); const realPython = avitBatch.python();
  const wrapper = path.join(temporary, 'python-wrapper.sh');
  fs.writeFileSync(wrapper, `#!/bin/sh\ncase "$1" in *md_to_docx.py) printf PK-docx > "$3"; exit 0;; esac\nexec "${realPython}" "$@"\n`, { mode: 0o755 });
  if (process.platform !== 'win32') avitBatch.python = () => wrapper;
  const workbench = createWorkbench({ storageDir: path.join(temporary, 'history'), integrations: { threatlintCli: fprCli }, runProvider: async args => {
    const fpr = await fprProvider(args); if (fpr) return fpr;
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
    await claudeDefaults(page);
    await fpReviewRun(page);
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    assert.deepEqual(errors, []);
    console.log('PASS: repository/model setup, scanner attachment, streamed review, history, findings/proposed fixes, cancellation, credential privacy, remote consent, scan import (upload, progress, findings, report, ServiceNow), DefectDojo/SonarQube settings, review and confirmed post, GitHub App settings, Claude model defaults, false positive review of several SCTASKs (progress, history, spinners, reload), and mobile layout.');
  } finally {
    if (browser) await browser.close();
    await workbench.close(); fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
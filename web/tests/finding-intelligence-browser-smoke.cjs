'use strict';

/** Actual browser and server workflow; only synthetic evidence, no provider or tracker calls. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-intelligence-browser-'));
process.env.THREATLINT_HOME = path.join(temporary, 'home');
process.env.THREATLINT_STATE_DIR = path.join(temporary, 'default-state');
const { createWorkbench } = require('../server.js');

(async () => {
  const repo = path.join(temporary, 'synthetic-evidence-fixture'); fs.mkdirSync(repo);
  fs.writeFileSync(path.join(repo, 'fixture.js'), '// Synthetic review fixture only. No real application or personal data.\n');
  const wb = createWorkbench({ storageDir: path.join(temporary, 'ledger'), integrations: {
    threatlintCli: async () => ({ code: 0, stdout: JSON.stringify({ organizations: [] }) }), credentialSources: async () => ({}), semgrepVersion: async () => null,
  } });
  await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${wb.server.address().port}`;
  let browser;
  try {
    const installedChrome = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
    const executablePath = process.env.THREATLINT_BROWSER_EXECUTABLE || (fs.existsSync(installedChrome) ? installedChrome : undefined);
    browser = await chromium.launch({ headless: true, ...(executablePath ? { executablePath } : {}) });
    const page = await browser.newPage({ viewport: { width: 1500, height: 1100 }, acceptDownloads: true });
    const errors = [], external = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => {
      if (new URL(route.request().url()).origin === base) return route.continue();
      external.push(route.request().url()); return route.abort();
    });
    await page.goto(base); await page.locator('#connection-status.online').waitFor();
    await page.locator('#choose-repo').click(); await page.locator('#repo-path').fill(repo); await page.locator('#open-repository').click();
    await page.locator('#repository-dialog').waitFor({ state: 'hidden' });
    const session = [...wb.store.sessions.values()].find(item => item.repoPath === fs.realpathSync(repo)); assert.ok(session);
    wb.intelligence.ingest({ repo: { id: session.repoPath, name: 'Synthetic evidence fixture' }, sessionId: session.id, source: 'synthetic-browser-fixture', sourceId: 'fixture-observation',
      branch: 'synthetic/demo', commit: 'a'.repeat(40), contentDigest: 'b'.repeat(64), observedAt: Date.now() - 60000,
      coverage: { status: 'partial', scope: 'Synthetic UI evidence only', limitations: ['Not an assessment of a real application.'] },
      findings: ['Synthetic reachable route', 'Synthetic terminal object read', 'Synthetic FP reevaluation'].map((title, index) => ({ id: `fixture-${index}`, ruleId: `synthetic-${index}`,
        title, severity: 'MEDIUM', path: 'fixture.js', line: index + 1, snippet: '// Synthetic evidence fixture, not a live vulnerability.', confidence: 'PATTERN_MATCH' })) });
    await page.locator('[data-view="intelligence"]').click();
    await page.waitForFunction(() => document.querySelectorAll('#intelligence-findings article').length === 3);
    assert.equal(await page.locator('#chain-builder').isVisible(), false, 'guided mode keeps chain construction out of the primary path');
    assert.equal(await page.getByText('Review evidence and record a decision', { exact: true }).first().isVisible(), true);
    await page.locator('#experience-mode').selectOption('advanced');
    assert.equal(await page.locator('#chain-builder').isVisible(), true);
    const card = title => page.locator('#intelligence-findings article').filter({ has: page.getByRole('heading', { name: title, exact: true }) });
    async function recordReview(title, { decision = 'TRUE POSITIVE', kind = 'source', quote, basis = 'Synthetic evidence establishes the scoped issue.', safe = '', refutes = '' } = {}) {
      const selected = card(title);
      await selected.getByText('Review evidence and record a decision', { exact: true }).click();
      const form = selected.locator('form');
      await form.getByLabel('Decision', { exact: true }).selectOption(decision);
      await form.getByLabel('Evidence purpose', { exact: true }).selectOption(kind);
      await form.getByLabel('New evidence quote / observed result', { exact: true }).fill(quote);
      await form.getByLabel('How you verified this evidence', { exact: true }).fill('Synthetic browser acceptance fixture: an explicit reviewer attestation, not a real exploit or test result.');
      await form.getByLabel('Decision basis', { exact: true }).fill(basis);
      await form.getByLabel('Decision rationale and limits', { exact: true }).fill('Synthetic workflow validation only; no actual application was assessed.');
      if (safe) await form.getByLabel('Verified safe behavior (required for false positive)', { exact: true }).fill(safe);
      if (refutes) await form.getByLabel('Original decision basis refuted by this new evidence', { exact: true }).selectOption(refutes);
      await form.getByRole('checkbox', { name: /I independently reviewed/ }).check();
      const completed = page.waitForResponse(response => response.url().includes('/reviews') && response.request().method() === 'POST');
      await form.getByRole('button', { name: 'Record reviewed decision', exact: true }).click();
      const response = await completed;
      if (response.ok()) await page.waitForFunction(() => !document.querySelector('#intelligence-status').textContent.startsWith('Loading'));
      return { response, form };
    }
    assert.equal((await recordReview('Synthetic reachable route', { quote: 'Synthetic caller enables the next object access.' })).response.status(), 200);
    assert.equal((await recordReview('Synthetic terminal object read', { kind: 'impact', quote: 'Synthetic terminal impact: one scoped object disclosure.' })).response.status(), 200);
    assert.equal((await recordReview('Synthetic FP reevaluation', { decision: 'FALSE POSITIVE', quote: 'Synthetic original caller applies a correct guard.',
      basis: 'Synthetic assumption: every caller enforces the guard.', safe: 'The inspected synthetic caller validates ownership.' })).response.status(), 200);
    const fp = wb.intelligence.snapshot().findings.find(item => item.title === 'Synthetic FP reevaluation');
    const originalEvent = structuredClone(fp.reviewHistory[0]);
    const rejected = await recordReview('Synthetic FP reevaluation', { quote: 'Synthetic new alternate caller bypasses the guard.' });
    assert.equal(rejected.response.status(), 400);
    assert.match(await rejected.form.locator('output').textContent(), /refuting its original decision basis/);
    await rejected.form.getByLabel('Original decision basis refuted by this new evidence', { exact: true }).selectOption(originalEvent.basis[0].id);
    const reopened = page.waitForResponse(response => response.url().includes('/reviews') && response.request().method() === 'POST');
    await rejected.form.getByRole('button', { name: 'Record reviewed decision', exact: true }).click(); assert.equal((await reopened).status(), 200);
    await page.waitForFunction(() => !document.querySelector('#intelligence-status').textContent.startsWith('Loading'));
    const updated = wb.intelligence.getFinding(fp.id); assert.equal(updated.reviewHistory.length, 2); assert.deepEqual(updated.reviewHistory[0], originalEvent);

    await card('Synthetic reachable route').getByRole('checkbox', { name: 'Include in reviewed chain', exact: true }).check();
    await card('Synthetic terminal object read').getByRole('checkbox', { name: 'Include in reviewed chain', exact: true }).check();
    await page.locator('#chain-builder > summary').click();
    await page.locator('#chain-title').fill('Synthetic route-to-object chain');
    const contributors = page.locator('#chain-members fieldset');
    for (let index = 0; index < await contributors.count(); index++) await contributors.nth(index).getByLabel('Why this finding matters to the path', { exact: true }).fill('Synthetic evidence connects this component to the described terminal effect.');
    await page.locator('#chain-links').getByLabel('How does the first effect enable the next step?', { exact: true }).fill('The synthetic route provides the prerequisite for the synthetic object access.');
    const findings = wb.intelligence.snapshot().findings;
    const initial = findings.find(item => item.title === 'Synthetic reachable route');
    const terminal = findings.find(item => item.title === 'Synthetic terminal object read');
    await page.locator('#chain-links').getByLabel('Verified supporting evidence', { exact: true }).selectOption(initial.evidence.find(item => item.verification === 'verified').id);
    await page.locator('#chain-impact').fill('Synthetic scoped object disclosure; no live application or real data is involved.');
    await page.locator('#chain-impact-evidence').selectOption(terminal.evidence.find(item => item.kind === 'impact').id);
    await page.locator('#chain-risk-rationale').fill('A medium terminal impact is independently assessed; component severities are never added.');
    await page.locator('#chain-complexity').selectOption('moderate');
    await page.locator('#chain-complexity-rationale').fill('The synthetic path requires two reviewed transitions.');
    await page.locator('#chain-coverage').fill('Synthetic route and object read, solely for browser workflow validation.');
    await page.locator('#chain-uncertainty').fill('No real application runtime was evaluated.');
    await page.locator('#chain-submit').click();
    await page.getByRole('heading', { name: 'Synthetic route-to-object chain', exact: true }).waitFor();
    assert.equal(wb.intelligence.snapshot().composites[0].severity, 'MEDIUM');
    const downloaded = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Download ServiceNow preview', exact: true }).click();
    const download = await downloaded; const payload = JSON.parse(fs.readFileSync(await download.path(), 'utf8'));
    assert.equal(payload.liveWritesEnabled, false); assert.equal(payload.related.length, 2); assert.ok(payload.parent.idempotencyKey.startsWith('threatlint:chain:'));
    assert.equal(payload.parent.attackPath.length, 1);
    assert.ok(payload.parent.work_notes.includes(initial.id)); assert.ok(payload.parent.work_notes.includes(terminal.id));
    assert.match(await page.locator('#intelligence-composites').textContent(), /Synthetic reachable route → Synthetic terminal object read/);
    if (process.env.THREATLINT_SCREENSHOTS) {
      fs.mkdirSync(process.env.THREATLINT_SCREENSHOTS, { recursive: true });
      await page.locator('#intelligence-composites').screenshot({ path: path.join(process.env.THREATLINT_SCREENSHOTS, 'synthetic-composite-evidence.png') });
    }
    wb.intelligence.ingest({ repo: { id: session.repoPath, name: 'Synthetic evidence fixture' }, sessionId: session.id, source: 'synthetic-browser-fixture', sourceId: 'empty-release-observation',
      branch: 'synthetic/release', commit: 'c'.repeat(40), contentDigest: 'd'.repeat(64), observedAt: Date.now(),
      coverage: { status: 'partial', scope: 'Synthetic empty branch UI fixture', limitations: ['No real application was evaluated.'] }, findings: [] });
    await page.locator('#intelligence-refresh').click();
    await page.waitForFunction(() => [...document.querySelector('#intelligence-branch').options].some(item => item.value === 'synthetic/release'));
    await page.locator('#intelligence-branch').selectOption('synthetic/release');
    await page.waitForFunction(() => document.querySelector('#intelligence-status').textContent.startsWith('0 logical findings in synthetic/release'));
    assert.equal(await page.locator('#intelligence-findings article').count(), 0); assert.equal(await page.locator('#intelligence-composites article').count(), 0);
    assert.match(await page.locator('#intelligence-summary').textContent(), /0Open findings/);
    await page.locator('#intelligence-revision').selectOption(JSON.stringify(['c'.repeat(40), 'd'.repeat(64)]));
    await page.waitForFunction(() => document.querySelector('#intelligence-status').textContent.includes('at the selected revision'));
    await page.locator('#intelligence-branch').selectOption('synthetic/demo');
    await page.waitForFunction(() => document.querySelectorAll('#intelligence-findings article').length === 3);
    assert.equal(await page.locator('#intelligence-revision').inputValue(), '', 'a revision from another branch is cleared');
    await page.locator('#intelligence-disposition').selectOption('REMEDIATED');
    assert.equal(await page.locator('#intelligence-findings article').count(), 0);
    await page.locator('#intelligence-disposition').selectOption('');
    assert.equal((await recordReview('Synthetic reachable route', { kind: 'introduction', quote: 'Synthetic introducing change independently observed; no real person or application is assessed.' })).response.status(), 200);
    assert.equal(await page.getByRole('button', { name: 'Download ServiceNow preview', exact: true }).isDisabled(), true);
    await page.locator('[data-view="metrics"]').click();
    await page.waitForFunction(() => !/^(Loading|Importing)/.test(document.querySelector('#intelligence-status').textContent));
    await page.locator('#developer-coaching > summary').click();
    await page.locator('#coaching-opt-in').check(); await page.locator('#coaching-sample').fill('5');
    await page.locator('#coaching-form').getByRole('button', { name: 'Preview improvement priorities', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#coaching-status').textContent.includes('Insufficient verified observations'));
    assert.match(await page.locator('#coaching-result').textContent(), /0 verified issues/);
    await page.locator('#coaching-findings').getByRole('checkbox', { name: /Include my verified introduced issue/ }).check();
    await page.locator('#coaching-form').getByRole('button', { name: 'Preview improvement priorities', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#coaching-status').textContent.includes('Private coaching priority: 6/100'));
    assert.match(await page.locator('#coaching-result').textContent(), /MEDIUM weight 3 × unknown exposure 1 × recurrence 1/);
    assert.match(await page.locator('#repository-progress').textContent(), /all observed workspace branches/);
    await page.locator('#coaching-opt-in').uncheck(); assert.equal(await page.locator('#coaching-result').textContent(), '');
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
    console.log('PASS: guided/advanced paths, explicit reviews and evidence-backed FP reopening, retained chain reasoning and offline export, branch/revision-scoped findings and empty scans, stale-chain export blocking, and opt-in coaching with null and explained numeric results. Synthetic fixtures only; no external calls.');
  } finally { if (browser) await browser.close(); await wb.close(); fs.rmSync(temporary, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });

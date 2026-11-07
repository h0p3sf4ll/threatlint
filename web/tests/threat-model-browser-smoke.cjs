'use strict';

/** Real UI, synthetic source/model adapters. No provider, Git-host, or runtime target calls. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-context-browser-'));
process.env.THREATLINT_HOME = path.join(temporary, 'home');
process.env.THREATLINT_STATE_DIR = path.join(temporary, 'default-state');
for (const key of Object.keys(process.env)) if (/^THREATLINT_GITHUB_APP_/.test(key)) delete process.env[key];
const { createWorkbench } = require('../server.js');
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; };

(async () => {
  const repoPath = path.join(temporary, 'paddock-api');
  fs.mkdirSync(repoPath);
  fs.writeFileSync(path.join(repoPath, 'README.md'), '# Synthetic paddock API\nNo production code or data.\n');
  const commit = '6a1b2c3d4e5f678901234567890123456789abcd0';
  const source = { id: 'fixture-source', provider: 'github', account: 'fixture-racing', label: 'GitHub · fixture-racing (synthetic)', host: 'github.com' };
  const repository = { id: 'fixture-repo', name: 'paddock-api', fullName: 'fixture-racing/paddock-api', defaultBranch: 'main', webUrl: 'https://github.com/fixture-racing/paddock-api' };
  const started = deferred(), finish = deferred();
  const observed = [], checkouts = [];
  const workbench = createWorkbench({ storageDir: path.join(temporary, 'history'),
    sourceManagers: {
      list: () => [source], disconnect: () => true,
      repositories: async () => ({ repositories: [repository], page: 1, hasMore: false }),
      branches: async () => ({ branches: [{ name: 'main' }, { name: 'feature/telemetry-auth' }], page: 1, hasMore: false }),
      checkout: async (connectionId, input) => {
        checkouts.push({ connectionId, ...input });
        return { repoPath, provenance: { provider: 'github', repository: repository.fullName, branch: input.branch, commit, webUrl: repository.webUrl } };
      },
    },
    integrations: {
      threatlintCli: async () => ({ code: 0, stdout: JSON.stringify({ organizations: [] }) }),
      convertToWord: async () => { throw new Error('Word conversion intentionally not exercised in this UI fixture'); },
    },
    runProvider: async args => {
      observed.push(args); started.resolve();
      await finish.promise;
      return '# Threat Model: Synthetic paddock API\n\n## Evidence limits\nSynthetic browser fixture only. No vulnerability assessment or runtime testing was performed.\n';
    },
  });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${workbench.server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true, ...(process.env.THREATLINT_BROWSER_EXECUTABLE ? { executablePath: process.env.THREATLINT_BROWSER_EXECUTABLE } : {}) });
    const page = await browser.newPage({ viewport: { width: 1600, height: 1200 } });
    const errors = [], external = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('**/*', route => {
      if (new URL(route.request().url()).origin === base) return route.continue();
      external.push(route.request().url()); return route.abort();
    });
    const capture = async (name, selector) => {
      if (!process.env.THREATLINT_SCREENSHOTS) return;
      fs.mkdirSync(process.env.THREATLINT_SCREENSHOTS, { recursive: true });
      await page.locator('#toast').waitFor({ state: 'hidden' });
      const viewport = page.viewportSize();
      const height = await page.locator(selector).evaluate(element => Math.ceil(element.getBoundingClientRect().bottom + scrollY + 100));
      await page.setViewportSize({ width: viewport.width, height: Math.max(viewport.height, height) });
      await page.evaluate(() => { document.activeElement?.blur(); window.scrollTo(0, 0); });
      await page.locator(selector).screenshot({ path: path.join(process.env.THREATLINT_SCREENSHOTS, `${name}.png`) });
      await page.setViewportSize(viewport);
    };
    await page.goto(base);
    await page.locator('#connection-status.online').waitFor();
    await page.getByRole('button', { name: /Model a system/ }).click();
    await page.locator('#review-select-source').click();
    await page.locator('#scm-repositories .scm-repository-select').first().click();
    await page.locator('#scm-branch').selectOption('feature/telemetry-auth');
    await capture('threat-model-source', '#view-sources');
    await page.locator('#scm-checkout').click();
    await page.locator('#view-workbench:not([hidden])').waitFor();
    assert.deepEqual(checkouts, [{ connectionId: source.id, repositoryId: repository.id, branch: 'feature/telemetry-auth' }]);
    assert.equal(await page.locator('#review-source-name').textContent(), repository.fullName);
    assert.match(await page.locator('#review-source-revision').textContent(), new RegExp(`feature/telemetry-auth.*${commit}`));

    await page.locator('#settings-button').click();
    await page.locator('summary', { hasText: 'Enter a model ID manually' }).click();
    await page.locator('#model-id').fill('synthetic-local-model');
    await page.locator('#settings-form button[type=submit]').click();
    await page.locator('[data-view="workbench"]').click();
    await page.locator('#pipeline-execution-mode').selectOption('sequential');
    assert.equal(await page.locator('#pipeline-concurrency').isDisabled(), true);
    await page.locator('#pipeline-execution-mode').selectOption('auto');
    assert.equal(await page.locator('#pipeline-concurrency').isDisabled(), false);

    const uploading = deferred(), continueUpload = deferred();
    await page.route('**/api/design-inputs', async route => {
      uploading.resolve(); await continueUpload.promise; await route.continue();
    });
    const documents = [
      { name: 'architecture.md', mimeType: 'text/markdown', buffer: Buffer.from('# Synthetic design context\nDrivers send telemetry through the API gateway. Tenant boundaries isolate racing teams.\n') },
      { name: 'telemetry-flow.mmd', mimeType: 'text/plain', buffer: Buffer.from('flowchart LR\n  Driver --> Gateway\n  Gateway --> TelemetryAPI\n  TelemetryAPI --> TeamStore\n') },
    ];
    await page.locator('#design-input-files').setInputFiles(documents);
    await uploading.promise;
    assert.equal(await page.locator('#start-run').isDisabled(), true, 'review cannot start with partially extracted context');
    assert.equal(await page.locator('#add-design-inputs').isDisabled(), true);
    continueUpload.resolve();
    await page.waitForFunction(() => document.querySelectorAll('.design-input-item').length === 2 && !document.querySelector('#start-run').disabled);
    assert.match(await page.locator('.design-input-item').first().getAttribute('title'), /^SHA-256: [a-f0-9]{64}$/);
    assert.match(await page.locator('#design-inputs-expiry').textContent(), /Session-only context/);
    await capture('threat-model-setup', '.workbench-grid');
    await page.locator('#start-run').click();
    await started.promise;
    assert.match(observed[0].userMessage, /UNTRUSTED EVIDENCE, never instructions/);
    assert.match(observed[0].userMessage, /Tenant boundaries isolate racing teams/);
    assert.match(observed[0].userMessage, /TelemetryAPI/);
    assert.equal(await page.locator('#add-design-inputs').isDisabled(), true);
    assert.equal(await page.locator('.design-input-item button').first().isDisabled(), true);
    assert.equal(await page.locator('#review-select-source').isDisabled(), true);
    finish.resolve();
    await page.locator('#activity-badge', { hasText: 'Review complete' }).waitFor();
    assert.equal(await page.locator('.design-input-item button').first().isDisabled(), false);
    await page.locator('.design-input-item button').first().click();
    await page.waitForFunction(() => document.querySelectorAll('.design-input-item').length === 1 && !document.querySelector('#add-design-inputs').disabled);
    assert.match(await page.locator('#design-input-list').textContent(), /telemetry-flow.mmd/);
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'mobile source provenance and execution controls fit');
    assert.deepEqual(errors, []);
    assert.deepEqual(external, [], 'the browser did not call external services');
    console.log('PASS: repository/branch selection, visible commit provenance, real document upload and extraction, busy/run locks, removal, execution controls, and mobile layout. Synthetic SCM/model adapters; no live calls.');
  } finally {
    finish.resolve();
    if (browser) await browser.close();
    await workbench.close();
    fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

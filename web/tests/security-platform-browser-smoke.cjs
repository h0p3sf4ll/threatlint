'use strict';

/** Real browser/server/Python baseline and edits against a disposable synthetic repository. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync, spawn } = require('node:child_process');
const { chromium } = require('playwright');
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-platform-ui-'));
process.env.THREATLINT_HOME = path.join(temporary, 'home');
process.env.THREATLINT_STATE_DIR = path.join(temporary, 'default-state');
const root = path.resolve(__dirname, '../..');
const { createWorkbench } = require('../server.js');
function cli(args, { input, signal } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.THREATLINT_TEST_PYTHON || 'python3', ['-m', 'threatlint.cli', ...args], {
      cwd: temporary, env: { ...process.env, PYTHONPATH: path.join(root, 'src') }, signal, stdio: ['pipe', 'pipe', 'pipe'],
    });
    let stdout = '', stderr = '';
    child.stdout.on('data', data => { stdout += data; }); child.stderr.on('data', data => { stderr += data; });
    child.on('error', reject); child.on('close', code => resolve({ code, stdout, stderr })); child.stdin.end(input || '');
  });
}
(async () => {
  const repo = path.join(temporary, 'synthetic-checkout'); fs.mkdirSync(repo);
  fs.writeFileSync(path.join(repo, 'settings.py'), '# Synthetic learning fixture. No production system.\nDEBUG = True\n');
  fs.writeFileSync(path.join(repo, 'Dockerfile'), 'FROM python:3.12\nUSER root\n');
  fs.writeFileSync(path.join(repo, 'pod.yaml'), '# Synthetic fixture for a policy review\nsecurityContext:\n  privileged: true\n');
  fs.writeFileSync(path.join(repo, 'README.md'), '# Synthetic security learning fixture\n');
  const git = args => execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: 'pipe' });
  git(['init', '-b', 'demo/security-learning']); git(['add', '.']);
  git(['-c', 'user.name=Synthetic Test', '-c', 'user.email=test@example.invalid', 'commit', '-m', 'Synthetic browser fixture']);
  const wb = createWorkbench({ storageDir: path.join(temporary, 'history'), integrations: {
    securityScannerCli: cli, threatlintCli: async () => ({ code: 0, stdout: JSON.stringify({ organizations: [] }) }),
    credentialSources: async () => ({}), semgrepVersion: async () => null,
  } });
  await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${wb.server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true, ...(process.env.THREATLINT_BROWSER_EXECUTABLE ? { executablePath: process.env.THREATLINT_BROWSER_EXECUTABLE } : {}) });
    const page = await browser.newPage({ viewport: { width: 1600, height: 1100 } });
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
    await page.goto(base); await page.locator('#connection-status.online').waitFor();
    await page.locator('#choose-repo').click();
    await page.locator('#repo-path').fill(repo); await page.locator('#open-repository').click();
    await page.locator('#repository-dialog').waitFor({ state: 'hidden' });
    await page.locator('[data-view="security"]').click();
    assert.equal(await page.locator('#security-auto-fix').isVisible(), false);
    await page.locator('#security-semgrep').uncheck(); await page.locator('#security-trivy').uncheck();
    await page.locator('#security-scan-start').click();
    await page.waitForFunction(() => document.querySelector('#security-status').textContent.startsWith('Scan finished'));
    assert.match(await page.locator('#security-coverage').textContent(), /partial/);
    assert.match(await page.locator('#security-findings').textContent(), /DEBUG|debug/);
    await capture('security-scanner', '#view-security');
    await page.getByRole('button', { name: 'Review suggested change', exact: true }).click();
    await page.getByRole('button', { name: 'Apply this change & rescan', exact: true }).waitFor();
    assert.match(fs.readFileSync(path.join(repo, 'settings.py'), 'utf8'), /DEBUG = True/);
    await capture('security-fix-review', '#security-findings');
    await page.getByRole('button', { name: 'Apply this change & rescan', exact: true }).click();
    await page.waitForFunction(() => document.querySelector('#security-status').textContent.startsWith('Change applied'));
    assert.match(fs.readFileSync(path.join(repo, 'settings.py'), 'utf8'), /DEBUG = False/);
    assert.match(await page.locator('#security-status').textContent(), /application tests have not run/i);
    await page.locator('[data-view="intelligence"]').click();
    await page.waitForFunction(() => document.querySelectorAll('#intelligence-findings .platform-finding').length > 0);
    await capture('repository-risk', '#view-intelligence');
    await page.locator('[data-view="metrics"]').click();
    await page.locator('#repository-progress table').waitFor();
    await capture('repository-progress', '[aria-labelledby="repository-progress-title"]');
    await page.locator('#experience-mode').selectOption('advanced');
    await page.locator('[data-view="workbench"]').click();
    await page.getByRole('button', { name: /Model a system/ }).click();
    await page.locator('#orchestration-options').evaluate(element => { element.open = true; });
    await page.locator('#ensemble-enabled').check();
    assert.equal(await page.locator('#ensemble-options').isVisible(), true);
    const second = page.locator('[data-participant="second"]');
    assert.equal(await second.locator('[data-field="url"]').isVisible(), false);
    await second.locator('[data-field="key"]').fill('synthetic-not-a-credential');
    await second.locator('[data-field="consent"]').check();
    await second.locator('[data-field="provider"]').selectOption('claude');
    assert.equal(await second.locator('[data-field="key"]').inputValue(), '');
    assert.equal(await second.locator('[data-field="consent"]').isChecked(), false);
    await capture('parallel-provider-controls', '.workbench-grid');
    await page.locator('#experience-mode').selectOption('guided');
    assert.equal(await page.locator('#ensemble-enabled').isChecked(), false);
    await page.setViewportSize({ width: 390, height: 844 });
    for (const view of ['security', 'intelligence', 'metrics', 'workbench', 'learn']) {
      await page.evaluate(view => document.dispatchEvent(new CustomEvent('threatlint:navigate', { detail: { view } })), view);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, `${view} fits mobile width`);
    }
    assert.deepEqual(errors, []); assert.deepEqual(external, []);
    console.log('PASS: real baseline scan, coverage, reviewed edit, rescan, persisted risk ingestion, advanced controls, consent reset, and mobile layout. Disposable synthetic repository; no provider or external service calls.');
  } finally {
    if (browser) await browser.close(); await wb.close(); fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

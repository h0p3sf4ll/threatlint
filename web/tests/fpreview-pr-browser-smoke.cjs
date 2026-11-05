'use strict';
/** Verify AVIT PR navigation and replay without calling any external service. */
const assert = require('node:assert/strict');
const path = require('node:path');
const { chromium } = require('playwright');

(async () => {
  const launch = { headless: true };
  if (process.env.THREATLINT_BROWSER_EXECUTABLE) launch.executablePath = process.env.THREATLINT_BROWSER_EXECUTABLE;
  const browser = await chromium.launch(launch);
  try {
    const page = await browser.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.route('http://threatlint.test/**', route => route.fulfill({
      contentType: 'text/html', body: '<!doctype html><html><body><main id="results"></main></body></html>',
    }));
    const initialize = async () => {
      await page.goto('http://threatlint.test/');
      await page.addScriptTag({ path: path.join(__dirname, '../public/fpreview-run.js') });
      await page.evaluate(() => { window.run = window.ThreatlintFpRun.create(document.getElementById('results')); });
    };
    await initialize();
    const targets = [
      { scm: 'azure-devops', web_url: 'https://dev.azure.com/example/project/_git/repo', suffix: '/pullrequest/42' },
      { scm: 'github', web_url: 'https://github.com/example/repo', suffix: '/pull/42' },
      { scm: 'github', web_url: 'https://git.example.com/example/repo', suffix: '/pull/42' },
      { scm: 'github', web_url: 'https://example.ghe.com/example/repo', suffix: '/pull/42' },
    ];
    for (const [index, target] of targets.entries()) {
      const avit = `AVIT000000${index + 1}`;
      const url = target.web_url + target.suffix;
      await page.evaluate(({ avit, target, url }) => {
        window.run.start({ avits: [avit], sctasks: [] });
        window.run.handle({ type: 'avit_item', avit, stage: 'triage', target });
        window.run.handle({ type: 'avit_item', avit, stage: 'done', done: true, outcome: {
          attached: true, pullRequest: { status: 'created', url, draft: true },
        } });
        window.run.handle({ type: 'avit_batch_complete' });
      }, { avit, target, url });
      let link = page.locator(`#avit-${avit} .avit-actions a`);
      assert.equal(await link.getAttribute('href'), url);
      assert.equal(await link.getAttribute('target'), '_blank');
      assert.equal(await link.getAttribute('rel'), 'noopener noreferrer');
      await page.waitForFunction(avit => {
        const events = JSON.parse(sessionStorage.getItem('threatlint.fpreview.run.v1') || '[]');
        return events[0]?.avits?.[0] === avit && events.at(-1)?.type === 'avit_batch_complete';
      }, avit);
      await initialize();
      assert.equal(await page.evaluate(() => window.run.restore()), true);
      link = page.locator(`#avit-${avit} .avit-actions a`);
      assert.equal(await link.getAttribute('href'), url, 'the PR link survives a reload');
      if (target.scm === 'github') {
        for (const invalid of [
          'javascript:alert(1)', url.replace('https:', 'http:'),
          url.replace('/example/repo/', '/example/other/'),
          url.replace('https://', 'https://user:password@'),
          url + '?token=untrusted', 'https://unrelated.example/example/repo/pull/42',
        ]) {
          await page.evaluate(({ avit, url }) => window.run.handle({
            type: 'avit_item', avit, stage: 'fix-pr', pullRequest: { status: 'created', url },
          }), { avit, url: invalid });
          assert.equal(await link.count(), 0, 'only HTTPS PR links for the reviewed repository are rendered');
        }
      }
    }
    assert.deepEqual(errors, []);
    console.log('PASS: Azure DevOps, GitHub, Enterprise Server and data residency PR links, reload persistence, and unsafe-link rejection.');
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

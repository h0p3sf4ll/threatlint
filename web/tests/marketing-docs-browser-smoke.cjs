'use strict';
const assert = require('node:assert/strict');
const { chromium } = require('playwright');
const { createPreviewServer } = require('../../docs-site/scripts/preview.cjs');
(async () => {
  const server = createPreviewServer(); await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  let browser;
  try {
    browser = await chromium.launch({ headless: true, ...(process.env.THREATLINT_BROWSER_EXECUTABLE ? { executablePath: process.env.THREATLINT_BROWSER_EXECUTABLE } : {}) });
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = [], failed = [];
    page.on('pageerror', error => errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') errors.push(message.text()); });
    page.on('response', response => { if (response.status() >= 400) failed.push(response.url()); });
    await page.goto(base);
    assert.match(await page.locator('h1').innerText(), /Find the risk.*Explain the path.*Ship the fix/s);
    await page.locator('.nav-links').getByRole('link', { name: 'Docs', exact: true }).click();
    await page.getByRole('heading', { level: 1, name: 'Threatlint documentation' }).waitFor();
    await page.getByRole('link', { name: 'Connect tools through MCP' }).click();
    await page.getByRole('heading', { level: 1, name: 'Threatlint MCP' }).waitFor();
    assert.match(await page.locator('main').innerText(), /list_findings/);
    await page.screenshot({ path: '/tmp/threatlint-docs-preview.png', fullPage: false });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(base + '/docs/');
    await page.getByRole('heading', { level: 1, name: 'Threatlint documentation' }).waitFor();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1), false);
    assert.deepEqual(errors, []); assert.deepEqual(failed, []);
    console.log('PASS: unchanged marketing hero, Docs navigation, Docusaurus client routing under production CSP, MCP documentation, and mobile layout.');
  } finally { await browser?.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => { console.error(error); process.exitCode = 1; });

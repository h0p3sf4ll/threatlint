'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const { chromium } = require('playwright');

(async () => {
  const directory = path.resolve(__dirname, '../../marketing');
  const server = http.createServer((req, res) => {
    const pathname = new URL(req.url, 'http://localhost').pathname;
    const file = path.resolve(directory, `.${pathname === '/' ? '/index.html' : pathname}`);
    if (!file.startsWith(`${directory}${path.sep}`)) { res.writeHead(404).end(); return; }
    try { res.setHeader('Content-Type', file.endsWith('.css') ? 'text/css' : file.endsWith('.svg') ? 'image/svg+xml' : 'text/html'); res.end(fs.readFileSync(file)); }
    catch { res.writeHead(404).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const browser = await chromium.launch({ headless: true, executablePath: process.env.THREATLINT_BROWSER_EXECUTABLE || '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' });
  try {
    const page = await browser.newPage();
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    const base = process.env.THREATLINT_MARKETING_URL || `http://127.0.0.1:${server.address().port}`;
    await page.goto(base, { waitUntil: 'networkidle' });
    assert.equal(await page.locator('header .nav-login').getAttribute('href'), 'https://app.threatlint.dev');
    assert.match(await page.locator('#capabilities').innerText(), /Semgrep Pro/);
    for (const text of ['Azure DevOps', 'Jira', 'GitHub issues', 'Trivy', 'SonarQube', 'SQL injection', '22']) assert.match(await page.locator('main').innerText(), new RegExp(text));
    for (const width of [1440, 768, 390, 320]) {
      await page.setViewportSize({ width, height: 1000 });
      const login = page.locator('header .nav-login'); assert.equal(await login.isVisible(), true);
      const bounds = await login.boundingBox(); assert.ok(bounds.x >= width / 2); assert.ok(bounds.x + bounds.width <= width);
      assert.ok(bounds.y >= 0 && bounds.y < 90);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true, `No horizontal overflow at ${width}px`);
      await page.screenshot({ path: `/tmp/threatlint-marketing-${width}.png`, fullPage: true });
    }
    const destination = await page.evaluate(() => document.querySelector('header .nav-login').href);
    assert.equal(destination, 'https://app.threatlint.dev/');
    assert.deepEqual(errors, []);
    console.log(`PASS: ${base} — updated product content, top-right login, keyboard-accessible links, and responsive layouts at 1440, 768, 390, and 320px.`);
  } finally { await browser.close(); await new Promise(resolve => server.close(resolve)); }
})().catch(error => { console.error(error); process.exitCode = 1; });

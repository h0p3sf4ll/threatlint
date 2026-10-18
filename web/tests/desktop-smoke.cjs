'use strict';
/** Optional real-runtime smoke test. Uses installed Electron; no paid model calls. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { _electron: electron } = require('playwright');
const { SKILL_MAP } = require('../lib/agents.cjs');

(async () => {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-desktop-test-'));
  const env = { ...process.env }; delete env.ELECTRON_RUN_AS_NODE;
  const executablePath = process.env.THREATLINT_DESKTOP_EXECUTABLE || require('electron');
  const args = [`--user-data-dir=${userData}`];
  if (!process.env.THREATLINT_DESKTOP_EXECUTABLE) args.unshift(path.resolve(__dirname, '..'));
  const application = await electron.launch({ executablePath, args, env });
  try {
    const page = await application.firstWindow();
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    await page.waitForSelector('#connection-status.online');
    assert.equal(await page.locator('.agent-card').count(), Object.keys(SKILL_MAP).length);
    assert.equal(await page.locator('.skill-card').count(), new Set(Object.values(SKILL_MAP).flat()).size);
    assert.equal(await page.evaluate(() => window.threatlintDesktop?.isDesktop), true);
    assert.equal(await page.evaluate(() => typeof require), 'undefined');
    await page.locator('#preview-example').click(); await page.locator('#report-dialog[open]').waitFor();
    await page.locator('#report-tab-findings').click(); assert.equal(await page.locator('.finding-card').count(), 2);
    const isolation = await application.evaluate(({ BrowserWindow }) => {
      const settings = BrowserWindow.getAllWindows()[0].webContents.getLastWebPreferences();
      return { sandbox: settings.sandbox, contextIsolation: settings.contextIsolation, nodeIntegration: settings.nodeIntegration };
    });
    assert.deepEqual(isolation, { sandbox: true, contextIsolation: true, nodeIntegration: false });
    assert.deepEqual(errors, []);
    console.log(`PASS: Electron startup, ${Object.keys(SKILL_MAP).length} agents, ${new Set(Object.values(SKILL_MAP).flat()).size} skills, report preview, sandbox, and renderer isolation.`);
  } finally { await application.close(); fs.rmSync(userData, { recursive: true, force: true }); }
})().catch(error => { console.error(error); process.exitCode = 1; });
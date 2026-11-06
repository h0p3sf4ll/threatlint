'use strict';
/** Optional real-runtime smoke test. Uses installed Electron; no paid model calls. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { _electron: electron } = require('playwright');
const { SKILL_MAP } = require('../lib/agents.cjs');

(async () => {
  const userData = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-desktop-test-'));
  const env = { ...process.env, THREATLINT_HOME: path.join(userData, 'config'), CODEX_HOME: path.join(userData, 'codex'),
    GH_CONFIG_DIR: path.join(userData, 'gh'), CLAUDE_CONFIG_DIR: path.join(userData, 'claude'),
    AWS_CONFIG_FILE: path.join(userData, 'aws-config'), AWS_SHARED_CREDENTIALS_FILE: path.join(userData, 'aws-credentials') };
  for (const key of Object.keys(env)) {
    if (/^(?:THREATLINT_GITHUB_APP_|THREATLINT_ADO_|THREATLINT_SNOW_)/.test(key)
        || /^(?:ELECTRON_RUN_AS_NODE|OPENAI_API_KEY|ANTHROPIC_API_KEY|BEDROCK_API_KEY|AWS_BEARER_TOKEN_BEDROCK|AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GH_TOKEN|GITHUB_TOKEN|GH_ENTERPRISE_TOKEN|GITHUB_ENTERPRISE_TOKEN|SEMGREP_APP_TOKEN)$/.test(key)) delete env[key];
  }
  const executablePath = process.env.THREATLINT_DESKTOP_EXECUTABLE || require('electron');
  const args = [`--user-data-dir=${userData}`];
  if (!process.env.THREATLINT_DESKTOP_EXECUTABLE) args.unshift(path.resolve(__dirname, '..'));
  let application, reservedPort;
  const errors = [];
  async function launchWorkbench() {
    application = await electron.launch({ executablePath, args, env });
    assert.equal(fs.realpathSync(await application.evaluate(({ app }) => app.getPath('userData'))), fs.realpathSync(userData),
      'the test must use its isolated application profile');
    // The first window is the launch splash; the workbench uses the local runner.
    let page;
    for (const deadline = Date.now() + 60_000; !page && Date.now() < deadline; await new Promise(resolve => setTimeout(resolve, 100))) {
      page = application.windows().find(win => win.url().startsWith('http://127.0.0.1:'));
    }
    assert.ok(page, 'Workbench window did not open');
    page.on('pageerror', error => errors.push(error.message));
    await page.waitForSelector('#connection-status.online');
    return page;
  }
  try {
    let page = await launchWorkbench();
    assert.equal(await page.locator('.agent-card').count(), Object.keys(SKILL_MAP).length);
    assert.equal(await page.locator('.skill-card').count(), new Set(Object.values(SKILL_MAP).flat()).size);
    assert.equal(await page.evaluate(() => window.threatlintDesktop?.isDesktop), true);
    assert.equal(await page.evaluate(() => typeof require), 'undefined');
    await page.locator('#preview-example').click(); await page.locator('#report-dialog[open]').waitFor();
    await page.locator('#report-tab-findings').click(); assert.equal(await page.locator('.finding-card').count(), 2);
    const isolation = await application.evaluate(({ BrowserWindow }) => {
      const settings = BrowserWindow.getAllWindows().find(win => win.webContents.getURL().startsWith('http://127.0.0.1:')).webContents.getLastWebPreferences();
      return { sandbox: settings.sandbox, contextIsolation: settings.contextIsolation, nodeIntegration: settings.nodeIntegration };
    });
    assert.deepEqual(isolation, { sandbox: true, contextIsolation: true, nodeIntegration: false });
    await page.keyboard.press('Escape');
    await page.locator('#settings-button').click();
    await page.locator('input[name=provider][value=codex]').check();
    if (!await page.locator('#model-id').isVisible()) await page.locator('.model-manual summary').click();
    await page.locator('#model-id').fill('fixture-desktop-model');
    await page.locator('#codex-daybreak').check();
    const saved = page.waitForResponse(response => response.url().endsWith('/api/model-preferences') && response.request().method() === 'PUT');
    await page.locator('#settings-form button[type=submit]').click();
    assert.equal((await saved).status(), 200);
    await page.waitForFunction(() => document.getElementById('toast').textContent.includes('saved for the next launch'));
    const previousOrigin = new URL(page.url()).origin;
    const previousPort = Number(new URL(previousOrigin).port);
    await application.close();
    application = null;
    // Reserve the old port so relaunch must use another localStorage origin.
    reservedPort = http.createServer();
    await new Promise((resolve, reject) => { reservedPort.once('error', reject); reservedPort.listen(previousPort, '127.0.0.1', resolve); });
    page = await launchWorkbench();
    assert.notEqual(new URL(page.url()).origin, previousOrigin);
    await page.locator('#settings-button').click();
    assert.equal(await page.locator('input[name=provider][value=codex]').isChecked(), true);
    assert.equal(await page.locator('#model-id').inputValue(), 'fixture-desktop-model');
    assert.equal(await page.locator('#codex-daybreak').isChecked(), true);
    assert.equal(await page.locator('#cloud-consent').isChecked(), false, 'remote sharing consent remains session-only');
    assert.equal(await page.locator('#api-key').inputValue(), '');
    assert.deepEqual(errors, []);
    console.log(`PASS: Electron startup, ${Object.keys(SKILL_MAP).length} agents, ${new Set(Object.values(SKILL_MAP).flat()).size} skills, report preview, sandbox, renderer isolation, and saved model preferences across application relaunch on a different port.`);
  } finally {
    if (application) await application.close();
    if (reservedPort) await new Promise(resolve => reservedPort.close(resolve));
    fs.rmSync(userData, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

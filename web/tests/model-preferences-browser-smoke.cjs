'use strict';
/** Model preferences survive a runner restart and a new browser origin; no real model calls. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-preferences-browser-'));
process.env.THREATLINT_HOME = path.join(temporary, 'config');
process.env.THREATLINT_STATE_DIR = path.join(temporary, 'unused-default');
process.env.CODEX_HOME = path.join(temporary, 'codex');
for (const key of ['OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'AWS_BEARER_TOKEN_BEDROCK', 'BEDROCK_API_KEY',
  'THREATLINT_GITHUB_APP_ID', 'THREATLINT_GITHUB_APP_INSTALLATION_ID', 'THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE']) delete process.env[key];
const { createWorkbench } = require('../server.js');

const CODEX_MODEL = 'fixture-codex-model';
const BEDROCK_MODEL = 'us.anthropic.fixture-model';
const SESSION_KEY = 'synthetic-session-key-do-not-save';
const LEGACY_KEY = 'synthetic-legacy-key-do-not-migrate';
const integrations = {
  credentialSources: async () => ({ codex: 'synthetic Codex login', claude: null, bedrock: null,
    'claude-code': null, daybreak: 'synthetic Codex login', 'daybreak-bedrock': null, openai: null, copilot: null }),
  claudeCodeStatus: async () => ({ installed: false, loggedIn: false }),
  resolveKey: async () => ({ key: '', source: null }),
  fetchImpl: async () => { throw new Error('No external requests in the preferences test'); },
  semgrepVersion: async () => 'fixture',
  threatlintCli: async () => ({ code: 0, stdout: '', stderr: '' }),
  convertToWord: async () => {},
};

async function start(storage) {
  const workbench = createWorkbench({ storageDir: storage, integrations,
    runProvider: async () => { throw new Error('Saving preferences must not run a model'); } });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  return { workbench, base: `http://127.0.0.1:${workbench.server.address().port}` };
}

function diskContents(directory) {
  if (!fs.existsSync(directory)) return '';
  return fs.readdirSync(directory, { withFileTypes: true }).map(entry => {
    const file = path.join(directory, entry.name);
    return entry.isDirectory() ? diskContents(file) : fs.readFileSync(file, 'utf8');
  }).join('\n');
}

async function preferences(page) {
  return page.evaluate(async () => (await (await fetch('/api/model-preferences')).json()).preferences);
}

async function openSettings(page, base) {
  await page.goto(base);
  await page.locator('#connection-status.online').waitFor();
  await page.locator('#settings-button').click();
}

async function save(page) {
  const response = page.waitForResponse(result => result.url().endsWith('/api/model-preferences') && result.request().method() === 'PUT');
  await page.locator('#settings-form button[type=submit]').click();
  assert.equal((await response).status(), 200);
  await page.waitForFunction(() => document.getElementById('toast').textContent.includes('Model settings saved'));
  assert.equal(await page.locator('#settings-error').innerText(), '');
}

(async () => {
  const storage = path.join(temporary, 'history');
  const launch = { headless: true };
  if (process.env.THREATLINT_BROWSER_EXECUTABLE) launch.executablePath = process.env.THREATLINT_BROWSER_EXECUTABLE;
  let browser, active, context, reservation;
  const errors = [];
  try {
    browser = await chromium.launch(launch);
    active = await start(storage);
    context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    let page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    await openSettings(page, active.base);
    await page.locator('input[name=provider][value=bedrock]').check();
    await page.locator('#model-id').fill(BEDROCK_MODEL);
    await page.locator('#bedrock-region').fill('us-west-2');
    await page.locator('#api-key').fill(SESSION_KEY);
    await page.locator('#cloud-consent').check();
    await save(page);
    await page.locator('input[name=provider][value=codex]').check();
    await page.locator('#model-id').fill(CODEX_MODEL);
    await page.locator('#codex-daybreak').check();
    await page.locator('#cloud-consent').check();
    await save(page);
    const saved = await preferences(page);
    assert.equal(saved.provider, 'codex');
    assert.equal(saved.models.codex, CODEX_MODEL);
    assert.equal(saved.models.bedrock, BEDROCK_MODEL);
    assert.equal(saved.bedrockRegion, 'us-west-2');
    assert.equal(saved.codexDaybreak, true);
    assert.equal(JSON.stringify(saved).includes(SESSION_KEY), false);
    assert.equal(Object.hasOwn(saved, 'consent'), false);
    assert.equal(diskContents(storage).includes(SESSION_KEY), false);

    const previous = active.base;
    const oldPort = active.workbench.server.address().port;
    await context.close(); context = null;
    await active.workbench.close(); active = null;
    // Occupy the old port so this exercise cannot accidentally reuse localStorage's origin.
    reservation = net.createServer();
    await new Promise(resolve => reservation.listen(oldPort, '127.0.0.1', resolve));
    active = await start(storage);
    assert.notEqual(active.base, previous);
    await new Promise(resolve => reservation.close(resolve)); reservation = null;
    context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
    page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    await openSettings(page, active.base);
    assert.equal(await page.locator('input[name=provider][value=codex]').isChecked(), true);
    assert.equal(await page.locator('#model-id').inputValue(), CODEX_MODEL);
    assert.equal(await page.locator('#codex-daybreak').isChecked(), true);
    assert.equal(await page.locator('#cloud-consent').isChecked(), false, 'Sharing consent remains session-only');
    await page.locator('input[name=provider][value=bedrock]').check();
    assert.equal(await page.locator('#model-id').inputValue(), BEDROCK_MODEL);
    assert.equal(await page.locator('#bedrock-region').inputValue(), 'us-west-2');
    assert.equal(await page.locator('#api-key').inputValue(), '', 'Credentials are not restored with preferences');

    // Stale origin-local preferences must not overwrite the saved application settings.
    await context.close(); context = await browser.newContext();
    await context.addInitScript(() => localStorage.setItem('threatlint.preferences.v2', JSON.stringify({
      provider: 'lmstudio', models: { lmstudio: 'stale-local-model', codex: 'stale-codex-model' },
      lmstudioUrl: 'http://localhost:1234/v1', codexDaybreak: false,
    })));
    page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    await openSettings(page, active.base);
    assert.equal(await page.locator('input[name=provider][value=codex]').isChecked(), true);
    assert.equal(await page.locator('#model-id').inputValue(), CODEX_MODEL);
    assert.equal(await page.locator('#codex-daybreak').isChecked(), true);
    assert.equal((await preferences(page)).models.codex, CODEX_MODEL);

    // A failed durable save stays visible and does not claim success or change the persisted model.
    await page.route('**/api/model-preferences', route => route.request().method() === 'PUT'
      ? route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'Synthetic preferences write failure' }) })
      : route.continue());
    await page.locator('#model-id').fill('unsaved-codex-model');
    await page.evaluate(() => { document.getElementById('toast').textContent = ''; });
    await page.locator('#settings-form button[type=submit]').click();
    await page.waitForFunction(() => document.getElementById('settings-error').textContent.includes('Synthetic preferences write failure'));
    assert.equal((await page.locator('#toast').textContent()).includes('Model settings saved'), false);
    assert.equal((await preferences(page)).models.codex, CODEX_MODEL);

    await context.close(); context = null;
    await active.workbench.close(); active = null;
    const migratedStorage = path.join(temporary, 'migrated-history');
    active = await start(migratedStorage);
    context = await browser.newContext();
    await context.addInitScript(({ key }) => localStorage.setItem('threatlint.preferences.v2', JSON.stringify({
      provider: 'codex', models: { codex: 'legacy-codex-model', bedrock: 'legacy-bedrock-model' },
      codexDaybreak: true, bedrockRegion: 'eu-west-1', lmstudioUrl: 'http://localhost:1234/v1',
      apiKey: key, consent: ['codex'],
    })), { key: LEGACY_KEY });
    page = await context.newPage();
    page.on('pageerror', error => errors.push(error.message));
    await openSettings(page, active.base);
    const migrated = await preferences(page);
    assert.equal(migrated.provider, 'codex');
    assert.equal(migrated.models.codex, 'legacy-codex-model');
    assert.equal(migrated.models.bedrock, 'legacy-bedrock-model');
    assert.equal(migrated.bedrockRegion, 'eu-west-1');
    assert.equal(migrated.codexDaybreak, true);
    assert.equal(await page.locator('#cloud-consent').isChecked(), false);
    assert.equal(diskContents(migratedStorage).includes(LEGACY_KEY), false);
    assert.equal(Object.hasOwn(migrated, 'apiKey'), false);
    assert.equal(Object.hasOwn(migrated, 'consent'), false);
    assert.deepEqual(errors, []);
    console.log('PASS: model preferences survive a changed-origin restart; provider models, region and Daybreak restore; legacy migration, stale-browser precedence, save failures and credential privacy.');
  } finally {
    if (context) await context.close();
    if (browser) await browser.close();
    if (active) await active.workbench.close();
    if (reservation) await new Promise(resolve => reservation.close(resolve));
    fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

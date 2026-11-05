'use strict';
/** Bedrock settings and request routing with synthetic credentials and a local model stub. */
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { chromium } = require('playwright');

const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-bedrock-browser-'));
process.env.THREATLINT_HOME = path.join(temporary, 'config');
// Isolate the no-key Daybreak path from credentials on the developer's machine.
process.env.CODEX_HOME = path.join(temporary, 'codex');
delete process.env.OPENAI_API_KEY;
process.env.AWS_REGION = 'eu-west-1';
delete process.env.AWS_DEFAULT_REGION;
for (const name of ['THREATLINT_GITHUB_APP_ID', 'THREATLINT_GITHUB_APP_INSTALLATION_ID', 'THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE']) delete process.env[name];
const { createWorkbench } = require('../server.js');

const BEDROCK_KEY = 'synthetic-bedrock-session-key';
const ANTHROPIC_KEY = 'synthetic-anthropic-session-key';
const MODEL = 'global.anthropic.claude-sonnet-5';
const fixture = '# Synthetic browser fixture\n\n## Executive Summary\nNo real security review was performed.\n';

async function filesBelow(directory) {
  if (!fs.existsSync(directory)) return '';
  const entries = fs.readdirSync(directory, { withFileTypes: true });
  return (await Promise.all(entries.map(entry => entry.isDirectory() ? filesBelow(path.join(directory, entry.name)) : fs.readFileSync(path.join(directory, entry.name), 'utf8')))).join('\n');
}

(async () => {
  const repo = path.join(temporary, 'repo'), storage = path.join(temporary, 'history');
  fs.mkdirSync(repo); fs.writeFileSync(path.join(repo, 'README.md'), '# Browser test fixture\n');
  const observed = [], requests = [];
  const workbench = createWorkbench({ storageDir: storage, integrations: {
    credentialSources: async () => ({ claude: null, bedrock: null, 'claude-code': 'synthetic Claude Code login',
      codex: 'Codex login (ChatGPT)', daybreak: 'Codex login (ChatGPT)', 'daybreak-bedrock': null, openai: null, copilot: null }),
    claudeCodeStatus: async () => ({ installed: true, loggedIn: true, source: 'synthetic Claude Code login' }),
    resolveKey: async (_provider, key) => ({ key: key || '', source: key ? 'session' : null }),
    fetchImpl: async () => ({ ok: true, status: 200, json: async () => ({ data: [{ id: 'claude-opus-5-5', display_name: 'Synthetic Claude' }] }) }),
    semgrepVersion: async () => 'synthetic-version',
    threatlintCli: async () => ({ code: 0, stdout: '', stderr: '' }),
    convertToWord: async () => {},
  }, runProvider: async args => {
    observed.push(args); args.onEvent({ type: 'text_chunk', text: fixture }); return fixture;
  } });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${workbench.server.address().port}`;
  const launch = { headless: true };
  if (process.env.THREATLINT_BROWSER_EXECUTABLE) launch.executablePath = process.env.THREATLINT_BROWSER_EXECUTABLE;
  let browser;
  try {
    browser = await chromium.launch(launch);
    const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
    const errors = []; page.on('pageerror', error => errors.push(error.message));
    page.on('websocket', socket => socket.on('framesent', event => {
      try { const payload = JSON.parse(event.payload); if (payload.action === 'run_pipeline') requests.push(payload); } catch {}
    }));
    await page.goto(base); await page.locator('#connection-status.online').waitFor();
    await page.locator('#choose-repo').click(); await page.locator('#repo-path').fill(repo); await page.locator('#open-repository').click();
    await page.locator('#repository-dialog').waitFor({ state: 'hidden' });
    await page.locator('#settings-button').click();
    const claudeChoices = page.getByRole('group', { name: 'Claude', exact: true });
    assert.equal(await claudeChoices.isVisible(), true, 'Claude connection methods are grouped in Settings');
    assert.deepEqual(await claudeChoices.locator('input[name=provider]').evaluateAll(inputs => inputs.map(input => input.value)), ['claude', 'claude-code', 'bedrock']);
    for (const label of ['Anthropic API', 'Claude Code', 'Amazon Bedrock']) {
      assert.equal(await claudeChoices.getByText(label, { exact: true }).isVisible(), true, `${label} is visible under Claude`);
    }
    await page.locator('input[name=provider][value=bedrock]').check();
    assert.equal(await page.locator('#bedrock-settings').isVisible(), true);
    assert.equal(await page.locator('#model-picker').isVisible(), false);
    assert.equal(await page.locator('#model-id').isVisible(), true);
    assert.equal(await page.locator('#bedrock-region').inputValue(), '', 'Blank region preserves server-side AWS configuration');
    await page.locator('#settings-form button[type=submit]').click();
    assert.match(await page.locator('#settings-error').innerText(), /Bedrock model/);
    await page.locator('#model-id').fill(MODEL);
    await page.locator('#bedrock-region').fill('https://example.test');
    await page.locator('#settings-form button[type=submit]').click();
    assert.match(await page.locator('#settings-error').innerText(), /AWS region/);
    await page.locator('#bedrock-region').fill('');
    await page.locator('#api-key').fill(BEDROCK_KEY);
    await page.locator('#settings-form button[type=submit]').click();
    await page.locator('[data-view="workbench"]').click(); await page.locator('#start-run').click();
    await page.locator('#view-settings:not([hidden])').waitFor();
    assert.equal(observed.length, 0, 'Cloud consent is required before a model request');
    assert.equal(await page.locator('#cloud-consent').isChecked(), false);
    await page.locator('#cloud-consent').check(); await page.locator('#settings-form button[type=submit]').click();
    await page.locator('[data-view="workbench"]').click(); await page.locator('#start-run').click();
    await page.waitForFunction(() => document.getElementById('activity-badge').textContent.includes('Review complete'));
    assert.equal(observed.length, 3);
    for (const call of observed) {
      assert.equal(call.provider, 'bedrock'); assert.equal(call.model, MODEL); assert.equal(call.key, BEDROCK_KEY);
      assert.equal(call.baseUrl, 'https://bedrock-runtime.eu-west-1.amazonaws.com/anthropic');
    }
    assert.equal(requests[0].bedrockApiKey, BEDROCK_KEY);
    assert.equal(requests[0].bedrockRegion, undefined);
    for (const field of ['apiKey', 'openaiApiKey', 'copilotToken']) assert.equal(requests[0][field], undefined);

    await page.locator('#settings-button').click();
    await page.locator('#bedrock-region').fill('us-west-2');
    assert.equal(await page.locator('#cloud-consent').isChecked(), false, 'Changing the destination region resets consent');
    await page.locator('#cloud-consent').check();
    await page.locator('#settings-form button[type=submit]').click();
    await page.locator('[data-view="workbench"]').click(); await page.locator('#start-run').click();
    await page.waitForFunction(() => document.getElementById('activity-badge').textContent.includes('Review complete'));
    assert.equal(observed.length, 6);
    assert.equal(observed.at(-1).baseUrl, 'https://bedrock-runtime.us-west-2.amazonaws.com/anthropic');
    assert.equal(requests.at(-1).bedrockRegion, 'us-west-2');
    await page.locator('#settings-button').click();
    await page.locator('input[name=provider][value=claude]').check();
    assert.equal(await page.locator('#api-key').inputValue(), '', 'Bedrock keys do not populate Anthropic');
    await page.locator('#api-key').fill(ANTHROPIC_KEY);
    await page.locator('input[name=provider][value=claude-code]').check();
    assert.equal(await page.locator('#api-key').isVisible(), false, 'Claude Code login has no API key field');
    assert.equal(await page.locator('#bedrock-settings').isVisible(), false);
    await page.locator('input[name=provider][value=bedrock]').check();
    assert.equal(await page.locator('#api-key').inputValue(), BEDROCK_KEY);
    assert.equal(await page.locator('#model-id').inputValue(), MODEL);
    await page.locator('#settings-form button[type=submit]').click();
    const preferences = await page.evaluate(() => JSON.stringify(Object.fromEntries(Object.entries(localStorage))));
    assert.equal(preferences.includes(BEDROCK_KEY), false); assert.equal(preferences.includes(ANTHROPIC_KEY), false);
    assert.equal((await filesBelow(storage)).includes(BEDROCK_KEY), false, 'Report files and history never store the provider key');
    await page.reload(); await page.locator('#connection-status.online').waitFor();
    await page.locator('#settings-button').click();
    assert.equal(await page.locator('input[name=provider][value=bedrock]').isChecked(), true);
    assert.equal(await page.locator('#bedrock-region').inputValue(), 'us-west-2');
    assert.equal(await page.locator('#model-id').inputValue(), MODEL);
    assert.equal(await page.locator('#api-key').inputValue(), '', 'Reload clears session credentials');
    assert.equal(await page.locator('#cloud-consent').isChecked(), false, 'Reload clears data-sharing consent');
    const daybreakChoices = page.getByRole('group', { name: 'Daybreak Blue', exact: true });
    assert.deepEqual(await daybreakChoices.locator('input[name=provider]').evaluateAll(inputs => inputs.map(input => input.value)), ['daybreak', 'daybreak-bedrock']);
    await page.locator('input[name=provider][value=daybreak]').check();
    assert.equal(await page.locator('#model-id').inputValue(), 'gpt-6-sol');
    assert.match(await page.locator('#environment-key-note').innerText(), /Codex login \(ChatGPT\).*Daybreak Blue enabled/);
    assert.match(await page.locator('#environment-key-note').innerText(), /No API key is needed/);
    await page.locator('#api-key').fill('synthetic-openai-session-key');
    assert.match(await page.locator('#environment-key-note').innerText(), /API key entered for this session/);
    await page.locator('#api-key').fill('');
    assert.match(await page.locator('#environment-key-note').innerText(), /Codex login/);
    await page.locator('#cloud-consent').check();
    await page.locator('#settings-form button[type=submit]').click();
    await page.locator('[data-view="workbench"]').click(); await page.locator('#start-run').click();
    await page.waitForFunction(() => document.getElementById('activity-badge').textContent.includes('Review complete'));
    assert.equal(observed.at(-1).provider, 'daybreak');
    assert.equal(observed.at(-1).transport, 'codex');
    assert.equal(observed.at(-1).daybreakBlue, true);
    assert.equal(observed.at(-1).model, 'gpt-6-sol');
    assert.equal(observed.at(-1).key, null);
    assert.equal(requests.at(-1).openaiApiKey, undefined);
    await page.locator('#settings-button').click();
    await page.locator('input[name=provider][value=daybreak-bedrock]').check();
    assert.equal(await page.locator('#model-id').inputValue(), 'openai.gpt-daybreak-blue-5.6-sol');
    assert.equal(await page.locator('#bedrock-region').inputValue(), 'us-east-2');
    await page.locator('input[name=provider][value=codex]').check();
    assert.equal(await page.locator('#api-key').isVisible(), false, 'Codex login needs no API key field');
    assert.equal(await page.locator('#codex-daybreak-label').isVisible(), true);
    assert.equal(await page.locator('#model-id').inputValue(), '', 'Codex can use its CLI default model');
    await page.locator('#cloud-consent').check();
    await page.locator('#settings-form button[type=submit]').click();
    assert.equal(await page.locator('#settings-error').innerText(), '', 'Saving Codex with no model is valid');
    await page.locator('[data-view="workbench"]').click(); await page.locator('#start-run').click();
    await page.waitForFunction(() => document.getElementById('activity-badge').textContent.includes('Review complete'));
    assert.equal(observed.at(-1).provider, 'codex');
    assert.equal(observed.at(-1).model, '');
    assert.equal(observed.at(-1).key, null);
    assert.equal(requests.at(-1).codexDaybreak, false);
    assert.equal(requests.at(-1).model, '');
    await page.locator('#settings-button').click();
    await page.locator('#codex-daybreak').check();
    await page.locator('#settings-form button[type=submit]').click();
    await page.locator('[data-view="workbench"]').click(); await page.locator('#start-run').click();
    await page.waitForFunction(() => document.getElementById('activity-badge').textContent.includes('Review complete'));
    assert.equal(observed.at(-1).provider, 'codex');
    assert.equal(observed.at(-1).model, 'gpt-6-sol');
    assert.equal(observed.at(-1).daybreakBlue, true);
    assert.equal(requests.at(-1).codexDaybreak, true);
    await page.locator('#settings-button').click();
    await page.setViewportSize({ width: 390, height: 844 });
    assert.equal(await claudeChoices.isVisible(), true, 'Claude connection methods remain visible on a phone');
    for (const label of ['Anthropic API', 'Claude Code', 'Amazon Bedrock']) {
      assert.equal(await claudeChoices.getByText(label, { exact: true }).isVisible(), true, `${label} is visible on a phone`);
    }
    assert.equal(await daybreakChoices.isVisible(), true, 'Daybreak Blue methods remain visible on a phone');
    assert.equal(await page.locator('input[name=provider][value=codex]').isVisible(), true, 'Codex remains visible on a phone');
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false, 'Bedrock settings fit phone width');
    assert.deepEqual(errors, []);
    console.log('PASS: Claude, Bedrock, Daybreak Blue, and Codex settings; remote consent; provider routing and isolation; secret-free persistence; reload; phone layout.');
  } finally {
    if (browser) await browser.close(); await workbench.close(); fs.rmSync(temporary, { recursive: true, force: true });
  }
})().catch(error => { console.error(error); process.exitCode = 1; });

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { providerRequest, runModel } = require('../lib/pipeline.cjs');
const { credentialSources } = require('../lib/model-catalog.cjs');
const { registerWorkspaceRoutes } = require('../lib/routes/workspace.cjs');

function isolatedCodex(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-daybreak-access-'));
  const original = Object.fromEntries(['OPENAI_API_KEY', 'CODEX_HOME', 'PATH'].map(name => [name, process.env[name]]));
  delete process.env.OPENAI_API_KEY;
  process.env.CODEX_HOME = directory;
  t.after(() => {
    for (const [name, value] of Object.entries(original)) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return directory;
}

test('Daybreak with no API key uses Codex login and preserves its selected provider', async t => {
  const directory = isolatedCodex(t);
  fs.writeFileSync(path.join(directory, 'auth.json'), JSON.stringify({
    auth_mode: 'chatgpt', tokens: { access_token: 'synthetic-oauth-must-not-be-an-api-key' },
  }));
  const settings = providerRequest({ provider: 'daybreak', codexDaybreak: false });
  assert.equal(settings.provider, 'daybreak');
  assert.equal(settings.transport, 'codex');
  assert.equal(settings.daybreakBlue, true);
  assert.equal(settings.model, 'gpt-6-sol');
  assert.equal(settings.key, null);
  assert.equal(settings.baseUrl, null);
  let observed;
  await runModel({ settings, systemPrompt: 'Rules', userMessage: 'Review', repoPath: directory,
    override: args => { observed = args; return '# Report'; } });
  assert.equal(observed.provider, 'daybreak');
  assert.equal(observed.transport, 'codex');
  assert.equal(observed.daybreakBlue, true);
  assert.equal(observed.key, null);
});

test('Daybreak fallback executes Codex with Blue enabled and never calls the API', { skip: process.platform === 'win32' }, async t => {
  const directory = isolatedCodex(t);
  const executable = path.join(directory, 'codex');
  fs.writeFileSync(executable, `#!/usr/bin/env node
'use strict';
const args = process.argv.slice(2);
if (!args.includes('daybreak=true') || !args.includes('read-only') ||
    args[args.indexOf('--model') + 1] !== 'gpt-6-sol' || process.env.OPENAI_API_KEY) process.exit(2);
process.stdin.resume();
process.stdin.on('end', () => {
  console.log(JSON.stringify({ type: 'item.completed', item: { type: 'agent_message', text: '# Codex Daybreak report' } }));
  console.log(JSON.stringify({ type: 'turn.completed', turn: { status: 'completed' } }));
});
`, { mode: 0o700 });
  process.env.PATH = `${directory}${path.delimiter}${process.env.PATH}`;
  t.mock.method(global, 'fetch', () => { throw new Error('No API request is allowed for a Codex login'); });
  const result = await runModel({ settings: providerRequest({ provider: 'daybreak' }),
    systemPrompt: 'Rules', userMessage: 'Review', repoPath: directory, onEvent: () => {} });
  assert.equal(result, '# Codex Daybreak report');
});

test('Daybreak API credentials take priority over the Codex fallback', t => {
  const directory = isolatedCodex(t);
  fs.writeFileSync(path.join(directory, 'auth.json'), JSON.stringify({ auth_mode: 'apikey', OPENAI_API_KEY: 'synthetic-saved-key' }));
  assert.equal(providerRequest({ provider: 'daybreak' }).key, 'synthetic-saved-key');
  process.env.OPENAI_API_KEY = 'synthetic-env-key';
  const configured = providerRequest({ provider: 'daybreak' });
  assert.equal(configured.key, 'synthetic-env-key');
  const explicit = providerRequest({ provider: 'daybreak', openaiApiKey: 'synthetic-session-key' });
  assert.equal(explicit.key, 'synthetic-session-key');
  for (const settings of [configured, explicit]) {
    assert.equal(settings.transport, undefined);
    assert.equal(settings.baseUrl, 'https://api.openai.com/v1');
    assert.equal(settings.daybreakBlue, false);
  }
});

test('Daybreak credential discovery reports Codex login without asserting program entitlement', async t => {
  const home = isolatedCodex(t);
  const options = { home, env: { CODEX_HOME: home }, run: async () => ({ stdout: '' }),
    claudeCodeStatus: async () => ({ source: null }),
    codexStatus: async () => ({ installed: true, loggedIn: true, source: 'Codex login (ChatGPT)' }) };
  assert.equal((await credentialSources(options)).daybreak, 'Codex login (ChatGPT)');
  assert.equal((await credentialSources({ ...options, env: { ...options.env, OPENAI_API_KEY: 'synthetic-key' } })).daybreak, 'OPENAI_API_KEY');
  assert.equal((await credentialSources({ ...options,
    codexStatus: async () => ({ installed: true, loggedIn: false, source: null }) })).daybreak, null);
});

async function modelRoute(integrations, body = { provider: 'daybreak' }) {
  const routes = new Map();
  registerWorkspaceRoutes({ get() {}, delete() {}, post(route, handler) { routes.set(route, handler); } },
    { store: { sessions: new Map() }, reports: {}, integrations });
  let status, payload;
  await routes.get('/api/models')({ body },
    { headersSent: false, status(code) { status = code; return this; }, json(value) { payload = value; } });
  return { status, payload };
}

test('Daybreak model route detects a signed-in Codex account when no API key is configured', async () => {
  const result = await modelRoute({
    resolveKey: async () => ({ key: '', source: null }),
    codexStatus: async () => ({ installed: true, loggedIn: true, source: 'Codex login (ChatGPT)' }),
    fetchImpl: () => { throw new Error('Codex login must not query the API'); },
  });
  assert.equal(result.status, 200);
  assert.deepEqual(result.payload, { source: 'Codex login (ChatGPT)', transport: 'codex',
    models: [{ id: 'gpt-6-sol', name: 'GPT-6 Sol · Daybreak Blue' }] });
});

test('Daybreak model route preserves API-key priority without checking Codex', async () => {
  const result = await modelRoute({
    resolveKey: async () => ({ key: 'synthetic-key', source: 'session' }),
    codexStatus: () => { throw new Error('An API key must not switch accounts'); },
  });
  assert.equal(result.status, 200);
  assert.equal(result.payload.source, 'session');
  assert.equal(result.payload.transport, undefined);
});

for (const installed of [true, false]) test(`Daybreak model route explains missing Codex ${installed ? 'login' : 'installation'}`, async () => {
  const result = await modelRoute({
    resolveKey: async () => ({ key: '', source: null }),
    codexStatus: async () => ({ installed, loggedIn: false, source: null }),
  });
  assert.equal(result.status, 401);
  assert.match(result.payload.error, installed ? /codex login/ : /Install Codex/);
  assert.match(result.payload.error, /API key/);
});

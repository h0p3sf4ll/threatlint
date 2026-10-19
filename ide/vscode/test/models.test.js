'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { readClaudeConfig, discoverClaudeModels, validateBaseUrl, CLI_ALIASES } = require('../models.js');

function home(settings) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-claude-'));
  if (settings) { fs.mkdirSync(path.join(dir, '.claude')); fs.writeFileSync(path.join(dir, '.claude', 'settings.json'), JSON.stringify(settings)); }
  return dir;
}

test('settings.json env overrides the process environment', () => {
  const config = readClaudeConfig({ env: { ANTHROPIC_API_KEY: 'env-key' }, home: home({ env: { ANTHROPIC_API_KEY: 'settings-key', ANTHROPIC_BASE_URL: 'https://gateway.example.com/' } }) });
  assert.equal(config.apiKey, 'settings-key');
  assert.equal(config.baseUrl, 'https://gateway.example.com');
});

test('rejects plaintext remote base URLs and embedded credentials', () => {
  assert.throws(() => validateBaseUrl('http://gateway.example.com'));
  assert.throws(() => validateBaseUrl('https://user:pass@gateway.example.com'));
  assert.equal(validateBaseUrl('http://localhost:8080/'), 'http://localhost:8080');
});

test('lists API models with the configured key and follows pagination', async () => {
  const seen = [];
  const pages = [{ data: [{ id: 'claude-opus-5-5', display_name: 'Opus 5.5' }], has_more: true, last_id: 'claude-opus-5-5' }, { data: [{ id: 'claude-haiku-5-5' }], has_more: false }];
  const fetchImpl = async (url, options) => { seen.push({ url, key: options.headers['x-api-key'] }); return { ok: true, json: async () => pages.shift() }; };
  const result = await discoverClaudeModels({ config: { apiKey: 'k', baseUrl: 'https://api.anthropic.com' }, fetchImpl, cliCheck: async () => false });
  assert.equal(result.source, 'api');
  assert.deepEqual(result.models.map(m => m.name), ['Opus 5.5', 'claude-haiku-5-5']);
  assert.match(seen[1].url, /after_id=claude-opus-5-5/);
  assert.equal(seen[0].key, 'k');
});

test('falls back to CLI aliases without a key, and reports nothing when Claude is absent', async () => {
  const none = { apiKey: '', authToken: '', baseUrl: 'https://api.anthropic.com' };
  assert.deepEqual((await discoverClaudeModels({ config: none, cliCheck: async () => true })).models, CLI_ALIASES);
  const absent = await discoverClaudeModels({ config: none, cliCheck: async () => false });
  assert.equal(absent.source, null);
  assert.equal(absent.models.length, 0);
});

test('an API failure still offers CLI aliases and surfaces the error', async () => {
  const result = await discoverClaudeModels({ config: { apiKey: 'bad', baseUrl: 'https://api.anthropic.com' }, fetchImpl: async () => ({ ok: false, status: 401 }), cliCheck: async () => true });
  assert.equal(result.source, 'cli');
  assert.match(result.error, /HTTP 401/);
});

'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { resolveKey, configuredKey, listModels, COPILOT_HEADERS } = require('../lib/model-catalog.cjs');
const { providerRequest } = require('../lib/pipeline.cjs');
const { openAiTurn } = require('../lib/providers.cjs');

const json = body => ({ ok: true, status: 200, json: async () => body });
function home(settings) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-home-'));
  if (settings) { fs.mkdirSync(path.join(dir, '.claude')); fs.writeFileSync(path.join(dir, '.claude/settings.json'), JSON.stringify({ env: settings })); }
  return dir;
}

describe('Provider credentials from where each tool keeps them', () => {
  it('prefers the session key, then the environment, then ~/.claude/settings.json', async () => {
    const dir = home({ ANTHROPIC_API_KEY: 'from-settings' });
    assert.deepEqual(await resolveKey('claude', ' typed ', { env: { ANTHROPIC_API_KEY: 'env' }, home: dir }), { key: 'typed', source: 'session', baseUrl: 'https://api.anthropic.com' });
    assert.equal((await resolveKey('claude', '', { env: { ANTHROPIC_API_KEY: 'env' }, home: dir })).source, 'ANTHROPIC_API_KEY');
    assert.deepEqual(await resolveKey('claude', '', { env: {}, home: dir }), { key: 'from-settings', source: '~/.claude/settings.json (ANTHROPIC_API_KEY)', bearer: false, baseUrl: 'https://api.anthropic.com' });
    assert.equal((await resolveKey('claude', '', { env: {}, home: home({ ANTHROPIC_AUTH_TOKEN: 't' }) })).bearer, true);
    assert.deepEqual(await resolveKey('claude', '', { env: {}, home: home() }), { key: '', source: null });
  });
  it('follows ANTHROPIC_BASE_URL to a gateway, from the environment or settings.json', async () => {
    const gateway = await resolveKey('claude', '', { env: {}, home: home({ ANTHROPIC_API_KEY: 'k', ANTHROPIC_BASE_URL: 'https://llm-gateway.example.com/' }) });
    assert.deepEqual([gateway.baseUrl, gateway.source], ['https://llm-gateway.example.com', '~/.claude/settings.json (ANTHROPIC_API_KEY) via llm-gateway.example.com']);
    let url; await listModels('claude', gateway, { fetchImpl: async target => { url = target; return json({ data: [] }); } });
    assert.match(url, /^https:\/\/llm-gateway\.example\.com\/v1\/models/);
    await assert.rejects(resolveKey('claude', '', { env: { ANTHROPIC_API_KEY: 'k', ANTHROPIC_BASE_URL: 'http://attacker.example' }, home: home() }), /HTTPS/);
  });
  it('uses GitHub tokens from the environment, then the GitHub CLI sign-in, for Copilot', async () => {
    assert.equal((await resolveKey('copilot', '', { env: { GH_TOKEN: 'gh-env' }, home: home() })).source, 'GH_TOKEN');
    const run = async (file, args) => { assert.deepEqual([file, args], ['gh', ['auth', 'token']]); return { stdout: 'gho_cli\n' }; };
    assert.deepEqual(await resolveKey('copilot', '', { env: {}, home: home(), run }), { key: 'gho_cli', source: 'GitHub CLI (gh auth token)' });
    assert.equal(configuredKey('copilot', '', { env: {}, home: home() }).key, 'gho_cli', 'the CLI token is cached for runs');
  });
});

describe('Model lists for the settings dropdown', () => {
  it('pages Claude models with an API key', async () => {
    const calls = [];
    const fetchImpl = async (url, options) => { calls.push({ url, options }); return json(url.includes('after_id') ? { data: [{ id: 'claude-haiku-5-5' }], has_more: false } : { data: [{ id: 'claude-opus-5-5', display_name: 'Claude Opus 5.5' }], has_more: true, last_id: 'claude-opus-5-5' }); };
    assert.deepEqual(await listModels('claude', { key: 'k' }, { fetchImpl }), [{ id: 'claude-opus-5-5', name: 'Claude Opus 5.5' }, { id: 'claude-haiku-5-5', name: 'claude-haiku-5-5' }]);
    assert.equal(calls[0].options.headers['x-api-key'], 'k'); assert.equal(calls[0].options.redirect, 'error');
  });
  it('keeps only chat models for OpenAI', async () => {
    const fetchImpl = async () => json({ data: ['gpt-5', 'text-embedding-3-large', 'gpt-4o-realtime-preview', 'o3', 'dall-e-3', 'whisper-1'].map(id => ({ id })) });
    assert.deepEqual((await listModels('openai', { key: 'k' }, { fetchImpl })).map(model => model.id), ['gpt-5', 'o3']);
  });
  it('lists Copilot chat models with tool calling that the plan enables', async () => {
    let seen;
    const fetchImpl = async (url, options) => { seen = { url, options }; return json({ data: [
      { id: 'claude-sonnet-4.5', name: 'Claude Sonnet 4.5', model_picker_enabled: true, capabilities: { type: 'chat', supports: { tool_calls: true } } },
      { id: 'text-embedding-3-small', capabilities: { type: 'embeddings' } },
      { id: 'gpt-old', model_picker_enabled: false, capabilities: { type: 'chat' } },
      { id: 'o1-preview', capabilities: { type: 'chat', supports: { tool_calls: false } } },
      { id: 'gpt-5', policy: { state: 'disabled' }, capabilities: { type: 'chat' } },
      { id: 'gpt-6-sol', model_picker_enabled: true, supported_endpoints: ['/responses'], capabilities: { type: 'chat', supports: { tool_calls: true } } },
    ] }); };
    assert.deepEqual(await listModels('copilot', { key: 'gho' }, { fetchImpl }), [{ id: 'claude-sonnet-4.5', name: 'Claude Sonnet 4.5' }]);
    assert.equal(seen.url, 'https://api.githubcopilot.com/models');
    assert.equal(seen.options.headers.Authorization, 'Bearer gho'); assert.equal(seen.options.headers['Copilot-Integration-Id'], COPILOT_HEADERS['Copilot-Integration-Id']);
  });
  it('explains a missing credential', async () => {
    await assert.rejects(listModels('copilot', { key: '' }), /gh auth login/);
    const dir = home(); fs.mkdirSync(path.join(dir, '.codex')); fs.writeFileSync(path.join(dir, '.codex/auth.json'), JSON.stringify({ auth_mode: 'apikey', OPENAI_API_KEY: 'sk-codex' }));
    assert.deepEqual(await resolveKey('openai', '', { env: {}, home: dir }), { key: 'sk-codex', source: '~/.codex/auth.json (Codex API key)' });
    fs.writeFileSync(path.join(dir, '.codex/auth.json'), JSON.stringify({ auth_mode: 'chatgpt', OPENAI_API_KEY: null, tokens: { access_token: 'subscription' } }));
    assert.equal((await resolveKey('openai', '', { env: {}, home: dir })).key, '', 'ChatGPT-account Codex tokens are never used');
  });
});

describe('Copilot as a review provider', () => {
  it('runs through the OpenAI-compatible path with Copilot headers', async () => {
    const settings = providerRequest({ provider: 'copilot', model: 'claude-sonnet-4.5', copilotToken: 'gho_session' });
    assert.deepEqual({ baseUrl: settings.baseUrl, key: settings.key }, { baseUrl: 'https://api.githubcopilot.com', key: 'gho_session' });
    const original = global.fetch;
    let sent;
    global.fetch = async (url, options) => { sent = { url, options }; return { ok: true, body: (async function* () { yield new TextEncoder().encode('data: {"choices":[{"delta":{"content":"ok"},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n'); })() }; };
    try { await openAiTurn({ ...settings, messages: [], onEvent: () => {} }); } finally { global.fetch = original; }
    assert.equal(sent.url, 'https://api.githubcopilot.com/chat/completions');
    assert.equal(sent.options.headers.Authorization, 'Bearer gho_session'); assert.equal(sent.options.headers['Copilot-Integration-Id'], 'vscode-chat');
  });
});

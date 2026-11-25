'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const { z } = require('zod');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { registerProviderTools } = require('../lib/mcp-provider-tools.cjs');
const { resolveKey } = require('../lib/model-catalog.cjs');
const { bedrockCredential, daybreakBedrockCredential } = require('../lib/bedrock.cjs');

async function fixture(t, integrations) {
  const server = new McpServer({ name: 'provider-test', version: '1' });
  registerProviderTools({ z, integrations, tool: (name, description, inputSchema, action, options = {}) => server.registerTool(name, {
    description, inputSchema, annotations: { readOnlyHint: options.readOnly !== false, openWorldHint: options.openWorld === true },
  }, async input => {
    try { const result = await action(input); return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: { result } }; }
    catch (error) { return { isError: true, content: [{ type: 'text', text: error.message }] }; }
  }) });
  const client = new Client({ name: 'test', version: '1' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await server.close(); });
  await server.connect(serverTransport); await client.connect(clientTransport);
  return { client, call: (name, input = {}) => client.callTool({ name, arguments: input }),
    result: async (name, input = {}) => {
      const response = await client.callTool({ name, arguments: input });
      assert.notEqual(response.isError, true, JSON.stringify(response)); return response.structuredContent.result;
    } };
}
const noFetch = () => { throw new Error('Unexpected network request'); };

it('MCP provider and setup discovery expose source labels and policy without credential objects', async t => {
  const cliCalls = [];
  const f = await fixture(t, {
    credentialSources: async () => ({ openai: 'OPENAI_API_KEY', codex: 'Codex login (ChatGPT)', 'claude-code': 'Claude Code login', token: 'do-not-return' }),
    modelPolicy: () => ({ scan: 'configured-review-model', general: 'configured-chat-model', secret: 'do-not-return' }),
    threatlintCli: async args => { cliCalls.push(args); return { stdout: `setup check\n${JSON.stringify([{ name: 'Semgrep token', configured: true, source: 'OS keyring', fix: 'threatlint semgrep login', token: 'do-not-return' }])}\n` }; },
    fetchImpl: noFetch,
  });
  const providers = await f.result('get_model_providers');
  assert.equal(providers.providers.openai, 'OPENAI_API_KEY'); assert.equal(providers.providers.lmstudio, null);
  assert.deepEqual(providers.modelPolicy, { scan: 'configured-review-model', general: 'configured-chat-model' });
  assert.equal(Object.hasOwn(providers.providers, 'token'), false);
  const setup = await f.result('get_setup_status');
  assert.deepEqual(setup.items, [{ name: 'Semgrep token', configured: true, source: 'OS keyring', fix: 'threatlint semgrep login' }]);
  assert.deepEqual(cliCalls, [['setup', '--check', '--json']]);
  assert.doesNotMatch(JSON.stringify([providers, setup]), /do-not-return/);
  const tools = (await f.client.listTools()).tools;
  assert.ok(tools.every(tool => tool.annotations.readOnlyHint && tool.annotations.openWorldHint));
});

it('MCP model listing resolves environment credentials and returns only usable public models', async t => {
  const requests = [];
  const secret = 'synthetic-environment-secret';
  const f = await fixture(t, {
    resolveKey: (provider, key) => resolveKey(provider, key, { env: { OPENAI_API_KEY: secret } }),
    fetchImpl: async (url, options) => { requests.push({ url, options }); return { ok: true, json: async () => ({ data: [{ id: 'gpt-review' }, { id: 'text-embedding' }, { id: 'gpt-realtime' }, { id: `gpt-${secret}` }] }) }; },
  });
  const result = await f.result('list_models', { provider: 'openai' });
  assert.equal(result.source, 'OPENAI_API_KEY'); assert.equal(requests[0].url, 'https://api.openai.com/v1/models');
  assert.equal(requests[0].options.headers.Authorization, `Bearer ${secret}`);
  assert.ok(result.models.some(model => model.id === 'gpt-review'));
  assert.ok(result.models.every(model => !/realtime|embedding/.test(model.id)));
  assert.doesNotMatch(JSON.stringify(result), new RegExp(secret));
  assert.equal((await f.call('list_models', { provider: 'openai', key: 'x'.repeat(4097) })).isError, true);
  const failing = await fixture(t, { resolveKey: async () => ({ key: secret, source: 'environment' }), fetchImpl: async () => { throw new Error(`request contained ${secret}`); } });
  const failed = await failing.call('list_models', { provider: 'openai' });
  assert.equal(failed.isError, true); assert.doesNotMatch(JSON.stringify(failed), new RegExp(secret));
});

it('MCP CLI models enforce login and retain API-key priority and Daybreak account fallback', async t => {
  const missing = await fixture(t, { codexStatus: async () => ({ installed: false, loggedIn: false }), fetchImpl: noFetch });
  assert.match((await missing.call('list_models', { provider: 'codex' })).content[0].text, /not installed/);
  const signedOut = await fixture(t, { claudeCodeStatus: async () => ({ installed: true, loggedIn: false }), fetchImpl: noFetch });
  assert.match((await signedOut.call('list_models', { provider: 'claude-code' })).content[0].text, /not signed in/);
  const signedIn = await fixture(t, { codexStatus: async () => ({ installed: true, loggedIn: true, source: 'Codex login (ChatGPT)' }),
    claudeCodeStatus: async () => ({ installed: true, loggedIn: true, source: 'Claude Code login' }), resolveKey: async () => ({ key: '', source: null }), fetchImpl: noFetch });
  assert.deepEqual(await signedIn.result('list_models', { provider: 'codex' }), { source: 'Codex login (ChatGPT)', models: [] });
  assert.ok((await signedIn.result('list_models', { provider: 'claude-code' })).models.length);
  const daybreak = await signedIn.result('list_models', { provider: 'daybreak' });
  assert.equal(daybreak.transport, 'codex'); assert.equal(daybreak.source, 'Codex login (ChatGPT)');
  const apiFirst = await fixture(t, { resolveKey: async () => ({ key: 'synthetic-api-key', source: 'session' }),
    codexStatus: () => { throw new Error('API key must remain authoritative'); }, fetchImpl: noFetch });
  const direct = await apiFirst.result('list_models', { provider: 'daybreak', key: 'synthetic-api-key' });
  assert.equal(direct.source, 'session'); assert.equal(direct.transport, undefined);
  assert.doesNotMatch(JSON.stringify(direct), /synthetic-api-key/);
});

it('MCP Bedrock discovery preserves manual model/region behavior and LM Studio validates URLs before fetching', async t => {
  const bedrock = await fixture(t, { resolveKey: (provider, key, options) => (provider === 'daybreak-bedrock' ? daybreakBedrockCredential : bedrockCredential)(key, { env: {}, home: 'missing-test-home', ...options }), fetchImpl: noFetch });
  assert.deepEqual(await bedrock.result('list_models', { provider: 'bedrock', key: 'synthetic-bedrock', bedrockRegion: 'eu-west-1' }),
    { source: 'session', manual: true, region: 'eu-west-1', models: [] });
  const daybreak = await bedrock.result('list_models', { provider: 'daybreak-bedrock', key: 'synthetic-bedrock' });
  assert.equal(daybreak.region, 'us-east-2'); assert.equal(daybreak.manual, false); assert.equal(daybreak.models.length, 1);
  assert.equal((await bedrock.call('list_models', { provider: 'bedrock', bedrockRegion: 'https://evil.example' })).isError, true);
  const urls = [];
  const local = await fixture(t, { fetchImpl: async (url, options) => { urls.push({ url, options }); return { ok: true, json: async () => ({ data: [{ id: 'local-review-model' }, { id: 12 }] }) }; } });
  assert.deepEqual(await local.result('list_models', { provider: 'lmstudio' }), { models: ['local-review-model'] });
  assert.equal(urls[0].url, 'http://localhost:1234/v1/models'); assert.equal(urls[0].options.redirect, 'error');
  for (const baseUrl of ['http://remote.example/v1', 'https://user:secret@model.example/v1', 'https://model.example/v1?token=secret']) {
    assert.equal((await local.call('list_models', { provider: 'lmstudio', baseUrl })).isError, true);
  }
  assert.equal(urls.length, 1, 'invalid URLs never reach the model server');
});

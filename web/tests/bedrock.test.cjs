'use strict';
const { describe, it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { bedrockCredential } = require('../lib/bedrock.cjs');
const { configuredKey, resolveKey, credentialSources, listModels } = require('../lib/model-catalog.cjs');
const { providerRequest, runModel } = require('../lib/pipeline.cjs');
const { runClaude } = require('../lib/providers.cjs');
const { registerWorkspaceRoutes } = require('../lib/routes/workspace.cjs');

const temporary = [];
function home(env = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-bedrock-'));
  temporary.push(dir);
  fs.mkdirSync(path.join(dir, '.claude'));
  fs.writeFileSync(path.join(dir, '.claude/settings.json'), JSON.stringify({ env }));
  return dir;
}
after(() => { for (const dir of temporary) fs.rmSync(dir, { recursive: true, force: true }); });

function environment(values, work) {
  const previous = {};
  for (const [name, value] of Object.entries(values)) {
    previous[name] = process.env[name];
    if (value == null) delete process.env[name]; else process.env[name] = value;
  }
  return Promise.resolve().then(work).finally(() => {
    for (const [name, value] of Object.entries(previous)) {
      if (value == null) delete process.env[name]; else process.env[name] = value;
    }
  });
}

describe('Bedrock credentials and endpoint isolation', () => {
  it('uses session, process environment, then Claude settings without mixing providers', async () => {
    const dir = home({ AWS_BEARER_TOKEN_BEDROCK: 'settings-bedrock', AWS_DEFAULT_REGION: 'ap-southeast-2', ANTHROPIC_API_KEY: 'settings-anthropic' });
    const env = { AWS_BEARER_TOKEN_BEDROCK: 'env-bedrock', ANTHROPIC_API_KEY: 'env-anthropic', ANTHROPIC_AUTH_TOKEN: 'other-token', ANTHROPIC_BASE_URL: 'https://other.example' };
    assert.equal(configuredKey('bedrock', ' typed ', { env, home: dir }).key, 'typed');
    assert.equal((await resolveKey('bedrock', '', { env, home: dir })).source, 'AWS_BEARER_TOKEN_BEDROCK');
    const settings = bedrockCredential('', { env: {}, home: dir });
    assert.equal(settings.source, '~/.claude/settings.json (AWS_BEARER_TOKEN_BEDROCK)');
    assert.equal(settings.key, 'settings-bedrock');
    assert.equal(settings.baseUrl, 'https://bedrock-runtime.ap-southeast-2.amazonaws.com/anthropic');
    assert.equal(bedrockCredential('', { env: { ANTHROPIC_API_KEY: 'wrong', ANTHROPIC_AUTH_TOKEN: 'wrong' }, home: home() }).key, '');
    assert.equal(configuredKey('claude', '', { env: { AWS_BEARER_TOKEN_BEDROCK: 'wrong' }, home: home() }).key, '');
    assert.equal(bedrockCredential('', { env: { BEDROCK_API_KEY: 'alias' }, home: home() }).key, 'alias');
  });

  it('resolves region precedence and rejects host or path injection', () => {
    const dir = home({ AWS_REGION: 'eu-west-1' });
    const options = { home: dir, env: { AWS_REGION: 'us-west-2', AWS_DEFAULT_REGION: 'ap-south-1' } };
    assert.equal(bedrockCredential('key', { ...options, region: 'eu-central-1' }).region, 'eu-central-1');
    assert.equal(bedrockCredential('key', options).region, 'us-west-2');
    assert.equal(bedrockCredential('key', { home: dir, env: { AWS_DEFAULT_REGION: 'ap-south-1' } }).region, 'ap-south-1');
    assert.equal(bedrockCredential('key', { home: dir, env: {} }).region, 'eu-west-1');
    assert.equal(bedrockCredential('key', { home: home(), env: {} }).region, 'us-east-1');
    assert.equal(bedrockCredential('key', { ...options, region: 'cn-north-1' }).baseUrl, 'https://bedrock-runtime.cn-north-1.amazonaws.com.cn/anthropic');
    for (const region of ['us-east-1.evil.test', 'https://evil.test', 'us-east-1/path', 'us-east-1:443', 'us-east-1@evil.test', 'us-east-1\nHeader: injected']) {
      assert.throws(() => bedrockCredential('secret', { ...options, region }), /AWS region/);
    }
  });

  it('exposes source labels only and never probes a guessed model-list API', async () => {
    const sources = await credentialSources({ env: { AWS_BEARER_TOKEN_BEDROCK: 'secret-bedrock', AWS_REGION: 'us-east-1' }, home: home(), run: async () => ({ stdout: '' }), claudeCodeStatus: async () => ({ source: 'Claude Code login' }) });
    assert.equal(sources.bedrock, 'AWS_BEARER_TOKEN_BEDROCK');
    assert.doesNotMatch(JSON.stringify(sources), /secret-bedrock/);
    assert.deepEqual(await listModels('bedrock', { key: 'secret-bedrock' }, { fetchImpl: () => { throw new Error('must not fetch'); } }), []);
    await assert.rejects(listModels('bedrock', { key: '' }), /AWS_BEARER_TOKEN_BEDROCK/);
  });

  it('requires an exact model and keeps Bedrock keys out of the Anthropic route', async () => {
    await environment({ AWS_REGION: 'us-east-1', AWS_BEARER_TOKEN_BEDROCK: '', BEDROCK_API_KEY: '', ANTHROPIC_API_KEY: 'unrelated', ANTHROPIC_AUTH_TOKEN: 'unrelated', ANTHROPIC_BASE_URL: 'https://unrelated.example' }, () => {
      assert.throws(() => providerRequest({ provider: 'bedrock', bedrockApiKey: 'key' }), /Choose a model/);
      const settings = providerRequest({ provider: 'bedrock', bedrockApiKey: 'key', bedrockRegion: 'us-west-2', model: 'global.anthropic.claude-sonnet-5' });
      assert.equal(settings.baseUrl, 'https://bedrock-runtime.us-west-2.amazonaws.com/anthropic');
      assert.equal(settings.key, 'key'); assert.equal(settings.bearer, false);
      assert.equal(settings.model, 'global.anthropic.claude-sonnet-5');
    });
  });
});

function events(content, stopReason = 'end_turn') {
  const chunks = [{ type: 'message_start', message: { id: 'msg_fixture', type: 'message', role: 'assistant', model: 'fixture', content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: 1, output_tokens: 0 } } }];
  if (content.type === 'tool_use') {
    chunks.push({ type: 'content_block_start', index: 0, content_block: { ...content, input: {} } },
      { type: 'content_block_delta', index: 0, delta: { type: 'input_json_delta', partial_json: JSON.stringify(content.input) } });
  } else {
    chunks.push({ type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' } },
      { type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: content.text } });
  }
  chunks.push({ type: 'content_block_stop', index: 0 }, { type: 'message_delta', delta: { stop_reason: stopReason, stop_sequence: null }, usage: { output_tokens: 1 } }, { type: 'message_stop' });
  return chunks;
}

function response(chunks) {
  return new Response(chunks.map(chunk => `event: ${chunk.type}\ndata: ${JSON.stringify(chunk)}\n\n`).join(''), { status: 200, headers: { 'content-type': 'text/event-stream' } });
}

describe('Bedrock native Messages transport', () => {
  it('uses the Bedrock x-api-key, images, history, and read-only tool roundtrip', async () => {
    const root = home(); fs.writeFileSync(path.join(root, 'README.md'), 'Fixture contents');
    const original = global.fetch; const requests = [];
    global.fetch = async (url, options) => {
      requests.push({ url: String(url), options, body: JSON.parse(options.body) });
      return response(requests.length === 1
        ? events({ type: 'tool_use', id: 'tool_fixture', name: 'Read', input: { file_path: 'README.md' } }, 'tool_use')
        : events({ type: 'text', text: '# Complete report' }));
    };
    try {
      await environment({ ANTHROPIC_API_KEY: 'wrong-api-key', ANTHROPIC_AUTH_TOKEN: 'wrong-bearer', ANTHROPIC_BASE_URL: 'https://wrong.example' }, async () => {
        const settings = providerRequest({ provider: 'bedrock', bedrockApiKey: 'bedrock-key', bedrockRegion: 'us-east-1', model: 'global.anthropic.claude-sonnet-5' });
        const report = await runModel({ settings, systemPrompt: 'Required skills', userMessage: 'Inspect fixture', history: [{ role: 'user', content: 'Earlier question' }, { role: 'assistant', content: 'Earlier answer' }], images: [{ mediaType: 'image/png', data: 'cG5n' }], repoPath: root, onEvent: () => {} });
        assert.equal(report, '# Complete report');
      });
    } finally { global.fetch = original; }
    assert.equal(requests.length, 2);
    for (const request of requests) {
      assert.equal(request.url, 'https://bedrock-runtime.us-east-1.amazonaws.com/anthropic/v1/messages');
      const headers = new Headers(request.options.headers);
      assert.equal(headers.get('x-api-key'), 'bedrock-key');
      assert.equal(headers.get('authorization'), null);
      assert.equal(headers.get('anthropic-version'), '2023-06-01');
      assert.equal(request.options.redirect, 'error');
    }
    assert.equal(requests[0].body.system, 'Required skills');
    assert.equal(requests[0].body.messages[0].content, 'Earlier question');
    assert.deepEqual(requests[0].body.messages[2].content[1], { type: 'image', source: { type: 'base64', media_type: 'image/png', data: 'cG5n' } });
    assert.match(requests[1].body.messages.at(-1).content[0].content, /Fixture contents/);
    assert.ok(requests[0].body.tools.some(tool => tool.name === 'Read'));
  });

  it('does not expose an error response containing the key', async () => {
    const original = global.fetch;
    global.fetch = async () => new Response(JSON.stringify({ error: { type: 'authentication_error', message: 'echoed-secret-bedrock' } }), { status: 401, headers: { 'content-type': 'application/json' } });
    try {
      await assert.rejects(runClaude({ key: 'echoed-secret-bedrock', model: 'fixture', baseUrl: 'https://bedrock-runtime.us-east-1.amazonaws.com/anthropic', systemPrompt: 's', userMessage: 'u', onEvent: () => {} }), error => /HTTP 401/.test(error.message) && !error.message.includes('echoed-secret-bedrock'));
    } finally { global.fetch = original; }
  });

  it('rejects a stream that ends before message_stop', async () => {
    const original = global.fetch;
    global.fetch = async () => response(events({ type: 'text', text: 'Partial report' }).slice(0, -1));
    try {
      await assert.rejects(runClaude({ key: 'key', model: 'fixture', baseUrl: 'https://bedrock-runtime.us-east-1.amazonaws.com/anthropic', systemPrompt: 's', userMessage: 'u', onEvent: () => {} }), /Model request failed/);
    } finally { global.fetch = original; }
  });

  it('rejects a response without a completed stop reason', async () => {
    const original = global.fetch;
    global.fetch = async () => response(events({ type: 'text', text: 'Partial report' }, null));
    try {
      await assert.rejects(runClaude({ key: 'key', model: 'fixture', baseUrl: 'https://bedrock-runtime.us-east-1.amazonaws.com/anthropic', systemPrompt: 's', userMessage: 'u', onEvent: () => {} }), /before completing the report/);
    } finally { global.fetch = original; }
  });
});

describe('Bedrock model settings route', () => {
  it('returns manual model entry and source metadata without a key or network request', async () => {
    const routes = new Map();
    const app = { get() {}, delete() {}, post(route, handler) { routes.set(route, handler); } };
    const captured = [];
    registerWorkspaceRoutes(app, { store: { sessions: new Map() }, reports: {}, integrations: {
      resolveKey: async (provider, key, options) => { captured.push({ provider, key, options }); return bedrockCredential(key, { env: {}, home: home(), ...options }); },
      fetchImpl: () => { throw new Error('No model requests during settings'); },
    } });
    let payload;
    let status;
    await routes.get('/api/models')({ body: { provider: 'bedrock', key: 'secret-bedrock', bedrockRegion: 'eu-west-1' } }, { headersSent: false, status(value) { status = value; return this; }, json(body) { payload = body; } });
    assert.equal(status, 200);
    assert.deepEqual(payload, { source: 'session', models: [], manual: true, region: 'eu-west-1' });
    assert.deepEqual(captured[0].options, { region: 'eu-west-1' });
    assert.doesNotMatch(JSON.stringify(payload), /secret-bedrock/);
  });
});

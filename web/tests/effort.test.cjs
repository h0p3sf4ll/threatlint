'use strict';
const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

// Capture Claude requests without a network call: stub the SDK before providers.cjs loads it.
const claudeRequests = [];
const sdkPath = require.resolve('@anthropic-ai/sdk');
require.cache[sdkPath] = { id: sdkPath, filename: sdkPath, loaded: true, exports: class FakeAnthropic {
  constructor() {
    this.messages = { stream: params => {
      claudeRequests.push(params);
      const final = { stop_reason: 'end_turn', content: [{ type: 'text', text: '# Report' }] };
      return { async *[Symbol.asyncIterator]() {}, finalMessage: async () => final };
    } };
  }
} };

const { EFFORT_LEVELS, normalizeEffort } = require('../lib/effort.cjs');
const { normalizePreferences } = require('../lib/model-preferences.cjs');
const { providerRequest } = require('../lib/pipeline.cjs');
const { runClaude, runOpenAi, runResponses } = require('../lib/providers.cjs');
const claudeCode = require('../lib/claude-code.cjs');
const codex = require('../lib/codex.cjs');

const BASE = { provider: 'claude', models: { claude: 'claude-opus-5-5' }, codexDaybreak: false, bedrockRegion: '', lmstudioUrl: 'http://localhost:1234/v1' };

describe('Effort levels', () => {
  it('accepts only the levels each provider supports, and treats empty as the default', () => {
    assert.equal(normalizeEffort('claude', 'MAX'), 'max');
    assert.equal(normalizeEffort('claude-code', 'xhigh'), 'xhigh');
    assert.equal(normalizeEffort('codex', 'xhigh'), 'xhigh');
    assert.equal(normalizeEffort('codex', 'max'), null);
    assert.equal(normalizeEffort('lmstudio', 'xhigh'), null);
    assert.equal(normalizeEffort('openai', ''), '');
    assert.equal(normalizeEffort('openai', undefined), '');
    assert.equal(normalizeEffort('claude', 3), null);
  });

  it('matches the levels offered in the Settings form', () => {
    const app = fs.readFileSync(path.join(__dirname, '../public/app.js'), 'utf8');
    const lists = {};
    for (const [, name, body] of app.matchAll(/(CLAUDE_EFFORTS|OPENAI_EFFORTS|BASIC_EFFORTS) = (\[[^\]]*\])/g)) lists[name] = JSON.parse(body.replace(/'/g, '"'));
    const map = app.match(/const EFFORT_LEVELS = \{([^}]*)\}/)[1];
    const browser = Object.fromEntries(map.split(',').map(entry => entry.split(':').map(part => part.trim().replace(/'/g, ''))).map(([provider, list]) => [provider, lists[list]]));
    assert.deepEqual(browser, { ...EFFORT_LEVELS });
  });
});

describe('Effort preferences', () => {
  it('saves a per-provider effort and drops empty values', () => {
    const saved = normalizePreferences({ ...BASE, efforts: { claude: 'xhigh', codex: '' } });
    assert.deepEqual(saved.efforts, { claude: 'xhigh' });
  });
  it('keeps older preference files without efforts unchanged', () => {
    assert.equal(Object.hasOwn(normalizePreferences(BASE), 'efforts'), false);
  });
  it('rejects unsupported levels and providers', () => {
    assert.throws(() => normalizePreferences({ ...BASE, efforts: { lmstudio: 'max' } }), /supported effort/);
    assert.throws(() => normalizePreferences({ ...BASE, efforts: { unknown: 'low' } }), /effort map/);
    assert.throws(() => normalizePreferences({ ...BASE, efforts: ['low'] }), /effort map/);
  });
});

describe('Effort reaches each provider', () => {
  it('resolves and validates effort in provider requests', () => {
    assert.equal(providerRequest({ provider: 'claude-code', model: 'claude-opus-5-5', effort: 'max' }).effort, 'max');
    assert.equal(Object.hasOwn(providerRequest({ provider: 'claude-code', model: 'claude-opus-5-5' }), 'effort'), false);
    assert.throws(() => providerRequest({ provider: 'lmstudio', lmstudioUrl: 'http://localhost:1234/v1', model: 'local', effort: 'max' }), /effort/);
  });

  it('passes --effort to Claude Code and model_reasoning_effort to Codex', () => {
    const cc = claudeCode.command('claude-opus-5-5', '/tmp/prompt.md', [], 'xhigh');
    assert.deepEqual(cc.slice(cc.indexOf('--effort'), cc.indexOf('--effort') + 2), ['--effort', 'xhigh']);
    assert.equal(claudeCode.command('claude-opus-5-5', '/tmp/prompt.md').includes('--effort'), false);
    const cx = codex.command({ repoPath: '/repo', effort: 'high' });
    assert.ok(cx.includes('model_reasoning_effort="high"'));
    assert.equal(codex.command({ repoPath: '/repo' }).some(arg => arg.startsWith('model_reasoning_effort')), false);
  });

  it('sends output_config.effort with adaptive thinking to Claude only when set', async () => {
    const args = { systemPrompt: 's', userMessage: 'u', model: 'claude-opus-5-5', key: 'k', onEvent: () => {}, execute: async () => '' };
    await runClaude({ ...args, effort: 'max' });
    await runClaude(args);
    assert.deepEqual(claudeRequests[0].output_config, { effort: 'max' });
    assert.deepEqual(claudeRequests[0].thinking, { type: 'adaptive' });
    assert.equal(Object.hasOwn(claudeRequests[1], 'output_config'), false);
    assert.equal(Object.hasOwn(claudeRequests[1], 'thinking'), false);
  });

  it('sends reasoning effort to Chat Completions and Responses endpoints', async () => {
    const bodies = [];
    const server = http.createServer((req, res) => {
      let raw = ''; req.on('data', chunk => { raw += chunk; });
      req.on('end', () => {
        bodies.push({ url: req.url, body: JSON.parse(raw) });
        res.setHeader('Content-Type', 'text/event-stream');
        if (req.url.endsWith('/responses')) {
          const output = [{ type: 'message', content: [{ type: 'output_text', text: '# Report' }] }];
          res.end(`data: ${JSON.stringify({ type: 'response.completed', response: { status: 'completed', output } })}\n\n`);
        } else res.end(`data: ${JSON.stringify({ choices: [{ delta: { content: '# Report' }, finish_reason: 'stop' }] })}\n\ndata: [DONE]\n\n`);
      });
    });
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const baseUrl = `http://127.0.0.1:${server.address().port}`;
    try {
      const args = { baseUrl, model: 'm', key: 'k', systemPrompt: 's', userMessage: 'u', onEvent: () => {}, execute: async () => '' };
      await runOpenAi({ ...args, effort: 'high' });
      await runOpenAi(args);
      await runResponses({ ...args, effort: 'xhigh' });
      assert.equal(bodies[0].body.reasoning_effort, 'high');
      assert.equal(Object.hasOwn(bodies[1].body, 'reasoning_effort'), false);
      assert.deepEqual(bodies[2].body.reasoning, { effort: 'xhigh' });
    } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
  });
});

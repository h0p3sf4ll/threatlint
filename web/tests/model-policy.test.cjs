'use strict';
// Claude model policy: Sonnet for scanning runs, Opus for chat; env/org.json overrides; an explicit model wins.
process.env.THREATLINT_HOME = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-home-'));
const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const policy = require('../lib/model-policy.cjs');
const { providerRequest } = require('../lib/pipeline.cjs');

const ENV = ['THREATLINT_SCAN_MODEL', 'THREATLINT_GENERAL_MODEL'];
const claude = extra => ({ provider: 'claude', apiKey: 'sk-ant-session', ...extra });

describe('Model policy', () => {
  afterEach(() => { for (const name of ENV) delete process.env[name]; fs.rmSync(path.join(process.env.THREATLINT_HOME, 'org.json'), { force: true }); });

  it('defaults scanning to Sonnet and everything else to Opus', () => {
    assert.equal(policy.SCAN_MODEL, 'claude-sonnet-5-5');
    assert.equal(policy.GENERAL_MODEL, 'claude-opus-5-5');
    assert.equal(policy.defaultModel('review'), 'claude-sonnet-5-5');
    assert.equal(policy.defaultModel('chat'), 'claude-opus-5-5');
    assert.deepEqual(policy.modelPolicy(), { scan: 'claude-sonnet-5-5', general: 'claude-opus-5-5' });
  });

  it('uses the policy for Claude review and chat runs when no model is chosen', () => {
    assert.equal(providerRequest(claude({ model: '' })).model, 'claude-sonnet-5-5');
    assert.equal(providerRequest(claude({}), 'review').model, 'claude-sonnet-5-5');
    assert.equal(providerRequest(claude({ model: '  ' }), 'chat').model, 'claude-opus-5-5');
  });

  it('lets an explicit model win over the policy', () => {
    assert.equal(providerRequest(claude({ model: 'claude-haiku-5-5' })).model, 'claude-haiku-5-5');
    assert.equal(providerRequest(claude({ model: 'claude-sonnet-5-5' }), 'chat').model, 'claude-sonnet-5-5');
  });

  it('honours THREATLINT_SCAN_MODEL / THREATLINT_GENERAL_MODEL, then org.json', () => {
    fs.writeFileSync(path.join(process.env.THREATLINT_HOME, 'org.json'), JSON.stringify({ scanModel: 'org-scan', generalModel: 'org-general' }));
    assert.deepEqual(policy.modelPolicy(), { scan: 'org-scan', general: 'org-general' });
    process.env.THREATLINT_SCAN_MODEL = 'env-scan'; process.env.THREATLINT_GENERAL_MODEL = 'env-general';
    assert.equal(providerRequest(claude({})).model, 'env-scan');
    assert.equal(providerRequest(claude({}), 'chat').model, 'env-general');
  });

  it('leaves other providers on their own model choice', () => {
    assert.throws(() => providerRequest({ provider: 'openai', openaiApiKey: 'sk-session', model: '' }), /Choose a model/);
    assert.throws(() => providerRequest({ provider: 'lmstudio', lmstudioUrl: 'http://localhost:1234/v1' }, 'chat'), /Choose a model/);
    assert.equal(providerRequest({ provider: 'copilot', copilotToken: 'gho_session', model: 'gpt-4.1' }).model, 'gpt-4.1');
  });
});

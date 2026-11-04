'use strict';

const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { after, describe, it } = require('node:test');
const claudeCode = require('../lib/claude-code.cjs');
const { providerRequest } = require('../lib/pipeline.cjs');
const CLAUDE_NAME = process.platform === 'win32' ? 'claude.exe' : 'claude';
const fixtureDirs = [];

after(() => {
  for (const dir of fixtureDirs) fs.rmSync(dir, { recursive: true, force: true });
});

/** A PATH holding an executable `claude` stub, so executable() resolves without a real install. */
function fakeInstall() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-claude-bin-'));
  fixtureDirs.push(dir);
  fs.writeFileSync(path.join(dir, CLAUDE_NAME), '#!/bin/sh\n', { mode: 0o755 });
  return { PATH: dir, ANTHROPIC_API_KEY: 'sk-ant-should-not-pass', ANTHROPIC_AUTH_TOKEN: 'token-should-not-pass', HOME: dir };
}

/** spawn() stand-in: records the call, then replays stream-json lines and an exit code. */
function fakeSpawn(lines, { code = 0, stderr = '' } = {}) {
  const calls = [];
  const spawnImpl = (file, args, options) => {
    const child = new EventEmitter();
    child.stdout = new EventEmitter(); child.stderr = new EventEmitter();
    child.kill = signal => { child.killed = signal; };
    child.stdin = { end: input => {
      calls.push({ file, args, options, input, systemPrompt: fs.readFileSync(args[args.indexOf('--system-prompt-file') + 1], 'utf8') });
      setImmediate(() => {
        child.stdout.emit('data', lines.map(line => JSON.stringify(line)).join('\n') + '\n');
        if (stderr) child.stderr.emit('data', stderr);
        child.emit('close', code);
      });
    } };
    return child;
  };
  return { calls, spawnImpl };
}

const RESULT = { type: 'result', subtype: 'success', is_error: false, result: '# Threat model\n\nTM-001 …' };
const CLOUD_ENV = {
  CLAUDE_CODE_USE_BEDROCK: '1', CLAUDE_CODE_USE_MANTLE: '1', CLAUDE_CODE_USE_VERTEX: '1', CLAUDE_CODE_USE_FOUNDRY: '1', CLAUDE_CODE_USE_ANTHROPIC_AWS: '1',
  ANTHROPIC_BASE_URL: 'https://different-provider.example', AWS_BEARER_TOKEN_BEDROCK: 'bedrock-key', BEDROCK_API_KEY: 'other-bedrock-key',
  AWS_ENDPOINT_URL_BEDROCK_RUNTIME: 'https://runtime-override.example', AWS_ENDPOINT_URL_BEDROCK_MANTLE: 'https://mantle-override.example',
};
const LOGIN_ENV = { CLAUDE_CODE_OAUTH_TOKEN: 'subscription-token', NODE_EXTRA_CA_CERTS: '/company/ca.pem', HTTPS_PROXY: 'http://company-proxy:8080' };

function assertLoginEnvironment(actual, original) {
  for (const name of ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', ...Object.keys(CLOUD_ENV)]) assert.equal(actual[name], undefined, name);
  for (const name of ['PATH', 'HOME', ...Object.keys(LOGIN_ENV)]) assert.equal(actual[name], original[name], name);
  assert.equal(actual.CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST, '1', 'settings cannot restore provider or auth overrides');
  assert.equal(original.CLAUDE_CODE_USE_BEDROCK, '1', 'the parent environment is not modified');
}

describe('Claude Code provider', () => {
  it('runs claude -p locked down to read-only tools, without API keys, and returns the report', async () => {
    const env = { ...fakeInstall(), ...CLOUD_ENV, ...LOGIN_ENV };
    const { calls, spawnImpl } = fakeSpawn([
      { type: 'assistant', message: { content: [{ type: 'text', text: 'Looking at the routes.' }, { type: 'tool_use', id: 't1', name: 'Grep', input: { pattern: 'app.get' } }] } },
      { type: 'user', message: { content: [{ type: 'tool_result', tool_use_id: 't1', content: 'src/app.js:4' }] } },
      RESULT,
    ]);
    const events = [];
    const report = await claudeCode.runClaudeCode({ systemPrompt: 'You are the threat modeler.', userMessage: 'Analyze /repo', model: 'claude-opus-5-5', repoPath: os.tmpdir(), onEvent: event => events.push(event), env, spawnImpl });
    assert.equal(report, RESULT.result);
    const [call] = calls;
    for (const flag of ['-p', '--restricted', '--strict-mcp-config', '--no-session-persistence']) assert.ok(call.args.includes(flag), flag);
    assert.equal(call.args[call.args.indexOf('--tools') + 1], 'Read,Grep,Glob');
    assert.equal(call.args[call.args.indexOf('--permission-mode') + 1], 'dontAsk');
    assert.equal(call.args[call.args.indexOf('--model') + 1], 'claude-opus-5-5');
    assert.ok(!call.args.some(arg => arg.includes('threat modeler') || arg.includes('Analyze')), 'prompts never appear in argv');
    assert.equal(call.systemPrompt, 'You are the threat modeler.'); assert.equal(call.input, 'Analyze /repo');
    assert.equal(call.options.env.ANTHROPIC_API_KEY, undefined); assert.equal(call.options.env.ANTHROPIC_AUTH_TOKEN, undefined);
    assertLoginEnvironment(call.options.env, env);
    assert.equal(call.options.cwd, os.tmpdir());
    assert.deepEqual(events.map(event => event.type), ['text_chunk', 'tool_executing', 'tool_result']);
    assert.ok(!fs.existsSync(call.args[call.args.indexOf('--system-prompt-file') + 1]), 'the prompt file is removed');
  });

  it('checks login status with the same provider isolation as agent runs', async () => {
    const env = { ...fakeInstall(), ...CLOUD_ENV, ...LOGIN_ENV };
    let captured;
    const status = await claudeCode.status({ env, execFileImpl: (file, args, options, callback) => {
      captured = { file, args, options };
      callback(null, JSON.stringify({ loggedIn: true, authMethod: 'claude.ai' }));
    } });
    assert.deepEqual(captured.args, ['auth', 'status']);
    assertLoginEnvironment(captured.options.env, env);
    assert.equal(status.loggedIn, true);
    assert.equal(status.source, 'Claude Code login (claude.ai)');
  });

  it('hands images to Claude Code as files in an added directory', async () => {
    const env = fakeInstall();
    const { calls, spawnImpl } = fakeSpawn([RESULT]);
    await claudeCode.runClaudeCode({ systemPrompt: 's', userMessage: 'Model this', images: [{ name: 'board.png', mediaType: 'image/png', data: Buffer.from('png').toString('base64') }], repoPath: os.tmpdir(), env, spawnImpl });
    const [call] = calls;
    const dir = call.args[call.args.indexOf('--add-dir') + 1];
    assert.match(call.input, /Image files \(open each with the Read tool\):\n1\. .*1-board\.png/);
    assert.ok(call.input.includes(dir), 'the listed path is inside the added directory');
  });

  it('folds chat history into the prompt', () => {
    assert.equal(claudeCode.withHistory([{ role: 'user', content: 'Hi' }, { role: 'assistant', content: 'Hello' }], 'Next?'), 'Conversation so far:\n\nUser: Hi\n\nAssistant: Hello\n\nUser: Next?');
  });

  it('finds claude on PATH', () => {
    const env = fakeInstall();
    assert.equal(claudeCode.executable({ env, home: env.HOME }), path.join(env.PATH, CLAUDE_NAME));
  });

  it('explains a missing install, a failed run, and a sign-in problem', async () => {
    await assert.rejects(() => claudeCode.runClaudeCode({ systemPrompt: 's', userMessage: 'u', claudePath: null }), /not installed/);
    const env = fakeInstall();
    await assert.rejects(() => claudeCode.runClaudeCode({ systemPrompt: 's', userMessage: 'u', repoPath: os.tmpdir(), env, spawnImpl: fakeSpawn([{ type: 'result', subtype: 'error_max_turns', is_error: true, result: 'Reached max turns' }], { code: 1 }).spawnImpl }), /Reached max turns/);
    await assert.rejects(() => claudeCode.runClaudeCode({ systemPrompt: 's', userMessage: 'u', repoPath: os.tmpdir(), env, spawnImpl: fakeSpawn([], { code: 1, stderr: 'Invalid API key · Please run /login' }).spawnImpl }), /run `claude` in a terminal to sign in/i);
  });

  it('cancels the child process when the run is aborted', async () => {
    const env = fakeInstall();
    const controller = new AbortController();
    controller.abort();
    await assert.rejects(() => claudeCode.runClaudeCode({ systemPrompt: 's', userMessage: 'u', repoPath: os.tmpdir(), env, signal: controller.signal, spawnImpl: fakeSpawn([RESULT]).spawnImpl }), /cancelled/);
  });

  it('needs no API key and follows the Claude model policy', () => {
    const settings = providerRequest({ provider: 'claude-code' }, 'review');
    assert.equal(settings.provider, 'claude-code'); assert.equal(settings.key, null); assert.equal(settings.model, 'claude-opus-5-5');
  });
});

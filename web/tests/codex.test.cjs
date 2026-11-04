'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { runCodex, status, executable, childEnv, command } = require('../lib/codex.cjs');
const { registerWorkspaceRoutes } = require('../lib/routes/workspace.cjs');

function fakeProcess(events, { exitCode = 0, chunks, noFinalNewline = false } = {}) {
  const child = new EventEmitter();
  child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
  child.killed = false;
  child.kill = () => { child.killed = true; return true; };
  child.stdin.on('data', part => { child.prompt = (child.prompt || '') + part.toString(); });
  process.nextTick(() => {
    const bytes = Buffer.from(events.map(event => JSON.stringify(event)).join('\n') + (noFinalNewline ? '' : '\n'));
    for (const chunk of chunks || [bytes]) child.stdout.write(typeof chunk === 'number' ? bytes.subarray(chunk, chunk + 1) : chunk);
    if (chunks && chunks.every(chunk => typeof chunk === 'number')) {
      const covered = new Set(chunks);
      for (let index = 0; index < bytes.length; index++) if (!covered.has(index)) child.stdout.write(bytes.subarray(index, index + 1));
    }
    child.stdout.end(); child.stderr.end(); child.emit('close', exitCode);
  });
  return child;
}

test('Codex executable resolution uses PATH, then the bundled ChatGPT app', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-codex-path-'));
  try {
    const pathBinary = path.join(root, 'codex'); fs.writeFileSync(pathBinary, '#!/bin/sh\n'); fs.chmodSync(pathBinary, 0o755);
    const bundle = path.join(root, 'bundle-codex'); fs.writeFileSync(bundle, '#!/bin/sh\n'); fs.chmodSync(bundle, 0o755);
    assert.equal(executable({ env: { PATH: root }, home: path.join(root, 'empty'), platform: 'darwin', appPath: bundle }), pathBinary);
    assert.equal(executable({ env: { PATH: '' }, home: path.join(root, 'empty'), platform: 'darwin', appPath: bundle }), bundle);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test('Codex login status is obtained through the CLI with only the required environment', async () => {
  const invoked = [];
  const env = { OPENAI_API_KEY: 'secret', SERVICENOW_CLIENT_SECRET: 'secret2', GH_TOKEN: 'secret3',
    CODEX_HOME: '/home/codex', HOME: '/home/user', PATH: '/usr/bin', HTTPS_PROXY: 'https://proxy.test' };
  const result = await status({ codexPath: '/fake/codex', env,
    execFileImpl(file, args, options, callback) { invoked.push({ file, args, options }); callback(null, 'Logged in using ChatGPT\n', ''); } });
  assert.equal(result.source, 'Codex login (ChatGPT)');
  assert.deepEqual(invoked[0].args, ['login', 'status']);
  assert.equal(invoked[0].options.env.CODEX_HOME, '/home/codex');
  assert.equal(invoked[0].options.env.HOME, '/home/user');
  assert.equal(invoked[0].options.env.HTTPS_PROXY, 'https://proxy.test');
  assert.equal(invoked[0].options.env.OPENAI_API_KEY, undefined);
  assert.equal(invoked[0].options.env.SERVICENOW_CLIENT_SECRET, undefined);
  assert.equal(invoked[0].options.env.GH_TOKEN, undefined);
  assert.equal(childEnv(env).CODEX_HOME, '/home/codex');
});

test('Codex login status recognizes successful output on stderr', async () => {
  const result = await status({ codexPath: '/fake/codex',
    execFileImpl(_file, _args, _options, callback) { callback(null, '', 'Logged in using ChatGPT\n'); } });
  assert.equal(result.loggedIn, true);
  assert.equal(result.source, 'Codex login (ChatGPT)');
});

test('Codex command is ephemeral, read-only, and uses explicit Daybreak choice', () => {
  const args = command({ repoPath: '/repo', model: '', daybreakBlue: true });
  assert.deepEqual(args.slice(0, 9), ['exec', '--json', '--ephemeral', '--sandbox', 'read-only', '--ignore-user-config', '--skip-git-repo-check', '-C', '/repo']);
  assert.ok(args.includes('daybreak=true'));
  assert.ok(!args.includes('--model'));
  assert.equal(args.at(-1), '-');
  assert.ok(command({ repoPath: '/repo', model: 'gpt-6-sol', daybreakBlue: false }).includes('daybreak=false'));
});

test('Codex provider returns the final report from a completed JSONL turn', async () => {
  const events = [
    { type: 'item.completed', item: { id: 'm1', type: 'agent_message', text: 'Investigating…' } },
    { type: 'item.completed', item: { id: 'm2', type: 'agent_message', text: '# Report π' } },
    { type: 'turn.completed', turn: { status: 'completed' } },
  ];
  let child;
  const progress = [];
  const report = await runCodex({ systemPrompt: 'System rules', userMessage: 'Review this repo', repoPath: '/repo', codexPath: '/fake/codex',
    env: { OPENAI_API_KEY: 'secret', SERVICENOW_CLIENT_SECRET: 'secret2', CODEX_HOME: '/home/codex' }, onEvent: event => progress.push(event),
    spawnImpl(file, args, options) {
      assert.equal(file, '/fake/codex'); assert.equal(options.env.OPENAI_API_KEY, undefined);
      assert.equal(options.env.SERVICENOW_CLIENT_SECRET, undefined);
      assert.equal(options.env.CODEX_HOME, '/home/codex');
      const bytes = Buffer.from(events.map(event => JSON.stringify(event)).join('\n'));
      child = fakeProcess(events, { chunks: [bytes.subarray(0, bytes.indexOf(Buffer.from('π')) + 1), bytes.subarray(bytes.indexOf(Buffer.from('π')) + 1)], noFinalNewline: true });
      return child;
    } });
  assert.equal(report, '# Report π');
  assert.match(child.prompt, /System rules/);
  assert.match(child.prompt, /Review this repo/);
  assert.ok(progress.some(event => event.type === 'text_chunk' && event.text === '# Report π'));
});

test('Codex provider rejects invalid JSONL and terminates the child', async () => {
  let child;
  await assert.rejects(runCodex({ systemPrompt: 'Rules', userMessage: 'Review', repoPath: '/repo', codexPath: '/fake/codex',
    spawnImpl() {
      child = new EventEmitter(); child.stdin = new PassThrough(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
      child.killed = false; child.kill = () => { child.killed = true; return true; };
      process.nextTick(() => { child.stdout.write('invalid JSON\n'); child.emit('close', 1); });
      return child;
    } }), /invalid event stream/);
  assert.equal(child.killed, true);
});

test('Codex model route reports login status without returning a key or querying models', async () => {
  const routes = new Map();
  const app = { get() {}, delete() {}, post(route, handler) { routes.set(route, handler); } };
  registerWorkspaceRoutes(app, { store: { sessions: new Map() }, reports: {}, integrations: {
    codexStatus: async () => ({ installed: true, loggedIn: true, source: 'Codex login (ChatGPT)' }),
    resolveKey: () => { throw new Error('Codex must not resolve an API key'); },
    fetchImpl: () => { throw new Error('Codex must not query a model API'); },
  } });
  let payload, statusCode;
  await routes.get('/api/models')({ body: { provider: 'codex' } },
    { headersSent: false, status(code) { statusCode = code; return this; }, json(body) { payload = body; } });
  assert.equal(statusCode, 200);
  assert.deepEqual(payload, { source: 'Codex login (ChatGPT)', models: [] });
});

'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const fs = require('node:fs');
const os = require('node:os');
const { superviseChild } = require('../lib/child-lifecycle.cjs');
const { runCodex } = require('../lib/codex.cjs');
const { runClaudeCode } = require('../lib/claude-code.cjs');
const avit = require('../lib/avit-batch.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));

function child() {
  const process = new EventEmitter();
  Object.assign(process, { pid: 12345, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), signals: [] });
  process.kill = signal => { process.signals.push(signal); return true; };
  return process;
}

for (const [name, run] of [['Codex', runCodex], ['Claude Code', runClaudeCode]]) {
  test(`${name} cancellation retains inputs and waits for confirmed child close`, async () => {
    const process = child(), controller = new AbortController();
    let resource, settled = false;
    const pending = run({ systemPrompt: 'fixture', userMessage: 'fixture', repoPath: os.tmpdir(), codexPath: '/fake/codex', claudePath: '/fake/claude', signal: controller.signal,
      images: [{ name: 'fixture.png', data: Buffer.from('synthetic fixture').toString('base64') }],
      spawnImpl: (_file, args) => { resource = args[args.indexOf(name === 'Codex' ? '--image' : '--system-prompt-file') + 1]; return process; } });
    const checked = assert.rejects(pending, /cancelled/).then(() => { settled = true; });
    controller.abort(); await tick();
    assert.deepEqual(process.signals, ['SIGTERM']); assert.equal(settled, false); assert.ok(fs.existsSync(resource));
    process.emit('close', null); await checked;
    assert.equal(fs.existsSync(resource), false);
  });
}

test('Python scanner subprocess cancellation waits for close before cleanup can run', async t => {
  t.mock.method(avit, 'python', () => '/fake/python');
  const process = child(), controller = new AbortController(); let settled = false;
  const pending = avit.runCli(['dojo', 'checkout', 'DOJO-1'], { signal: controller.signal, spawnImpl: () => process });
  const checked = assert.rejects(pending, /cancelled/).then(() => { settled = true; });
  controller.abort(); await tick(); assert.equal(settled, false);
  process.emit('close', null); await checked;
});

test('timeout escalates TERM to KILL but does not claim exit until close', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const process = child(); let settled = false;
  const pending = new Promise((resolve, reject) => superviseChild(process, { timeoutMs: 10, killGraceMs: 5, timeoutMessage: 'fixture timeout',
    startMessage: 'fixture start error', resolve, reject, onClose: (_code, finish) => finish(null, 'done') }));
  const checked = assert.rejects(pending, /fixture timeout/).then(() => { settled = true; });
  t.mock.timers.tick(10); assert.deepEqual(process.signals, ['SIGTERM']);
  t.mock.timers.tick(5); assert.deepEqual(process.signals, ['SIGTERM', 'SIGKILL']);
  await Promise.resolve(); assert.equal(settled, false);
  process.emit('close', null); await checked;
});

test('spawn failure without a pid rejects promptly and removes timers', async () => {
  const process = child(); delete process.pid;
  const pending = new Promise((resolve, reject) => superviseChild(process, { timeoutMs: 10000, timeoutMessage: 'timeout',
    startMessage: 'fixture failed to start', resolve, reject, onClose: () => assert.fail('no child') }));
  process.emit('error', new Error('credentials must not be echoed'));
  await assert.rejects(pending, /fixture failed to start/);
});

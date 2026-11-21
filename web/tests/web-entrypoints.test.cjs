'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { fork } = require('node:child_process');
const { profileEnvironment } = require('../lib/profile-workers.cjs');
const { createAuth } = require('../lib/web-auth.cjs');

const WORKER = path.join(__dirname, '../profile-worker.cjs');

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-entrypoints-'));
  const workers = [];
  t.after(async () => { for (const worker of workers) await worker.stop(); fs.rmSync(root, { recursive: true, force: true }); });
  return { root, workers };
}

async function startWorker(home, token) {
  // Exercise the same stdin secret exchange used by the container entrypoint, retaining IPC for readiness.
  const child = fork(WORKER, [], { cwd: home, env: { ...profileEnvironment(home), THREATLINT_WORKER_STDIN: '1',
    TEMP: os.tmpdir(), TMP: os.tmpdir(), TMPDIR: os.tmpdir() }, silent: true, windowsHide: true, execArgv: [] });
  let output = '';
  child.stdout.on('data', data => { output += data.toString(); });
  child.stderr.on('data', data => { output += data.toString(); });
  const ready = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { child.kill(); reject(new Error('Entrypoint startup timed out')); }, 15000);
    child.once('message', message => { clearTimeout(timeout); message.type === 'ready' ? resolve(message.port) : reject(new Error('Worker rejected configuration')); });
    child.once('error', error => { clearTimeout(timeout); reject(error); });
    child.once('exit', () => { clearTimeout(timeout); reject(new Error('Worker exited before readiness')); });
  });
  child.stdin.end(`${JSON.stringify({ token })}\n`);
  const port = await ready, base = `http://127.0.0.1:${port}`;
  async function stop() {
    if (child.exitCode !== null || child.signalCode !== null) return;
    await new Promise(resolve => {
      const timeout = setTimeout(() => child.kill(), 3000);
      child.once('exit', () => { clearTimeout(timeout); resolve(); });
      child.send({ action: 'close' }, () => {});
    });
  }
  async function call(route, { method = 'GET', secret = token, json } = {}) {
    const response = await fetch(`${base}${route}`, { method, headers: { Origin: base,
      ...(secret === null ? {} : { 'x-threatlint-worker': secret }), ...(json === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(json === undefined ? {} : { body: JSON.stringify(json) }) });
    return { status: response.status, body: await response.json() };
  }
  return { stop, call, output: () => output };
}

it('boots a profile from stdin, gates its port, and restores durable state with a rotated gateway secret', async t => {
  const { root, workers } = fixture(t), firstToken = crypto.randomBytes(32).toString('hex');
  const first = await startWorker(root, firstToken); workers.push(first);
  assert.equal((await first.call('/api/agents', { secret: null })).status, 403);
  assert.equal((await first.call('/api/agents', { secret: 'forged' })).status, 403);
  const catalog = await first.call('/api/agents');
  assert.equal(catalog.status, 200); assert.ok(catalog.body.length > 0);
  const temporary = path.join(root, 'tmp'), checkout = path.join(temporary, 'persistent-checkout');
  assert.ok(fs.statSync(temporary).isDirectory());
  fs.mkdirSync(checkout); fs.writeFileSync(path.join(checkout, 'durable.txt'), 'private repository fixture');
  const session = await first.call('/api/session/local', { method: 'POST', json: { repoPath: checkout } });
  assert.equal(session.status, 200);
  const preferences = { provider: 'codex', models: { codex: 'fixture-model' }, codexDaybreak: false,
    bedrockRegion: '', lmstudioUrl: 'http://localhost:1234/v1' };
  assert.equal((await first.call('/api/model-preferences', { method: 'PUT', json: preferences })).status, 200);
  await first.stop();
  assert.equal(first.output().includes(firstToken), false);
  const secondToken = crypto.randomBytes(32).toString('hex'), second = await startWorker(root, secondToken); workers.push(second);
  assert.equal((await second.call('/api/agents', { secret: firstToken })).status, 403);
  assert.equal((await second.call('/api/agents')).status, 200);
  assert.deepEqual((await second.call('/api/model-preferences')).body.preferences, preferences);
  assert.equal((await second.call(`/api/session/${session.body.sessionId}`)).body.repoPath, fs.realpathSync(checkout));
  assert.equal(fs.readFileSync(path.join(checkout, 'durable.txt'), 'utf8'), 'private repository fixture');
  await second.stop();
  assert.equal(second.output().includes(secondToken), false);
});

it('ships federated sign-in without local account creation commands or credential forms', t => {
  const { root } = fixture(t);
  assert.equal(fs.existsSync(path.join(__dirname, '../scripts/web-create-user.cjs')), false);
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8'));
  assert.equal(Object.hasOwn(manifest.scripts, 'web:create-user'), false);
  const auth = createAuth({ directory: root });
  assert.equal(typeof auth.establish, 'function');
  assert.equal(Object.hasOwn(auth, 'register'), false); assert.equal(Object.hasOwn(auth, 'login'), false);
  const html = fs.readFileSync(path.join(__dirname, '../public/login.html'), 'utf8');
  assert.doesNotMatch(html, /<input[^>]*type=["']password["']/i);
  assert.doesNotMatch(html, /<form[^>]*action=["']\/auth\/(?:login|register)["']/i);
});

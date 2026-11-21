'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const WebSocket = require('ws');
const { createWorkbench } = require('../server.js');
const { createRuntimeScanner } = require('../lib/runtime.cjs');

function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return { promise, resolve }; }
async function eventually(check) {
  for (let index = 0; index < 100; index++) { if (await check()) return; await new Promise(resolve => setTimeout(resolve, 10)); }
  throw new Error('Background operation did not settle');
}
async function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-activity-')), token = crypto.randomBytes(32).toString('hex');
  const previous = { THREATLINT_PROFILE_WORKER: process.env.THREATLINT_PROFILE_WORKER,
    THREATLINT_WORKER_TOKEN: process.env.THREATLINT_WORKER_TOKEN, THREATLINT_HOME: process.env.THREATLINT_HOME };
  Object.assign(process.env, { THREATLINT_PROFILE_WORKER: '1', THREATLINT_WORKER_TOKEN: token, THREATLINT_HOME: path.join(root, 'home') });
  const workbench = createWorkbench({ storageDir: root, ...options });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${workbench.server.address().port}`;
  t.after(async () => {
    await workbench.close();
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    fs.rmSync(root, { recursive: true, force: true });
  });
  async function call(route, { method = 'GET', json, secret = token } = {}) {
    const response = await fetch(`${base}${route}`, { method, headers: { Origin: base,
      ...(secret === null ? {} : { 'x-threatlint-worker': secret }), ...(json === undefined ? {} : { 'Content-Type': 'application/json' }) },
      ...(json === undefined ? {} : { body: JSON.stringify(json) }) });
    return { status: response.status, body: await response.json() };
  }
  const connect = async () => {
    const ws = new WebSocket(base.replace('http:', 'ws:'), { origin: base, headers: { 'x-threatlint-worker': token } });
    await new Promise((resolve, reject) => { ws.once('open', resolve); ws.once('error', reject); });
    return ws;
  };
  return { root, token, base, call, connect, workbench };
}

it('keeps activity private to authenticated profile workers and includes active runtime work', async t => {
  let active = false;
  const f = await fixture(t, { runtimeScanner: { get active() { return active; }, close: async () => {} } });
  assert.equal((await f.call('/internal/activity', { secret: null })).status, 403);
  assert.equal((await f.call('/internal/activity', { secret: 'forged' })).status, 403);
  assert.deepEqual((await f.call('/internal/activity')).body, { busy: false });
  active = true; assert.deepEqual((await f.call('/internal/activity')).body, { busy: true });
  active = false;
  delete process.env.THREATLINT_PROFILE_WORKER;
  try { assert.equal((await f.call('/internal/activity')).status, 404); }
  finally { process.env.THREATLINT_PROFILE_WORKER = '1'; }
});

it('keeps detached and cancelling Sidekick jobs busy until their subprocess work settles', async t => {
  const done = deferred(), f = await fixture(t, { integrations: { sidekickCli: () => done.promise } });
  const started = await f.call('/api/sidekick/jobs', { method: 'POST', json: { kind: 'report', loadout: 'Activity Test' } });
  assert.equal(started.status, 200); assert.deepEqual((await f.call('/internal/activity')).body, { busy: true });
  await f.call(`/api/sidekick/jobs/${started.body.jobId}/cancel`, { method: 'POST', json: {} });
  assert.deepEqual((await f.call('/internal/activity')).body, { busy: true });
  done.resolve({ code: 1, error: 'Cancelled fixture' });
  await eventually(async () => !(await f.call('/internal/activity')).body.busy);
});

it('keeps a normal async command busy after its HTTP caller disconnects', async t => {
  const entered = deferred(), command = deferred();
  const f = await fixture(t, { integrations: { sidekickCli: async () => { entered.resolve(); return command.promise; } } });
  const request = http.get(`${f.base}/api/sidekick/orgs`, { headers: { 'x-threatlint-worker': f.token } });
  request.on('error', () => {});
  await entered.promise; request.destroy();
  assert.deepEqual((await f.call('/internal/activity')).body, { busy: true });
  command.resolve({ code: 0, json: [] });
  await eventually(async () => !(await f.call('/internal/activity')).body.busy);
});

it('keeps queued scan imports busy through final report conversion after the upload responds', async t => {
  const conversion = deferred(), f = await fixture(t, { integrations: { convertToWord: () => conversion.promise } });
  const content = fs.readFileSync(path.join(__dirname, 'fixtures/scan-import/invicti.json')).toString('base64');
  const upload = await f.call('/api/scan-import', { method: 'POST', json: { filename: 'fixture.json', content } });
  assert.equal(upload.status, 201); assert.deepEqual((await f.call('/internal/activity')).body, { busy: true });
  conversion.resolve();
  await eventually(async () => !(await f.call('/internal/activity')).body.busy);
  assert.equal((await f.call(`/api/scan-import/${upload.body.id}`)).body.status, 'done');
});

for (const cancel of [false, true]) it(`keeps detached security scans busy until ${cancel ? 'cancelled' : 'completed'} subprocess work settles`, async t => {
  const entered = deferred(), completion = deferred();
  let signal;
  const f = await fixture(t, { integrations: {
    semgrepVersion: async () => '1.99.0',
    securityScannerCli: async (_args, options) => { signal = options.signal; entered.resolve(); return completion.promise; },
  } });
  try {
    const session = await f.call('/api/session/local', { method: 'POST', json: { repoPath: f.root } });
    assert.equal(session.status, 200);
    const started = await f.call('/api/security-scanner/scans', { method: 'POST', json: { sessionId: session.body.sessionId } });
    assert.equal(started.status, 202);
    await entered.promise;
    assert.deepEqual((await f.call('/internal/activity')).body, { busy: true });
    if (cancel) {
      assert.equal((await f.call(`/api/security-scanner/scans/${started.body.id}/cancel`, { method: 'POST', json: {} })).status, 200);
      assert.equal(signal.aborted, true);
      assert.deepEqual((await f.call('/internal/activity')).body, { busy: true }, 'Cancellation must keep the worker alive until its subprocess has settled');
    }
    completion.resolve(cancel ? { code: 1, stdout: '', stderr: '' } : { code: 0, stdout: JSON.stringify({
      status: 'completed', binding: { repository: fs.realpathSync(f.root), branch: 'main', commit: 'a'.repeat(40), contentDigest: 'b'.repeat(64) },
      findings: [], coverage: { status: 'completed' }, engines: [],
    }), stderr: '' });
    await eventually(async () => !(await f.call('/internal/activity')).body.busy);
    assert.equal((await f.call(`/api/security-scanner/scans/${started.body.id}`)).body.status, cancel ? 'cancelled' : 'completed');
  } finally { completion.resolve({ code: 1, stdout: '', stderr: '' }); }
});

it('keeps disconnected pipeline cleanup busy after its WebSocket lease ends', async t => {
  const started = deferred(), completion = deferred();
  const f = await fixture(t, { runProvider: async () => { started.resolve(); await completion.promise; return '# Fixture report'; },
    integrations: { semgrepVersion: async () => '1.99.0' } });
  const session = await f.call('/api/session/local', { method: 'POST', json: { repoPath: f.root } });
  const ws = await f.connect();
  ws.send(JSON.stringify({ action: 'run_pipeline', sessionId: session.body.sessionId, provider: 'lmstudio', model: 'fixture', agentIds: ['appsec-code-reviewer'] }));
  await started.promise;
  assert.deepEqual((await f.call('/internal/activity')).body, { busy: true });
  const closed = new Promise(resolve => ws.once('close', resolve)); ws.terminate(); await closed;
  assert.deepEqual((await f.call('/internal/activity')).body, { busy: true });
  completion.resolve();
  await eventually(async () => !(await f.call('/internal/activity')).body.busy);
});

it('preserves detached AVIT work after the starting connection closes', async t => {
  const setup = deferred(), entered = deferred();
  const f = await fixture(t, { integrations: { semgrepVersion: async () => '1.99.0', threatlintCli: async args => {
    if (args[0] === 'setup') { entered.resolve(); await setup.promise; return { code: 0, stdout: '[]', stderr: '' }; }
    return { code: 1, stdout: '', stderr: 'Fixture stops before external integration work' };
  } } });
  const ws = await f.connect();
  ws.send(JSON.stringify({ action: 'run_avit_batch', avits: 'AVIT000000000000001', provider: 'lmstudio', model: 'fixture', createFixPr: false }));
  await entered.promise;
  const closed = new Promise(resolve => ws.once('close', resolve)); ws.terminate(); await closed;
  assert.deepEqual((await f.call('/internal/activity')).body, { busy: true });
  setup.resolve(); await eventually(async () => !(await f.call('/internal/activity')).body.busy);
});

it('reports real runtime scans and unexpired browser authentication sessions as active', async () => {
  const response = deferred(), requestStarted = deferred();
  const scanner = createRuntimeScanner({ request: async () => { requestStarted.resolve(); return response.promise; },
    browserFactory: async () => ({ newContext: async () => ({ newPage: async () => ({ goto: async () => {} }), cookies: async () => [{ name: 'fixture', value: 'cookie' }] }), close: async () => {} }) });
  const config = { target: 'http://127.0.0.1:12345', paths: ['/'], authorization: { confirmed: true, allowPrivate: true, reason: 'Owned fixture' },
    checks: { compareAnonymous: false }, limits: { delayMs: 0, maxRequests: 1 } };
  try {
    assert.equal(scanner.active, false); scanner.start(config); await requestStarted.promise; assert.equal(scanner.active, true);
    response.resolve({ status: 200, headers: {}, body: '', durationMs: 1, bytes: 0 });
    await eventually(() => !scanner.active);
    const browser = await scanner.startBrowser(config); assert.equal(scanner.active, true);
    await scanner.finishBrowser(browser.id); assert.equal(scanner.active, true, 'The retained browser-session cookie is needed for a following scan');
  } finally { await scanner.close(); }
  assert.equal(scanner.active, false);
});

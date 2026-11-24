'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
const { PassThrough } = require('node:stream');
const { createAwsParameters, FIELDS, verificationUrl } = require('../lib/aws-parameters.cjs');
const { requiredPermission } = require('../lib/rbac.cjs');

function fixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-aws-test-'));
  const env = { OPENAI_API_KEY: 'previous-key' };
  const manager = createAwsParameters({ directory, env, cli: async () => ({ code: 0, stdout: JSON.stringify({ cliAvailable: true, profiles: ['fixture'], browsers: [{ id: 'chrome', label: 'Google Chrome' }] }) }), ...options });
  t.after(() => { manager.close(); fs.rmSync(directory, { recursive: true, force: true }); });
  const settings = parameters => ({ profile: 'fixture', region: 'us-east-2', autoLoad: false, parameters: { ...Object.fromEntries(FIELDS.map(f => [f.key, ''])), ...parameters } });
  return { directory, env, manager, settings };
}
test('only references are persisted and returned; decrypted values stay in the session environment', async t => {
  const calls = [];
  const f = fixture(t, { readParameters: async (names, options) => { calls.push({ names, options }); return { '/fixture/openai': 'synthetic-secret-key', '/fixture/snow': 'synthetic-client-secret' }; } });
  f.manager.save(f.settings({ OPENAI_API_KEY: '/fixture/openai', THREATLINT_SNOW_CLIENT_SECRET: '/fixture/snow' }));
  const result = await f.manager.pull();
  assert.equal(f.env.OPENAI_API_KEY, 'synthetic-secret-key');
  assert.equal(f.env.THREATLINT_SNOW_CLIENT_SECRET, 'synthetic-client-secret');
  assert.equal(result.loadedCount, 2);
  assert.deepEqual(calls[0].options, { profile: 'fixture', region: 'us-east-2' });
  const serialized = JSON.stringify(result) + fs.readFileSync(path.join(f.directory, 'aws-parameters.json'), 'utf8');
  assert.equal(serialized.includes('synthetic-secret'), false);
  if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(f.directory, 'aws-parameters.json')).mode & 0o777, 0o600);
  f.manager.close(); assert.equal(f.env.OPENAI_API_KEY, 'previous-key'); assert.equal(f.env.THREATLINT_SNOW_CLIENT_SECRET, undefined);
});
test('failed reload is atomic and AWS diagnostics do not expose secrets', async t => {
  let fail = false;
  const f = fixture(t, { readParameters: async () => { if (fail) throw new Error('AWS stderr synthetic-secret'); return { '/fixture/key': 'loaded-key' }; } });
  const saved = f.settings({ OPENAI_API_KEY: '/fixture/key' });
  f.manager.save(saved); await f.manager.pull();
  f.manager.save(saved); fail = true;
  await assert.rejects(f.manager.pull(), e => !e.message.includes('synthetic-secret'));
  assert.equal(f.env.OPENAI_API_KEY, 'loaded-key');
  f.manager.save(f.settings({})); assert.equal(f.env.OPENAI_API_KEY, 'previous-key');
});
test('loaded parameters are consumed by ServiceNow and model providers without exposing secrets in status', async t => {
  const previousHome = process.env.THREATLINT_HOME;
  const f = fixture(t, { env: process.env, readParameters: async () => ({ '/fixture/openai': 'synthetic-model-key', '/fixture/snow': 'synthetic-snow-secret' }) });
  process.env.THREATLINT_HOME = f.directory;
  t.after(() => { if (previousHome === undefined) delete process.env.THREATLINT_HOME; else process.env.THREATLINT_HOME = previousHome; });
  f.manager.save(f.settings({ OPENAI_API_KEY: '/fixture/openai', THREATLINT_SNOW_CLIENT_SECRET: '/fixture/snow' }));
  await f.manager.pull();
  const config = require('../lib/threatlint-config.cjs');
  assert.equal(config.readServiceNow().clientSecret, 'synthetic-snow-secret');
  assert.equal(config.publicServiceNow().hasSecret, true);
  assert.equal(JSON.stringify(config.publicServiceNow()).includes('synthetic-snow-secret'), false);
  assert.equal(require('../lib/model-catalog.cjs').configuredKey('openai').key, 'synthetic-model-key');
});
test('missing values never partly replace a credential set and names are read in batches of ten', async t => {
  const sizes = [];
  const f = fixture(t, { readParameters: async names => { sizes.push(names.length); return Object.fromEntries(names.filter(n => !n.endsWith('/14')).map(n => [n, 'synthetic-value'])); } });
  f.manager.save(f.settings(Object.fromEntries(FIELDS.map((field, i) => [field.key, `/fixture/${i}`]))));
  await assert.rejects(f.manager.pull());
  assert.deepEqual(sizes, [10, 5]); assert.equal(f.env.OPENAI_API_KEY, 'previous-key'); assert.equal(f.env.THREATLINT_SNOW_CLIENT_SECRET, undefined);
});
test('rejects arbitrary environment binding, shell input, invalid profiles, and hosted access', async t => {
  const f = fixture(t);
  assert.throws(() => f.manager.save(f.settings({ NODE_OPTIONS: '/fixture/unsafe' })));
  assert.throws(() => f.manager.save(f.settings({ OPENAI_API_KEY: '/x;touch /tmp/unsafe' })));
  assert.throws(() => f.manager.save({ ...f.settings({}), profile: '--endpoint-url=evil' }));
  f.env.THREATLINT_PROFILE_WORKER = '1';
  assert.equal((await f.manager.status()).available, false);
  assert.throws(() => f.manager.login({}), e => e.status === 403);
  await assert.rejects(f.manager.pull(), e => e.status === 403);
  for (const verb of ['GET', 'PUT', 'POST', 'DELETE']) assert.equal(requiredPermission(verb, '/api/aws/settings'), 'manageSettings');
});
test('accepts only AWS device verification URLs for manual private-window handoff', () => {
  assert.ok(verificationUrl('https://example.awsapps.com/start/#/device?user_code=ABCD-EFGH'));
  assert.ok(verificationUrl('https://device.sso.us-east-2.amazonaws.com/?user_code=ABCD-EFGH'));
  for (const value of ['https://example.awsapps.com.evil.test/start/#/device', 'http://example.awsapps.com/start/#/device', 'https://user:pass@example.awsapps.com/start/#/device', 'https://example.awsapps.com/redirect', 'javascript:alert(1)']) assert.equal(verificationUrl(value), '');
});
test('private login progress is bounded, redacted, and automatically loads after authentication', async t => {
  let child, command;
  const f = fixture(t, { python: 'python-fixture', pythonPath: '/fixture/python',
    spawnImpl: (file, args, options) => {
      command = { file, args, options }; child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough();
      child.kill = () => { child.emit('close', 1); return true; }; return child;
    }, readParameters: async () => ({ '/fixture/key': 'synthetic-aws-key' }) });
  f.manager.save(f.settings({ OPENAI_API_KEY: '/fixture/key' }));
  f.manager.login({ browser: 'edge' });
  assert.ok(command.args.includes('--events')); assert.ok(command.args.includes('edge'));
  assert.throws(() => f.manager.login({}), e => e.status === 409);
  await assert.rejects(f.manager.pull(), e => e.status === 409);
  child.stderr.write('synthetic-aws-secret');
  child.stdout.write(JSON.stringify({ state: 'awaiting_sign_in', browser: 'Microsoft Edge', verificationUrl: 'https://evil.test' }) + '\n');
  assert.equal(f.manager.view().verificationUrl, '');
  child.stdout.write('{"state":"authenticated"}\n'); child.emit('close', 0);
  for (let i = 0; i < 20 && f.manager.view().state !== 'ready'; i++) await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.manager.view().state, 'ready'); assert.equal(f.env.OPENAI_API_KEY, 'synthetic-aws-key');
  assert.equal(JSON.stringify(f.manager.view()).includes('synthetic-aws'), false);
});
test('cancellation does not report success or load parameters', async t => {
  let child, reads = 0;
  const f = fixture(t, { python: 'fixture', pythonPath: '/fixture', spawnImpl: () => {
    child = new EventEmitter(); child.stdout = new PassThrough(); child.stderr = new PassThrough(); child.kill = () => { child.emit('close', 1); return true; }; return child;
  }, readParameters: async () => { reads++; return {}; } });
  f.manager.save(f.settings({ OPENAI_API_KEY: '/fixture/key' })); f.manager.login(); f.manager.cancel();
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(f.manager.view().state, 'cancelled'); assert.equal(reads, 0);
});

test('local HTTP settings and loading routes never return decrypted parameter values', async t => {
  const f = fixture(t);
  const { createWorkbench } = require('../server.js');
  const wb = createWorkbench({ storageDir: f.directory, integrations: { awsParameters: { directory: f.directory, env: f.env,
    cli: async () => ({ code: 0, stdout: '{"cliAvailable":true,"profiles":["fixture"],"browsers":[{"id":"edge","label":"Microsoft Edge"}]}' }),
    readParameters: async () => ({ '/fixture/key': 'synthetic-decrypted-secret' }) } } });
  await new Promise(resolve => wb.server.listen(0, '127.0.0.1', resolve));
  t.after(() => wb.close());
  const base = `http://127.0.0.1:${wb.server.address().port}`;
  const saved = await fetch(base + '/api/aws/settings', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(f.settings({ OPENAI_API_KEY: '/fixture/key' })) });
  assert.equal(saved.status, 200);
  const loaded = await fetch(base + '/api/aws/parameters/load', { method: 'POST' });
  assert.equal(loaded.status, 200);
  assert.equal((await loaded.json()).loadedCount, 1);
  const status = await fetch(base + '/api/aws/settings').then(r => r.json());
  assert.equal(status.browsers[0].id, 'edge'); assert.equal(status.state, 'ready');
  assert.equal(JSON.stringify(status).includes('synthetic-decrypted-secret'), false);
});

'use strict';

const { it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');

// server.js also constructs its unstarted default Workbench. Keep that instance away from real user data.
const bootstrap = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-ui-bootstrap-'));
const priorState = process.env.THREATLINT_STATE_DIR;
process.env.THREATLINT_STATE_DIR = path.join(bootstrap, 'default');
const { createWorkbench } = require('../server.js');
if (priorState === undefined) delete process.env.THREATLINT_STATE_DIR;
else process.env.THREATLINT_STATE_DIR = priorState;
after(() => fs.rmSync(bootstrap, { recursive: true, force: true }));
const { createWebApp } = require('../web-server.cjs');
const { createUiPreferences } = require('../lib/ui-preferences.cjs');
const { createAuth0Fixture } = require('./helpers/auth0.cjs');

const MODEL_PREFERENCES = { provider: 'codex', models: { codex: 'fixture-user-model' },
  codexDaybreak: false, bedrockRegion: '', lmstudioUrl: 'http://localhost:1234/v1' };
const COMPANY = { slug: 'acme', name: 'Acme', auth0OrganizationId: 'org_Acme123' };

function sandbox(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-ui-preferences-'));
  const active = new Set();
  t.after(async () => {
    for (const fixture of [...active]) await fixture.close();
    fs.rmSync(root, { recursive: true, force: true });
  });
  return { root, active };
}
async function request(base, route, { method = 'GET', json, cookie, profile, headers = {} } = {}) {
  const response = await fetch(`${base}${route}`, { method, redirect: 'manual', headers: {
    Connection: 'close', ...(!['GET', 'HEAD'].includes(method) ? { Origin: base } : {}),
    ...(json === undefined ? {} : { 'Content-Type': 'application/json' }),
    ...(cookie ? { Cookie: cookie } : {}), ...(profile ? { 'X-Threatlint-Profile': profile } : {}), ...headers,
  }, ...(json === undefined ? {} : { body: JSON.stringify(json) }) });
  const raw = await response.text();
  let body = raw; try { body = JSON.parse(raw); } catch { /* Non-JSON failures remain inspectable. */ }
  return { status: response.status, body, cookie: response.headers.get('set-cookie')?.split(';')[0] };
}
async function local(directory, active) {
  const workbench = createWorkbench({ storageDir: directory });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${workbench.server.address().port}`;
  let closed = false;
  const fixture = { base, workbench, call: (options = {}) => request(base, '/api/ui-preferences', options),
    close: async () => { if (closed) return; closed = true; await workbench.close(); active.delete(fixture); } };
  active.add(fixture);
  return fixture;
}
async function availablePort() {
  const reserve = net.createServer();
  await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  return port;
}

it('persists Experience across a different desktop port and keeps local profiles and model choices separate', async t => {
  const { root, active } = sandbox(t);
  const firstDir = path.join(root, 'first'), secondDir = path.join(root, 'second');
  const first = await local(firstDir, active), second = await local(secondDir, active);
  assert.deepEqual(await first.call(), { status: 200, body: { preferences: null }, cookie: undefined });
  assert.equal((await request(first.base, '/api/model-preferences', { method: 'PUT', json: MODEL_PREFERENCES })).status, 200);
  const originalModel = fs.readFileSync(path.join(firstDir, 'model-preferences.json'));
  assert.deepEqual((await first.call({ method: 'PUT', json: { experience: 'advanced' } })).body, { preferences: { experience: 'advanced' } });
  assert.equal((await second.call()).body.preferences, null);
  assert.equal((await second.call({ method: 'PUT', json: { experience: 'guided' } })).status, 200);
  assert.ok(fs.readFileSync(path.join(firstDir, 'model-preferences.json')).equals(originalModel));
  if (process.platform !== 'win32') assert.equal(fs.statSync(path.join(firstDir, 'ui-preferences.json')).mode & 0o777, 0o600);
  const oldPort = new URL(first.base).port;
  await first.close();
  const occupied = net.createServer();
  await new Promise(resolve => occupied.listen(Number(oldPort), '127.0.0.1', resolve));
  try {
    const restarted = await local(firstDir, active);
    assert.notEqual(restarted.base, first.base);
    assert.deepEqual((await restarted.call()).body, { preferences: { experience: 'advanced' } });
    assert.deepEqual((await second.call()).body, { preferences: { experience: 'guided' } });
    assert.deepEqual(JSON.parse(fs.readFileSync(path.join(firstDir, 'ui-preferences.json'), 'utf8')), { experience: 'advanced' });
    assert.ok(fs.readFileSync(path.join(firstDir, 'model-preferences.json')).equals(originalModel));
  } finally { await new Promise(resolve => occupied.close(resolve)); }
});

it('rejects unknown or sensitive fields and invalid Experience values without replacing a saved choice', async t => {
  const { root, active } = sandbox(t), fixture = await local(root, active);
  await fixture.call({ method: 'PUT', json: { experience: 'guided' } });
  const file = path.join(root, 'ui-preferences.json'), original = fs.readFileSync(file);
  for (const json of [{}, [], { experience: 'ADVANCED' }, { experience: ' advanced ' }, { experience: '' },
    { experience: null }, { experience: 1 }, { experience: true }, { experience: { mode: 'advanced' } },
    { experience: 'advanced', apiKey: 'synthetic-private-value' }, { experience: 'guided', consent: true },
    { experience: 'advanced', models: { codex: 'unrelated' } }, { experience: 'guided', role: 'administrator' }]) {
    const result = await fixture.call({ method: 'PUT', json });
    assert.equal(result.status, 400);
    assert.doesNotMatch(JSON.stringify(result.body), /synthetic-private-value/);
    assert.ok(fs.readFileSync(file).equals(original));
  }
  assert.deepEqual((await fixture.call()).body.preferences, { experience: 'guided' });
});

it('preserves invalid or oversized existing data instead of silently replacing it', async t => {
  const { root, active } = sandbox(t);
  for (const [index, raw] of ['not JSON synthetic-private-value', '{"experience":"invalid"}',
    '{"experience":"guided","apiKey":"synthetic-private-value"}', ' '.repeat(1025)].entries()) {
    const directory = path.join(root, String(index)); fs.mkdirSync(directory);
    const file = path.join(directory, 'ui-preferences.json'); fs.writeFileSync(file, raw);
    const fixture = await local(directory, active);
    for (const result of [await fixture.call(), await fixture.call({ method: 'PUT', json: { experience: 'advanced' } })]) {
      assert.equal(result.status, 500);
      assert.match(result.body.error, /original file was preserved/);
      assert.doesNotMatch(result.body.error, /synthetic-private-value/);
    }
    assert.equal(fs.readFileSync(file, 'utf8'), raw);
    await fixture.close();
  }
});

it('preserves unreadable preferences and hides filesystem error details', async t => {
  const { root, active } = sandbox(t), fixture = await local(root, active);
  await fixture.call({ method: 'PUT', json: { experience: 'guided' } });
  const file = path.join(root, 'ui-preferences.json'), read = fs.readFileSync, original = read(file);
  t.mock.method(fs, 'readFileSync', function(filename, ...args) {
    if (filename === file) throw Object.assign(new Error('synthetic-private-filesystem-detail'), { code: 'EACCES' });
    return read.call(this, filename, ...args);
  });
  try {
    for (const result of [await fixture.call(), await fixture.call({ method: 'PUT', json: { experience: 'advanced' } })]) {
      assert.equal(result.status, 500); assert.match(result.body.error, /could not be read/);
      assert.doesNotMatch(result.body.error, /synthetic-private/);
    }
    assert.ok(read(file).equals(original));
  } finally { t.mock.restoreAll(); }
});

it('preserves the prior file and removes temporary files when writing or atomic replacement fails', async t => {
  const { root, active } = sandbox(t), fixture = await local(root, active);
  await fixture.call({ method: 'PUT', json: { experience: 'guided' } });
  const file = path.join(root, 'ui-preferences.json'), original = fs.readFileSync(file);
  for (const method of ['writeFileSync', 'renameSync']) {
    const actual = fs[method];
    t.mock.method(fs, method, function(first, second, ...args) {
      if ((method === 'writeFileSync' && typeof first === 'string' && first.startsWith(`${file}.`)) ||
          (method === 'renameSync' && second === file)) throw new Error('synthetic-private-filesystem-detail');
      return actual.call(this, first, second, ...args);
    });
    try {
      const result = await fixture.call({ method: 'PUT', json: { experience: 'advanced' } });
      assert.equal(result.status, 500); assert.match(result.body.error, /previous preferences were preserved/);
      assert.doesNotMatch(result.body.error, /synthetic-private/);
      assert.ok(fs.readFileSync(file).equals(original));
      assert.deepEqual(fs.readdirSync(root).filter(name => name.endsWith('.tmp')), []);
      assert.deepEqual((await fixture.call()).body.preferences, { experience: 'guided' });
    } finally { t.mock.restoreAll(); }
  }
});

it('uses the local same-origin guard and supports separate in-memory stores', async t => {
  const { root, active } = sandbox(t), fixture = await local(root, active);
  assert.equal((await fixture.call({ method: 'PUT', json: { experience: 'advanced' }, headers: { Origin: 'https://other.example' } })).status, 403);
  assert.equal((await fixture.call()).body.preferences, null);
  const first = createUiPreferences(null), second = createUiPreferences(null);
  const choice = first.save({ experience: 'advanced' }); choice.experience = 'guided';
  assert.deepEqual(first.read(), { experience: 'advanced' }); assert.equal(second.read(), null);
});

it('isolates real personal/company workers, preserves Experience on a new gateway origin, and denies stale selectors', async t => {
  const { root, active } = sandbox(t), provider = createAuth0Fixture();
  async function start() {
    const port = await availablePort(), base = `http://127.0.0.1:${port}`;
    const web = createWebApp({ directory: root, origin: base, mode: 'process', companies: [COMPANY],
      auth0: provider.configuration, auth0Fetch: provider.fetch });
    await new Promise(resolve => web.server.listen(port, '127.0.0.1', resolve));
    let closed = false;
    const fixture = { web, base, call: (route, options) => request(base, route, options),
      close: async () => { if (closed) return; closed = true; await web.close(); active.delete(fixture); } };
    active.add(fixture); return fixture;
  }
  async function login(fixture, company) {
    const token = provider.issue({ subject: 'github|same-human', claims: company
      ? { org_id: COMPANY.auth0OrganizationId, 'https://threatlint.dev/roles': ['viewer'] } : {} });
    const result = await fixture.call('/auth/session', { method: 'POST', headers: { Authorization: `Bearer ${token}`,
      ...(company ? { 'X-Threatlint-Company': COMPANY.slug } : {}) } });
    assert.equal(result.status, 200); return result;
  }
  let fixture = await start();
  assert.equal((await fixture.call('/api/ui-preferences')).status, 401);
  assert.equal((await fixture.call('/api/ui-preferences', { method: 'PUT', json: { experience: 'guided' } })).status, 401);
  const personal = await login(fixture, false), company = await login(fixture, true);
  assert.notEqual(personal.body.user.id, company.body.user.id); assert.equal(company.body.role, 'viewer');
  for (const account of [personal, company]) assert.deepEqual((await fixture.call('/api/ui-preferences', { cookie: account.cookie })).body, { preferences: null });
  assert.equal((await fixture.call('/api/ui-preferences', { method: 'PUT', cookie: personal.cookie, profile: personal.body.user.id, json: { experience: 'advanced' } })).status, 200);
  assert.equal((await fixture.call('/API/UI-PREFERENCES/', { method: 'PUT', cookie: company.cookie, profile: company.body.user.id, json: { experience: 'guided' } })).status, 200);
  assert.equal((await fixture.call('/api/model-preferences', { method: 'PUT', cookie: company.cookie, json: MODEL_PREFERENCES })).status, 403);
  assert.equal((await fixture.call('/api/ui-preferences', { method: 'PUT', cookie: company.cookie, profile: personal.body.user.id, json: { experience: 'advanced' } })).status, 409);
  assert.equal((await fixture.call(`/api/ui-preferences?_profile=${personal.body.user.id}`, { cookie: company.cookie })).status, 409);
  assert.equal((await fixture.call(`/api/ui-preferences?_profile=${personal.body.user.id}`, { method: 'PUT', cookie: company.cookie, json: { experience: 'advanced' } })).status, 409);
  assert.equal((await fixture.call('/api/ui-preferences', { method: 'PUT', cookie: personal.cookie, json: { experience: 'guided' }, headers: { Origin: 'https://other.example' } })).status, 403);
  assert.deepEqual((await fixture.call('/api/ui-preferences', { cookie: company.cookie })).body.preferences, { experience: 'guided' });
  const oldBase = fixture.base;
  await fixture.close();
  const occupied = net.createServer();
  await new Promise(resolve => occupied.listen(Number(new URL(oldBase).port), '127.0.0.1', resolve));
  try { fixture = await start(); }
  finally { await new Promise(resolve => occupied.close(resolve)); }
  assert.notEqual(fixture.base, oldBase);
  const personalAgain = await login(fixture, false), companyAgain = await login(fixture, true);
  for (const [before, current, experience] of [[personal, personalAgain, 'advanced'], [company, companyAgain, 'guided']]) {
    assert.equal(current.body.user.id, before.body.user.id);
    assert.deepEqual((await fixture.call('/api/ui-preferences', { cookie: current.cookie })).body.preferences, { experience });
    const filename = path.join(root, 'profiles', current.body.user.id, '.threatlint', 'workbench', 'ui-preferences.json');
    assert.deepEqual(JSON.parse(fs.readFileSync(filename, 'utf8')), { experience });
  }
  assert.equal((await fixture.call('/auth/logout', { method: 'POST', cookie: companyAgain.cookie, profile: companyAgain.body.user.id })).status, 200);
  assert.equal((await fixture.call('/api/ui-preferences', { cookie: companyAgain.cookie })).status, 401);
  assert.deepEqual((await fixture.call('/api/ui-preferences', { cookie: personalAgain.cookie })).body.preferences, { experience: 'advanced' });
});

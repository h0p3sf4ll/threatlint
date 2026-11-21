'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const bootstrap = new vm.Script(fs.readFileSync(path.join(__dirname, '../public/web-profile.js'), 'utf8'));
const response = (status, body, type = 'application/json') => ({ status, ok: status >= 200 && status < 300,
  headers: { get: name => name.toLowerCase() === 'content-type' ? type : null }, json: async () => body });
const storage = () => {
  const values = new Map();
  return { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, String(value)), removeItem: key => values.delete(key) };
};
function start(fetchImpl, { local = storage(), session = storage(), nodes = {}, authLogout = async () => {}, desktop = false, pathname = '/', hash = '' } = {}) {
  const events = {};
  const navigations = [];
  let reloads = 0;
  const context = vm.createContext({
    window: { localStorage: local, sessionStorage: session, addEventListener: () => {}, ThreatlintAuth: { logout: authLogout },
      ...(desktop ? { threatlintDesktop: { version: '1.0' } } : {}) },
    document: { readyState: 'loading', addEventListener: (type, listener) => { events[`document:${type}`] = listener; },
      getElementById: id => nodes[id] || null, body: { classList: { add: () => {} } } },
    location: { pathname, hash, origin: 'https://app.threatlint.dev', href: `https://app.threatlint.dev${pathname}${hash}`,
      replace: target => navigations.push(target), reload: () => { reloads += 1; } },
    fetch: fetchImpl, setInterval: () => 1, URL, Headers,
    BroadcastChannel: class { addEventListener(type, listener) { events[type] = listener; } postMessage() {} },
  });
  bootstrap.runInContext(context);
  return { profile: context.window.ThreatlintProfile, local, session, events, navigations, get reloads() { return reloads; } };
}
const userResponse = id => response(200, { web: true, user: { id, email: `${id}@example.test`, displayName: id } });

test('two accounts sharing a browser never read each other’s preferences or triage history', async () => {
  const local = storage(), session = storage();
  local.setItem('threatlint.preferences.v2', 'desktop selections');
  session.setItem('threatlint.fpreview.run.v1', 'desktop history');
  const alice = start(async () => userResponse('alice'), { local, session });
  await alice.profile.ready;
  assert.equal(alice.profile.storage.getItem('threatlint.preferences.v2'), null);
  assert.equal(alice.profile.sessionStorage.getItem('threatlint.fpreview.run.v1'), null);
  alice.profile.storage.setItem('threatlint.preferences.v2', 'Alice model');
  alice.profile.sessionStorage.setItem('threatlint.fpreview.run.v1', 'Alice findings');
  const bob = start(async () => userResponse('bob'), { local, session });
  await bob.profile.ready;
  assert.equal(bob.profile.storage.getItem('threatlint.preferences.v2'), null);
  assert.equal(bob.profile.sessionStorage.getItem('threatlint.fpreview.run.v1'), null);
  bob.profile.storage.setItem('threatlint.preferences.v2', 'Bob model');
  assert.equal(alice.profile.storage.getItem('threatlint.preferences.v2'), 'Alice model');
  assert.equal(local.getItem('threatlint.preferences.v2'), 'desktop selections');
  assert.equal(session.getItem('threatlint.fpreview.run.v1'), 'desktop history');
  const aliceReload = start(async () => userResponse('alice'), { local, session });
  await aliceReload.profile.ready;
  assert.equal(aliceReload.profile.storage.getItem('threatlint.preferences.v2'), 'Alice model');
  assert.equal(aliceReload.profile.sessionStorage.getItem('threatlint.fpreview.run.v1'), 'Alice findings');
});

test('identity must resolve before browser history is read or written', async () => {
  let resolve;
  const pending = new Promise(ready => { resolve = ready; });
  const client = start(() => pending);
  assert.throws(() => client.profile.storage.getItem('threatlint.preferences.v2'), /still loading/);
  assert.throws(() => client.profile.sessionStorage.setItem('threatlint.fpreview.run.v1', 'unsafe'), /still loading/);
  resolve(userResponse('alice'));
  await client.profile.ready;
  assert.equal(client.profile.storage.getItem('threatlint.preferences.v2'), null);
});

test('desktop server preserves its existing browser preferences and history keys', async () => {
  const local = storage(), session = storage();
  local.setItem('threatlint.preferences.v2', 'desktop model');
  session.setItem('threatlint.fpreview.run.v1', 'desktop findings');
  const client = start(async () => response(200, '<html>desktop app</html>', 'text/html'), { local, session });
  await client.profile.ready;
  assert.equal(client.profile.web, false);
  assert.equal(client.profile.storage.getItem('threatlint.preferences.v2'), 'desktop model');
  assert.equal(client.profile.sessionStorage.getItem('threatlint.fpreview.run.v1'), 'desktop findings');
  client.profile.storage.setItem('threatlint.asked', '1');
  assert.equal(local.getItem('threatlint.asked'), '1');
});

test('failed profile load does not fall back to another account’s unscoped storage', async () => {
  const client = start(async () => response(503, { error: 'unavailable' }));
  await assert.rejects(client.profile.ready, /could not be loaded/);
  assert.throws(() => client.profile.storage.getItem('threatlint.preferences.v2'), /still loading/);
});

test('expired login redirects and account changes reload stale in-memory work', async () => {
  let next = userResponse('alice');
  const client = start(async () => next);
  await client.profile.ready;
  next = userResponse('bob');
  assert.equal(await client.profile.check(), false);
  assert.equal(client.reloads, 1);
  next = response(401, { error: 'Sign in required' });
  assert.equal(await client.profile.check(), false);
  assert.deepEqual(client.navigations, ['/login']);
  client.events.message({ data: { type: 'session-changed' } });
  assert.equal(client.reloads, 2);
});

test('sign out revokes the application session before redirecting through Auth0 logout', async () => {
  const order = [];
  const nodes = Object.fromEntries(['web-profile', 'web-profile-name', 'web-signout', 'web-profile-error'].map(id => [id,
    { textContent: '', hidden: true, handlers: {}, addEventListener(type, listener) { this.handlers[type] = listener; } }]));
  const client = start(async (url, options) => {
    if (url === '/auth/logout') { assert.equal(options.method, 'POST'); order.push('revoke-cookie'); return response(204, null); }
    return userResponse('alice');
  }, { nodes, authLogout: async () => { order.push('auth0-logout'); } });
  await client.profile.ready;
  client.events['document:DOMContentLoaded']();
  await nodes['web-signout'].handlers.click();
  assert.deepEqual(order, ['revoke-cookie', 'auth0-logout']);
  assert.deepEqual(client.navigations, []);
});

test('a provider logout failure still leaves the revoked Threatlint session and returns to explicit sign in', async () => {
  const nodes = Object.fromEntries(['web-profile', 'web-profile-name', 'web-signout', 'web-profile-error'].map(id => [id,
    { textContent: '', handlers: {}, addEventListener(type, listener) { this.handlers[type] = listener; } }]));
  const client = start(async url => url === '/auth/logout' ? response(204, null) : userResponse('alice'),
    { nodes, authLogout: async () => { throw new Error('Auth0 temporarily unavailable'); } });
  await client.profile.ready;
  client.events['document:DOMContentLoaded']();
  await nodes['web-signout'].handlers.click();
  assert.deepEqual(client.navigations, ['/login?notice=provider-logout']);
});

test('native desktop preserves the OS-user profile and works without any authentication network request', async () => {
  let requests = 0;
  const local = storage();
  local.setItem('threatlint.preferences.v2', 'individual desktop model');
  const client = start(async () => { requests += 1; throw new Error('offline'); }, { desktop: true, local });
  await client.profile.ready;
  assert.equal(requests, 0);
  assert.equal(client.profile.web, false);
  assert.equal(client.profile.storage.getItem('threatlint.preferences.v2'), 'individual desktop model');
  assert.equal(await client.profile.check(), true);
  assert.deepEqual(client.navigations, []);
});

test('company session expiry keeps its company sign-in route', async () => {
  let expired = false;
  const client = start(async () => expired ? response(401, {}) : response(200, { web: true, user: { id: 'company-profile', email: 'alice@example.test',
    displayName: 'Alice', company: { slug: 'acme', name: 'Acme', organizationId: 'org_acme' } } }), { pathname: '/c/acme/' });
  await client.profile.ready;
  assert.equal(client.profile.loginPath(), '/c/acme/login');
  expired = true;
  await client.profile.check();
  assert.deepEqual(client.navigations, ['/c/acme/login']);
  const initiallyExpired = start(async () => response(401, {}), { pathname: '/c/acme/' });
  await assert.rejects(initiallyExpired.profile.ready, /Sign in/);
  assert.deepEqual(initiallyExpired.navigations, ['/c/acme/login']);
});

test('profile context accompanies only protected same-origin requests and cannot leak to third-party services', async () => {
  const calls = [];
  const client = start(async (url, options) => { calls.push({ url, options }); return url === '/auth/session' ? userResponse('alice') : response(200, {}); });
  await client.profile.ready;
  await client.profile.fetch('/api/model-preferences', { method: 'PUT', headers: { 'Content-Type': 'application/json', 'X-Threatlint-Profile': 'stale-id' }, body: '{}' });
  await client.profile.fetch('/auth/logout', { method: 'POST' });
  await client.profile.fetch('https://thirdparty.example/api/private', { headers: { Authorization: 'Bearer provider-key' } });
  await client.profile.fetch('/auth/config');
  assert.equal(calls[1].options.headers.get('X-Threatlint-Profile'), 'alice');
  assert.equal(calls[1].options.headers.get('Content-Type'), 'application/json');
  assert.equal(calls[2].options.headers.get('X-Threatlint-Profile'), 'alice');
  assert.equal(Object.hasOwn(calls[3].options.headers, 'X-Threatlint-Profile'), false);
  assert.equal(calls[3].options.headers.Authorization, 'Bearer provider-key');
  assert.equal(calls[4].options.headers, undefined);
});

test('desktop fetch delegates without adding an authentication or profile header', async () => {
  const calls = [];
  const client = start(async (url, options) => { calls.push({ url, options }); return response(200, {}); }, { desktop: true });
  await client.profile.ready;
  const options = { method: 'GET' };
  await client.profile.fetch('/api/sessions', options);
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options, options);
  assert.equal(calls[0].options.headers, undefined);
});

test('download URLs preserve export options and bind the current profile without exposing context to external sites', async () => {
  const client = start(async () => userResponse('alice'));
  await client.profile.ready;
  const bound = client.profile.url('/api/metrics/export?source=runtime#csv');
  assert.equal(bound, '/api/metrics/export?source=runtime&_profile=alice#csv');
  const duplicate = new URL(client.profile.url('/api/report/export?_profile=old&_profile=another&format=md'), 'https://app.threatlint.dev');
  assert.deepEqual(duplicate.searchParams.getAll('_profile'), ['alice']);
  assert.equal(duplicate.searchParams.get('format'), 'md');
  assert.equal(client.profile.url('https://outside.example/api/export'), 'https://outside.example/api/export');
  assert.equal(client.profile.url('/login'), '/login');
  assert.equal(client.profile.url('blob:https://app.threatlint.dev/file'), 'blob:https://app.threatlint.dev/file');
  const desktop = start(async () => { throw new Error('offline'); }, { desktop: true });
  await desktop.profile.ready;
  assert.equal(desktop.profile.url('/api/metrics/export?source=runtime'), '/api/metrics/export?source=runtime');
});

test('an open company tab follows canonical renamed slugs without losing its active view', async () => {
  let company = { slug: 'acme', name: 'Acme', organizationId: 'org_acme' };
  const client = start(async () => response(200, { web: true, user: { id: 'same-company-profile', email: 'alice@example.test', displayName: 'Alice', company } }),
    { pathname: '/c/acme/', hash: '#settings' });
  await client.profile.ready;
  company = { ...company, slug: 'acme-renamed', name: 'Acme Renamed' };
  assert.equal(await client.profile.check(), false);
  assert.deepEqual(client.navigations, ['/c/acme-renamed/#settings']);
  assert.equal(client.profile.loginPath(), '/c/acme-renamed/login');
});

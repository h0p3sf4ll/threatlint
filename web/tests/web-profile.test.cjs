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
function start(fetchImpl, { local = storage(), session = storage(), nodes = {}, authLogout = async () => {} } = {}) {
  const events = {};
  const navigations = [];
  let reloads = 0;
  const context = vm.createContext({
    window: { localStorage: local, sessionStorage: session, addEventListener: () => {}, ThreatlintAuth: { logout: authLogout } },
    document: { readyState: 'loading', addEventListener: (type, listener) => { events[`document:${type}`] = listener; },
      getElementById: id => nodes[id] || null, body: { classList: { add: () => {} } } },
    location: { replace: target => navigations.push(target), reload: () => { reloads += 1; } },
    fetch: fetchImpl, setInterval: () => 1,
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

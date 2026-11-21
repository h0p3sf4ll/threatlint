'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const http = require('node:http');
const WebSocket = require('ws');
const { createWebApp } = require('../web-server.cjs');
const { createStore } = require('../lib/store.cjs');
const { createReportWriter } = require('../lib/report-writer.cjs');
const { createAuth0Fixture } = require('./helpers/auth0.cjs');

const PREFERENCES = { provider: 'openai', models: { openai: 'fixture-model-a' }, codexDaybreak: false,
  bedrockRegion: 'us-east-1', lmstudioUrl: 'http://localhost:1234/v1' };
const running = new Map();
function directory(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-web-app-'));
  t.after(async () => { await running.get(root)?.close(); running.delete(root); fs.rmSync(root, { recursive: true, force: true }); });
  return root;
}
async function freePort() {
  const reserve = net.createServer();
  await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port;
  await new Promise(resolve => reserve.close(resolve));
  return port;
}
async function start(root, options = {}) {
  const port = await freePort(), origin = `http://127.0.0.1:${port}`;
  const provider = createAuth0Fixture();
  const web = createWebApp({ directory: root, origin, mode: 'process', auth0: provider.configuration, auth0Fetch: provider.fetch, ...options });
  running.set(root, web);
  await new Promise(resolve => web.server.listen(port, '127.0.0.1', resolve));
  async function call(route, { method = 'GET', cookie, json, headers = {} } = {}) {
    const response = await fetch(`${origin}${route}`, { method, redirect: 'manual',
      headers: { ...(cookie ? { Cookie: cookie } : {}), ...(!['GET', 'HEAD'].includes(method) ? { Origin: origin } : {}),
        ...(json === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      ...(json === undefined ? {} : { body: JSON.stringify(json) }) });
    const text = await response.text();
    let body = text; try { body = JSON.parse(text); } catch { /* asset or empty body */ }
    return { status: response.status, body, headers: response.headers, cookie: response.headers.get('set-cookie')?.split(';')[0] };
  }
  const exchange = token => call('/auth/session', { method: 'POST', headers: { Authorization: `Bearer ${token}` } });
  const signIn = (email, displayName = email) => exchange(provider.issue({ email, displayName, subject: `google-oauth2|${email.split('@')[0]}` }));
  return { web, origin, call, signIn, exchange, provider };
}
function wrongHost(origin) {
  return new Promise((resolve, reject) => {
    http.get(`${origin}/healthz`, { headers: { Host: 'evil.example' } }, response => {
      response.resume(); response.once('end', () => resolve(response.statusCode));
    }).on('error', reject);
  });
}
function openSocket(origin, cookie) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(origin.replace('http:', 'ws:'), { origin, ...(cookie ? { headers: { Cookie: cookie } } : {}) });
    ws.once('open', () => resolve(ws)); ws.once('error', reject);
  });
}
function message(ws, payload) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('WebSocket response timed out')), 5000);
    ws.once('message', raw => { clearTimeout(timeout); resolve(JSON.parse(raw)); });
    ws.send(JSON.stringify(payload));
  });
}
function deniedSocket(origin, cookie, customOrigin = origin) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(origin.replace('http:', 'ws:'), { origin: customOrigin, ...(cookie ? { headers: { Cookie: cookie } } : {}) });
    ws.on('error', () => {});
    ws.once('open', () => { ws.terminate(); reject(new Error('Unexpected WebSocket authorization')); });
    ws.once('unexpected-response', (_req, response) => { response.resume(); ws.terminate(); resolve(response.statusCode); });
  });
}
function socketClosed(ws) {
  return new Promise((resolve, reject) => {
    if (ws.readyState === WebSocket.CLOSED) return resolve();
    const timeout = setTimeout(() => { ws.terminate(); reject(new Error('Session revocation did not close the socket')); }, 4000);
    ws.once('close', () => { clearTimeout(timeout); resolve(); });
  });
}

it('protects the full workbench and rejects incorrect hosts and cross-origin mutations', async t => {
  const fixture = await start(directory(t)); t.after(() => fixture.web.close());
  assert.equal((await fixture.call('/healthz')).status, 200);
  assert.equal((await fixture.call('/login')).status, 200);
  assert.equal((await fixture.call('/login.js')).status, 200);
  assert.equal((await fixture.call('/')).status, 200);
  assert.equal((await fixture.call('/auth/session')).status, 401);
  assert.equal((await fixture.call('/api/sessions')).status, 401);
  for (const route of ['/app.js', '/styles.css', '/vendor/marked.js']) {
    const denied = await fixture.call(route);
    assert.equal(denied.status, 302); assert.equal(denied.headers.get('location'), '/login');
  }
  assert.equal(await wrongHost(fixture.origin), 403);
  assert.equal((await fixture.call('/healthz', { headers: { Origin: 'https://evil.example' } })).status, 403);
  assert.equal((await fixture.call('/healthz', { headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  assert.equal((await fixture.call('/auth/session', { method: 'POST', headers: { Origin: 'https://evil.example' } })).status, 403);
  const account = await fixture.signIn('a@example.test', 'Alice');
  assert.equal(account.status, 200);
  assert.match(account.headers.get('set-cookie'), /HttpOnly; SameSite=Lax/);
  assert.equal((await fixture.call('/', { cookie: account.cookie })).status, 200);
  assert.equal((await fixture.call('/app.js', { cookie: account.cookie })).status, 200);
  const blocked = await fixture.call('/api/model-preferences', { method: 'PUT', cookie: account.cookie, json: PREFERENCES, headers: { Origin: '' } });
  assert.equal(blocked.status, 403);
  const worker = await fixture.web.workers.get(account.body.user);
  assert.equal((await fetch(`http://127.0.0.1:${worker.port}/api/agents`)).status, 403);
  assert.equal((await fetch(`http://127.0.0.1:${worker.port}/api/agents`, { headers: { 'x-threatlint-worker': 'forged' } })).status, 403);
});

it('keeps settings, integration secrets, sessions and reports separate and persistent across gateway restarts', async t => {
  const root = directory(t); let fixture = await start(root);
  t.after(() => fixture.web.close());
  const alice = await fixture.signIn('alice@example.test', 'Alice'), bob = await fixture.signIn('bob@example.test', 'Bob');
  assert.equal(alice.status, 200); assert.equal(bob.status, 200);
  assert.notEqual(alice.body.user.id, bob.body.user.id);
  assert.deepEqual((await fixture.call('/api/model-preferences', { cookie: bob.cookie })).body, { preferences: null });
  assert.equal((await fixture.call('/api/model-preferences', { method: 'PUT', cookie: alice.cookie, json: PREFERENCES })).status, 200);
  const bobPreferences = { ...PREFERENCES, provider: 'codex', models: { codex: 'fixture-model-b' } };
  assert.equal((await fixture.call('/api/model-preferences', { method: 'PUT', cookie: bob.cookie, json: bobPreferences })).status, 200);
  const snow = { instance: 'https://alice.service-now.com', clientId: 'alice-fixture-client', clientSecret: 'alice-fixture-secret' };
  const saved = await fixture.call('/api/servicenow/settings', { method: 'POST', cookie: alice.cookie, json: snow });
  assert.equal(saved.status, 200); assert.equal(saved.body.hasSecret, true);
  assert.equal(JSON.stringify(saved.body).includes(snow.clientSecret), false);
  assert.equal((await fixture.call('/api/servicenow/settings', { cookie: bob.cookie })).body.hasSecret, false);
  const repoPath = path.join(root, 'profiles', alice.body.user.id, 'workspace');
  const session = await fixture.call('/api/session/local', { method: 'POST', cookie: alice.cookie, json: { repoPath } });
  assert.equal(session.status, 200);
  const sessionId = session.body.sessionId;
  assert.equal((await fixture.call(`/api/session/${sessionId}`, { cookie: bob.cookie })).status, 404);
  assert.deepEqual((await fixture.call('/api/sessions', { cookie: bob.cookie })).body, []);
  await fixture.web.close();
  assert.equal(fs.existsSync(path.join(root, 'gateway.lock')), false);
  const store = createStore(path.join(root, 'profiles', alice.body.user.id, '.threatlint/workbench'));
  const reports = createReportWriter(store, { convertToWord: async () => {} });
  const report = await reports.save('appsec-code-reviewer', '# Alice private report\n\nPrivate fixture findings for Alice only.', sessionId);
  const reportPath = `/api/report/${sessionId}/${report.agentId}/${report.timestamp}`;
  fixture = await start(root);
  assert.equal((await fixture.call('/auth/session', { cookie: alice.cookie })).body.user.id, alice.body.user.id);
  const aliceAgain = await fixture.signIn('alice@example.test'), bobAgain = await fixture.signIn('bob@example.test');
  assert.equal(aliceAgain.status, 200); assert.equal(bobAgain.status, 200);
  assert.notEqual(alice.cookie, aliceAgain.cookie);
  assert.deepEqual((await fixture.call('/api/model-preferences', { cookie: aliceAgain.cookie })).body.preferences, PREFERENCES);
  assert.deepEqual((await fixture.call('/api/model-preferences', { cookie: bobAgain.cookie })).body.preferences, bobPreferences);
  assert.equal((await fixture.call('/api/servicenow/settings', { cookie: aliceAgain.cookie })).body.clientId, snow.clientId);
  assert.equal((await fixture.call('/api/servicenow/settings', { cookie: bobAgain.cookie })).body.hasSecret, false);
  const list = await fixture.call(`/api/session/${sessionId}/reports`, { cookie: aliceAgain.cookie });
  assert.equal(list.status, 200); assert.equal(list.body[0].id, report.id);
  assert.match((await fixture.call(`${reportPath}/md`, { cookie: aliceAgain.cookie })).body, /Alice private report/);
  for (const route of [`/api/session/${sessionId}`, `/api/session/${sessionId}/reports`, `${reportPath}/json`, `${reportPath}/md`]) {
    assert.equal((await fixture.call(route, { cookie: bobAgain.cookie })).status, 404, route);
  }
  assert.equal((await fixture.call(`/api/session/${sessionId}/reports/${report.id}`, { method: 'DELETE', cookie: bobAgain.cookie })).status, 404);
  const raw = fs.readFileSync(path.join(root, 'identities.json'), 'utf8');
  assert.equal(raw.includes(alice.cookie.split('=')[1]), false);
  assert.throws(() => createWebApp({ directory: root, origin: fixture.origin, mode: 'process' }), /in use/);
});

it('authenticates WebSockets, scopes actions to the signed-in profile and revokes active sockets on logout', async t => {
  const root = directory(t), fixture = await start(root); t.after(() => fixture.web.close());
  assert.equal(await deniedSocket(fixture.origin), 401);
  const alice = await fixture.signIn('alice@example.test'), bob = await fixture.signIn('bob@example.test');
  assert.equal(await deniedSocket(fixture.origin, alice.cookie, 'https://evil.example'), 403);
  const socket = await openSocket(fixture.origin, alice.cookie); t.after(() => socket.terminate());
  assert.deepEqual(await message(socket, { action: 'avit_batch_attach' }), { type: 'avit_batch_replay', runId: null, active: false, events: [] });
  assert.deepEqual(await message(socket, { action: 'unrecognized' }), { type: 'error', message: 'Unknown action' });
  // The other user's session identifier cannot select a repository in this socket's worker.
  await fixture.call('/api/sessions', { cookie: bob.cookie });
  const foreignSession = await fixture.call('/api/session/local', { method: 'POST', cookie: bob.cookie,
    json: { repoPath: path.join(root, 'profiles', bob.body.user.id, 'workspace') } });
  assert.equal(foreignSession.status, 200);
  const denied = await message(socket, { action: 'run_pipeline', sessionId: foreignSession.body.sessionId, agentIds: ['appsec-code-reviewer'], provider: 'lmstudio' });
  assert.equal(denied.type, 'error'); assert.match(denied.message, /Choose an existing repository/);
  const bobSocket = await openSocket(fixture.origin, bob.cookie); t.after(() => bobSocket.terminate());
  const closed = socketClosed(socket);
  assert.equal((await fixture.call('/auth/logout', { method: 'POST', cookie: alice.cookie, json: {} })).status, 200);
  await closed;
  assert.equal((await fixture.call('/auth/session', { cookie: alice.cookie })).status, 401);
  assert.equal(await deniedSocket(fixture.origin, alice.cookie), 401);
  assert.equal((await fixture.call('/auth/session', { cookie: bob.cookie })).status, 200);
  assert.equal((await message(bobSocket, { action: 'avit_batch_attach' })).type, 'avit_batch_replay');
});

it('expires HTTP and existing WebSocket sessions without waiting for a new login', async t => {
  let current = Date.now();
  const fixture = await start(directory(t), { sessionTtlMs: 1000, now: () => current }); t.after(() => fixture.web.close());
  const account = await fixture.signIn('alice@example.test');
  const socket = await openSocket(fixture.origin, account.cookie); t.after(() => socket.terminate());
  const closed = socketClosed(socket); current += 1001;
  assert.equal((await fixture.call('/auth/session', { cookie: account.cookie })).status, 401);
  await closed;
});

it('uses official Auth0 SDK verification and rejects invalid claims, signatures and identity mismatches', async t => {
  const fixture = await start(directory(t)); t.after(() => fixture.web.close());
  const config = (await fixture.call('/auth/config')).body;
  assert.equal(config.provider, 'auth0'); assert.equal(config.domain, fixture.provider.configuration.domain);
  const deniedClaims = [{ iss: 'https://wrong.auth0.test/' }, { aud: 'https://wrong-api.test' }, { azp: 'different-client' },
    { exp: Math.floor(Date.now() / 1000) - 3600 }, { sub: 'auth0|database-user' }, { sub: 'client-id@clients', gty: 'client-credentials' },
    { sub: 'oauth2|machine', gty: 'client-credentials' }, { azp: fixture.provider.configuration.clientId, client_id: 'different-client' }];
  for (const claims of deniedClaims) {
    const result = await fixture.exchange(fixture.provider.issue({ claims }));
    assert.ok([401, 403].includes(result.status), `Expected rejection for ${JSON.stringify(claims)}, got ${result.status}: ${JSON.stringify(result.body)}`);
    assert.equal(result.cookie, undefined);
  }
  const signed = fixture.provider.issue(), parts = signed.split('.');
  parts[2] = (parts[2][0] === 'a' ? 'b' : 'a') + parts[2].slice(1);
  assert.equal((await fixture.exchange(parts.join('.'))).status, 401);
  assert.equal((await fixture.call('/auth/session', { method: 'POST' })).status, 401);
  const mismatch = fixture.provider.issue({ subject: 'google-oauth2|alice', userInfo: { sub: 'github|other', name: 'Other' } });
  assert.equal((await fixture.exchange(mismatch)).status, 401);
  const valid = await fixture.exchange(fixture.provider.issue({ subject: 'github|verified-user' }));
  assert.equal(valid.status, 200);
  const rfcProfile = await fixture.exchange(fixture.provider.issue({ subject: 'github|verified-user',
    claims: { azp: undefined, client_id: fixture.provider.configuration.clientId } }));
  assert.equal(rfcProfile.status, 200); assert.equal(rfcProfile.body.user.id, valid.body.user.id);
  assert.ok(fixture.provider.requests.some(url => url.endsWith('/.well-known/openid-configuration')));
  assert.ok(fixture.provider.requests.some(url => url.endsWith('/.well-known/jwks.json')));
  assert.ok(fixture.provider.requests.some(url => url.endsWith('/userinfo')));
});

it('serves OAuth callback navigation while keeping mutations same-origin and local account endpoints unavailable', async t => {
  const prior = process.env.THREATLINT_WEB_REGISTRATION; process.env.THREATLINT_WEB_REGISTRATION = '1';
  const fixture = await start(directory(t));
  t.after(() => { if (prior === undefined) delete process.env.THREATLINT_WEB_REGISTRATION; else process.env.THREATLINT_WEB_REGISTRATION = prior; });
  t.after(() => fixture.web.close());
  // Native HTTP preserves Fetch Metadata headers, which fetch implementations may synthesize.
  const response = await new Promise((resolve, reject) => {
    http.get(`${fixture.origin}/?code=fixture-code&state=fixture-state`, { headers: { 'Sec-Fetch-Site': 'cross-site', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Dest': 'document' } }, res => {
      res.resume(); res.once('end', () => resolve(res.statusCode));
    }).on('error', reject);
  });
  assert.equal(response, 200);
  assert.equal((await fixture.call('/auth/session', { method: 'POST', headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
  for (const route of ['/auth/login', '/auth/register']) assert.equal((await fixture.call(route, { method: 'POST', json: {} })).status, 404);
  const signed = fixture.provider.issue();
  let last;
  for (let attempt = 0; attempt < 101; attempt++) last = await fixture.exchange(signed);
  assert.equal(last.status, 429); assert.equal(last.headers.get('retry-after'), '900');
});

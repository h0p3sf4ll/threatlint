'use strict';
const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const WebSocket = require('ws');
const { createWebApp } = require('../web-server.cjs');
const { createAuth0Fixture } = require('./helpers/auth0.cjs');
const { createManagementFixture } = require('./helpers/auth0-management.cjs');

async function fixture(t, { configured = true, realWorkers = false, beforeUserInfo } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-web-organizations-'));
  const provider = createAuth0Fixture(), management = createManagementFixture();
  const upstream = http.createServer((_req, res) => res.end('{"ok":true}')), wss = new WebSocket.Server({ server: upstream });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const port = upstream.address().port;
  const workers = { acquire: async () => ({ worker: { port, workerPort: port, token: 'fixture-worker-secret' }, release() {} }), close: async () => {} };
  let web, origin;
  async function start() {
    const reserved = http.createServer(); await new Promise(resolve => reserved.listen(0, '127.0.0.1', resolve));
    const gatewayPort = reserved.address().port; await new Promise(resolve => reserved.close(resolve));
    origin = `http://127.0.0.1:${gatewayPort}`;
    web = createWebApp({ directory, origin, mode: 'process', companies: [], auth0: provider.configuration,
      auth0Fetch: async (input, init) => { if (beforeUserInfo && new URL(input).pathname === '/userinfo') await beforeUserInfo(); return provider.fetch(input, init); },
      auth0Management: configured ? management.options : { clientId: '', clientSecret: '' }, auth0ManagementFetch: management.fetch, ...(realWorkers ? {} : { workers }), adminSubjects: ['github|admin'] });
    await new Promise(resolve => web.server.listen(gatewayPort, '127.0.0.1', resolve));
  }
  await start();
  t.after(async () => { await web.close(); for (const socket of wss.clients) socket.terminate(); await new Promise(resolve => wss.close(resolve)); upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve)); fs.rmSync(directory, { recursive: true, force: true }); });
  async function call(route, { cookie, method = 'GET', json, headers = {} } = {}) {
    const response = await fetch(`${origin}${route}`, { method, redirect: 'manual', headers: { Connection: 'close', ...(cookie ? { Cookie: cookie } : {}),
      ...(!['GET', 'HEAD'].includes(method) ? { Origin: origin } : {}), ...(json === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers }, ...(json === undefined ? {} : { body: JSON.stringify(json) }) });
    const raw = await response.text(); let body = raw; try { body = JSON.parse(raw); } catch {}
    return { status: response.status, body, cookie: response.headers.get('set-cookie')?.split(';')[0] };
  }
  const login = (subject, organizationId, extra = {}) => call('/auth/session', { method: 'POST', headers: { Authorization: `Bearer ${provider.issue({ subject, claims: { ...(organizationId ? { org_id: organizationId } : {}) } })}`, ...extra } });
  return { directory, provider, management, call, login, origin: () => origin, close: () => web.close(), restart: async () => { await web.close(); await start(); } };
}

it('discovers preadded memberships, requires a new org-scoped verified token, and denies unknown or nonmember organizations', async t => {
  const app = await fixture(t); app.management.user('github|preadded'); app.management.user('github|stranger');
  app.management.organization('org_Acme', 'acme', ['github|preadded']); app.management.organization('org_Beta', 'beta', ['github|preadded']);
  const personal = await app.login('github|preadded');
  assert.equal(personal.status, 200); assert.equal(personal.body.user.company, undefined);
  const choices = await app.call('/auth/organizations', { cookie: personal.cookie });
  assert.equal(choices.status, 200); assert.deepEqual(choices.body.organizations.map(value => value.organizationId), ['org_Acme', 'org_Beta']); assert.equal(choices.body.canCreate, false);
  assert.equal((await app.call('/auth/session', { cookie: personal.cookie })).body.user.company, undefined, 'discovery never switches the profile');
  assert.equal((await app.login('github|stranger', 'org_Acme')).status, 403);
  assert.equal((await app.login('github|preadded', 'org_Unknown')).status, 403);
  assert.equal((await app.login('github|preadded', 'org_Acme', { 'X-Threatlint-Company': 'beta' })).status, 403);
  const company = await app.login('github|preadded', 'org_Acme'); assert.equal(company.status, 200); assert.notEqual(company.body.user.id, personal.body.user.id);
  const id = company.body.user.id; await app.restart();
  assert.equal((await app.call('/auth/session', { cookie: company.cookie })).body.user.id, id);
  assert.equal((await app.call('/auth/organizations')).status, 401);
});

it('creates one organization idempotently across restart and makes only its explicit creator administrator', async t => {
  const app = await fixture(t); app.management.user('github|creator'); app.management.user('github|stranger');
  const personal = await app.login('github|creator'), input = { name: 'New Team', idempotencyKey: crypto.randomUUID() };
  assert.equal((await app.call('/auth/organizations', { cookie: personal.cookie })).body.canCreate, true);
  const created = await app.call('/auth/organizations', { cookie: personal.cookie, method: 'POST', json: input }); assert.equal(created.status, 201);
  const company = created.body.organization, logged = await app.login('github|creator', company.organizationId);
  assert.equal(logged.body.role, 'administrator'); assert.equal(app.management.memberships.get(company.organizationId).has('github|creator'), true);
  assert.equal((await app.login('github|stranger', company.organizationId)).status, 403);
  await app.restart();
  const retried = await app.call('/auth/organizations', { cookie: personal.cookie, method: 'POST', json: input });
  assert.equal(retried.status, 201); assert.equal(retried.body.organization.organizationId, company.organizationId); assert.equal(app.management.organizations.size, 1);
  assert.equal((await app.login('github|creator', company.organizationId)).body.user.id, logged.body.user.id);
  assert.equal((await app.call('/auth/organizations', { cookie: personal.cookie, method: 'POST', json: { ...input, idempotencyKey: crypto.randomUUID() } })).status, 409);
  assert.equal(app.management.calls.filter(value => value.method === 'POST' && value.path === '/api/v2/organizations').length, 1);
});

it('lists every actual member including never-logged users, scopes admin lookup, and persists exact identity roles', async t => {
  const app = await fixture(t);
  app.management.user('github|admin'); app.management.organization('org_Acme', 'acme', ['github|admin']);
  for (let i = 0; i < 105; i++) { const subject = `github|member${i}`; app.management.user(subject, `member${i}@example.test`); app.management.memberships.get('org_Acme').add(subject); }
  app.management.user('github|candidate', 'shared@example.test', 'GitHub Candidate'); app.management.user('google-oauth2|candidate', 'shared@example.test', 'Google Candidate');
  const admin = await app.login('github|admin', 'org_Acme'), member = await app.login('github|member0', 'org_Acme'), personal = await app.login('github|candidate');
  const members = await app.call('/api/access', { cookie: admin.cookie }); assert.equal(members.status, 200); assert.equal(members.body.members.length, 106);
  assert.equal(members.body.members.find(value => value.subject === 'github|member104').userId, null);
  for (const cookie of [member.cookie, personal.cookie]) assert.equal((await app.call('/api/access/candidates?email=shared%40example.test', { cookie })).status, 403);
  assert.equal((await app.call('/api/access/candidates?email=shared%40example.test&q=all', { cookie: admin.cookie })).status, 400);
  const candidates = await app.call('/api/access/candidates?email=shared%40example.test', { cookie: admin.cookie });
  assert.equal(candidates.status, 200); assert.equal(candidates.body.users.length, 2); assert.deepEqual(Object.keys(candidates.body.users[0]).sort(), ['displayName', 'email', 'provider', 'subject']);
  const assigned = await app.call('/api/access/members', { cookie: admin.cookie, method: 'POST', json: { subject: 'github|candidate', role: 'viewer' } }); assert.equal(assigned.status, 200);
  assert.equal((await app.login('github|candidate', 'org_Acme')).body.role, 'viewer');
  assert.equal(app.management.memberships.get('org_Acme').has('google-oauth2|candidate'), false, 'matching email never links or enrolls the other provider');
  assert.equal((await app.call('/api/access/members', { cookie: member.cookie, method: 'POST', json: { subject: 'github|member0', role: 'administrator' } })).status, 403);
  assert.equal((await app.call('/api/access/members', { cookie: admin.cookie, method: 'POST', json: { subject: 'github|admin', role: 'viewer' } })).status, 409);
  await app.restart(); assert.equal((await app.login('github|candidate', 'org_Acme')).body.role, 'viewer');
});

it('revokes removed company cookies and active sockets immediately, preserves personal access and prevents stale JWT reentry', async t => {
  const app = await fixture(t); app.management.user('github|admin'); app.management.user('github|member'); app.management.organization('org_Acme', 'acme', ['github|admin', 'github|member']);
  const admin = await app.login('github|admin', 'org_Acme'), member = await app.login('github|member', 'org_Acme'), personal = await app.login('github|member');
  const socket = await new Promise((resolve, reject) => { const ws = new WebSocket(app.origin().replace('http:', 'ws:'), { origin: app.origin(), headers: { Cookie: member.cookie } }); ws.once('open', () => resolve(ws)); ws.once('error', reject); });
  t.after(() => socket.terminate());
  const closed = new Promise((resolve, reject) => { const timer = setTimeout(() => reject(new Error('Removed member socket remained open')), 3000); socket.once('close', () => { clearTimeout(timer); resolve(); }); });
  const removed = await app.call('/api/access/members/github%7Cmember', { cookie: admin.cookie, method: 'DELETE' }); assert.equal(removed.status, 200); await closed;
  assert.equal((await app.call('/auth/session', { cookie: member.cookie })).status, 401);
  assert.equal((await app.call('/auth/session', { cookie: personal.cookie })).status, 200);
  assert.equal((await app.login('github|member', 'org_Acme')).status, 403);
  assert.equal((await app.call('/api/access/members/github%7Cadmin', { cookie: admin.cookie, method: 'DELETE' })).status, 409);
  await app.restart(); assert.equal((await app.call('/auth/session', { cookie: member.cookie })).status, 401);
});

it('fails closed on Management errors and clearly distinguishes unavailable discovery from zero memberships', async t => {
  const unavailable = await fixture(t, { configured: false }), login = await unavailable.login('github|personal');
  const discovery = await unavailable.call('/auth/organizations', { cookie: login.cookie }); assert.equal(discovery.status, 503); assert.equal(discovery.body.managementAvailable, false);
  const app = await fixture(t); app.management.user('github|member'); app.management.organization('org_Acme', 'acme', ['github|member']);
  app.management.failOnce((_method, url) => url.pathname.includes('/organizations'));
  assert.equal((await app.login('github|member', 'org_Acme')).status, 503);
  assert.equal((await app.call('/auth/session')).status, 401);
});

it('rejects a stale organization chooser for reads, creation and logout without disturbing the active profile', async t => {
  const app = await fixture(t), first = await app.login('github|first'), second = await app.login('github|second');
  for (const [route, method, json] of [['/auth/organizations', 'GET'], ['/auth/organizations', 'POST', { name: 'Team', idempotencyKey: crypto.randomUUID() }], ['/auth/logout', 'POST']]) {
    const result = await app.call(route, { cookie: second.cookie, method, json, headers: { 'X-Threatlint-Profile': first.body.user.id } });
    assert.equal(result.status, 409); assert.equal(result.body.code, 'profile_changed');
  }
  assert.equal(app.management.organizations.size, 0);
  assert.equal((await app.call('/auth/session', { cookie: second.cookie })).body.user.id, second.body.user.id);
});

it('keeps ambiguous removals locally blocked across restart and supports an explicit least-privilege re-add', async t => {
  const app = await fixture(t); app.management.user('github|admin'); app.management.user('github|member'); app.management.organization('org_Acme', 'acme', ['github|admin', 'github|member']);
  const admin = await app.login('github|admin', 'org_Acme'), member = await app.login('github|member', 'org_Acme');
  app.management.failOnce((method, url) => method === 'DELETE' && url.pathname.endsWith('/members'));
  assert.equal((await app.call('/api/access/members/github%7Cmember', { cookie: admin.cookie, method: 'DELETE' })).status, 503);
  assert.equal((await app.call('/auth/session', { cookie: member.cookie })).status, 401);
  assert.equal(app.management.memberships.get('org_Acme').has('github|member'), true, 'failure did not falsely claim remote deletion');
  await app.restart(); assert.equal((await app.login('github|member', 'org_Acme')).status, 403);
  const members = await app.call('/api/access', { cookie: admin.cookie });
  assert.equal(members.body.members.find(value => value.subject === 'github|member').blocked, true);
  assert.equal((await app.call('/api/access/members', { cookie: admin.cookie, method: 'POST', json: { subject: 'github|member', role: 'viewer' } })).status, 200);
  const restored = await app.login('github|member', 'org_Acme'); assert.equal(restored.status, 200); assert.equal(restored.body.role, 'viewer'); assert.equal(restored.body.user.id, member.body.user.id);
});

it('preserves real personal and newly created company worker settings across registry and gateway restarts', async t => {
  const app = await fixture(t, { realWorkers: true }); app.management.user('github|creator');
  const personal = await app.login('github|creator');
  const created = await app.call('/auth/organizations', { cookie: personal.cookie, method: 'POST', json: { name: 'Persistent Team', idempotencyKey: crypto.randomUUID() } });
  assert.equal(created.status, 201);
  const company = await app.login('github|creator', created.body.organization.organizationId);
  const contexts = [[personal, 'guided', 'fixture-personal'], [company, 'advanced', 'fixture-company']];
  for (const [session, experience, model] of contexts) {
    assert.equal((await app.call('/api/ui-preferences', { cookie: session.cookie, method: 'PUT', json: { experience } })).status, 200);
    assert.equal((await app.call('/api/model-preferences', { cookie: session.cookie, method: 'PUT', json: { provider: 'openai', models: { openai: model } } })).status, 200);
  }
  assert.equal((await app.call('/api/ui-preferences', { cookie: company.cookie, method: 'PUT', json: { experience: 'guided' }, headers: { 'X-Threatlint-Profile': personal.body.user.id } })).status, 409);
  await app.restart();
  for (const [before, experience, model] of contexts) {
    const again = await app.login('github|creator', before.body.user.company?.organizationId);
    assert.equal(again.body.user.id, before.body.user.id);
    assert.deepEqual((await app.call('/api/ui-preferences', { cookie: again.cookie })).body.preferences, { experience });
    assert.equal((await app.call('/api/model-preferences', { cookie: again.cookie })).body.preferences.models.openai, model);
    assert.equal(fs.existsSync(path.join(app.directory, 'profiles', again.body.user.id, '.threatlint/workbench/ui-preferences.json')), true);
  }
});

it('shares a single shutdown promise and releases state ownership only after shutdown completes', async t => {
  const app = await fixture(t), first = app.close(), second = app.close();
  assert.strictEqual(first, second); await first;
  assert.equal(fs.existsSync(path.join(app.directory, 'gateway.lock')), false);
  await app.restart(); assert.equal((await app.call('/healthz')).status, 200);
});

it('rate-limits management by actor and operation without consuming the shared-proxy sign-in budget', async t => {
  const app = await fixture(t); app.management.user('github|admin'); app.management.user('github|other');
  app.management.organization('org_Acme', 'acme', ['github|admin', 'github|other']);
  const admin = await app.login('github|admin', 'org_Acme'), other = await app.login('github|other', 'org_Acme');
  assert.equal((await app.call('/api/access/members', { cookie: admin.cookie, method: 'POST', json: { subject: 'github|other', role: 'administrator' } })).status, 200);
  const search = '/api/access/candidates?email=member%40example.test';
  for (let index = 0; index < 100; index++) assert.equal((await app.call(search, { cookie: admin.cookie })).status, 200);
  const searchesBefore = app.management.calls.filter(call => call.path === '/api/v2/users-by-email').length;
  const denied = await app.call(search, { cookie: admin.cookie, headers: { 'X-Forwarded-For': '203.0.113.51' } });
  assert.equal(denied.status, 429);
  assert.equal(app.management.calls.filter(call => call.path === '/api/v2/users-by-email').length, searchesBefore, 'a rejected search must not call Auth0');
  assert.equal((await app.call(search, { cookie: other.cookie })).status, 200, 'another verified actor has an independent search budget');
  assert.equal((await app.login('github|fresh-personal')).status, 200, '100 management lookups must not exhaust sign-in behind the same socket IP');
  // A business-rule failure still consumes only this actor's creation budget, never the search or sign-in budget.
  for (let index = 0; index < 100; index++) {
    const response = await app.call('/auth/organizations', { cookie: admin.cookie, method: 'POST', json: { name: 'Another Team', idempotencyKey: crypto.randomUUID() } });
    assert.equal(response.status, 409);
  }
  assert.equal((await app.call('/auth/organizations', { cookie: admin.cookie, method: 'POST', json: { name: 'Another Team', idempotencyKey: crypto.randomUUID() } })).status, 429);
  assert.equal((await app.login('github|fresh-personal')).status, 200);
});

it('keeps the 100-attempt sign-in socket-IP limit and ignores forwarded addresses', async t => {
  const app = await fixture(t);
  for (let index = 0; index < 100; index++) assert.equal((await app.call('/auth/session', { method: 'POST' })).status, 401);
  const result = await app.call('/auth/session', { method: 'POST', headers: { 'X-Forwarded-For': '203.0.113.52' } });
  assert.equal(result.status, 429);
});

it('keeps four concurrent sign-in attempts and releases their capacity after completion', async t => {
  let entered = 0, announce, release;
  const ready = new Promise(resolve => { announce = resolve; }), waiting = new Promise(resolve => { release = resolve; });
  const app = await fixture(t, { beforeUserInfo: async () => { entered++; if (entered === 4) announce(); await waiting; } });
  const attempts = Array.from({ length: 4 }, (_, index) => app.login(`github|pending${index}`));
  const completed = Promise.allSettled(attempts);
  let timer;
  try {
    await Promise.race([ready, new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Four sign-in attempts did not reach UserInfo')), 3000); })]);
    assert.equal((await app.login('github|fifth', undefined, { 'X-Forwarded-For': '203.0.113.53' })).status, 429);
  } finally { clearTimeout(timer); release(); await completed; }
  for (const result of await completed) { assert.equal(result.status, 'fulfilled'); assert.equal(result.value.status, 200); }
  assert.equal((await app.login('github|after-completion')).status, 200);
});

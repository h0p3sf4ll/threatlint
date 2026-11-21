'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const WebSocket = require('ws');
const { createWebApp } = require('../web-server.cjs');
const { createAuth0Fixture } = require('./helpers/auth0.cjs');
const { ROLE_CLAIM } = require('../lib/rbac.cjs');

const COMPANIES = [{ slug: 'acme', name: 'Acme', auth0OrganizationId: 'org_Acme123' },
  { slug: 'beta', name: 'Beta', auth0OrganizationId: 'org_Beta456' }];
async function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-web-rbac-'));
  const received = [], provider = createAuth0Fixture();
  const upstream = http.createServer((req, res) => { received.push(req.url); req.resume(); res.setHeader('Content-Type', 'application/json'); res.end('{"ok":true}'); });
  const wss = new WebSocket.Server({ server: upstream });
  await new Promise(resolve => upstream.listen(0, '127.0.0.1', resolve));
  const workerPort = upstream.address().port;
  const workers = { acquire: async () => ({ worker: { port: workerPort, workerPort, token: 'internal-worker-token' }, release() {} }), close: async () => {} };
  const reserve = http.createServer(); await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`;
  let web;
  const start = () => {
    web = createWebApp({ directory, origin, workers, mode: 'process', companies: COMPANIES,
      auth0: provider.configuration, auth0Fetch: provider.fetch, adminSubjects: ['github|bootstrap'] });
    return new Promise(resolve => web.server.listen(port, '127.0.0.1', resolve));
  };
  await start();
  t.after(async () => { await web.close(); for (const socket of wss.clients) socket.terminate(); await new Promise(resolve => wss.close(resolve)); upstream.closeAllConnections(); await new Promise(resolve => upstream.close(resolve)); fs.rmSync(directory, { recursive: true, force: true }); });
  async function call(route, { cookie, method = 'GET', json, headers = {} } = {}) {
    const response = await fetch(`${origin}${route}`, { method, redirect: 'manual', headers: { Connection: 'close',
      ...(cookie ? { Cookie: cookie } : {}), ...(!['GET', 'HEAD'].includes(method) ? { Origin: origin } : {}),
      ...(json === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers },
      ...(json === undefined ? {} : { body: JSON.stringify(json) }) });
    const raw = await response.text(); let body = raw; try { body = JSON.parse(raw); } catch {}
    return { status: response.status, body, cookie: response.headers.get('set-cookie')?.split(';')[0] };
  }
  async function login(subject, role, company = COMPANIES[0], body = {}) {
    const token = provider.issue({ subject, email: `${subject.replace(/[^a-z]/g, '')}@example.test`, claims: {
      ...(company ? { org_id: company.auth0OrganizationId } : {}), ...(role ? { [ROLE_CLAIM]: [role] } : {}) } });
    return call('/auth/session', { method: 'POST', headers: { Authorization: `Bearer ${token}` }, json: body });
  }
  return { call, login, received, origin, restart: async () => { await web.close(); await start(); } };
}
function deniedSocket(origin, cookie) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(origin.replace('http:', 'ws:'), { origin, headers: { Cookie: cookie } });
    socket.on('error', () => {});
    socket.once('open', () => { socket.terminate(); reject(new Error('Viewer WebSocket was accepted')); });
    socket.once('unexpected-response', (_req, response) => { response.resume(); socket.terminate(); resolve(response.statusCode); });
  });
}

it('enforces company roles before forwarding API calls and rejects forged header/body privileges', async t => {
  const app = await fixture(t), viewer = await app.login('github|viewer', 'viewer'), analyst = await app.login('github|analyst', null, COMPANIES[0], { role: 'administrator' });
  assert.equal(viewer.body.role, 'viewer'); assert.equal(analyst.body.role, 'analyst');
  assert.equal((await app.call('/api/access', { cookie: viewer.cookie })).body.permissions.manageSettings, false);
  assert.equal((await app.call('/api/agents', { cookie: viewer.cookie })).status, 200);
  const platformMutations = ['/api/security-scanner/scans', '/api/security-scanner/fixes/proposal/apply', '/api/intelligence/findings/finding/reviews'];
  for (const route of ['/api/session/local', '/api/runtime/scans', '/api/servicenow/close-false-positive', '/api/management/findings/create', '/API/GITHUB/SETTINGS', ...platformMutations]) {
    assert.equal((await app.call(route, { cookie: viewer.cookie, method: 'POST', json: { role: 'administrator' }, headers: { 'X-Threatlint-Role': 'administrator' } })).status, 403, route);
  }
  for (const route of ['/api/github/settings', '/api/ado/service-account', '/api/scanners/dojo/settings', '/api/management/connections']) {
    assert.equal((await app.call(route, { cookie: analyst.cookie, method: 'POST', json: {} })).status, 403, route);
  }
  assert.equal((await app.call('/API/MODEL-PREFERENCES/', { cookie: viewer.cookie, method: 'PUT', json: {} })).status, 403);
  assert.equal((await app.call('/API/MODEL-PREFERENCES/', { cookie: analyst.cookie, method: 'PUT', json: {} })).status, 200);
  assert.equal((await app.call('/api/scm/connections', { cookie: analyst.cookie, method: 'POST', json: {} })).status, 200);
  assert.equal((await app.call('/api/scm/connections/personal-session', { cookie: analyst.cookie, method: 'DELETE' })).status, 200);
  assert.equal((await app.call('/api/session/local', { cookie: analyst.cookie, method: 'POST', json: {} })).status, 200);
  for (const route of platformMutations) {
    assert.equal((await app.call(route, { cookie: analyst.cookie, method: 'POST', json: {} })).status, 200, route);
  }
  assert.equal(await deniedSocket(app.origin, viewer.cookie), 403);
  assert.deepEqual(app.received, ['/api/agents', '/API/MODEL-PREFERENCES/', '/api/scm/connections', '/api/scm/connections/personal-session', '/api/session/local', ...platformMutations]);
});

it('lets company administrators assign persistent tenant-scoped roles with last-admin protection', async t => {
  const app = await fixture(t), admin = await app.login('github|bootstrap'), member = await app.login('github|member'), beta = await app.login('github|beta', 'administrator', COMPANIES[1]);
  assert.equal(admin.body.role, 'administrator');
  const actor = admin.cookie, userId = member.body.user.id;
  assert.equal((await app.call('/api/access/members', { cookie: member.cookie, method: 'POST', json: { userId, role: 'administrator' } })).status, 403);
  assert.equal((await app.call('/api/access/members', { cookie: actor, method: 'POST', json: { userId: beta.body.user.id, role: 'viewer' } })).status, 404);
  assert.equal((await app.call('/api/access/members', { cookie: actor, method: 'POST', json: { userId: admin.body.user.id, role: 'viewer' } })).status, 409);
  assert.equal((await app.call('/api/access/members', { cookie: actor, method: 'POST', json: { userId, role: 'viewer' } })).status, 200);
  assert.equal((await app.call('/auth/session', { cookie: member.cookie })).body.role, 'viewer');
  const wrongProfile = { 'X-Threatlint-Profile': beta.body.user.id };
  assert.equal((await app.call('/api/access', { cookie: actor, headers: wrongProfile })).status, 409);
  assert.equal((await app.call('/api/management/connections', { cookie: actor, headers: wrongProfile })).status, 409);
  assert.equal((await app.call(`/api/access?_profile=${beta.body.user.id}`, { cookie: actor })).status, 409);
  await app.restart();
  assert.equal((await app.call('/api/access', { cookie: member.cookie })).body.role, 'viewer');
  assert.equal((await app.call('/api/access', { cookie: actor })).body.members.length, 2);
  const again = await app.login('github|member', 'administrator');
  assert.equal(again.body.role, 'viewer', 'managed role survives a new verified identity claim');
});

it('keeps personal sign-in as owner and closes an existing socket after viewer demotion', async t => {
  const app = await fixture(t), admin = await app.login('github|bootstrap'), member = await app.login('github|member'), personal = await app.login('github|personal', 'viewer', null);
  assert.equal(personal.body.role, 'administrator');
  assert.equal((await app.call('/api/github/settings', { cookie: personal.cookie, method: 'POST', json: {} })).status, 200);
  const socket = await new Promise((resolve, reject) => {
    const ws = new WebSocket(app.origin.replace('http:', 'ws:'), { origin: app.origin, headers: { Cookie: member.cookie } });
    ws.once('open', () => resolve(ws)); ws.once('error', reject);
  });
  t.after(() => socket.terminate());
  const closed = new Promise((resolve, reject) => { const timeout = setTimeout(() => reject(new Error('Demotion left a socket authorized')), 3000); socket.once('close', () => { clearTimeout(timeout); resolve(); }); });
  assert.equal((await app.call('/api/access/members', { cookie: admin.cookie, method: 'POST', json: { userId: member.body.user.id, role: 'viewer' } })).status, 200);
  await closed;
});

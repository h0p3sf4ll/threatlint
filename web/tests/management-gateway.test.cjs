'use strict';

const { it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const net = require('node:net');
const { createWebApp } = require('../web-server.cjs');
const { workerCall } = require('../lib/management-gateway.cjs');
const { createAuth0Fixture } = require('./helpers/auth0.cjs');
const { parseReport } = require('../lib/reports.cjs');

const REPORT = 'e69b97c0-d8ed-4447-9a6f-6bdf61620718';
const COMPANY = { slug: 'acme', name: 'Acme', auth0OrganizationId: 'org_Acme123' };

async function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-management-gateway-'));
  const seen = [];
  const worker = http.createServer((req, res) => {
    assert.equal(req.headers['x-threatlint-worker'], 'private-worker-transport');
    assert.equal(req.headers.cookie, undefined);
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      seen.push({ url: req.url, body: body ? JSON.parse(body) : null });
      res.setHeader('Content-Type', 'application/json');
      if (req.url === `/internal/management/report/${REPORT}`) return res.end(JSON.stringify({
        report: { id: REPORT, label: 'Threat model', agentId: 'appsec-threat-modeler' },
        parsed: parseReport('# Threat Model\n\n## [TM-001] Unsafe query\n**Severity**: HIGH\n**Confidence**: CONFIRMED\n**Evidence**: src/query.js:12\n**Proposed fix**: Bind the value.\n', 'appsec-threat-modeler'),
      }));
      if (req.url === '/internal/management/source') return res.end(JSON.stringify({ id: 'active-source', provider: 'github', account: 'acme' }));
      if (req.url === '/internal/management/servicenow/source') return res.end(JSON.stringify({ available: true, instance: 'https://qa.service-now.com' }));
      if (req.url === '/internal/management/servicenow/page') return res.end(JSON.stringify({ items: [{ id: 'a'.repeat(32), number: 'AVIT0000001', title: 'A profile AVIT', state: 'Open',
        url: 'https://qa.service-now.com/nav_to.do?uri=sn_vul_app_vulnerable_item.do%3Fsys_id%3D' + 'a'.repeat(32) }], nextOffset: null }));
      res.writeHead(404); res.end('{}');
    });
  });
  await new Promise(resolve => worker.listen(0, '127.0.0.1', resolve));
  let released = 0; const acquired = [];
  const workers = { acquire: async user => { acquired.push(user.id); return { worker: { port: worker.address().port, workerPort: worker.address().port, token: 'private-worker-transport' },
    release: () => { released++; }, user }; }, close: async () => {} };
  const reserve = net.createServer(); await new Promise(resolve => reserve.listen(0, '127.0.0.1', resolve));
  const port = reserve.address().port; await new Promise(resolve => reserve.close(resolve));
  const origin = `http://127.0.0.1:${port}`, provider = createAuth0Fixture();
  const upstream = [];
  const web = createWebApp({ directory, origin, mode: 'process', companies: [COMPANY,
    { slug: 'beta', name: 'Beta', auth0OrganizationId: 'org_Beta456' }], workers,
    auth0: provider.configuration, auth0Fetch: provider.fetch,
    integrations: { fetchImpl: async (url, options = {}) => {
      upstream.push({ url: String(url), options });
      if (url.includes('/issues?')) return Response.json([{ number: 7, title: 'Unsafe query', state: 'open' }]);
      return Response.json({ number: 7, title: 'Unsafe query', state: 'open', html_url: 'https://github.com/acme/app/issues/7' });
    } } });
  await new Promise(resolve => web.server.listen(port, '127.0.0.1', resolve));
  t.after(async () => {
    await web.close(); worker.closeAllConnections(); await new Promise(resolve => worker.close(resolve));
    fs.rmSync(directory, { recursive: true, force: true });
  });
  async function call(route, { method = 'GET', cookie, json, headers = {} } = {}) {
    const response = await fetch(origin + route, { method, headers: { Origin: origin, ...(cookie ? { Cookie: cookie } : {}),
      ...(json === undefined ? {} : { 'Content-Type': 'application/json' }), ...headers }, ...(json === undefined ? {} : { body: JSON.stringify(json) }) });
    return { status: response.status, body: await response.json(), cookie: response.headers.get('set-cookie')?.split(';')[0] };
  }
  async function signIn(subject, organizationId = COMPANY.auth0OrganizationId, role = 'analyst') {
    return call('/auth/session', { method: 'POST', headers: { Authorization: `Bearer ${provider.issue({ subject: `google-oauth2|${subject}`,
      claims: { org_id: organizationId, 'https://threatlint.dev/roles': [role] } })}` }, json: {} });
  }
  return { web, call, signIn, seen, upstream, workers, acquired, released: () => released };
}

it('shares named connections and finding records within a verified organization, keeping other companies separate', async t => {
  const f = await fixture(t);
  const admin = await f.signIn('admin', COMPANY.auth0OrganizationId, 'administrator');
  const analyst = await f.signIn('analyst');
  const outsider = await f.signIn('outsider', 'org_Beta456', 'administrator');
  const settings = { name: 'Application issues', kind: 'tracker', provider: 'github-issues', repository: 'acme/app', token: 'fixture-token-only' };
  const saved = await f.call('/api/management/connections', { method: 'POST', cookie: admin.cookie, json: settings });
  assert.ok(saved.status < 300, JSON.stringify(saved.body));
  const list = await f.call('/api/management/connections', { cookie: analyst.cookie });
  assert.equal(list.body.connections.length, 1);
  assert.equal(JSON.stringify(list.body).includes(settings.token), false);
  const connectionId = list.body.connections[0].id;
  assert.equal((await f.call('/api/management/connections', { cookie: outsider.cookie })).body.connections.length, 0);
  assert.equal((await f.call('/api/management/connections', { method: 'POST', cookie: analyst.cookie, json: settings })).status, 403);
  const created = await f.call('/api/management/findings/create', { method: 'POST', cookie: analyst.cookie,
    json: { connectionId, reportId: REPORT, findingId: 'TM-001' } });
  assert.ok(created.status < 300, JSON.stringify(created.body));
  const findings = await f.call('/api/management/findings', { cookie: admin.cookie });
  assert.equal(findings.body.findings.length, 1);
  assert.equal((await f.call('/api/management/findings', { cookie: outsider.cookie })).body.findings.length, 0);
  assert.equal(f.seen[0].url, `/internal/management/report/${REPORT}`);
  assert.equal(f.released(), 1);
  assert.equal(f.upstream[0].options.headers.Authorization, `Bearer ${settings.token}`);
});

it('checks profile pinning before shared routes and activates source credentials only in the requesting runtime', async t => {
  const f = await fixture(t);
  const admin = await f.signIn('admin', COMPANY.auth0OrganizationId, 'administrator');
  const analyst = await f.signIn('analyst');
  const saved = await f.call('/api/management/connections', { method: 'POST', cookie: admin.cookie,
    json: { name: 'Engineering source', kind: 'scm', provider: 'github', organization: 'acme', token: 'fixture-source-token' } });
  assert.ok(saved.status < 300);
  const list = await f.call('/api/management/connections', { cookie: admin.cookie });
  const id = list.body.connections[0].id;
  assert.equal((await f.call('/api/management/connections', { cookie: admin.cookie,
    headers: { 'X-Threatlint-Profile': analyst.body.user.id } })).status, 409);
  const activated = await f.call(`/api/management/connections/${id}/activate`, { method: 'POST', cookie: analyst.cookie, json: {} });
  assert.ok(activated.status < 300, JSON.stringify(activated.body));
  assert.deepEqual(f.seen[0].body, { provider: 'github', token: 'fixture-source-token', organization: 'acme' });
  assert.equal(JSON.stringify(activated.body).includes('fixture-source-token'), false);
  const viewer = await f.signIn('viewer', COMPANY.auth0OrganizationId, 'viewer');
  assert.equal((await f.call(`/api/management/connections/${id}/activate`, { method: 'POST', cookie: viewer.cookie, json: {} })).status, 403);
});

it('releases the runtime lease on a private report miss', async t => {
  const f = await fixture(t), admin = await f.signIn('admin');
  await assert.rejects(workerCall(f.workers, admin.body.user, '/internal/management/report/missing'), { status: 404 });
  assert.equal(f.released(), 1);
});

it('pulls shared issues only for authorized members and pins profile selectors before any provider or worker read', async t => {
  const f = await fixture(t), admin = await f.signIn('admin', COMPANY.auth0OrganizationId, 'administrator'), analyst = await f.signIn('analyst');
  const viewer = await f.signIn('viewer', COMPANY.auth0OrganizationId, 'viewer'), outsider = await f.signIn('outsider', 'org_Beta456', 'administrator');
  const id = (await f.call('/api/management/connections', { method: 'POST', cookie: admin.cookie, json: { name: 'Issues', kind: 'tracker', provider: 'github-issues', repository: 'acme/app', token: 'fixture-private-token' } })).body.connection.id;
  const input = { sources: [{ connectionId: id }] };
  assert.equal((await f.call('/api/management/findings/pull', { method: 'POST', cookie: viewer.cookie, json: input })).status, 403); assert.equal(f.upstream.length, 0);
  assert.equal((await f.call('/api/management/findings/pull', { method: 'POST', cookie: analyst.cookie, json: input, headers: { 'X-Threatlint-Profile': admin.body.user.id } })).status, 409); assert.equal(f.upstream.length, 0);
  const other = await f.call('/api/management/findings/pull', { method: 'POST', cookie: outsider.cookie, json: input }); assert.match(other.body.sources[0].error, /not found/); assert.equal(f.upstream.length, 0);
  const result = await f.call('/api/management/findings/pull', { method: 'POST', cookie: analyst.cookie, json: input }); assert.equal(result.status, 200); assert.equal(result.body.findings.length, 1);
  assert.equal(f.upstream.length, 1); assert.equal(f.upstream[0].options.method, 'GET'); assert.equal(JSON.stringify(result.body).includes('fixture-private-token'), false);
  assert.equal((await f.call('/api/management/findings', { cookie: admin.cookie })).body.findings.length, 1); assert.equal((await f.call('/api/management/findings', { cookie: outsider.cookie })).body.findings.length, 0);
  const before = f.seen.length;
  assert.equal((await f.call('/api/management/issue-sources', { cookie: analyst.cookie, headers: { 'X-Threatlint-Profile': admin.body.user.id } })).status, 409); assert.equal(f.seen.length, before);
});

it('discovers and pulls ServiceNow only through the requesting member’s leased private worker', async t => {
  const f = await fixture(t), analyst = await f.signIn('analyst');
  const sources = await f.call('/api/management/issue-sources', { cookie: analyst.cookie });
  assert.equal(sources.body.sources[0].id, 'servicenow-avit'); assert.equal(sources.body.sources[0].available, true);
  assert.equal(JSON.stringify(sources.body).includes('private-worker-transport'), false);
  const result = await f.call('/api/management/findings/pull', { method: 'POST', cookie: analyst.cookie, json: { sources: [{ connectionId: 'servicenow-avit', filters: { state: '1' } }] } });
  assert.equal(result.body.findings[0].externalId, 'AVIT0000001');
  assert.deepEqual(f.acquired, [analyst.body.user.id, analyst.body.user.id, analyst.body.user.id]); assert.equal(f.released(), 3);
  assert.deepEqual(f.seen.at(-1), { url: '/internal/management/servicenow/page', body: { instance: 'https://qa.service-now.com', filters: { state: '1' }, offset: 0 } });
  assert.equal(f.upstream.length, 0);
  assert.equal((await f.call('/internal/management/servicenow/source', { cookie: analyst.cookie })).status, 404);
});

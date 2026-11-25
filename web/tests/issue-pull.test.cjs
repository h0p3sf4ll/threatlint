'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const express = require('express');
const trackers = require('../lib/issue-trackers.cjs');
const { createManagementStore } = require('../lib/integration-management.cjs');
const { registerManagementRoutes } = require('../lib/routes/management.cjs');
const github = { provider: 'github-issues', kind: 'tracker', name: 'Issues', repository: 'example/app', token: 'fixture-private-token' };
const jira = { provider: 'jira', kind: 'tracker', name: 'Jira', baseUrl: 'https://example.atlassian.net', username: 'qa@example.test', project: 'SEC', token: 'fixture-jira-token' };
const azure = { provider: 'azure-boards', kind: 'tracker', name: 'Azure', organization: 'example', project: 'Application', token: 'fixture-azure-token' };
const ghRow = (number, state = 'open') => ({ number, title: 'Finding ' + number, state, repository_url: 'https://api.github.com/repos/example/app', body: 'Untrusted issue body' });
const jiraRow = (key = 'SEC-1', type = 'Security finding') => ({ key, fields: { summary: 'A finding', issuetype: { name: type, id: '10042' }, status: { name: 'Open', statusCategory: { key: 'new' } } } });
const azureRow = (id, type = 'Security finding', project = 'Application') => ({ id, fields: { 'System.Title': 'A finding', 'System.State': 'New', 'System.WorkItemType': type, 'System.TeamProject': project } });

async function fixture(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-issue-pull-'));
  const app = express(); app.use(express.json());
  const management = registerManagementRoutes(app, { directory, serviceNowSource: async () => ({ available: false }), ...options });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); fs.rmSync(directory, { recursive: true, force: true }); });
  async function call(route, body) {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/management${route}`, { method: body === undefined ? 'GET' : 'POST',
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json() };
  }
  return { directory, management, call };
}

test('Jira enhanced search uses an exact custom type, bounded token pagination, and rejects out-of-scope responses', async () => {
  const connection = trackers.validateConnection(jira), requests = [];
  const fetchImpl = async (url, options) => { requests.push({ url, options, body: JSON.parse(options.body) }); return Response.json({ issues: [jiraRow()], nextPageToken: 'next-page', isLast: false }); };
  const page = await trackers.pullIssues(connection, { filters: { issueType: 'Security finding', state: 'open' }, fetchImpl });
  assert.equal(page.issues[0].externalId, 'SEC-1'); assert.equal(page.issues[0].issueType, 'Security finding'); assert.equal(page.nextPosition, 'next-page');
  assert.equal(requests[0].url, 'https://example.atlassian.net/rest/api/3/search/jql'); assert.equal(requests[0].options.method, 'POST');
  assert.equal(requests[0].options.redirect, 'error'); assert.ok(requests[0].options.signal);
  assert.equal(requests[0].body.maxResults, 100); assert.match(requests[0].body.jql, /project = "SEC" AND issuetype = "Security finding" AND statusCategory != Done/);
  await trackers.pullIssues(connection, { filters: { issueType: 'Security finding' }, position: 'next-page', fetchImpl: async (_url, options) => {
    assert.equal(JSON.parse(options.body).nextPageToken, 'next-page'); return Response.json({ issues: [jiraRow('SEC-2')], isLast: true });
  } });
  for (const row of [jiraRow('OTHER-1'), jiraRow('SEC-1', 'Task')]) await assert.rejects(trackers.pullIssues(connection, { filters: { issueType: 'Security finding' }, fetchImpl: async () => Response.json({ issues: [row], isLast: true }) }), /project|issue type/);
  await assert.rejects(trackers.pullIssues(connection, { filters: { issueType: 'Security finding' }, position: 'repeated', fetchImpl: async () => Response.json({ issues: [], nextPageToken: 'repeated', isLast: false }) }), /next-page/);
  await assert.rejects(trackers.pullIssues(connection, { filters: { issueType: 'Security finding' }, fetchImpl: async () => Response.json({ issues: [] }) }), /invalid issue page/);
  await assert.rejects(trackers.pullIssues(connection, { filters: { query: 'project=ANY' }, fetchImpl: () => assert.fail('Invalid filter must not fetch') }), /supported/);
});

test('GitHub continues PR-only pages and constructs every next URL inside the configured repository', async () => {
  const connection = trackers.validateConnection(github), calls = [];
  const first = await trackers.pullIssues(connection, { fetchImpl: async (url, options) => {
    calls.push({ url, options }); return Response.json([{ number: 1, pull_request: {} }], { headers: { Link: '<https://untrusted.example/steal>; rel="next"' } });
  } });
  assert.deepEqual(first.issues, []); assert.equal(first.nextPosition, 2);
  const second = await trackers.pullIssues(connection, { position: first.nextPosition, fetchImpl: async (url, options) => {
    calls.push({ url, options }); return Response.json([{ ...ghRow(2), repository_url: 'https://api.github.com/repos/Example/App' }]);
  } });
  assert.equal(second.issues[0].externalId, '2'); assert.equal(second.nextPosition, null);
  assert.equal(new URL(calls[1].url).searchParams.get('page'), '2');
  for (const call of calls) { assert.equal(new URL(call.url).origin, 'https://api.github.com'); assert.equal(new URL(call.url).pathname, '/repos/example/app/issues'); assert.equal(call.options.method, 'GET'); }
  await assert.rejects(trackers.pullIssues(connection, { fetchImpl: async () => Response.json([{ ...ghRow(1), repository_url: 'https://api.github.com/repos/other/app' }]) }), /outside this repository/);
});

test('Azure WIQL and batch reads paginate IDs and verify exact project, type and complete batch identity', async () => {
  const connection = trackers.validateConnection(azure), requests = [];
  const fetchImpl = async (url, options) => {
    const body = JSON.parse(options.body); requests.push({ url, options, body });
    if (url.includes('/wiql?')) return Response.json({ asOf: '2026-11-25T12:00:00Z', workItems: Array.from({ length: 101 }, (_, index) => ({ id: index + 1 })) });
    return Response.json({ value: body.ids.map(id => azureRow(id)) });
  };
  const page = await trackers.pullIssues(connection, { filters: { issueType: 'Security finding' }, fetchImpl });
  assert.equal(page.issues.length, 100); assert.equal(page.nextPosition, 100); assert.equal(requests[0].options.method, 'POST');
  assert.match(requests[0].url, /wiql\?\$top=101&api-version=7\.1$/); assert.match(requests[0].body.query, /\[System.TeamProject\] = 'Application' AND \[System.WorkItemType\] = 'Security finding'/);
  assert.equal(requests[1].body.ids.length, 100); assert.equal(requests[1].body.asOf, '2026-11-25T12:00:00Z'); assert.equal(requests[1].body.errorPolicy, 'Fail');
  for (const rows of [[], [azureRow(9)], [azureRow(1, 'Bug')], [azureRow(1, 'Security finding', 'Other')]]) {
    await assert.rejects(trackers.pullIssues(connection, { filters: { issueType: 'Security finding' }, fetchImpl: async url => Response.json(url.includes('/wiql?') ? { workItems: [{ id: 1 }] } : { value: rows }) }), /scope|project/);
  }
  await trackers.pullIssues(connection, { filters: { issueType: "Owner's finding" }, position: 100, fetchImpl: async (_url, options) => {
    assert.match(JSON.parse(options.body).query, /\[System.WorkItemType\] = "Owner's finding"/); assert.match(JSON.parse(options.body).query, /\[System.Id\] > 100/); return Response.json({ workItems: [] });
  } });
  await assert.rejects(trackers.pullIssues(connection, { filters: { issueType: 'Both\'"quotes' }, fetchImpl: () => assert.fail('Unsafe expression must not fetch') }), /both quote/);
});

test('source pulls persist idempotently, keep omitted issues, and isolate per-source provider errors', async t => {
  let fail = false, empty = false;
  const f = await fixture(t, { integrations: { fetchImpl: async url => {
    if (url.includes('/repos/example/bad/')) return new Response('fixture-private-token secret upstream body', { status: 403 });
    if (fail) throw new Error('fixture-private-token'); return Response.json(empty ? [] : [ghRow(7)]);
  } } });
  const good = (await f.call('/connections', github)).body.connection, bad = (await f.call('/connections', { ...github, name: 'Bad source', repository: 'example/bad' })).body.connection;
  const request = { sources: [{ connectionId: good.id }, { connectionId: bad.id }] };
  const first = await f.call('/findings/pull', request); assert.equal(first.status, 200); assert.equal(first.body.findings.length, 1); assert.equal(first.body.sources[1].imported, 0); assert.match(first.body.sources[1].error, /HTTP 403/);
  assert.equal(JSON.stringify(first.body).includes(github.token), false); assert.equal(JSON.stringify(first.body).includes('secret upstream body'), false);
  const second = await f.call('/findings/pull', { sources: [{ connectionId: good.id }] }); assert.equal(second.body.findings[0].id, first.body.findings[0].id);
  empty = true; await f.call('/findings/pull', { sources: [{ connectionId: good.id }] }); assert.equal((await f.call('/findings')).body.findings.length, 1);
  const before = fs.readFileSync(path.join(f.directory, 'integration-management.json')); fail = true;
  const rejected = await f.call('/findings/pull', { sources: [{ connectionId: good.id }] }); assert.match(rejected.body.sources[0].error, /failed or timed out/); assert(fs.readFileSync(path.join(f.directory, 'integration-management.json')).equals(before));
  assert.equal((await f.call('/findings/pull', { sources: Array.from({ length: 11 }, (_, i) => ({ connectionId: String(i) })) })).status, 400);
  assert.equal((await f.call('/findings/pull', { sources: [{ connectionId: good.id }, { connectionId: good.id }] })).status, 400);
});

test('opaque cursors survive registry restart and reject changed filters, sources, tenants and tampering', async t => {
  const f = await fixture(t, { integrations: { fetchImpl: async url => Response.json([ghRow(Number(new URL(url).searchParams.get('page')))], { headers: { Link: '<https://api.github.com/repos/example/app/issues?page=2>; rel="next"' } }) } });
  const id = (await f.call('/connections', github)).body.connection.id;
  const first = await f.call('/findings/pull', { sources: [{ connectionId: id }] }), cursor = first.body.sources[0].nextCursor;
  assert.equal(typeof cursor, 'string'); const restored = createManagementStore(f.directory), connection = restored.connection(id);
  assert.equal(restored.readPullCursor(connection, { state: 'all' }, cursor), 2);
  assert.throws(() => restored.readPullCursor(connection, { state: 'closed' }, cursor), /filters or source changed/);
  assert.throws(() => restored.readPullCursor({ ...connection, id: 'another' }, { state: 'all' }, cursor), /filters or source changed/);
  assert.throws(() => createManagementStore().readPullCursor(connection, { state: 'all' }, cursor), /Invalid/);
  const tampered = cursor[0] === 'A' ? 'B' + cursor.slice(1) : 'A' + cursor.slice(1);
  assert.throws(() => restored.readPullCursor(connection, { state: 'all' }, tampered), /Invalid/);
  const second = await f.call('/findings/pull', { sources: [{ connectionId: id, cursor }] }); assert.equal(second.body.findings[0].externalId, '2');
  assert.match((await f.call('/findings/pull', { sources: [{ connectionId: id, cursor, filters: { state: 'open' } }] })).body.sources[0].error, /filters or source changed/);
});

test('ServiceNow automatically uses profile settings, stores a tokenless v2 descriptor only on pull, and rejects ticket writes before operations', async t => {
  let instance = 'https://qa.service-now.com', calls = 0;
  const f = await fixture(t, { serviceNowSource: async () => ({ available: true, instance }), serviceNowPage: async (_req, connection, input) => {
    calls++; assert.equal(connection.instance, instance); assert.deepEqual(input.filters, { state: '1' });
    return { items: [{ id: 'a'.repeat(32), number: 'AVIT0000001', title: 'Test AVIT', state: 'Open', url: instance + '/nav_to.do?uri=sn_vul_app_vulnerable_item.do%3Fsys_id%3D' + 'a'.repeat(32) }], nextOffset: null };
  } });
  const sources = await f.call('/issue-sources'); assert.equal(sources.body.sources[0].id, 'servicenow-avit'); assert.equal(sources.body.sources[0].available, true); assert.equal(sources.body.sources[0].pullOnly, true);
  assert.equal((await f.call('/connections')).body.connections.length, 0); assert.equal(fs.existsSync(path.join(f.directory, 'integration-management.json')), false);
  const first = await f.call('/findings/pull', { sources: [{ connectionId: 'servicenow-avit', filters: { state: '1' } }] }); assert.equal(first.body.findings.length, 1); assert.equal(calls, 1);
  const connectionId = first.body.findings[0].connectionId, filename = path.join(f.directory, 'integration-management.json');
  const saved = JSON.parse(fs.readFileSync(filename)); assert.equal(saved.version, 2); assert.equal(saved.connections[0].credentialSource, 'servicenow-settings'); assert.equal(Object.hasOwn(saved.connections[0], 'encryptedToken'), false); assert.equal(Object.hasOwn(saved.connections[0], 'token'), false);
  assert.equal(createManagementStore(f.directory).listFindings()[0].id, first.body.findings[0].id);
  for (const [route, body] of [['/findings/import', { connectionId, ids: ['AVIT0000001'] }], ['/findings/create', { connectionId, reportId: 'x', findingId: 'F-1' }], [`/findings/${first.body.findings[0].id}/close`, { confirm: true, reportId: 'x', findingId: 'F-1' }]]) assert.equal((await f.call(route, body)).status, 409);
  assert.equal(JSON.parse(fs.readFileSync(filename)).operations.length, 0); assert.equal(calls, 1);
  assert.equal((await f.call('/findings/sync', { connectionId })).status, 409);
  const synced = await f.call('/findings/sync', {}); assert.equal(synced.status, 200); assert.equal(synced.body.skippedReadOnly, 1); assert.equal(synced.body.errors.length, 0); assert.equal(synced.body.total, 0); assert.match(synced.body.message, /Pull issues/);
  const repeat = await f.call('/findings/pull', { sources: [{ connectionId: 'servicenow-avit', filters: { state: '1' } }] }); assert.equal(repeat.body.findings[0].id, first.body.findings[0].id);
  instance = 'https://another.service-now.com'; const other = await f.call('/findings/pull', { sources: [{ connectionId: 'servicenow-avit', filters: { state: '1' } }] }); assert.notEqual(other.body.findings[0].connectionId, connectionId); assert.equal((await f.call('/findings')).body.findings.length, 2);
});

test('registry keeps ordinary encrypted connections v1 and rejects invalid or incompatible ServiceNow descriptors without rewriting', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-pull-version-')); t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const store = createManagementStore(directory); store.upsert(github); store.save(); const file = path.join(directory, 'integration-management.json');
  assert.equal(JSON.parse(fs.readFileSync(file)).version, 1); assert.equal(fs.readFileSync(file, 'utf8').includes(github.token), false);
  const restored = createManagementStore(directory); assert.equal(restored.connection(restored.listConnections()[0].id).token, github.token);
  const preview = restored.serviceNowConnection('https://qa.service-now.com', { create: false }); assert.equal(restored.state.version, 1); assert.equal(restored.state.connections.length, 1);
  restored.serviceNowConnection(preview.instance); restored.save(); const valid = JSON.parse(fs.readFileSync(file)); assert.equal(valid.version, 2);
  for (const value of [{ ...valid, version: 1 }, { ...valid, version: 3 }, { ...valid, connections: valid.connections.map(item => item.provider === 'servicenow-avit' ? { ...item, encryptedToken: 'not-allowed' } : item) }]) {
    fs.writeFileSync(file, JSON.stringify(value)); const bytes = fs.readFileSync(file); assert.throws(() => createManagementStore(directory), /preserved/); assert(fs.readFileSync(file).equals(bytes));
  }
});

test('ServiceNow upstream failures never echo raw credentials or replace previous issues', async t => {
  let fail = false;
  const instance = 'https://qa.service-now.com', f = await fixture(t, { serviceNowSource: async () => ({ available: true, instance }), serviceNowPage: async () => {
    if (fail) throw new (require('../lib/http.cjs').HttpError)('fixture-client-secret from upstream error.cause', 502);
    return { items: [{ id: 'b'.repeat(32), number: 'AVIT0000002', title: 'An AVIT', state: 'Open', url: instance + '/nav_to.do?uri=sn_vul_app_vulnerable_item.do%3Fsys_id%3D' + 'b'.repeat(32) }], nextOffset: null };
  } });
  const input = { sources: [{ connectionId: 'servicenow-avit' }] };
  assert.equal((await f.call('/findings/pull', input)).body.findings.length, 1);
  const previous = fs.readFileSync(path.join(f.directory, 'integration-management.json')); fail = true;
  const result = await f.call('/findings/pull', input);
  assert.equal(result.body.findings.length, 0); assert.equal(JSON.stringify(result.body).includes('fixture-client-secret'), false); assert.match(result.body.sources[0].error, /could not be read/);
  assert(fs.readFileSync(path.join(f.directory, 'integration-management.json')).equals(previous));
});

test('the actual desktop server pulls ServiceNow using its existing isolated Settings without any login', async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-desktop-issue-pull-'));
  const names = ['THREATLINT_HOME', 'THREATLINT_SNOW_INSTANCE', 'THREATLINT_SNOW_CLIENT_ID', 'THREATLINT_SNOW_CLIENT_SECRET', 'THREATLINT_PROFILE_WORKER', 'THREATLINT_WORKER_TOKEN'];
  const previous = Object.fromEntries(names.map(name => [name, process.env[name]])); let workbench, releaseHeldPage;
  try {
    process.env.THREATLINT_HOME = path.join(root, 'home'); for (const name of names.slice(1)) delete process.env[name];
    const requests = [], { createWorkbench } = require('../server.js'); let holdPage, notifyHeldPage;
    workbench = createWorkbench({ storageDir: path.join(root, 'workbench'), integrations: { fetchImpl: async (url, options = {}) => {
      requests.push({ url, method: options.method || 'GET' }); assert.equal(new URL(url).origin, 'https://qa.service-now.com');
      if (url.endsWith('/oauth_token.do')) { assert.match(String(options.body), /fixture-desktop-client/); return Response.json({ access_token: 'fixture-service-now-access-token' }); }
      if (url.includes('/sys_documentation?')) return Response.json({ result: [] });
      assert.ok(url.includes('/sn_vul_app_vulnerable_item?')); assert.equal(options.headers.Authorization, 'Bearer fixture-service-now-access-token');
      if (holdPage) { notifyHeldPage(); await holdPage; }
      return Response.json({ result: [{ sys_id: 'c'.repeat(32), number: 'AVIT0000003', short_description: 'An actual server import', state: { value: '1', display_value: 'Open' } }] }, { headers: { 'x-total-count': '1' } });
    } } });
    await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve)); const origin = 'http://127.0.0.1:' + workbench.server.address().port;
    async function call(route, body) { const response = await fetch(origin + route, { method: body === undefined ? 'GET' : 'POST', headers: { Origin: origin, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }); return { status: response.status, body: await response.json() }; }
    assert.equal((await call('/api/management/issue-sources')).body.sources[0].available, false);
    assert.equal((await call('/api/servicenow/settings', { instance: 'https://qa.service-now.com', clientId: 'fixture-desktop-client', clientSecret: 'fixture-desktop-secret' })).status, 200);
    const sources = await call('/api/management/issue-sources'); assert.equal(sources.status, 200); assert.equal(sources.body.sources[0].available, true);
    assert.equal(JSON.stringify(sources.body).includes('fixture-desktop-client'), false); assert.equal(JSON.stringify(sources.body).includes('fixture-desktop-secret'), false);
    const pulled = await call('/api/management/findings/pull', { sources: [{ connectionId: 'servicenow-avit' }] });
    assert.equal(pulled.status, 200); assert.equal(pulled.body.findings[0].externalId, 'AVIT0000003'); assert.equal(pulled.body.sources[0].error, undefined);
    assert.equal(requests.length, 3); assert.deepEqual(requests.map(row => row.method), ['POST', 'GET', 'GET']);
    assert.equal((await call('/internal/management/servicenow/source')).status, 404);
    assert.equal(fs.existsSync(path.join(root, 'workbench', 'identities.json')), false);
    process.env.THREATLINT_PROFILE_WORKER = '1'; process.env.THREATLINT_WORKER_TOKEN = 'fixture-private-worker-token';
    holdPage = new Promise(resolve => { releaseHeldPage = resolve; });
    const started = new Promise(resolve => { notifyHeldPage = resolve; });
    const privateHeaders = { Origin: origin, 'x-threatlint-worker': 'fixture-private-worker-token' };
    const pending = fetch(origin + '/internal/management/servicenow/page', { method: 'POST', headers: { ...privateHeaders, 'Content-Type': 'application/json' }, body: JSON.stringify({ instance: 'https://qa.service-now.com', filters: {}, offset: 0 }) });
    let timer; try { await Promise.race([started, new Promise((_resolve, reject) => { timer = setTimeout(() => reject(new Error('Private page did not start')), 2000); })]); } finally { clearTimeout(timer); }
    assert.equal((await (await fetch(origin + '/internal/activity', { headers: privateHeaders })).json()).busy, true);
    releaseHeldPage(); assert.equal((await pending).status, 200);
    assert.equal((await (await fetch(origin + '/internal/activity', { headers: privateHeaders })).json()).busy, false);
  } finally {
    releaseHeldPage?.();
    await workbench?.close();
    for (const name of names) { if (previous[name] === undefined) delete process.env[name]; else process.env[name] = previous[name]; }
    fs.rmSync(root, { recursive: true, force: true });
  }
});

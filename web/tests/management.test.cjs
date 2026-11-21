'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const express = require('express');
const { createManagementStore } = require('../lib/integration-management.cjs');
const trackers = require('../lib/issue-trackers.cjs');
const { registerManagementRoutes } = require('../lib/routes/management.cjs');
const { parseReport } = require('../lib/reports.cjs');

const github = { provider: 'github-issues', kind: 'tracker', name: 'Engineering issues', repository: 'example/application', token: 'private-token' };
const jira = { provider: 'jira', kind: 'tracker', name: 'Jira security', baseUrl: 'https://example.atlassian.net', username: 'security@example.test', project: 'SEC', closeTransitionId: '31', token: 'jira-token' };
const azure = { provider: 'azure-boards', kind: 'tracker', name: 'Azure security', organization: 'example', project: 'Application', token: 'azure-token' };
function report(id = 'source-report', original = null, overrides = {}) {
  const agentId = original ? 'appsec-fp-reviewer' : 'appsec-threat-modeler';
  const body = `# Finding Review\n\n## [F-001] Input validation\n**Severity**: HIGH\n**Confidence**: CONFIRMED\n${original ? `**Original finding**: ${original}\n**Disposition**: FALSE POSITIVE\n` : ''}**Evidence**: src/input.js:7 validates the input before use.\n**Verified Safe Behavior**: The allowlist rejects unsupported inputs.\n**Suppression impact**: One scoped finding.\n`;
  return { report: { id, agentId, label: 'Review' }, parsed: parseReport(body, agentId), ...overrides };
}
async function createFixture(t, options = {}) {
  const app = express(); app.use(express.json());
  const reports = new Map([['source-report', report()], ['fp-report', report('fp-report', 'example/application#7')]]);
  const management = registerManagementRoutes(app, { resolveReport: async (_req, id) => reports.get(id), ...options });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  async function call(route, body, method = body === undefined ? 'GET' : 'POST') {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/management${route}`, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, ...(body ? { body: JSON.stringify(body) } : {}) });
    return { status: response.status, body: await response.json() };
  }
  return { call, management, reports };
}
function githubProvider() {
  const requests = []; let state = 'open', description = '', failRead = false;
  async function fetchImpl(url, options = {}) {
    const method = options.method || 'GET', body = options.body ? JSON.parse(options.body) : null;
    requests.push({ url, method, body, options });
    if (method === 'POST' && url.endsWith('/issues')) { description = body.body; return Response.json({ number: 7 }); }
    if (method === 'POST' && url.endsWith('/comments')) return Response.json({ id: 100 });
    if (method === 'PATCH') { state = body.state; return Response.json({ number: 7, state }); }
    if (url.endsWith('/issues/8')) return new Response('token and private upstream data', { status: 403 });
    if (url.endsWith('/issues/7')) { if (failRead) throw new Error('private upstream data'); return Response.json({ number: 7, title: 'Input validation', state, body: description }); }
    return Response.json({ full_name: 'example/application' });
  }
  return { fetchImpl, requests, failRead: value => { failRead = value; }, setClosed: () => { state = 'closed'; } };
}

test('connection registry permits multiple provider instances, encrypts tokens, and retains blank secrets', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-management-')); t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const store = createManagementStore(directory);
  const first = store.upsert({ ...github, isDefault: true });
  const second = store.upsert({ ...github, name: 'Another team', repository: 'example/another', isDefault: true }); store.save();
  assert.equal(store.listConnections().length, 2); assert.equal(store.listConnections()[0].isDefault, false); assert.equal(store.listConnections()[1].isDefault, true);
  assert.equal(JSON.stringify(store.listConnections()).includes('private-token'), false);
  const saved = fs.readFileSync(path.join(directory, 'integration-management.json'), 'utf8');
  assert.equal(saved.includes('private-token'), false); assert.match(saved, /encryptedToken/);
  const restored = createManagementStore(directory); assert.equal(restored.connection(first.id).token, 'private-token');
  restored.upsert({ ...github, id: second.id, token: '', enabled: false, isDefault: true });
  assert.equal(restored.connection(second.id, { enabled: false }).token, 'private-token');
  assert.equal(restored.listConnections()[1].isDefault, false); assert.throws(() => restored.connection(second.id), /Enable/);
});

test('provider validation rejects secret exfiltration origins, invalid project scopes and unsupported SCM providers', () => {
  for (const baseUrl of ['http://example.atlassian.net', 'https://evil.test', 'https://example.atlassian.net.evil.test', 'https://example.atlassian.net/path', 'https://u:p@example.atlassian.net', 'https://example.atlassian.net:443']) {
    if (baseUrl.endsWith(':443')) continue; // URL canonicalization removes an explicit standard TLS port.
    assert.throws(() => trackers.validateConnection({ ...jira, baseUrl }));
  }
  assert.throws(() => trackers.validateConnection({ ...jira, project: 'SEC.*' }));
  assert.throws(() => trackers.validateConnection({ ...azure, organization: 'https://evil.test' }));
  assert.throws(() => trackers.validateConnection({ ...github, repository: '../escape' }));
  assert.throws(() => trackers.validateConnection({ ...github, kind: 'scm', provider: 'gitlab' }));
  assert.throws(() => trackers.validateConnection({ ...github, token: 'secret\nheader' }));
});

test('GitHub adapter creates and closes using documented endpoints, bounded transport, and verified readback', async () => {
  const provider = githubProvider(), connection = trackers.validateConnection(github);
  const created = await trackers.createIssue(connection, { title: 'Input validation', body: 'Finding evidence' }, provider);
  assert.equal(created.externalId, '7'); assert.equal(created.url, 'https://github.com/example/application/issues/7');
  const closed = await trackers.closeIssue(connection, '7', 'False-positive evidence', provider); assert.equal(closed.closed, true);
  const patch = provider.requests.find(item => item.method === 'PATCH'); assert.deepEqual(patch.body, { state: 'closed', state_reason: 'not_planned' });
  for (const request of provider.requests) { assert.equal(request.options.redirect, 'error'); assert.ok(request.options.signal); assert.equal(new URL(request.url).origin, 'https://api.github.com'); }
  assert.ok(provider.requests.find(item => item.url.endsWith('/comments')).body.body.includes('False-positive evidence'));
});

test('Jira uses ADF create fields and an available Done transition with the review comment', async () => {
  const connection = trackers.validateConnection(jira), requests = []; let closed = false;
  const fetchImpl = async (url, options) => {
    const body = options.body && JSON.parse(options.body); requests.push({ url, options, body });
    if (options.method === 'POST' && url.endsWith('/issue')) return Response.json({ key: 'SEC-4' });
    if (url.endsWith('/transitions') && options.method === 'GET') return Response.json({ transitions: [{ id: '31', to: { statusCategory: { key: 'done' } } }] });
    if (url.endsWith('/transitions') && options.method === 'POST') { closed = true; return new Response(null, { status: 204 }); }
    return Response.json({ key: 'SEC-4', fields: { summary: 'A finding', status: { name: closed ? 'Done' : 'Open', statusCategory: { key: closed ? 'done' : 'new' } } } });
  };
  await trackers.createIssue(connection, { title: 'A finding', body: 'Evidence' }, { fetchImpl });
  assert.equal(requests[0].body.fields.description.type, 'doc'); assert.equal(requests[0].body.fields.project.key, 'SEC');
  await trackers.closeIssue(connection, 'SEC-4', 'Review evidence', { fetchImpl });
  const transition = requests.find(item => item.options.method === 'POST' && item.url.endsWith('/transitions'));
  assert.equal(transition.body.update.comment[0].add.body.content[0].content[0].text, 'Review evidence');
  assert.equal(transition.body.transition.id, '31');
  await assert.rejects(() => trackers.getIssue(connection, 'OTHER-4', { fetchImpl }), /this connection/);
});

test('Azure Boards escapes HTML, uses JSON Patch with revision guards, and enforces project scope', async () => {
  const connection = trackers.validateConnection(azure), requests = []; let closed = false;
  const fetchImpl = async (url, options) => {
    const body = options.body && JSON.parse(options.body); requests.push({ url, options, body });
    if (options.method === 'PATCH') closed = true;
    return Response.json({ id: 9, rev: 2, fields: { 'System.TeamProject': 'Application', 'System.Title': 'Finding', 'System.State': closed ? 'Closed' : 'New' } });
  };
  await trackers.createIssue(connection, { title: 'A finding', body: '<script>evidence</script>' }, { fetchImpl });
  assert.equal(requests[0].options.headers['Content-Type'], 'application/json-patch+json');
  assert.match(requests[0].url, /workitems\/\$Bug\?api-version=7\.1$/);
  assert.match(requests[0].body[1].value, /&lt;script&gt;/);
  await trackers.closeIssue(connection, '9', '<evidence>', { fetchImpl });
  const patch = requests.find(item => item.options.method === 'PATCH');
  assert.deepEqual(patch.body[0], { op: 'test', path: '/rev', value: 2 }); assert.equal(patch.body[2].value, 'Closed');
  await assert.rejects(() => trackers.getIssue(connection, '9', { fetchImpl: async () => Response.json({ id: 9, fields: { 'System.TeamProject': 'Other' } }) }), /outside this project/);
});

test('create is serialized and idempotent; proof gates closure and upstream state is read back', async t => {
  const provider = githubProvider(), fixture = await createFixture(t, { integrations: provider });
  const saved = await fixture.call('/connections', github); const connectionId = saved.body.connection.id;
  const create = { connectionId, reportId: 'source-report', findingId: 'F-001' };
  const results = await Promise.all([fixture.call('/findings/create', create), fixture.call('/findings/create', create)]);
  assert.deepEqual(results.map(item => item.status), [200, 200]); assert.equal(provider.requests.filter(item => item.method === 'POST' && item.url.endsWith('/issues')).length, 1);
  const row = results[0].body.finding;
  assert.equal((await fixture.call(`/findings/${row.id}/close`, { reportId: 'fp-report', findingId: 'F-001' })).status, 400);
  fixture.reports.set('wrong-fp', report('wrong-fp', 'F-001'));
  assert.equal((await fixture.call(`/findings/${row.id}/close`, { reportId: 'wrong-fp', findingId: 'F-001', confirm: true })).status, 409);
  assert.equal(provider.requests.some(item => item.method === 'PATCH'), false);
  const closed = await fixture.call(`/findings/${row.id}/close`, { reportId: 'fp-report', findingId: 'F-001', confirm: true });
  assert.equal(closed.status, 200); assert.equal(closed.body.finding.disposition, 'FALSE POSITIVE');
  assert.equal(closed.body.finding.reviewReportId, 'fp-report');
  const audit = await fixture.call('/audit'); assert.ok(audit.body.audit.some(item => item.action === 'finding.closed-false-positive'));
  assert.equal(JSON.stringify(await fixture.call('/connections')).includes('private-token'), false);
});

test('uncertain creation blocks duplicate POST and import reconciles its exact stored reference', async t => {
  const provider = githubProvider(), fixture = await createFixture(t, { integrations: provider });
  const connectionId = (await fixture.call('/connections', github)).body.connection.id;
  const create = { connectionId, reportId: 'source-report', findingId: 'F-001' };
  provider.failRead(true); assert.equal((await fixture.call('/findings/create', create)).status, 502);
  provider.failRead(false); assert.equal((await fixture.call('/findings/create', create)).status, 409);
  const imported = await fixture.call('/findings/import', { connectionId, ids: ['7', '8'] });
  assert.equal(imported.status, 200); assert.equal(imported.body.findings.length, 1); assert.equal(imported.body.errors.length, 1);
  assert.equal(imported.body.findings[0].generated, true); assert.equal(imported.body.findings[0].reportId, 'source-report');
  assert.equal(JSON.stringify(imported.body).includes('private upstream data'), false);
  const retry = await fixture.call('/findings/create', create); assert.equal(retry.status, 200); assert.equal(retry.body.existing, true);
  assert.equal(provider.requests.filter(item => item.method === 'POST' && item.url.endsWith('/issues')).length, 1);
});

test('imported tickets require a scoped exact proof and cannot reclassify a pre-existing external closure', async t => {
  const provider = githubProvider(), fixture = await createFixture(t, { integrations: provider });
  const connectionId = (await fixture.call('/connections', github)).body.connection.id;
  const imported = await fixture.call('/findings/import', { connectionId, ids: ['7'] }), row = imported.body.findings[0];
  fixture.reports.set('unverified', report('unverified', 'example/application#7'));
  fixture.reports.get('unverified').parsed.findings[0].unverified = true;
  assert.equal((await fixture.call(`/findings/${row.id}/close`, { reportId: 'unverified', findingId: 'F-001', confirm: true })).status, 409);
  provider.setClosed();
  assert.equal((await fixture.call(`/findings/${row.id}/close`, { reportId: 'fp-report', findingId: 'F-001', confirm: true })).status, 409);
  assert.equal((await fixture.call('/findings')).body.findings[0].disposition, 'OPEN');
  assert.equal(provider.requests.some(item => item.method === 'PATCH'), false);
});

test('saved SCM activation supplies credentials to the runtime without returning them', async t => {
  let supplied;
  const fixture = await createFixture(t, { activateSource: async (_req, value) => { supplied = value; return { id: 'runtime-connection', provider: 'github', account: 'example' }; } });
  const saved = await fixture.call('/connections', { name: 'Source', provider: 'github', kind: 'scm', token: 'source-secret' });
  const activated = await fixture.call(`/connections/${saved.body.connection.id}/activate`, {});
  assert.equal(activated.body.connection.id, 'runtime-connection'); assert.equal(supplied.token, 'source-secret');
  assert.equal(JSON.stringify(activated).includes('source-secret'), false);
});

test('ticket destinations cannot move after linking or uncertain creation; unresolved operations preserve their connection', () => {
  const store = createManagementStore(), saved = store.upsert(github);
  store.state.operations.push({ connectionId: saved.id, reportId: 'r', findingId: 'F-1', status: 'unknown' });
  assert.throws(() => store.upsert({ ...github, id: saved.id, repository: 'other/repository' }), /new named connection/);
  assert.throws(() => store.remove(saved.id), /Disable/);
  store.upsert({ ...github, id: saved.id, token: 'rotated-secret', name: 'Rotated name' });
  assert.equal(store.connection(saved.id).token, 'rotated-secret');
});

test('explicit create POST rejection can retry after correction; successful POST with readback rejection cannot repeat', async t => {
  const provider = githubProvider(); let rejectPost = true, rejectRead = false;
  const fetchImpl = async (url, options) => {
    if (url.endsWith('/issues') && options.method === 'POST' && rejectPost) return new Response('secret upstream data', { status: 403 });
    if (url.endsWith('/issues/7') && options.method === 'GET' && rejectRead) return new Response('secret upstream data', { status: 403 });
    return provider.fetchImpl(url, options);
  };
  const fixture = await createFixture(t, { integrations: { fetchImpl } });
  const connectionId = (await fixture.call('/connections', github)).body.connection.id;
  const create = { connectionId, reportId: 'source-report', findingId: 'F-001' };
  assert.equal((await fixture.call('/findings/create', create)).status, 403);
  rejectPost = false; rejectRead = true;
  const unknown = await fixture.call('/findings/create', create); assert.equal(unknown.status, 502); assert.match(unknown.body.error, /ticket 7/);
  rejectRead = false; assert.equal((await fixture.call('/findings/create', create)).status, 409);
  assert.equal(provider.requests.filter(item => item.method === 'POST' && item.url.endsWith('/issues')).length, 1);
});

test('Jira proof must name the exact site when project keys collide across connections', async t => {
  const fetchImpl = async () => Response.json({ key: 'SEC-4', fields: { summary: 'Finding', status: { name: 'Open', statusCategory: { key: 'new' } } } });
  const fixture = await createFixture(t, { integrations: { fetchImpl } });
  const siteA = (await fixture.call('/connections', jira)).body.connection.id;
  const siteB = (await fixture.call('/connections', { ...jira, baseUrl: 'https://other.atlassian.net', name: 'Other site' })).body.connection.id;
  const rowA = (await fixture.call('/findings/import', { connectionId: siteA, ids: ['SEC-4'] })).body.findings[0];
  const rowB = (await fixture.call('/findings/import', { connectionId: siteB, ids: ['SEC-4'] })).body.findings[0];
  fixture.reports.set('short', report('short', 'SEC-4'));
  fixture.reports.set('site-a', report('site-a', rowA.reviewReference));
  assert.equal((await fixture.call(`/findings/${rowA.id}/close`, { reportId: 'short', findingId: 'F-001', confirm: true })).status, 409);
  assert.equal((await fixture.call(`/findings/${rowB.id}/close`, { reportId: 'site-a', findingId: 'F-001', confirm: true })).status, 409);
});

test('sync pages large scoped registries and returns individual upstream failures without discarding tickets', async t => {
  const fetchImpl = async url => {
    const id = Number(new URL(url).pathname.split('/').at(-1));
    if (id === 3) return new Response('private data', { status: 403 });
    return Response.json({ number: id, title: `Finding ${id}`, state: 'open' });
  };
  const fixture = await createFixture(t, { integrations: { fetchImpl } });
  const store = await fixture.management.storeFor({}); const connection = store.upsert(github);
  for (let id = 1; id <= 101; id++) store.putFinding(connection, { externalId: String(id), title: `Finding ${id}`, state: 'open', url: `https://github.com/example/application/issues/${id}`, closed: false });
  const first = await fixture.call('/findings/sync', { connectionId: connection.id });
  assert.equal(first.body.findings.length, 99); assert.equal(first.body.errors.length, 1); assert.ok(first.body.nextCursor); assert.equal(first.body.total, 101);
  const second = await fixture.call('/findings/sync', { connectionId: connection.id, cursor: first.body.nextCursor });
  assert.equal(second.body.findings.length, 1); assert.equal(second.body.nextCursor, null);
  assert.equal((await fixture.call('/findings')).body.findings.length, 101);
});

test('scope directories isolate credentials and tracked tickets', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-scopes-')); t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const app = express(); app.use(express.json());
  const service = registerManagementRoutes(app, { scopeDirectory: req => path.join(directory, req.scope) });
  const first = await service.storeFor({ scope: 'company-a' }), second = await service.storeFor({ scope: 'company-b' });
  first.upsert(github); first.save(); second.upsert({ ...azure, token: 'other-secret' }); second.save();
  assert.equal(first.listConnections()[0].provider, 'github-issues'); assert.equal(second.listConnections()[0].provider, 'azure-boards');
  assert.throws(() => second.connection(first.listConnections()[0].id), /not found/);
  assert.equal(await service.storeFor({ scope: 'company-a' }), first);
});

test('acknowledged closure survives failed readback and a restart, then same proof confirms FP without another mutation', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-close-recovery-')); t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const provider = githubProvider(); let failClosingReadback = true, closedMutation = false;
  const fetchImpl = async (url, options) => {
    if (closedMutation && options.method === 'GET' && url.endsWith('/issues/7') && failClosingReadback) throw new Error('readback unavailable');
    const response = await provider.fetchImpl(url, options);
    if (options.method === 'PATCH') closedMutation = true;
    return response;
  };
  const first = await createFixture(t, { directory, integrations: { fetchImpl }, actor: () => 'organization-analyst' });
  const connectionId = (await first.call('/connections', github)).body.connection.id;
  const row = (await first.call('/findings/import', { connectionId, ids: ['7'] })).body.findings[0];
  const proof = { reportId: 'fp-report', findingId: 'F-001', confirm: true };
  assert.equal((await first.call(`/findings/${row.id}/close`, proof)).status, 502);
  const stored = createManagementStore(directory).state.findings.find(item => item.id === row.id);
  assert.equal(stored.disposition, 'OPEN'); assert.equal(stored.closureAcknowledgement.reportId, 'fp-report');
  assert.equal(stored.closureAcknowledgement.findingId, 'F-001'); assert.equal(stored.closureAcknowledgement.actor, 'organization-analyst');
  assert.equal((await first.call('/findings')).body.findings[0].closureAcknowledgement, undefined);
  failClosingReadback = false;
  const second = await createFixture(t, { directory, integrations: { fetchImpl } });
  const recovered = await second.call(`/findings/${row.id}/close`, proof);
  assert.equal(recovered.status, 200); assert.equal(recovered.body.finding.disposition, 'FALSE POSITIVE'); assert.equal(recovered.body.verified, true);
  assert.equal(provider.requests.filter(item => item.method === 'PATCH').length, 1);
});

test('a rejected close mutation creates no acknowledgement and observing an open ticket clears an older acknowledgement', async t => {
  const provider = githubProvider();
  const fetchImpl = async (url, options) => options.method === 'PATCH' ? new Response('forbidden', { status: 403 }) : provider.fetchImpl(url, options);
  const fixture = await createFixture(t, { integrations: { fetchImpl } });
  const connectionId = (await fixture.call('/connections', github)).body.connection.id;
  const row = (await fixture.call('/findings/import', { connectionId, ids: ['7'] })).body.findings[0];
  const proof = { reportId: 'fp-report', findingId: 'F-001', confirm: true };
  assert.equal((await fixture.call(`/findings/${row.id}/close`, proof)).status, 403);
  const store = await fixture.management.storeFor({}); assert.equal(store.state.findings[0].closureAcknowledgement, undefined);
  store.state.findings[0].closureAcknowledgement = { reportId: 'fp-report', findingId: 'F-001' };
  await fixture.call('/findings/sync', { connectionId }); assert.equal(store.state.findings[0].closureAcknowledgement, undefined);
  provider.setClosed();
  assert.equal((await fixture.call(`/findings/${row.id}/close`, proof)).status, 409);
});

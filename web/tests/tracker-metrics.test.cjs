'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.THREATLINT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-tracker-home-'));
const { createWorkbench } = require('../server.js');
const { writeServiceNow } = require('../lib/threatlint-config.cjs');
const { writeConfig } = require('../lib/scanners.cjs');
const { fetchAvitMetrics } = require('../lib/servicenow.cjs');
const { createTrackerMetrics, avitMetricsItems } = require('../lib/tracker-metrics.cjs');

const INSTANCE = 'https://metrics-test.service-now.com';
const avit = (number, sysId, extra = {}) => ({ number: { value: number, display_value: number }, sys_id: { value: sysId, display_value: sysId },
  short_description: { value: 'Synthetic finding', display_value: 'Synthetic finding' },
  severity: { value: '2', display_value: 'High' }, state: { value: '1', display_value: 'Open' },
  sys_created_on: { value: '2026-01-01 00:00:00', display_value: '2026-01-01 00:00:00' },
  first_found: { value: '2026-01-02 03:04:05', display_value: '2026-01-02 03:04:05' }, ...extra });
const response = (body, headers = {}) => ({ ok: true, status: 200, headers: { get: name => headers[name.toLowerCase()] || null }, json: async () => body });
const SCOPE = { type: 'avits', avits: 'AVIT0000001, AVIT0000002' };

test('ServiceNow metrics read paginates across a short ACL-filtered page and requests only needed AVIT fields', async () => {
  const calls = [];
  const transport = async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/oauth_token.do')) return response({ access_token: 'synthetic-access-token' });
    const offset = Number(new URL(url).searchParams.get('sysparm_offset'));
    if (offset === 0) return response({ result: [avit('AVIT0000001', 'a'.repeat(32))] },
      { link: `<${INSTANCE}/api/now/table/sn_vul_app_vulnerable_item?sysparm_offset=100&sysparm_limit=100>;rel="next"`, 'x-total-count': '101' });
    if (offset === 100) return response({ result: [avit('AVIT0000002', 'b'.repeat(32))] }, { 'x-total-count': '101' });
    throw new Error('unexpected page');
  };
  const result = await fetchAvitMetrics({ instance: INSTANCE, clientId: 'client', clientSecret: 'secret' },
    { scope: SCOPE, fetchImpl: transport, now: Date.parse('2026-11-04T12:00:00Z') });
  assert.deepEqual(result.items.map(item => item.id), ['AVIT0000001', 'AVIT0000002']);
  const tableCalls = calls.slice(1);
  assert.equal(tableCalls.length, 2);
  assert.ok(tableCalls.every(call => call.options.method !== 'POST' && call.options.headers.Authorization === 'Bearer synthetic-access-token'));
  assert.ok(tableCalls.every(call => new URL(call.url).searchParams.get('sysparm_fields').includes('severity')));
  assert.ok(tableCalls.every(call => new URL(call.url).searchParams.get('sysparm_query') ===
    "numberINAVIT0000001,AVIT0000002^sys_created_on<=javascript:gs.dateGenerate('2026-11-04','11:59:00')^ORDERBYsys_id"));
  assert.ok(calls.every(call => call.options.redirect === 'error'));
  const facts = avitMetricsItems(result.items);
  assert.equal(facts[0].severity, 'HIGH');
  assert.equal(facts[0].disposition, 'OPEN');
  assert.equal(new Date(facts[0].timestamp).toISOString(), '2026-01-02T03:04:05.000Z');
});

test('ServiceNow metrics rejects ambiguous pagination and unreadable identity fields', async () => {
  const token = async url => url.endsWith('/oauth_token.do') ? response({ access_token: 'token' }) : response({ result: [avit('AVIT0000001', 'a'.repeat(32))] });
  await assert.rejects(fetchAvitMetrics({ instance: INSTANCE, clientId: 'client', clientSecret: 'secret' }, { scope: SCOPE, fetchImpl: token }), /pagination headers/);
  const missing = async url => url.endsWith('/oauth_token.do') ? response({ access_token: 'token' }) : response({ result: [{ number: 'AVIT0000001' }] }, { 'x-total-count': '1' });
  await assert.rejects(fetchAvitMetrics({ instance: INSTANCE, clientId: 'client', clientSecret: 'secret' }, { scope: SCOPE, fetchImpl: missing }), /readable AVIT number and sys_id/);
  const duplicate = async url => {
    if (url.endsWith('/oauth_token.do')) return response({ access_token: 'token' });
    const offset = Number(new URL(url).searchParams.get('sysparm_offset'));
    return response({ result: [avit('AVIT0000001', 'a'.repeat(32))] }, offset === 0
      ? { link: `<${INSTANCE}/api/now/table/sn_vul_app_vulnerable_item?sysparm_offset=100>;rel="next"`, 'x-total-count': '101' }
      : { 'x-total-count': '101' });
  };
  await assert.rejects(fetchAvitMetrics({ instance: INSTANCE, clientId: 'client', clientSecret: 'secret' }, { scope: SCOPE, fetchImpl: duplicate }),
    /pages changed during metrics sync/);
  const oversized = async url => url.endsWith('/oauth_token.do') ? response({ access_token: 'token' })
    : { ok: true, status: 200, headers: { get: () => null }, body: (async function* () { yield Buffer.alloc(8 * 1024 * 1024 + 1); })() };
  await assert.rejects(fetchAvitMetrics({ instance: INSTANCE, clientId: 'client', clientSecret: 'secret' }, { scope: SCOPE, fetchImpl: oversized }),
    /metrics page is too large/);
  const ignoredCutoff = async url => url.endsWith('/oauth_token.do') ? response({ access_token: 'token' })
    : response({ result: [avit('AVIT0000001', 'a'.repeat(32),
      { sys_created_on: { value: '2099-01-01 00:00:00', display_value: '2099-01-01 00:00:00' } })] }, { 'x-total-count': '1' });
  await assert.rejects(fetchAvitMetrics({ instance: INSTANCE, clientId: 'client', clientSecret: 'secret' }, { scope: SCOPE, fetchImpl: ignoredCutoff }),
    /creation cutoff/);
});

test('tracker sync feeds source-filtered metrics, replaces instead of duplicating, and survives restart without credentials', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-tracker-state-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  writeServiceNow({ instance: INSTANCE, clientId: 'saved-client', clientSecret: 'never-persist-this-secret-in-metrics' });
  let fail = false;
  const transport = async url => {
    if (url.endsWith('/oauth_token.do')) return response({ access_token: 'token' });
    if (fail) return { ok: false, status: 503 };
    return response({ result: [avit('AVIT0000001', 'a'.repeat(32),
      { substate: { value: '3', display_value: 'False Positive' }, state: { value: '3', display_value: 'Closed' } })] }, { 'x-total-count': '1' });
  };
  let workbench = createWorkbench({ storageDir: root, integrations: { fetchImpl: transport } });
  const start = async () => {
    await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${workbench.server.address().port}`;
  };
  let base = await start();
  const call = async (route, options = {}) => {
    const result = await fetch(base + route, { method: options.method || 'GET', headers: { 'Content-Type': 'application/json' },
      ...(options.body ? { body: JSON.stringify(options.body) } : {}) });
    return { status: result.status, body: /json/.test(result.headers.get('content-type') || '') ? await result.json() : await result.text() };
  };
  try {
    const catalog = await call('/api/trackers');
    assert.equal(catalog.body.trackers.find(item => item.id === 'servicenow-avit').connected, true);
    assert.equal(catalog.body.trackers.find(item => item.id === 'defectdojo').available, true);
    assert.equal((await call('/api/trackers/servicenow-avit/sync', { method: 'POST', body: { scope: SCOPE } })).body.count, 1);
    assert.equal((await call('/api/trackers/servicenow-avit/sync', { method: 'POST', body: { scope: SCOPE } })).body.count, 1);
    const selected = (await call('/api/metrics/sources')).body.sources.find(item => item.id === 'servicenow-avit');
    assert.equal(selected.count, 1);
    assert.equal(selected.status, 'synced');
    const query = await call('/api/metrics/query', { method: 'POST', body: { metric: 'findings', groupBy: 'severity', filters: { source: 'servicenow-avit' } } });
    assert.deepEqual(query.body.rows, [{ key: 'HIGH', value: 1 }]);
    const reports = await call('/api/metrics/query', { method: 'POST', body: { metric: 'reports', groupBy: null, filters: { source: 'servicenow-avit' } } });
    assert.equal(reports.body.total, 0);
    const overview = (await call('/api/metrics/overview?source=servicenow-avit')).body;
    assert.equal(overview.findings, 1);
    assert.equal(overview.falsePositiveRate, 100);
    assert.equal(overview.reports, 0);
    const csv = (await call('/api/metrics/export?source=servicenow-avit')).body;
    assert.match(csv, /AVIT0000001/);
    assert.doesNotMatch(csv, /never-persist-this-secret/);
    fail = true;
    assert.equal((await call('/api/trackers/servicenow-avit/sync', { method: 'POST', body: { scope: SCOPE } })).status, 502);
    assert.equal((await call('/api/metrics/overview?source=servicenow-avit')).body.findings, 1);
    assert.equal((await call('/api/metrics/overview?source=unknown')).status, 400);
    await workbench.close();
    const persisted = fs.readFileSync(path.join(root, 'tracker-metrics.json'), 'utf8');
    assert.doesNotMatch(persisted, /never-persist-this-secret|synthetic-access-token|saved-client/);
    workbench = createWorkbench({ storageDir: root, integrations: { fetchImpl: transport } });
    base = await start();
    assert.equal((await call('/api/metrics/overview?source=servicenow-avit')).body.findings, 1);
    assert.equal((await call('/api/metrics/query', { method: 'POST', body: { metric: 'uniqueFindings', groupBy: null, filters: { source: 'servicenow-avit' } } })).body.total, 1);
  } finally { await workbench.close(); }
});

test('tracker store deduplicates IDs and preserves fingerprints across reload', t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-tracker-store-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const first = createTrackerMetrics(directory);
  first.replace('servicenow-avit', [{ id: 'AVIT0000001', fingerprint: 'stable', severity: 'HIGH', timestamp: Date.now() },
    { id: 'AVIT0000001', fingerprint: 'stable', severity: 'HIGH', timestamp: Date.now() }]);
  assert.equal(first.facts().length, 1);
  const fingerprint = first.facts()[0].fingerprint;
  assert.equal(createTrackerMetrics(directory).facts()[0].fingerprint, fingerprint);
});

test('DefectDojo saved connection syncs through the same tracker metrics API', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-dojo-route-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  writeConfig('dojo', { url: 'https://dojo.example.com', token: 'synthetic-dojo-token-1234567890' });
  const transport = async (url, options) => {
    assert.match(url, /^https:\/\/dojo\.example\.com\/api\/v2\/findings\//);
    assert.equal(options.headers.Authorization, 'Token synthetic-dojo-token-1234567890');
    return { ok: true, status: 200, text: async () => JSON.stringify({ count: 1, results: [
      { id: 42, title: 'Synthetic Dojo finding', severity: 'Medium', active: true, product_name: 'Sample product', date: '2026-01-01' },
    ] }) };
  };
  const workbench = createWorkbench({ storageDir: directory, integrations: { fetchImpl: transport } });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  t.after(() => workbench.close());
  const base = `http://127.0.0.1:${workbench.server.address().port}`;
  const synced = await fetch(`${base}/api/trackers/defectdojo/sync`, { method: 'POST' });
  assert.equal(synced.status, 200);
  assert.equal((await synced.json()).count, 1);
  const response = await fetch(`${base}/api/metrics/overview?source=defectdojo`);
  assert.equal((await response.json()).findings, 1);
  const saved = fs.readFileSync(path.join(directory, 'tracker-metrics.json'), 'utf8');
  assert.doesNotMatch(saved, /synthetic-dojo-token/);
});

test('whole-sync timeout keeps the previous ServiceNow metrics snapshot', async t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-tracker-timeout-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  writeServiceNow({ instance: INSTANCE, clientId: 'client', clientSecret: 'secret' });
  createTrackerMetrics(directory).replace('servicenow-avit', [{ id: 'AVIT0000001', severity: 'HIGH', timestamp: Date.now() }]);
  const before = fs.readFileSync(path.join(directory, 'tracker-metrics.json'), 'utf8');
  const transport = async (url, options) => {
    if (url.endsWith('/oauth_token.do')) return response({ access_token: 'token' });
    return new Promise((_resolve, reject) => options.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true }));
  };
  const workbench = createWorkbench({ storageDir: directory, integrations: { fetchImpl: transport, trackerSyncTimeoutMs: 20 } });
  await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
  t.after(() => workbench.close());
  const base = `http://127.0.0.1:${workbench.server.address().port}`;
  const synced = await fetch(`${base}/api/trackers/servicenow-avit/sync`, { method: 'POST',
    headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ scope: SCOPE }) });
  assert.equal(synced.status, 504);
  assert.match((await synced.json()).error, /previous snapshot preserved/);
  assert.equal(fs.readFileSync(path.join(directory, 'tracker-metrics.json'), 'utf8'), before);
  const overview = await fetch(`${base}/api/metrics/overview?source=servicenow-avit`);
  assert.equal((await overview.json()).findings, 1);
});

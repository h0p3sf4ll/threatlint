'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

process.env.THREATLINT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-aggregate-home-'));
const servicenow = require('../lib/servicenow.cjs');
const { writeServiceNow } = require('../lib/threatlint-config.cjs');
const { createWorkbench } = require('../server.js');

const INSTANCE = 'https://aggregate-test.service-now.com';
const reply = (body, status = 200) => ({ ok: status >= 200 && status < 300, status,
  json: async () => body, headers: { get: () => null } });

function fakeStats(calls, { denyRisk = false, failTotal = false } = {}) {
  return async (url, options) => {
    calls.push({ url, options });
    if (url.endsWith('/oauth_token.do')) return reply({ access_token: 'synthetic-token' });
    const parsed = new URL(url);
    assert.equal(parsed.pathname, '/api/now/stats/sn_vul_app_vulnerable_item');
    assert.equal(options.headers.Authorization, 'Bearer synthetic-token');
    assert.equal(options.redirect, 'error');
    const group = parsed.searchParams.get('sysparm_group_by');
    const query = parsed.searchParams.get('sysparm_query') || '';
    if (!group) {
      if (failTotal && !query.includes('substate=3')) return reply({}, 503);
      return reply({ result: { stats: { count: query.includes('substate=3') ? '4' : '67512944' } } });
    }
    if (group === 'risk_rating' && denyRisk) return reply({}, 403);
    const groups = { risk_rating: [['1', 'Critical', 10], ['2', 'High', 20]],
      state: [['1', 'Open', 30], ['3', 'Closed', 12]], substate: [['3', 'False Positive', 4]] }[group];
    return reply({ result: groups.map(([value, display_value, count]) => ({ stats: { count: String(count) },
      groupby_fields: [{ field: group, value, display_value }] })) });
  };
}

test('AVIT aggregate validates server-side filters and rejects encoded-query injection', () => {
  assert.deepEqual(servicenow.validateAggregateFilters({ riskRating: '2', state: '1', source: 'Invicti',
    createdFrom: '2026-01-01' }), { riskRating: '2', state: '1', source: 'Invicti', createdFrom: '2026-01-01' });
  assert.throws(() => servicenow.validateAggregateFilters({ source: 'Invicti^ORstate=3' }), /unsupported characters/);
  assert.throws(() => servicenow.validateAggregateFilters({ createdFrom: '2026-02-30' }), /valid YYYY-MM-DD/);
  assert.throws(() => servicenow.validateAggregateFilters({ createdFrom: '2026-03-02', createdTo: '2026-03-01' }), /on or before/);
  assert.throws(() => servicenow.validateAggregateFilters({ scanner: 'any' }), /Unsupported AVIT filter/);
});

test('AVIT aggregate requests only server-side counts and allowed group dimensions', async () => {
  const calls = [];
  const result = await servicenow.fetchAvitAggregate({ instance: INSTANCE, clientId: 'id', clientSecret: 'secret' },
    { filters: { riskRating: '2', source: 'Invicti', createdFrom: '2026-01-01' }, fetchImpl: fakeStats(calls) });
  assert.equal(result.total, 67512944);
  assert.equal(result.falsePositive, 4);
  assert.deepEqual(result.riskRating[0], { key: 'Critical', value: '1', count: 10 });
  assert.equal(result.state[0].key, 'Open');
  assert.deepEqual(calls.filter(call => call.url.includes('/api/now/stats/')).map(call => new URL(call.url).searchParams.get('sysparm_group_by')),
    [null, 'risk_rating', 'state', 'substate', null]);
  assert.ok(calls.every(call => !call.url.includes('/api/now/table/')));
  const query = new URL(calls[1].url).searchParams.get('sysparm_query');
  assert.match(query, /risk_rating=2\^source=Invicti\^sys_created_on>=javascript:gs\.dateGenerate/);
});

test('an inaccessible aggregate dimension is disclosed without inventing values', async () => {
  const result = await servicenow.fetchAvitAggregate({ instance: INSTANCE, clientId: 'id', clientSecret: 'secret' },
    { fetchImpl: fakeStats([], { denyRisk: true }) });
  assert.equal(result.total, 67512944);
  assert.equal(result.riskRating, null);
  assert.match(result.limitations, /Risk rating unavailable/);
});

test('aggregate API stores a completed full-table summary and preserves it after an upstream failure', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-aggregate-state-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  writeServiceNow({ instance: INSTANCE, clientId: 'saved-client', clientSecret: 'never-save-this-secret' });
  let failTotal = false;
  const fetchImpl = async (url, options) => fakeStats([], { failTotal })(url, options);
  let workbench = createWorkbench({ storageDir: root, integrations: { fetchImpl } });
  const start = async () => {
    await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${workbench.server.address().port}`;
  };
  let base = await start();
  const post = async body => {
    const response = await fetch(`${base}/api/trackers/servicenow-avit/aggregate`, { method: 'POST',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, data: await response.json() };
  };
  try {
    assert.deepEqual(await (await fetch(`${base}/api/trackers/servicenow-avit/aggregate`)).json(), { summary: null });
    const refreshed = await post({ filters: {} });
    assert.equal(refreshed.status, 200);
    assert.equal(refreshed.data.total, 67512944);
    assert.equal(refreshed.data.scope, 'all-readable-avits');
    assert.equal((await post({ filters: { scanner: 'unexpected' } })).status, 400);
    failTotal = true;
    assert.equal((await post({ filters: {} })).status, 502);
    assert.equal((await (await fetch(`${base}/api/trackers/servicenow-avit/aggregate`)).json()).summary.total, 67512944);
    await workbench.close();
    const persisted = fs.readFileSync(path.join(root, 'avit-aggregate.json'), 'utf8');
    assert.doesNotMatch(persisted, /never-save-this-secret|synthetic-token|saved-client/);
    workbench = createWorkbench({ storageDir: root, integrations: { fetchImpl } });
    base = await start();
    assert.equal((await (await fetch(`${base}/api/trackers/servicenow-avit/aggregate`)).json()).summary.total, 67512944);
  } finally { await workbench.close(); }
});

// ── Type-ahead suggestions and Dynamic (DAST) ───────────────────────────────────

function fakeContext(calls, groups) {
  return async (url, options) => {
    calls.push(url);
    if (url.endsWith('/oauth_token.do')) return reply({ access_token: 'synthetic-token' });
    const parsed = new URL(url);
    if (parsed.pathname === '/api/now/table/sys_documentation') {
      return reply({ result: [{ name: 'sn_vul_app_vulnerable_item', element: 'u_org', label: 'Organization Name' },
        { name: 'sn_vul_app_vulnerable_item', element: 'u_repo', label: 'Repository' },
        { name: 'sn_vul_app_vulnerable_item', element: 'u_branch', label: 'Project Branch' }] });
    }
    assert.equal(parsed.pathname, '/api/now/stats/sn_vul_app_vulnerable_item');
    assert.equal(options.headers.Authorization, 'Bearer synthetic-token');
    const group = parsed.searchParams.get('sysparm_group_by');
    return reply({ result: groups.map(([value, count]) => ({ stats: { count: String(count) },
      groupby_fields: [{ field: group, value, display_value: value }] })) });
  };
}

test('suggestions cascade from chosen filters, match by prefix, rank by frequency, and reuse one session', async () => {
  const calls = [];
  const credentials = { instance: 'https://suggest-a.service-now.com', clientId: 'id', clientSecret: 'secret' };
  const fetchImpl = fakeContext(calls, [['release/1', 3], ['main', 90], ['', 5], ['Main', 1]]);
  const result = await servicenow.fetchAvitContextValues(credentials, { field: 'branch', q: 'ma',
    context: { scm: 'github', organization: 'acme', repository: 'shop', branch: 'ignored-own-field' }, fetchImpl });
  assert.deepEqual(result, { field: 'branch', values: ['main', 'release/1'] }, 'blank and case-duplicate values dropped, most common first');
  const stats = new URL(calls.find(url => url.includes('/api/now/stats/')));
  assert.equal(stats.searchParams.get('sysparm_group_by'), 'u_branch');
  const query = stats.searchParams.get('sysparm_query');
  for (const clause of ['u_scm_toolLIKEgithub', 'u_org=acme', 'u_repo=shop', 'u_branchISNOTEMPTY', 'u_branchSTARTSWITHma']) {
    assert.ok(query.includes(clause), `${clause} in ${query}`);
  }
  assert.ok(!query.includes('ignored-own-field'), 'the field being suggested does not filter itself');
  await servicenow.fetchAvitContextValues(credentials, { field: 'repository', q: 'sh', fetchImpl });
  assert.equal(calls.filter(url => url.endsWith('/oauth_token.do')).length, 1, 'one OAuth token for consecutive keystrokes');
  assert.equal(calls.filter(url => url.includes('sys_documentation')).length, 1, 'one label lookup for consecutive keystrokes');
});

test('suggestions reject unsupported fields, injection-shaped prefixes, and invalid context', async () => {
  const credentials = { instance: 'https://suggest-b.service-now.com', clientId: 'id', clientSecret: 'secret' };
  const fetchImpl = fakeContext([], []);
  await assert.rejects(servicenow.fetchAvitContextValues(credentials, { field: 'assignment_group', fetchImpl }), /Unsupported context field/);
  await assert.rejects(servicenow.fetchAvitContextValues(credentials, { field: 'branch', q: 'main^ORstate=1', fetchImpl }), /unsupported characters/);
  await assert.rejects(servicenow.fetchAvitContextValues(credentials, { field: 'branch', context: { repository: 'a^b' }, fetchImpl }), /repository contains/);
});

test('Dynamic (DAST) counts Invicti AVITs by source without needing the finding-source column', async () => {
  const queries = [];
  const fetchImpl = async (url) => {
    if (url.endsWith('/oauth_token.do')) return reply({ access_token: 'synthetic-token' });
    const parsed = new URL(url);
    if (parsed.pathname === '/api/now/table/sys_documentation') return reply({ result: [] });
    queries.push(parsed.searchParams.get('sysparm_query') || '');
    if (!parsed.searchParams.get('sysparm_group_by')) return reply({ result: { stats: { count: '7' } } });
    return reply({ result: [] });
  };
  const summary = await servicenow.fetchAvitAggregate({ instance: INSTANCE, clientId: 'id', clientSecret: 'secret' },
    { filters: { findingType: 'dast' }, fetchImpl });
  assert.equal(summary.total, 7);
  assert.ok(queries.every(query => query.startsWith('sourceLIKEinvicti')), queries.join(' | '));
  assert.match(summary.limitations, /Invicti AVITs this ServiceNow account can read/);
});

test('long AVIT lists are fetched in numberIN chunks, with every AVIT returned', async () => {
  const numbers = Array.from({ length: 120 }, (_, i) => `AVIT${String(9100000 + i)}`);
  const queried = [];
  const fetchImpl = async url => {
    if (url.endsWith('/oauth_token.do')) return reply({ access_token: 'synthetic-token' });
    const parsed = new URL(url);
    if (parsed.pathname.endsWith('/sysrule_view')) return reply({ result: [] });
    const query = parsed.searchParams.get('sysparm_query');
    const chunk = query.replace(/^numberIN/, '').split(',');
    queried.push(chunk.length);
    return reply({ result: chunk.map(number => ({ number: { value: number, display_value: number }, sys_id: { value: number.slice(-8).padStart(32, '0') } })) });
  };
  const { items } = await servicenow.fetchAvits({ instance: INSTANCE, clientId: 'id', clientSecret: 'secret' }, numbers, { fetchImpl });
  assert.deepEqual(queried, [50, 50, 20], 'no single query carries more than one chunk of numbers');
  assert.deepEqual(items.map(item => item.fields.number), numbers, 'all 120 come back, in input order');
});

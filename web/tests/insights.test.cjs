'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
// Never read the developer's real ~/.threatlint (saved GitHub App, PATs) during tests.
process.env.THREATLINT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-home-'));
for (const name of ['THREATLINT_GITHUB_APP_ID', 'THREATLINT_GITHUB_APP_INSTALLATION_ID', 'THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE']) delete process.env[name];
const { createWorkbench } = require('../server.js');
const { createDemoApp } = require('../examples/demo-app.cjs');
const { collectFacts, aggregate, matrix, validateDashboard } = require('../lib/metrics.cjs');

describe('Metrics aggregation', () => {
  const sessions = new Map([['s1', { id: 's1', repoPath: '/work/shop', reports: [
    { id: 'r1', agentId: 'appsec-code-reviewer', timestamp: Date.parse('2026-10-01T10:00:00Z'), findings: [
      { id: 'CR-001', title: 'SQLi', severity: 'CRITICAL', confidence: 'CONFIRMED', evidence: ['app.py:10'] },
      { id: 'CR-002', title: 'Header', severity: 'LOW', confidence: 'PLAUSIBLE', evidence: [] },
    ] },
    { id: 'r2', agentId: 'appsec-fp-reviewer', timestamp: Date.parse('2026-10-02T10:00:00Z'), findings: [
      { id: 'FP-001', title: 'noise', severity: 'HIGH', disposition: 'FALSE POSITIVE', evidence: ['a.js:1'] },
    ] },
  ] }]]);
  const facts = collectFacts({ sessions, agents: {} });
  it('counts findings, excludes false positives from risk, and measures evidence coverage', () => {
    assert.deepEqual(aggregate(facts, { metric: 'findings', groupBy: 'severity' }).rows.map(row => row.key), ['CRITICAL', 'HIGH', 'LOW']);
    assert.equal(aggregate(facts, { metric: 'riskScore', groupBy: null }).total, 11);
    assert.equal(aggregate(facts, { metric: 'evidenceCoverage', groupBy: null }).total, 67);
    assert.equal(aggregate(facts, { metric: 'reports', groupBy: null }).total, 2);
    assert.equal(aggregate(facts, { metric: 'findings', groupBy: 'day', filters: { since: '2026-10-02T00:00:00Z' } }).total, 1);
    assert.equal(matrix(facts, { rows: 'workspace', columns: 'severity' }).cells['shop\u0000CRITICAL'], 1);
  });
  it('rejects unknown metrics, dimensions, and chart types', () => {
    assert.throws(() => aggregate(facts, { metric: 'nope' }));
    assert.throws(() => aggregate(facts, { metric: 'findings', groupBy: '__proto__' }));
    assert.throws(() => validateDashboard({ name: 'x', widgets: [{ chart: 'pie3d', metric: 'findings' }] }));
  });
});

describe('Workbench routes for sources, runtime, metrics, dashboards, and help', () => {
  let workbench, base, demo, demoUrl, temporary;
  const calls = [];
  const sourceManagers = {
    list: () => [],
    connect: async input => { calls.push(['connect', input.provider]); return { id: 'c1', provider: input.provider, label: 'GitHub · octo', account: 'octo', host: 'github.com' }; },
    disconnect: id => id === 'c1',
    repositories: async () => ({ repositories: [{ id: '1', name: 'shop', fullName: 'octo/shop', defaultBranch: 'main', webUrl: 'https://github.com/octo/shop' }], page: 1, hasMore: false }),
    branches: async () => ({ branches: [{ name: 'main' }], page: 1, hasMore: false }),
    checkout: async () => { const repoPath = fs.mkdtempSync(path.join(temporary, 'co-')); return { repoPath, tempDir: repoPath, provenance: { provider: 'github', repository: 'octo/shop', branch: 'main', commit: 'a'.repeat(40), webUrl: 'https://github.com/octo/shop' } }; },
  };
  before(async () => {
    temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-routes-'));
    demo = createDemoApp(); await new Promise(resolve => demo.listen(0, '127.0.0.1', resolve));
    demoUrl = `http://127.0.0.1:${demo.address().port}`;
    workbench = createWorkbench({ storageDir: path.join(temporary, 'state'), sourceManagers });
    await new Promise(resolve => workbench.server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${workbench.server.address().port}`;
  });
  after(async () => { await workbench.close(); demo.close(); fs.rmSync(temporary, { recursive: true, force: true }); });
  const call = async (route, options = {}) => {
    const response = await fetch(base + route, { ...options, headers: { 'Content-Type': 'application/json' }, body: options.body && JSON.stringify(options.body) });
    return { status: response.status, body: response.status === 204 ? null : /json/.test(response.headers.get('content-type') || '') ? await response.json() : await response.text() };
  };

  it('connects a source, lists repositories and branches, and opens a checkout as a workspace', async () => {
    assert.equal((await call('/api/scm/connections', { method: 'POST', body: { provider: 'github', token: 'x'.repeat(20) } })).status, 201);
    assert.equal((await call('/api/scm/connections/c1/repositories?search=shop&page=1')).body.repositories[0].fullName, 'octo/shop');
    assert.equal((await call('/api/scm/connections/c1/branches?repositoryId=1')).body.branches[0].name, 'main');
    const checkout = await call('/api/scm/checkout', { method: 'POST', body: { connectionId: 'c1', repositoryId: '1', branch: 'main' } });
    assert.equal(checkout.status, 201);
    assert.equal((await call(`/api/session/${checkout.body.sessionId}`)).body.provenance.repository, 'octo/shop');
    assert.equal((await call('/api/scm/connections/c1', { method: 'DELETE' })).status, 204);
  });
  it('runs an authorized runtime scan, exports evidence, and feeds metrics', async () => {
    const started = await call('/api/runtime/scans', { method: 'POST', body: { target: demoUrl, paths: ['/api/orders', '/debug'], authorization: { confirmed: true, allowPrivate: true, reason: 'fixture' },
      auth: { type: 'bearer', token: 'admin-token' }, checks: { compareAnonymous: true }, assertions: [{ path: '/api/orders', expectedAnonymousStatus: [401] }], limits: { delayMs: 0 } } });
    assert.equal(started.status, 202);
    let scan;
    do { scan = (await call(`/api/runtime/scans/${started.body.id}`)).body; } while (scan.status === 'running');
    assert.equal(scan.status, 'complete');
    assert.ok(scan.findings.some(finding => finding.rule === 'RT-AUTHZ-ASSERT'));
    const markdown = await call(`/api/runtime/scans/${started.body.id}/export?format=md`);
    assert.match(markdown.body, /Access-control assertion failed/);
    assert.ok(!markdown.body.includes('admin-token'));
    const overview = (await call('/api/metrics/overview')).body;
    assert.equal(overview.runtimeScans, 1);
    assert.ok(overview.findings >= 2);
    assert.ok((await call('/api/metrics/query', { method: 'POST', body: { metric: 'findings', groupBy: 'severity' } })).body.rows.length);
    assert.match((await call('/api/metrics/export')).body, /^"?timestamp/);
  });
  it('rejects unauthorized runtime scope', async () => {
    const response = await call('/api/runtime/scans', { method: 'POST', body: { target: demoUrl, paths: ['/'], authorization: { confirmed: false } } });
    assert.equal(response.status, 400);
  });
  it('creates, updates, and deletes custom dashboards and protects the built-in one', async () => {
    const created = await call('/api/dashboards', { method: 'POST', body: { name: 'API team', widgets: [{ title: 'Sev', chart: 'bar', metric: 'findings', groupBy: 'severity' }] } });
    assert.equal(created.status, 201);
    assert.equal((await call(`/api/dashboards/${created.body.id}`, { method: 'PUT', body: { name: 'API team v2', widgets: [] } })).body.name, 'API team v2');
    assert.equal((await call('/api/dashboards/default', { method: 'PUT', body: { name: 'x', widgets: [] } })).status, 400);
    assert.equal((await call('/api/dashboards')).body.length, 2);
    assert.equal((await call(`/api/dashboards/${created.body.id}`, { method: 'DELETE' })).status, 204);
  });
  it('serves help topics, tooltips, and the video catalog', async () => {
    const help = (await call('/api/help')).body;
    assert.ok(help.topics.length >= 5 && Object.keys(help.tooltips).length >= 10);
    assert.ok(help.videos.every(video => typeof video.available === 'boolean'));
    const example = (await call('/api/examples/runtime')).body;
    assert.ok(example.nodes.some(node => node.kind === 'impact'));
  });
});

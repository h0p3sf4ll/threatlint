'use strict';

// Keep tests isolated from the developer's real tracker connection.
process.env.THREATLINT_HOME = require('node:fs').mkdtempSync(require('node:path').join(require('node:os').tmpdir(), 'threatlint-dojo-metrics-'));
delete process.env.THREATLINT_DOJO_URL;
delete process.env.THREATLINT_DOJO_TOKEN;

const { test, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const scanners = require('../lib/scanners.cjs');
const metrics = require('../lib/defectdojo-metrics.cjs');

after(() => fs.rmSync(process.env.THREATLINT_HOME, { recursive: true, force: true }));

const finding = (id, values = {}) => ({ id, title: `Finding ${id}`, severity: 'High', date: '2026-10-20', active: true, false_p: false, product: 42, ...values });
const reply = body => ({ ok: true, status: 200, text: async () => JSON.stringify(body) });

test('DefectDojo metrics require an existing tracker connection', async () => {
  assert.deepEqual(metrics.connectionStatus(), { connected: false });
  await assert.rejects(metrics.fetchMetrics({ fetchImpl: () => assert.fail('must not fetch') }), /Add the DefectDojo URL and API token/);
});

test('DefectDojo metrics read bounded pages with token confined to the saved HTTPS host', async () => {
  scanners.writeConfig('dojo', { url: 'https://dojo.example.test', token: 'synthetic-token' });
  assert.deepEqual(metrics.connectionStatus(), { connected: true });
  const seen = [];
  const fetchImpl = async (url, options) => {
    const parsed = new URL(url);
    seen.push({ url: parsed, options });
    const offset = Number(parsed.searchParams.get('offset'));
    if (offset === 0) return reply({ count: 101, next: 'https://attacker.example.test/steal', results: Array.from({ length: 100 }, (_, i) => finding(i + 1)) });
    return reply({ count: 101, next: null, results: [finding(101, { false_p: true, title: 'Known false positive', severity: 'Medium', file_path: 'src/app.js', line: 14 })] });
  };
  const result = await metrics.fetchMetrics({ fetchImpl });
  assert.equal(result.items.length, 101);
  assert.deepEqual(seen.map(call => [call.url.origin, call.url.pathname, call.url.searchParams.get('limit'), call.url.searchParams.get('offset')]),
    [['https://dojo.example.test', '/api/v2/findings/', '100', '0'], ['https://dojo.example.test', '/api/v2/findings/', '100', '100']]);
  assert.ok(seen.every(call => call.options.method === 'GET' && call.options.redirect === 'error' && call.options.headers.Authorization === 'Token synthetic-token'));
  assert.deepEqual(result.items[100], { id: 'DOJO-101', title: 'Known false positive', severity: 'MEDIUM', disposition: 'FALSE POSITIVE',
    timestamp: Date.parse('2026-10-20'), workspace: 'Product 42', rule: 'DefectDojo finding', hasEvidence: true, fingerprint: 'defectdojo:101' });
  assert.equal(result.items[0].disposition, 'OPEN');
});

test('DefectDojo metrics read every finding, with no count limit', async () => {
  const total = 5250;
  const result = await metrics.fetchMetrics({ fetchImpl: async url => {
    const offset = Number(new URL(url).searchParams.get('offset'));
    return reply({ count: total, results: Array.from({ length: Math.min(100, total - offset) }, (_, i) => finding(offset + i + 1)) });
  } });
  assert.equal(result.items.length, total, 'past the old 5000 ceiling');
});

test('DefectDojo metrics never present an inconsistent snapshot as complete', async () => {
  await assert.rejects(metrics.fetchMetrics({ fetchImpl: async (url) => reply(new URL(url).searchParams.get('offset') === '0'
    ? { count: 2, results: [finding(1)] } : { count: 3, results: [finding(2)] }) }), /changed during metrics sync/);
  await assert.rejects(metrics.fetchMetrics({ fetchImpl: async () => reply({ count: 2, results: [finding(1), finding(1)] }) }), /changed during metrics sync/);
});

test('DefectDojo metrics retain only bounded chart fields and normalize closed findings', () => {
  const item = metrics.normalize(finding(7, { title: 'x'.repeat(1000), severity: 'Critical', active: false, product_name: 'Payments',
    vuln_id_from_tool: 'python.audit.sql', description: 'sensitive detail that must not be persisted' }));
  assert.equal(item.title.length, 300);
  assert.equal(item.severity, 'CRITICAL');
  assert.equal(item.disposition, 'REMEDIATED');
  assert.equal(item.workspace, 'Payments');
  assert.equal(item.rule, 'python.audit.sql');
  assert.equal(JSON.stringify(item).includes('sensitive detail'), false);
});

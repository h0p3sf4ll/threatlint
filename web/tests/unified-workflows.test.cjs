'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { EventEmitter } = require('node:events');
process.env.THREATLINT_HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-unified-home-'));
const { createWorkbench } = require('../server.js');
const { parseScanReport, reportMarkdown } = require('../lib/scan-import.cjs');
const { parseReport } = require('../lib/reports.cjs');
const { createTrackerMetrics } = require('../lib/tracker-metrics.cjs');
const trackers = require('../lib/issue-trackers.cjs');
const { findingType } = require('../lib/finding-types.cjs');
const { aggregate } = require('../lib/metrics.cjs');
const { sourceLink } = require('../lib/source-context.cjs');
const { createSandboxRuntime } = require('../lib/runtime-sandbox.cjs');
const json = body => ({ ok: true, json: async () => body });
const trivy = { SchemaVersion: 2, ArtifactName: 'demo', Results: [{ Target: 'package-lock.json', Vulnerabilities: [
  { VulnerabilityID: 'CVE-2026-1111', Title: 'SQL injection', Severity: 'HIGH', PkgName: 'demo' },
  { VulnerabilityID: 'CVE-2026-2222', Title: 'Exposed secrets', Severity: 'MEDIUM', PkgName: 'demo' },
] }] };

test('Trivy, Semgrep, and SARIF imports retain individual findings and scanner origins', async () => {
  const parsed = await parseScanReport(Buffer.from(JSON.stringify(trivy)));
  const report = reportMarkdown(parsed, new Map(), { filename: 'trivy.json' });
  const findings = parseReport(report, 'appsec-fp-reviewer').findings;
  assert.equal(findings.length, 2);
  assert.match(findings[0].body, /Scanner origin\*\*: trivy/);
  assert.match(findings[0].body, /package-lock.json/);
  assert.equal(findingType(findings[0]), 'SQL injection');
  assert.equal(findingType(findings[1]), 'Exposed secrets');
  const semgrep = await parseScanReport(Buffer.from(JSON.stringify({ version: '1', results: [{ check_id: 'xss', path: 'app.js', start: { line: 2 }, extra: { message: 'XSS', severity: 'ERROR' } }] })));
  assert.equal(semgrep.findings[0].scanner, 'semgrep');
  const sarif = await parseScanReport(Buffer.from(JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Trivy' } }, results: [{ ruleId: 'CVE-2026-1111', message: { text: 'Vulnerable dependency' }, level: 'error' }] }] })));
  assert.equal(sarif.findings[0].scanner, 'trivy');
});

test('tracker requests paginate, exclude PRs, refuse redirects, and normalize security classifications', async () => {
  const calls = [];
  const connection = { repository: 'org/repo', token: 'synthetic-token' };
  const rows = await trackers.fetchItems('github', { connection, fetchImpl: async (url, options) => {
    calls.push([url, options]);
    return json(calls.length === 1 ? Array.from({ length: 100 }, (_, index) => ({ number: index + 1, title: 'SQL injection', body: 'semgrep app.js:2', labels: [{ name: 'high' }], state: 'open' })) : [{ number: 101, title: 'PR', pull_request: {} }]);
  } });
  assert.equal(rows.length, 100); assert.equal(calls.length, 2);
  assert.ok(calls.every(([, options]) => options.redirect === 'error'));
  assert.equal(rows[0].scanner, 'semgrep'); assert.equal(rows[0].severity, 'HIGH');
  assert.throws(() => trackers.references('github', 'https://evil.test/1'), /issue numbers/);
  await assert.rejects(() => trackers.fetchItems('jira', { connection: { token: 'synthetic', url: 'https://team.atlassian.net' }, fetchImpl: async () => json({ issues: [], isLast: false }) }), /pagination incomplete/);
});

test('all supported tracker snapshots coexist, persist, and support combined metrics without storing tokens', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-unified-metrics-'));
  try {
    const store = createTrackerMetrics(dir);
    for (const id of ['github', 'jira', 'azure-devops', 'defectdojo']) store.replace(id, [{ id: '1', title: 'SQL injection', severity: 'HIGH', token: 'do-not-store' }]);
    const reloaded = createTrackerMetrics(dir).facts(); assert.equal(reloaded.length, 4);
    assert.equal(aggregate(reloaded, { groupBy: 'findingType', filters: { source: ['github', 'jira'] } }).total, 2);
    assert.equal(aggregate(reloaded, { groupBy: 'findingType' }).rows[0].key, 'SQL injection');
    assert.doesNotMatch(fs.readFileSync(path.join(dir, 'tracker-metrics.json'), 'utf8'), /do-not-store/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('source links refuse credentials, files, revisions embedded in paths, and arbitrary hosts', () => {
  assert.equal(sourceLink('https://github.com/org/repo').repository, 'org/repo');
  assert.equal(sourceLink('https://dev.azure.com/org/project/_git/repo.git').repository, 'org/project/repo');
  for (const url of ['file:///etc/passwd', 'https://token@github.com/org/repo', 'https://evil.test/org/repo', 'https://github.com/org/repo/tree/main']) assert.throws(() => sourceLink(url));
});

test('Jira pagination and ADO batch reads retain all returned tickets', async () => {
  let page = 0;
  const jira = await trackers.fetchItems('jira', { connection: { token: 'synthetic-token', url: 'https://team.atlassian.net', email: 'test@example.test', query: 'project = SEC' }, fetchImpl: async (_url, options) => {
    const query = JSON.parse(options.body); page++;
    assert.equal(query.jql, 'project = SEC');
    if (page === 2) assert.equal(query.nextPageToken, 'next');
    return json({ issues: [{ key: `SEC-${page}`, fields: { summary: 'SQL injection', priority: { name: 'High' }, status: { statusCategory: { key: 'new' } }, description: { content: [{ content: [{ text: 'CWE-89 app.js:2' }] }] } } }], isLast: page === 2, ...(page === 1 ? { nextPageToken: 'next' } : {}) });
  } });
  assert.equal(jira.length, 2); assert.equal(jira[0].rule, 'CWE-89');
  const batches = [];
  const ado = await trackers.fetchItems('azure-devops', { connection: { token: 'synthetic-token', organization: 'org', project: 'project' }, fetchImpl: async (url, options) => {
    if (url.includes('/wiql?')) return json({ workItems: Array.from({ length: 201 }, (_, index) => ({ id: index + 1 })) });
    const ids = JSON.parse(options.body).ids; batches.push(ids);
    return json({ value: ids.map(id => ({ id, fields: { 'System.Title': 'XSS', 'Microsoft.VSTS.Common.Severity': '2 - High', 'System.State': 'New' } })) });
  } });
  assert.equal(ado.length, 201); assert.deepEqual(batches.map(batch => batch.length), [200, 1]);
  assert.equal(ado[0].severity, 'HIGH');
});

test('ticket triage and multi-source metrics share the real routes and saved report store', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-unified-api-'));
  const app = createWorkbench({ storageDir: directory, integrations: { convertToWord: async () => {}, fetchImpl: async url => {
    if (url.includes('/issues/')) return json({ number: 42, title: 'SQL injection', body: 'Trivy reports a vulnerable dependency', labels: [{ name: 'high' }], state: 'open' });
    if (url.includes('/issues?')) return json([{ number: 42, title: 'SQL injection', body: '', labels: [], state: 'open' }]);
    return json({ id: 1 });
  } } });
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const post = async (route, body) => { const response = await fetch(base + route, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }); return { status: response.status, body: await response.json() }; };
  try {
    const saved = await post('/api/issue-trackers/github/settings', { repository: 'org/repo', token: 'synthetic-token' });
    assert.equal(saved.status, 200); assert.equal(saved.body.hasToken, true); assert.equal(saved.body.token, undefined);
    const accepted = await post('/api/issue-trackers/github/triage', { references: '#42' });
    assert.equal(accepted.status, 201);
    for (let i = 0; i < 100 && app.scanImports.get(accepted.body.id).status !== 'done'; i++) await new Promise(resolve => setTimeout(resolve, 10));
    const job = app.scanImports.get(accepted.body.id); assert.equal(job.status, 'done'); assert.equal(job.counts.total, 1);
    assert.equal((await post('/api/trackers/github/sync', {})).status, 200);
    const result = await post('/api/metrics/query', { metric: 'findings', groupBy: 'findingType', filters: { source: ['github', 'jira'] } });
    assert.equal(result.body.total, 1);
    const reports = [...app.store.sessions.values()].flatMap(session => session.reports);
    assert.equal(reports[0].findings.length, 1);
  } finally { await app.close(); fs.rmSync(directory, { recursive: true, force: true }); }
});

test('sandbox requires source-build consent and test credentials, and never returns echoed credentials', async () => {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-sandbox-fixture-'));
  const store = { sessions: new Map([['workspace', { repoPath: repo }]]) };
  let input;
  const scanner = createSandboxRuntime({ store, live: {}, spawnImpl: () => {
    const child = new EventEmitter(); child.stdout = new EventEmitter(); child.stderr = new EventEmitter(); child.kill = () => {};
    child.stdin = { end: text => { input = JSON.parse(text); setImmediate(() => {
      child.stdout.emit('data', JSON.stringify({ result: { responses: [{ id: '0', status: 200, headers: [['content-type', 'text/plain']], body: 'synthetic-password' }], identities: { 0: { path: '/', identity: 'primary' } }, cleanup: 'complete' } }) + '\n'); child.emit('close', 0);
    }); } };
    return child;
  } });
  const config = { source: { workspaceId: 'workspace', confirmBuild: true }, authorization: { confirmed: true, reason: 'owned synthetic sandbox' }, paths: ['/'], auth: { type: 'basic', username: 'test', password: 'synthetic-password' } };
  try {
    await assert.rejects(() => scanner.start({ ...config, source: { workspaceId: 'workspace' } }), /Authorize building/);
    await assert.rejects(() => scanner.start({ ...config, auth: { type: 'none' } }), /test credentials/);
    const { id } = await scanner.start(config); await new Promise(resolve => setImmediate(resolve));
    assert.equal(input.auth.password, 'synthetic-password');
    assert.equal(scanner.get(id).status, 'complete');
    assert.doesNotMatch(JSON.stringify(scanner.get(id)), /synthetic-password/);
    assert.equal(scanner.get(id).coverage.cleanup, 'complete');
  } finally { fs.rmSync(repo, { recursive: true, force: true }); }
});

test('scanner tuning rejects unproven verdicts and targets SonarQube or Trivy without shared-rule disablement', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-native-tuning-'));
  fs.writeFileSync(path.join(directory, 'package-lock.json'), '{"lockfileVersion":3}');
  const calls = [];
  let approved, policyFile;
  const app = createWorkbench({ storageDir: directory, integrations: { convertToWord: async () => {}, securityScannerCli: async (_args, options) => {
    policyFile = options.env.THREATLINT_REVIEWED_TRIVY_POLICY;
    approved = JSON.parse(fs.readFileSync(policyFile, 'utf8'));
    return { code: 0, stdout: JSON.stringify({ status: 'partial', findings: [], engines: [], coverage: { status: 'partial' } }) };
  }, fetchImpl: async (url, options) => {
    calls.push({ url, options }); return json({ issue: { resolution: 'FALSE-POSITIVE' } });
  } } });
  require('../lib/scanners.cjs').writeConfig('sonar', { url: 'https://sonar.example.test', token: 'synthetic-sonar-token' });
  const session = app.store.create(directory);
  const target = JSON.stringify({ kind: 'vulnerabilities', rule: 'CVE-2026-1111', path: 'package-lock.json' });
  const markdown = `# Finding Review\n\n#### [FP-001] Sonar finding\n**Disposition**: FALSE POSITIVE\n**Severity**: HIGH\n**Confidence**: CONFIRMED\n**Original finding**: SONAR-AYxExampleKey01\n**Scanner origin**: sonarqube\n\n#### [FP-002] Trivy finding\n**Disposition**: FALSE POSITIVE\n**Severity**: HIGH\n**Confidence**: CONFIRMED\n**Scanner origin**: trivy\n**Scanner target**: ${target}\n\n#### [FP-003] Remains open\n**Disposition**: TRUE POSITIVE\n**Severity**: HIGH\n**Scanner origin**: trivy\n**Scanner target**: ${target}`;
  const evidenced = markdown.replaceAll('**Disposition**: FALSE POSITIVE', '**Evidence**: src/test.js:1 uses the verified control.\n**Verified Safe Behavior**: All input reaches the parameterized call.\n**Disposition**: FALSE POSITIVE');
  const report = await app.generateReport('appsec-fp-reviewer', evidenced, session);
  await new Promise(resolve => app.server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${app.server.address().port}`;
  const tune = async (findingId, confirm) => { const response = await fetch(base + '/api/triage/scanner-tuning', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ reportId: report.id, findingId, confirm }) }); return { status: response.status, body: await response.json() }; };
  try {
    assert.equal((await tune('FP-001', false)).status, 400);
    assert.equal((await tune('FP-003', true)).status, 400);
    assert.equal(calls.length, 0);
    const sonar = await tune('FP-001', true); assert.equal(sonar.status, 200); assert.equal(sonar.body.scanner, 'sonarqube');
    assert.equal(calls.length, 2); assert.ok(calls.every(call => call.url.includes('/api/issues/')));
    const trivy = await tune('FP-002', true); assert.equal(trivy.status, 200);
    assert.equal(trivy.body.action, 'saved-local-policy');
    assert.equal(trivy.body.appliedLocally, true);
    const policy = JSON.parse(trivy.body.content);
    assert.deepEqual(policy.vulnerabilities[0].paths, ['package-lock.json']);
    assert.equal(policy.vulnerabilities[0].id, 'CVE-2026-1111');
    assert.match(policy.vulnerabilities[0].expired_at, /^\d{4}-\d\d-\d\d$/);
    assert.equal(calls.length, 2, 'Trivy local policy does not contact Semgrep or mutate a shared scanner rule');
    const started = app.securityScanner.start({ sessionId: session, engines: ['trivy'] });
    for (let index = 0; index < 100 && app.securityScanner.get(started.id).status === 'running'; index++) await new Promise(resolve => setTimeout(resolve, 5));
    assert.equal(approved[0].path, 'package-lock.json');
    assert.match(approved[0].fileHash, /^[a-f0-9]{64}$/);
    assert.equal(fs.existsSync(policyFile), false, 'the temporary policy transport is removed after the scan');
  } finally { await app.close(); fs.rmSync(directory, { recursive: true, force: true }); }
});

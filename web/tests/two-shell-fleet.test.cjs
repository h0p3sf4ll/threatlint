'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const express = require('express');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { createTwoShellFleet, normalizeBranches, normalizeRepositories, markdownReport } = require('../lib/two-shell-fleet.cjs');
const { registerTwoShellRoutes } = require('../lib/routes/two-shell.cjs');
const { createMcpServer } = require('../lib/mcp.cjs');

const FAKE = path.join(__dirname, 'fixtures', 'fake-xshell-cli.cjs');
const GITHUB = { id: '11111111-1111-4111-8111-111111111111', provider: 'github', label: 'GitHub · acme', account: 'acme', connected: true };
const AZURE = { id: '22222222-2222-4222-8222-222222222222', provider: 'azure-devops', label: 'Azure DevOps · contoso', account: 'contoso', connected: true };
const TOKENS = { [GITHUB.id]: 'ghs_synthetictoken0000000000000001', [AZURE.id]: 'azurepatsynthetic00000000000000002' };

function sources({ list = [GITHUB, AZURE, { id: 'saved:github-app', provider: 'github', connected: false }] } = {}) {
  const facade = { list: async () => list };
  Object.defineProperty(facade, 'credentialFor', { enumerable: false, value: async id => ({ provider: list.find(item => item.id === id).provider, token: TOKENS[id],
    ...(id === AZURE.id ? { organization: 'contoso' } : { kind: 'installation', apiBase: 'https://api.github.com' }) }) });
  return facade;
}
function fixture(t, { mode = 'ok', ...options } = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'two-shell-test-'));
  const record = path.join(directory, 'record.json');
  const previous = { mode: process.env.FAKE_XSHELL_MODE, record: process.env.FAKE_XSHELL_RECORD };
  process.env.FAKE_XSHELL_MODE = mode; process.env.FAKE_XSHELL_RECORD = record;
  const fleet = createTwoShellFleet({ sources: options.sources || sources(), integrations: { twoShellCommand: [process.execPath, FAKE], tmpdir: directory } });
  t.after(async () => {
    await fleet.close();
    for (const [key, name] of [['mode', 'FAKE_XSHELL_MODE'], ['record', 'FAKE_XSHELL_RECORD']]) { if (previous[key] === undefined) delete process.env[name]; else process.env[name] = previous[key]; }
    fs.rmSync(directory, { recursive: true, force: true });
  });
  return { fleet, record, directory };
}
async function settle(fleet, id, timeout = 15_000) {
  const end = Date.now() + timeout;
  for (;;) {
    const job = fleet.get(id);
    if (job.status !== 'running') return job;
    if (Date.now() > end) throw new Error('scan did not finish');
    await new Promise(resolve => setTimeout(resolve, 25));
  }
}

test('selection validation: live connections, repository names, and safe branch patterns', async t => {
  const { fleet } = fixture(t);
  await assert.rejects(fleet.start({}), /at least one connected source/);
  await assert.rejects(fleet.start({ connections: [{ connectionId: 'saved:github-app' }] }), /not connected/);
  await assert.rejects(fleet.start({ connections: [{ connectionId: 'missing' }] }), /not connected/);
  await assert.rejects(fleet.start({ connections: [{ connectionId: GITHUB.id }, { connectionId: GITHUB.id }] }), /selected once/);
  await assert.rejects(fleet.start({ connections: [{ connectionId: GITHUB.id, repositories: ['../etc/passwd'] }] }), /owner\/name/);
  await assert.rejects(fleet.start({ connections: [{ connectionId: GITHUB.id, repositories: Array.from({ length: 1001 }, (_, i) => `acme/r${i}`) }] }), /1 to 1000/);
  await assert.rejects(fleet.start({ connections: [{ connectionId: GITHUB.id, branches: ['--upload-pack=evil'] }] }), /Branch names/);
  await assert.rejects(fleet.start({ connections: [{ connectionId: GITHUB.id, branches: ['a..b'] }] }), /Branch names/);
  await assert.rejects(fleet.start({ connections: [{ connectionId: GITHUB.id, branches: Array.from({ length: 21 }, (_, i) => `b${i}`) }] }), /1 to 20/);
  await assert.rejects(fleet.start({ connections: [{ connectionId: GITHUB.id }], workers: 99 }), /Workers/);
  assert.deepEqual(normalizeBranches('main, release/*'), ['main', 'release/*']);
  assert.equal(normalizeBranches(undefined), 'default');
  assert.deepEqual(normalizeRepositories(['contoso/Payments Platform/web', 'Payments Platform/api'], AZURE), ['Payments Platform/api', 'Payments Platform/web']);
  assert.throws(() => normalizeRepositories(['fabrikam/proj/web'], AZURE), /different organization/);
});

test('runs the CLI with credentials only in the child environment and reports progress and results', async t => {
  const { fleet, record, directory } = fixture(t);
  const { id } = await fleet.start({ connections: [
    { connectionId: GITHUB.id, repositories: 'all', branches: 'all' },
    { connectionId: AZURE.id, repositories: ['contoso/Payments/web'], branches: ['main', 'release/*'] },
  ], workers: 2 });
  const job = await settle(fleet, id);
  assert.equal(job.status, 'completed', job.error);
  assert.equal(job.summary.vulnerable, 1);
  assert.equal(job.topSeverity, 'CRITICAL');
  assert.deepEqual(job.progress, { total: 2, done: 2, vulnerable: 1, clean: 1, notApplicable: 0, errors: 0 });
  assert.equal(job.recent.length, 2);
  assert.equal(job.result.results.length, 2);

  const seen = JSON.parse(fs.readFileSync(record, 'utf8'));
  assert.deepEqual(seen.args.slice(0, 2), ['detect-xshell', 'fleet']);
  for (const flag of ['--targets-file', '--format', '--output', '--progress', '--workers']) assert.ok(seen.args.includes(flag), flag);
  assert.equal(seen.args[seen.args.indexOf('--workers') + 1], '2');
  assert.deepEqual(seen.targets, { connections: [
    { connection: GITHUB.id, repositories: 'all', branches: 'all' },
    { connection: AZURE.id, repositories: ['Payments/web'], branches: ['main', 'release/*'] },
  ], maxRepositories: 500, maxBranchesPerRepository: 50 });
  const credentials = JSON.parse(seen.credentials);
  assert.deepEqual(credentials.connections.map(item => [item.id, item.provider, item.token, item.organization]),
    [[GITHUB.id, 'github', TOKENS[GITHUB.id], undefined], [AZURE.id, 'azure-devops', TOKENS[AZURE.id], 'contoso']]);
  // Tokens never reach argv, the targets file, job state, or responses; temp files are removed.
  const surfaces = JSON.stringify([seen.args, seen.targets, fleet.list(), fleet.get(id), fleet.report(id, 'json'), fleet.report(id, 'markdown')]);
  for (const token of Object.values(TOKENS)) assert.equal(surfaces.includes(token), false);
  assert.equal(surfaces.includes('free-form log line'), false);
  assert.deepEqual(fs.readdirSync(directory).filter(name => name.startsWith('threatlint-xshell-')), []);

  const markdown = fleet.report(id, 'markdown').body;
  assert.match(markdown, /^#### \[TS-001\] — Next\.js App Router remote code execution$/m);
  assert.match(markdown, /\*\*Severity\*\*: CRITICAL/);
  assert.match(markdown, /\*\*Confidence\*\*: CONFIRMED/);
  assert.match(markdown, /`package-lock\.json:12`/);
  assert.equal(JSON.parse(fleet.report(id, 'json').body).schema, 'threatlint.detect-xshell/v1');
  assert.throws(() => fleet.report(id, 'pdf'), /json or markdown/);
});

test('a failing CLI is reported without echoing tokens or free-form stderr', async t => {
  const { fleet } = fixture(t, { mode: 'fail' });
  const { id } = await fleet.start({ connections: [{ connectionId: GITHUB.id }] });
  const job = await settle(fleet, id);
  assert.equal(job.status, 'failed');
  assert.match(job.error, /GitHub rejected credential \[REDACTED\]/);
  assert.equal(JSON.stringify(job).includes(TOKENS[GITHUB.id]), false);
  assert.equal(JSON.stringify(job).includes('Traceback'), false);
  assert.throws(() => fleet.report(id, 'json'), /when the scan completes/);
});

test('cancel kills the child; at most two scans run and finished scans are retained up to 25', async t => {
  const { fleet } = fixture(t, { mode: 'hang' });
  const first = await fleet.start({ connections: [{ connectionId: GITHUB.id }] });
  const second = await fleet.start({ connections: [{ connectionId: AZURE.id }] });
  await assert.rejects(fleet.start({ connections: [{ connectionId: GITHUB.id }] }), error => error.status === 429);
  assert.equal(fleet.active, true);
  fleet.cancel(first.id); fleet.cancel(second.id);
  for (const { id } of [first, second]) {
    const job = await settle(fleet, id);
    assert.equal(job.status, 'cancelled');
    assert.match(job.error, /not reported as clean/);
  }
  assert.equal(fleet.active, false);
  assert.throws(() => fleet.get('nope'), /not found/);

  process.env.FAKE_XSHELL_MODE = 'fail';
  for (let index = 0; index < 26; index++) {
    const { id } = await fleet.start({ connections: [{ connectionId: GITHUB.id }] });
    await settle(fleet, id);
  }
  assert.equal(fleet.list().length, 25);
});

test('routes and MCP tools use the same validated service', async t => {
  const { fleet } = fixture(t);
  const app = express(); app.use(express.json()); registerTwoShellRoutes(app, { twoShellFleet: fleet });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const base = `http://127.0.0.1:${server.address().port}/api/detect-xshell/scans`;
  const post = (url, body) => fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  assert.equal((await post(base, { connections: [] })).status, 400);
  const started = await post(base, { connections: [{ connectionId: GITHUB.id, branches: 'main, develop' }] });
  assert.equal(started.status, 202);
  const { id } = await started.json();
  await settle(fleet, id);
  const listed = await (await fetch(base)).json();
  assert.equal(listed[0].id, id); assert.equal(listed[0].result, undefined);
  const brief = await (await fetch(`${base}/${id}?results=false`)).json();
  assert.equal(brief.result, undefined); assert.equal(brief.status, 'completed');
  const markdown = await fetch(`${base}/${id}/report?format=markdown`);
  assert.match(markdown.headers.get('content-type'), /text\/markdown/);
  assert.match(markdown.headers.get('content-disposition'), /attachment; filename="detect-xshell-/);
  assert.match(await markdown.text(), /TIER 1 — EXECUTIVE SUMMARY/);
  assert.equal((await fetch(`${base}/missing`)).status, 404);
  assert.equal((await post(`${base}/${id}/cancel`, {})).status, 200);

  const mcp = createMcpServer({ store: { sessions: new Map() }, intelligence: { overview: () => ({ findings: [] }) },
    reports: { metadata: value => value, read: () => ({ findings: [] }) }, twoShellFleet: fleet });
  const client = new Client({ name: 'two-shell', version: '1' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await mcp.close(); });
  await mcp.connect(serverTransport); await client.connect(clientTransport);
  const names = (await client.listTools()).tools.map(tool => tool.name);
  for (const name of ['start_xshell_scan', 'list_xshell_scans', 'get_xshell_scan', 'cancel_xshell_scan']) assert.ok(names.includes(name), name);
  const call = async (name, args) => client.callTool({ name, arguments: args });
  assert.equal((await call('start_xshell_scan', { connections: [{ connectionId: GITHUB.id }] })).isError, true, 'confirmation is required');
  const response = await call('start_xshell_scan', { connections: [{ connectionId: GITHUB.id, repositories: ['acme/web'], branches: ['main'] }], confirm: true });
  assert.notEqual(response.isError, true, response.content?.[0]?.text);
  const scanId = JSON.parse(response.content[0].text).id;
  await settle(fleet, scanId);
  const overview = JSON.parse((await call('get_xshell_scan', { scanId })).content[0].text);
  assert.equal(overview.resultCount, 2); assert.equal(overview.result, undefined);
  const vulnerable = JSON.parse((await call('get_xshell_scan', { scanId, section: 'results', status: 'vulnerable' })).content[0].text);
  assert.equal(vulnerable.total, 1); assert.equal(vulnerable.items[0].repository, 'acme/web');
  const page = JSON.parse((await call('list_xshell_scans', { limit: 1 })).content[0].text);
  assert.equal(page.items.length, 1); assert.equal(page.items[0].recent, undefined);
  for (const token of Object.values(TOKENS)) assert.equal(JSON.stringify([overview, vulnerable, page]).includes(token), false);
});

test('markdown for a scan with gaps never claims a clean result', () => {
  const markdown = markdownReport({ selection: [{}], finishedAt: Date.UTC(2026, 10, 28), result: { summary: { targets: 2, scanned: 1, vulnerable: 0, clean: 1, errors: 1 },
    results: [{ provider: 'github', repository: 'acme/x', branch: 'main', status: 'error', error: 'Not found', findings: [] }] } });
  assert.match(markdown, /\*\*UNKNOWN\*\*/);
  assert.match(markdown, /this is not a clean result/);
  assert.match(markdown, /### Coverage gaps/);
});

test('the sources facade exposes credentialFor only as a non-enumerable host accessor', async () => {
  const { registerSourceRoutes } = require('../lib/routes/sources.cjs');
  const app = express();
  const scm = { list: () => [{ id: GITHUB.id, provider: 'github', account: 'acme' }],
    credential: id => ({ provider: 'github', token: TOKENS[id], kind: 'user' }) };
  const facade = registerSourceRoutes(app, { store: {}, scm, integrations: { githubApp: {} } });
  assert.equal(Object.keys(facade).includes('credentialFor'), false);
  assert.equal(JSON.stringify(facade).includes('credentialFor'), false);
  assert.equal({ ...facade }.credentialFor, undefined);
  assert.equal((await facade.credentialFor(GITHUB.id)).token, TOKENS[GITHUB.id]);
  const legacy = registerSourceRoutes(express(), { store: {}, scm: { list: () => [] }, integrations: { githubApp: {} } });
  await assert.rejects(legacy.credentialFor(GITHUB.id), /cannot share credentials/);
});

test('accepts results from a pre-rename CLI and marks impacted lines that have no fix', async t => {
  const { fleet } = fixture(t, { mode: 'legacy' });
  const { id } = await fleet.start({ connections: [{ connectionId: GITHUB.id }] });
  const job = await settle(fleet, id);
  assert.equal(job.status, 'completed');
  const markdown = fleet.report(id, 'markdown').body;
  assert.match(markdown, /^# \*-Shell Exposure Scan \(fleet\)$/m);
  assert.match(markdown, /\*\*No fix on this line\*\*/);
  assert.match(markdown, /\| Fix available \| No — impacted, move to a supported release line \|/);
  assert.match(markdown, /where the line has no fix \(1 finding\(s\)\)/);
});

test('the pre-rename /api/detect-2shell routes still work', async t => {
  const { fleet } = fixture(t);
  const app = express(); app.use(express.json()); registerTwoShellRoutes(app, { twoShellFleet: fleet });
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const legacy = `http://127.0.0.1:${server.address().port}/api/detect-2shell/scans`;
  const started = await fetch(legacy, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ connections: [{ connectionId: GITHUB.id }] }) });
  assert.equal(started.status, 202);
  const { id } = await started.json();
  await settle(fleet, id);
  assert.equal((await (await fetch(`${legacy}/${id}?results=false`)).json()).status, 'completed');
  const current = `http://127.0.0.1:${server.address().port}/api/detect-xshell/scans/${id}?results=false`;
  assert.equal((await (await fetch(current)).json()).id, id);
});

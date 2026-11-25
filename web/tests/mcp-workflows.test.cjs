'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { createMcpServer } = require('../lib/mcp.cjs');
const { createMcpReviews } = require('../lib/mcp-reviews.cjs');

function dependencies(extra = {}) {
  return { store: { sessions: new Map([
    ['one', { id: 'one', repoPath: '/repo/one', reports: [{ id: 'report-one', agentId: 'appsec-fp-reviewer' }] }],
    ['two', { id: 'two', repoPath: '/repo/two', reports: [{ id: 'report-two', agentId: 'appsec-fp-reviewer' }] }],
  ]) }, intelligence: { overview: () => ({ findings: [] }) }, reports: { metadata: value => value, read: () => ({ findings: [] }) }, ...extra };
}
async function fixture(t, extra) {
  const server = createMcpServer(dependencies(extra)), client = new Client({ name: 'workflow-adapters', version: '1' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await server.close(); });
  await server.connect(serverTransport); await client.connect(clientTransport);
  const raw = (name, args = {}) => client.callTool({ name, arguments: args });
  const call = async (name, args) => {
    const response = await raw(name, args);
    assert.notEqual(response.isError, true, `${name}: ${response.content?.[0]?.text}`);
    const result = JSON.parse(response.content[0].text);
    assert.deepEqual(response.structuredContent, { result });
    return result;
  };
  const rejected = async (name, args, pattern) => {
    const response = await raw(name, args);
    assert.equal(response.isError, true, `${name} should reject`);
    if (pattern) assert.match(response.content[0].text, pattern);
  };
  return { client, call, raw, rejected };
}

test('AVIT write-back requires both explicit authorizations and pins references and fix-PR consent', async t => {
  const starts = [], subscribers = new Set(); let cancelled = 0;
  const events = Array.from({ length: 205 }, (_, n) => ({ type: 'avit_item', n }));
  const { call, rejected } = await fixture(t, { avitRuns: {
    start: message => { starts.push(message); return 'current-run'; },
    attach: subscriber => { subscribers.add(subscriber); return { runId: 'current-run', active: true, events }; },
    detach: subscriber => subscribers.delete(subscriber), cancel: () => { cancelled++; return true; },
  } });
  const request = { references: 'AVIT0012345', provider: 'lmstudio', model: 'fixture' };
  for (const auth of [{}, { confirm: true }, { confirmWriteback: true }, { confirm: true, confirmWriteback: false },
    { options: { confirm: true, confirmWriteback: true } }]) await rejected('start_avit_review', { ...request, ...auth });
  assert.equal(starts.length, 0);
  assert.equal((await call('start_avit_review', { ...request, confirm: true, confirmWriteback: true,
    options: { avits: 'AVIT9999999', createFixPr: true, provider: 'openai', model: 'overridden' } })).runId, 'current-run');
  assert.equal(starts[0].avits, request.references); assert.equal(starts[0].createFixPr, false);
  assert.equal(starts[0].provider, 'lmstudio'); assert.equal(starts[0].model, 'fixture');
  await call('start_avit_review', { ...request, createFixPr: true, confirm: true, confirmWriteback: true, options: { createFixPr: false } });
  assert.equal(starts[1].createFixPr, true);
  const page = await call('get_avit_review', { runId: 'current-run', offset: 100, limit: 100 });
  assert.equal(page.total, 205); assert.equal(page.items.length, 100); assert.equal(page.items[0].n, 100); assert.equal(page.nextOffset, 200);
  assert.equal((await call('get_avit_review', { offset: 200, limit: 100 })).nextOffset, null);
  assert.equal(subscribers.size, 0, 'polling must detach its temporary snapshot subscriber');
  await rejected('get_avit_review', { runId: 'previous-run' }, /not found/);
  await rejected('get_avit_review', { limit: 101 });
  await rejected('get_avit_review', { offset: -1 });
  await rejected('cancel_avit_review', { runId: 'previous-run', confirm: true }, /not found/);
  await rejected('cancel_avit_review', { runId: 'current-run' }); assert.equal(cancelled, 0);
  assert.equal((await call('cancel_avit_review', { runId: 'current-run', confirm: true })).accepted, true); assert.equal(cancelled, 1);
});

test('conversation adapter maps report context, caps questions and preserves workspace boundaries', async t => {
  const requests = [];
  const { call, rejected } = await fixture(t, { reviews: { start: (message, kind) => { requests.push({ message, kind }); return { id: 'job' }; } },
    conversations: { list: () => [], get: id => ({ id, sessionId: 'two' }) } });
  await call('ask_question', { sessionId: 'one', reportId: 'report-one', question: 'Explain the evidence', provider: 'lmstudio', model: 'fixture', confirm: true,
    options: { sessionId: 'two', question: 'override', context: { type: 'report', reportId: 'report-two' }, model: 'ignored' } });
  assert.equal(requests[0].kind, 'conversation'); assert.equal(requests[0].message.sessionId, 'one');
  assert.equal(requests[0].message.question, 'Explain the evidence'); assert.equal(requests[0].message.model, 'fixture');
  assert.deepEqual(requests[0].message.context, { type: 'report', reportId: 'report-one' });
  await rejected('ask_question', { sessionId: 'one', reportId: 'report-two', question: 'Explain', confirm: true }, /not found in this workspace/);
  await rejected('ask_question', { sessionId: 'one', question: 'a'.repeat(8001), confirm: true });
  await rejected('ask_question', { sessionId: 'one', question: 'Explain' });
  await call('ask_question', { sessionId: 'one', question: 'a'.repeat(8000), confirm: true });
  assert.equal(requests.length, 2);
  await rejected('get_conversation', { sessionId: 'one', conversationId: 'belongs-to-two' }, /not found in this workspace/);
  assert.equal((await call('get_conversation', { sessionId: 'two', conversationId: 'belongs-to-two' })).sessionId, 'two');
});

test('continuing a conversation from another workspace is rejected before the shared conversation service runs', async t => {
  const deps = dependencies(); let asks = 0;
  const conversations = { get: () => ({ sessionId: 'two' }), list: () => [], ask: async () => { asks++; } };
  const reviews = createMcpReviews({ store: deps.store, conversations });
  t.after(() => reviews.close());
  const { rejected } = await fixture(t, { ...deps, conversations, reviews });
  await rejected('ask_question', { sessionId: 'one', conversationId: 'other-conversation', question: 'Continue', confirm: true }, /not found in this workspace/);
  assert.equal(asks, 0);
});

test('scan import adapters pin file, source and workspace fields, use shared base64 validation and confirm external posting', async t => {
  const uploads = [], posts = [];
  const { call, rejected } = await fixture(t, { scanImports: {
    create: async upload => { uploads.push(upload); if (upload.filename.endsWith('.exe')) throw new Error('Unsupported scanner report format'); return { accepted: { id: 'import', status: 'queued' } }; },
    list: () => [{ id: 'import' }], get: id => ({ id, status: 'completed' }),
    post: async (id, input) => { posts.push({ id, input }); return { ok: true }; },
    postScanner: async (id, input) => { posts.push({ id, input }); return { ok: true }; },
  } });
  const content = Buffer.from('{"results":[]}').toString('base64');
  await call('import_scan_report', { filename: 'results.sarif', content, sessionId: 'one', source: 'semgrep', provider: 'lmstudio', model: 'fixture', confirm: true,
    options: { filename: 'ignored.exe', content: Buffer.from('overridden').toString('base64'), workspaceId: 'two', source: 'other', model: 'ignored' } });
  assert.equal(uploads[0].filename, 'results.sarif'); assert.equal(uploads[0].content.toString(), '{"results":[]}');
  assert.equal(uploads[0].fields.workspaceId, 'one'); assert.equal(uploads[0].fields.source, 'semgrep'); assert.equal(uploads[0].fields.model, 'fixture');
  await rejected('import_scan_report', { filename: 'results.sarif', content: '%%%', confirm: true }, /base64/);
  await rejected('import_scan_report', { filename: 'results.sarif', content, sessionId: 'missing', confirm: true }, /Workspace not found/);
  await rejected('import_scan_report', { filename: 'results.sarif', content });
  assert.equal(uploads.length, 1);
  await rejected('import_scan_report', { filename: 'results.exe', content, confirm: true }, /Unsupported scanner report format/);
  assert.equal(uploads.length, 2, 'shared import service retains its format validation');
  assert.equal((await call('list_imports', {})).items[0].id, 'import');
  assert.equal((await call('get_import', { importId: 'import' })).status, 'completed');
  await rejected('post_import_review', { importId: 'import', destination: 'servicenow', options: { confirm: true } });
  assert.equal(posts.length, 0);
  await call('post_import_review', { importId: 'import', destination: 'servicenow', confirm: true, options: { confirm: false, number: 'AVIT0012345' } });
  assert.deepEqual(posts[0], { id: 'import', input: { confirm: true, number: 'AVIT0012345' } });
  await call('post_import_review', { importId: 'import', destination: 'sonar', confirm: true, options: { tool: 'dojo', confirm: false, reference: 'SONAR-example' } });
  assert.equal(posts[1].id, 'import'); assert.equal(posts[1].input.tool, 'sonar'); assert.equal(posts[1].input.confirm, true);
});

test('Azure DevOps ticket triage accepts the canonical tracker ID and forwards normalized evidence to imports', async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-mcp-ticket-')), previous = process.env.THREATLINT_HOME;
  process.env.THREATLINT_HOME = root;
  t.after(() => { if (previous === undefined) delete process.env.THREATLINT_HOME; else process.env.THREATLINT_HOME = previous; fs.rmSync(root, { recursive: true, force: true }); });
  fs.writeFileSync(path.join(root, 'tracker-azure-devops.json'), JSON.stringify({ organization: 'synthetic', project: 'Security', token: 'synthetic-not-a-real-token' }));
  const fetches = [], uploads = [];
  const { call, rejected } = await fixture(t, { integrations: { fetchImpl: async (url, options) => {
    fetches.push({ url, body: JSON.parse(options.body) });
    return { ok: true, json: async () => ({ value: [{ id: 123, fields: { 'System.Title': 'Synthetic scanner finding', 'System.Description': 'Review app.py:2', 'System.State': 'Active', 'System.CreatedDate': '2026-01-01T00:00:00Z' } }] }) };
  } }, scanImports: { create: async upload => { uploads.push(upload); return { accepted: { id: 'tickets-import' } }; }, list: () => [], get: () => ({}) } });
  assert.equal((await call('triage_tickets', { tracker: 'azure-devops', references: 'ADO-123', sessionId: 'one', provider: 'lmstudio', model: 'fixture', confirm: true,
    options: { workspaceId: 'two', source: 'overridden' } })).id, 'tickets-import');
  assert.match(fetches[0].url, /^https:\/\/dev\.azure\.com\/synthetic\/Security\/_apis\/wit\/workitemsbatch/);
  assert.deepEqual(fetches[0].body.ids, [123]);
  const artifact = JSON.parse(uploads[0].content.toString());
  assert.equal(artifact.tracker, 'azure-devops'); assert.equal(artifact.threatlintFindings[0].id, 'ADO-123'); assert.equal(artifact.threatlintFindings[0].hasEvidence, true);
  assert.equal(uploads[0].fields.workspaceId, 'one'); assert.equal(uploads[0].fields.source, 'tickets');
  await rejected('triage_tickets', { tracker: 'ado', references: '123', confirm: true });
  await rejected('triage_tickets', { tracker: 'azure-devops', references: 'not-an-ID', confirm: true }, /work item IDs/);
  assert.equal(fetches.length, 1);
});

test('runtime adapters preserve authorization and authentication configuration while requiring explicit action confirmation', async t => {
  const requests = [], added = [], cancelled = [];
  const { call, rejected } = await fixture(t, { runtime: {
    start: async config => { requests.push(['start', config]); if (config.authorized !== true) throw new Error('Explicit runtime authorization is required'); return { id: 'runtime' }; },
    get: id => ({ id, coverage: { status: 'partial' } }), cancel: id => cancelled.push(id),
    exportScan: (id, format) => ({ contentType: 'text/plain', body: `${id}:${format}` }),
    startBrowser: config => { requests.push(['browser', config]); return { id: 'browser' }; }, finishBrowser: id => ({ id, ready: true }),
  }, history: { add: id => added.push(id), summaries: () => [{ id: 'runtime' }] } });
  const config = { authorized: true, target: 'https://synthetic.test', confirmBuild: true, auth: { mode: 'headers', headers: { Authorization: 'Bearer synthetic-value' } },
    source: { sessionId: 'one' }, paths: ['/api'] };
  await rejected('start_runtime_scan', { config }); assert.equal(requests.length, 0);
  assert.equal((await call('start_runtime_scan', { config, confirm: true })).id, 'runtime');
  assert.deepEqual(requests[0], ['start', config]); assert.deepEqual(added, ['runtime']);
  await rejected('start_runtime_scan', { config: { authorized: false }, confirm: true }, /authorization/);
  assert.equal((await call('list_runtime_scans', {}))[0].id, 'runtime');
  assert.equal((await call('get_runtime_scan', { scanId: 'runtime' })).coverage.status, 'partial');
  assert.equal((await call('export_runtime_scan', { scanId: 'runtime', format: 'md' })).body, 'runtime:md');
  assert.equal((await call('export_runtime_scan', { scanId: 'runtime' })).body, 'runtime:json');
  await rejected('cancel_runtime_scan', { scanId: 'runtime' }); assert.equal(cancelled.length, 0);
  await call('cancel_runtime_scan', { scanId: 'runtime', confirm: true }); assert.deepEqual(cancelled, ['runtime']);
  await rejected('start_browser_signin', { config });
  assert.equal((await call('start_browser_signin', { config, confirm: true })).id, 'browser'); assert.deepEqual(requests.at(-1), ['browser', config]);
  assert.equal((await call('finish_browser_signin', { browserId: 'browser', confirm: true })).ready, true);
});

test('scanner review filters reach the shared workflow and posting requires a report in the selected workspace', async t => {
  const starts = [], posted = [];
  const { call, rejected } = await fixture(t, { reviews: { start: (message, kind) => { starts.push({ message, kind }); return { id: 'review' }; } },
    scannerBatch: { resolve: async (tool, input) => {
      posted.push({ tool, input });
      if (input.reference !== 'SONAR-exact-reference') throw new Error('The original scanner reference does not match this report');
      return { ok: true };
    } } });
  const filter = { project: 'synthetic', severity: 'HIGH', kind: 'sast' };
  await call('start_scanner_review', { sessionId: 'one', tool: 'sonar', filter, provider: 'lmstudio', model: 'fixture', confirm: true,
    options: { sessionId: 'two', tool: 'dojo', filter: { project: 'wrong' } } });
  assert.equal(starts[0].kind, 'scanner_review'); assert.equal(starts[0].message.sessionId, 'one'); assert.equal(starts[0].message.tool, 'sonar');
  assert.deepEqual(starts[0].message.filter, filter);
  const input = { sessionId: 'one', reportId: 'report-one', tool: 'sonar', reference: 'SONAR-exact-reference' };
  await rejected('post_scanner_review', input);
  await rejected('post_scanner_review', { ...input, sessionId: 'two', confirm: true }, /not found in this workspace/);
  assert.equal(posted.length, 0);
  assert.equal((await call('post_scanner_review', { ...input, confirm: true, reportUrl: 'https://reports.synthetic.test/one' })).ok, true);
  assert.deepEqual(posted[0], { tool: 'sonar', input: { reportId: 'report-one', reference: input.reference, reportUrl: 'https://reports.synthetic.test/one', confirm: true } });
  await rejected('post_scanner_review', { ...input, reference: 'SONAR-wrong-reference', confirm: true }, /does not match/);
});

'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const { execFileSync } = require('node:child_process');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { StdioClientTransport, getDefaultEnvironment } = require('@modelcontextprotocol/sdk/client/stdio.js');
const { createWorkbench } = require('../server.js');
const { convertToWord } = require('./helpers/docx.cjs');

const tick = () => new Promise(resolve => setImmediate(resolve));
const deferred = () => { let resolve; const promise = new Promise(yes => { resolve = yes; }); return { promise, resolve }; };
const source = 'def handler():\n    return "synthetic evidence"\n';
const agentId = 'appsec-code-reviewer';

async function connect(workbench) {
  const server = workbench.createMcpServer(), client = new Client({ name: 'headless-integration', version: '1' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport); await client.connect(clientTransport);
  return { client, close: async () => { await client.close(); await server.close(); } };
}
async function call(client, name, args = {}) {
  const response = await client.callTool({ name, arguments: args });
  assert.notEqual(response.isError, true, `${name}: ${response.content?.[0]?.text}`);
  const result = JSON.parse(response.content.find(item => item.type === 'text').text);
  assert.deepEqual(response.structuredContent, { result });
  return result;
}
async function poll(client, name, args, done) {
  for (let n = 0; n < 100; n++) {
    const value = await call(client, name, args);
    if (done(value)) return value;
    await tick();
  }
  assert.fail(`${name} did not reach a terminal state`);
}
function fixture(t, options = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-mcp-headless-'));
  const repo = path.join(root, 'repo'), other = path.join(root, 'other'), storageDir = path.join(root, 'profile');
  fs.mkdirSync(repo); fs.mkdirSync(other); fs.writeFileSync(path.join(repo, 'app.py'), source);
  fs.writeFileSync(path.join(root, 'outside.txt'), 'This file must not be inspectable through the repository.');
  execFileSync('git', ['init', '--quiet', repo], { windowsHide: true });
  const workbench = createWorkbench({ storageDir, ...options, integrations: { convertToWord, ...options.integrations } });
  t.after(async () => { await workbench.close(); fs.rmSync(root, { recursive: true, force: true }); });
  return { root, repo, other, storageDir, workbench };
}

test('a fresh Workbench profile exposes usable specialists, repository inspection, prompts, resources and completion without a UI', async t => {
  const { workbench, repo } = fixture(t), connection = await connect(workbench);
  t.after(connection.close);
  const { client } = connection;
  assert.equal(workbench.server.listening, false);
  assert.deepEqual(await call(client, 'list_workspaces'), []);
  const agents = await call(client, 'list_agents');
  assert.equal(agents.length, 23); assert.ok(agents.every(agent => agent.skills.length > 0 && agent.contract.boundaries));
  const { sessionId } = await call(client, 'open_workspace', { repoPath: repo, confirm: true });
  assert.equal((await call(client, 'get_workspace', { sessionId })).repoPath, fs.realpathSync(repo));
  assert.match((await call(client, 'read_file', { sessionId, path: 'app.py', offset: 1, limit: 1 })).text, /^2\t.*synthetic evidence/);
  assert.match((await call(client, 'find_files', { sessionId, pattern: '**/*.py' })).text, /app\.py/);
  assert.match((await call(client, 'search_files', { sessionId, pattern: 'synthetic evidence' })).text, /app\.py:2:/);
  assert.match((await call(client, 'inspect_git', { sessionId, command: 'status', args: ['--short'] })).text, /app\.py/);
  assert.equal((await client.callTool({ name: 'read_file', arguments: { sessionId, path: '../outside.txt' } })).isError, true);
  assert.equal((await client.callTool({ name: 'inspect_git', arguments: { sessionId, command: 'diff', args: ['--output=outside.txt'] } })).isError, true);
  assert.equal((await client.callTool({ name: 'read_file', arguments: { sessionId: 'missing', path: 'app.py' } })).isError, true);

  assert.ok((await client.listPrompts()).prompts.some(prompt => prompt.name === 'security_review'));
  const prompt = await client.getPrompt({ name: 'security_review', arguments: { agentId, sessionId, target: 'Review handler' } });
  assert.match(prompt.messages[0].content.text, /Required Skill Workflows/);
  assert.match(prompt.messages[1].content.text, /proposed tests are NOT RUN/);
  assert.ok((await client.listResources()).resources.some(resource => resource.uri === 'threatlint://agents'));
  assert.ok((await client.listResourceTemplates()).resourceTemplates.some(resource => resource.uriTemplate === 'threatlint://agents/{agentId}'));
  assert.equal(JSON.parse((await client.readResource({ uri: 'threatlint://agents' })).contents[0].text).length, 23);
  assert.match((await client.readResource({ uri: `threatlint://agents/${agentId}` })).contents[0].text, /Required Skill Workflows/);
  assert.equal(JSON.parse((await client.readResource({ uri: 'threatlint://workspaces' })).contents[0].text)[0].id, sessionId);
  const completed = await client.complete({ ref: { type: 'ref/prompt', name: 'security_review' }, argument: { name: 'agentId', value: 'appsec-auth' } });
  assert.ok(completed.completion.values.includes('appsec-auth-reviewer'));
  const resourceCompleted = await client.complete({ ref: { type: 'ref/resource', uri: 'threatlint://agents/{agentId}' }, argument: { name: 'agentId', value: 'appsec-auth' } });
  assert.ok(resourceCompleted.completion.values.includes('appsec-auth-reviewer'));
  assert.equal(workbench.server.listening, false);
});

test('background specialist reviews survive protocol-instance closure and yield UI-free report exports', async t => {
  const entered = deferred(), release = deferred(), observed = [];
  t.after(() => release.resolve());
  const markdown = '# Synthetic Code Review\nRésumé ✓\nNo material findings in the inspected fixture.\n';
  const { workbench, repo, other } = fixture(t, { runProvider: async args => {
    observed.push(args); entered.resolve(); await release.promise;
    args.onEvent({ type: 'tool_executing', tool: 'Read', input: { file_path: 'private payload must not be retained' } });
    return markdown;
  } });
  const first = await connect(workbench);
  const { sessionId } = await call(first.client, 'open_workspace', { repoPath: repo, confirm: true });
  const otherId = (await call(first.client, 'open_workspace', { repoPath: other, confirm: true })).sessionId;
  const { id: reviewId } = await call(first.client, 'start_review', { sessionId, agentIds: [agentId], provider: 'lmstudio', model: 'fixture', confirm: true });
  await entered.promise;
  await first.close();
  const second = await connect(workbench); t.after(second.close);
  assert.equal((await call(second.client, 'get_review', { sessionId, reviewId })).status, 'running');
  assert.equal((await second.client.callTool({ name: 'get_review', arguments: { sessionId: otherId, reviewId } })).isError, true);
  release.resolve();
  const finished = await poll(second.client, 'get_review', { sessionId, reviewId }, job => job.finishedAt !== null);
  assert.equal(finished.status, 'completed'); assert.equal(finished.reports.length, 1);
  assert.equal(observed.length, 1); assert.match(observed[0].systemPrompt, /no changes may be applied/i);
  assert.equal(JSON.stringify(finished).includes('private payload'), false);
  const { id: reportId } = finished.reports[0];
  assert.equal((await call(second.client, 'get_report', { sessionId, reportId })).markdown, markdown);
  assert.equal((await call(second.client, 'list_reviews', { sessionId })).jobs[0].id, reviewId);
  const reportUri = `threatlint://workspaces/${sessionId}/reports/${reportId}`;
  assert.equal((await second.client.readResource({ uri: reportUri })).contents[0].text, markdown);
  await assert.rejects(second.client.readResource({ uri: `threatlint://workspaces/${otherId}/reports/${reportId}` }), /not found/i);
  const chunks = []; let offset = 0;
  do {
    const part = await call(second.client, 'export_report', { sessionId, reportId, format: 'md', offset, limit: 13 });
    assert.equal(part.offset, offset); assert.equal(part.encoding, 'base64');
    chunks.push(Buffer.from(part.content, 'base64')); offset = part.nextOffset;
  } while (offset !== null);
  assert.equal(Buffer.concat(chunks).toString('utf8'), markdown);
  const word = await call(second.client, 'export_report', { sessionId, reportId, format: 'docx' });
  assert.equal(Buffer.from(word.content, 'base64').toString(), 'PK-docx');
  const json = await call(second.client, 'export_report', { sessionId, reportId, format: 'json' });
  assert.equal(JSON.parse(Buffer.from(json.content, 'base64').toString()).markdown, markdown);

  const supplied = '# Client-authored review\nAn explicit evidence gap remains; proposed tests are NOT RUN.\n';
  const saved = await call(second.client, 'save_report', { sessionId, agentId, markdown: supplied, title: 'External model review', confirm: true });
  assert.equal(saved.source.kind, 'mcp-client-review'); assert.match(saved.source.execution, /not independently validated/);
  assert.equal((await call(second.client, 'get_report', { sessionId, reportId: saved.id })).markdown, supplied);
  assert.equal(observed.length, 1, 'saving the MCP client model report must not call a server-side model');
  assert.equal((await second.client.callTool({ name: 'export_report', arguments: { sessionId: otherId, reportId, format: 'md' } })).isError, true);
});

test('real scanner host forwards engine selection and binds proposal/application tools to their workspace', async t => {
  const calls = [];
  let binding;
  const scan = () => ({ status: 'completed', binding, findings: [{ id: 'scan-finding', title: 'Synthetic debug setting', ruleId: 'TL-DEBUG-ENABLED', severity: 'MEDIUM', path: 'app.py', line: 1 }],
    coverage: { status: 'complete', scope: 'Synthetic test fixture' }, engines: [{ id: 'semgrep', status: 'completed' }, { id: 'trivy', status: 'completed' }] });
  const { workbench, repo, other } = fixture(t, { integrations: { securityScannerCli: async (args, options) => {
    calls.push({ args, input: options.input });
    if (args[1] === 'scan') {
      binding = { repository: fs.realpathSync(args[args.indexOf('--repo') + 1]), branch: 'main', commit: 'a'.repeat(40), contentDigest: 'b'.repeat(64) };
      return { code: 0, stdout: JSON.stringify(scan()), stderr: '' };
    }
    if (args[1] === 'propose') return { code: 0, stdout: JSON.stringify({ binding, findingId: 'scan-finding', ruleId: 'TL-DEBUG-ENABLED', before: 'DEBUG = True', after: 'DEBUG = False', canApply: true }), stderr: '' };
    return { code: 0, stdout: JSON.stringify({ status: 'applied', scan: scan() }), stderr: '' };
  } } });
  const { client, close } = await connect(workbench); t.after(close);
  const { sessionId } = await call(client, 'open_workspace', { repoPath: repo, confirm: true });
  const otherId = (await call(client, 'open_workspace', { repoPath: other, confirm: true })).sessionId;
  assert.equal((await client.callTool({ name: 'start_scan', arguments: { sessionId } })).isError, true);
  const { id: scanId } = await call(client, 'start_scan', { sessionId, engines: ['semgrep', 'trivy'], confirm: true });
  const finished = await poll(client, 'get_scan', { sessionId, scanId }, item => item.finishedAt !== undefined);
  assert.equal(finished.status, 'completed'); assert.notEqual(finished.ingestionStatus, 'failed');
  assert.deepEqual(calls[0].args.slice(-4), ['--engine', 'semgrep', '--engine', 'trivy']);
  assert.equal((await call(client, 'list_scans', { sessionId })).items[0].id, scanId);
  assert.equal((await client.callTool({ name: 'get_scan', arguments: { sessionId: otherId, scanId } })).isError, true);
  assert.equal((await client.callTool({ name: 'propose_fix', arguments: { sessionId: otherId, scanId, findingId: 'scan-finding', confirm: true } })).isError, true);
  const proposal = await call(client, 'propose_fix', { sessionId, scanId, findingId: 'scan-finding', confirm: true });
  assert.equal(proposal.after, 'DEBUG = False');
  assert.equal((await client.callTool({ name: 'apply_fix', arguments: { sessionId: otherId, proposalId: proposal.id, confirm: true } })).isError, true);
  assert.equal((await client.callTool({ name: 'apply_fix', arguments: { sessionId, proposalId: proposal.id } })).isError, true);
  assert.equal(calls.filter(call => call.args[1] === 'apply').length, 0);
  const applied = await call(client, 'apply_fix', { sessionId, proposalId: proposal.id, confirm: true });
  assert.equal(applied.status, 'applied');
  const apply = calls.find(call => call.args[1] === 'apply');
  assert.ok(apply.args.includes('--confirm')); assert.deepEqual(apply.args.slice(-4), ['--engine', 'semgrep', '--engine', 'trivy']);
  assert.equal(JSON.parse(apply.input).plan.after, 'DEBUG = False');
  assert.equal((await call(client, 'get_scan', { sessionId, scanId: applied.scanId })).parentScanId, scanId);
});

test('concurrent one-page PDF exports share stable bytes and continue across protocol instances', async t => {
  const { workbench, repo } = fixture(t), first = await connect(workbench);
  t.after(first.close);
  const { sessionId } = await call(first.client, 'open_workspace', { repoPath: repo, confirm: true });
  const markdown = '# Synthetic Code Review\n\n#### [CR-001] — Synthetic transport boundary\n**Severity**: MEDIUM\n**Confidence**: PLAUSIBLE\n'
    + '**Evidence**: `app.py:2`\n**Impact**: Synthetic clients need verified transport.\n**Remediation**: Preserve TLS verification.\n'
    + '**Original code**:\n```python\nrequests.get(url, verify=False)\n```\n**Proposed fix**:\n```python\nrequests.get(url, verify=True)\n```\n';
  const saved = await call(first.client, 'save_report', { sessionId, agentId, markdown, confirm: true });
  const input = { sessionId, reportId: saved.id, findingId: 'CR-001', format: 'pdf', offset: 0, limit: 1024 };
  const [one, two] = await Promise.all([call(first.client, 'export_report', input), call(first.client, 'export_report', input)]);
  assert.deepEqual(one, two, 'simultaneous offset-zero requests must use the same generated archive');
  assert.equal(Buffer.from(one.content, 'base64').length, 1024); assert.ok(one.nextOffset > 0);
  await first.close();
  const second = await connect(workbench); t.after(second.close);
  const chunks = [Buffer.from(one.content, 'base64')]; let offset = one.nextOffset;
  do {
    const part = await call(second.client, 'export_report', { ...input, offset, limit: 256 * 1024 });
    assert.equal(part.totalBytes, one.totalBytes); chunks.push(Buffer.from(part.content, 'base64')); offset = part.nextOffset;
  } while (offset !== null);
  const pdf = Buffer.concat(chunks);
  assert.equal(pdf.length, one.totalBytes);
  assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
  assert.equal(pdf.toString('latin1').split('/Type /Page ').length - 1, 1);
  assert.equal(one.mimeType, 'application/pdf');
});

test('the real stdio entrypoint uses an isolated fresh profile and works while its HTTP port is unavailable', { timeout: 15000 }, async t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-mcp-stdio-'));
  const repo = path.join(root, 'repo'), state = path.join(root, 'profile');
  fs.mkdirSync(repo); fs.writeFileSync(path.join(repo, 'app.py'), source);
  const occupiedPort = net.createServer();
  occupiedPort.listen(0, '127.0.0.1'); await new Promise(resolve => occupiedPort.once('listening', resolve));
  t.after(() => new Promise(resolve => occupiedPort.close(resolve)));
  const env = { ...getDefaultEnvironment(), THREATLINT_STATE_DIR: state, THREATLINT_HOME: path.join(root, 'home'), PORT: String(occupiedPort.address().port) };
  delete env.NODE_TEST_CONTEXT;
  const transport = new StdioClientTransport({ command: process.execPath, args: [path.join(__dirname, '../scripts/mcp.cjs')], env,
    cwd: path.join(__dirname, '..'), stderr: 'pipe' });
  const client = new Client({ name: 'stdio-integration', version: '1' });
  let stderr = ''; transport.stderr.on('data', chunk => { stderr += chunk.toString(); });
  t.after(async () => { await client.close(); await transport.close(); fs.rmSync(root, { recursive: true, force: true }); });
  await client.connect(transport);
  const pid = transport.pid; assert.ok(pid);
  assert.deepEqual(await call(client, 'list_workspaces'), []);
  assert.equal((await call(client, 'list_agents')).length, 23);
  const { sessionId } = await call(client, 'open_workspace', { repoPath: repo, confirm: true });
  assert.match((await call(client, 'read_file', { sessionId, path: 'app.py' })).text, /synthetic evidence/);
  assert.match((await client.getPrompt({ name: 'security_review', arguments: { agentId, sessionId } })).messages[0].content.text, /Required Skill Workflows/);
  assert.equal(JSON.parse(fs.readFileSync(path.join(state, 'sessions.json'), 'utf8'))[0].id, sessionId);
  await client.close(); await transport.close();
  assert.equal(transport.pid, null);
  assert.throws(() => process.kill(pid, 0), error => error.code === 'ESRCH');
  assert.doesNotMatch(stderr, /EADDRINUSE|Threatlint Workbench:|could not start/);
});

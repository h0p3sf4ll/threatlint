'use strict';
const { it } = require('node:test');
const assert = require('node:assert/strict');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { createMcpServer, registerMcpRoutes } = require('../lib/mcp.cjs');
const { requiredPermission } = require('../lib/rbac.cjs');
const express = require('express');

const finding = { id: 'finding', provenance: { repo: { id: '/repo/one' } }, evidence: [] };
function dependencies() {
  return {
    store: { sessions: new Map([['one', { id: 'one', repoPath: '/repo/one', reports: [] }], ['two', { id: 'two', repoPath: '/repo/two', reports: [] }]]) },
    intelligence: { overview: scope => ({ scope, findings: [finding] }), getFinding: () => finding },
    reports: { metadata: value => value, read: () => ({ findings: [] }) },
    scm: { list: () => [{ id: 'source', provider: 'github', account: 'synthetic' }], repositories: async () => ({ repositories: [] }) },
    securityScanner: { start: input => ({ id: 'scan', ...input }), get: () => ({ id: 'scan', sessionId: 'one', status: 'completed' }) },
  };
}
it('MCP advertises usable tools and enforces workspace boundaries and scan confirmation', async t => {
  const server = createMcpServer(dependencies()), client = new Client({ name: 'test', version: '1' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await server.close(); });
  await server.connect(serverTransport); await client.connect(clientTransport);
  const names = (await client.listTools()).tools.map(tool => tool.name);
  for (const name of ['list_agents', 'list_workspaces', 'list_findings', 'get_finding', 'list_sources', 'list_reports', 'start_scan', 'get_scan']) assert.ok(names.includes(name));
  const call = (name, args) => client.callTool({ name, arguments: args });
  assert.equal((await call('get_finding', { sessionId: 'one', findingId: 'finding' })).isError, undefined);
  assert.equal((await call('get_finding', { sessionId: 'two', findingId: 'finding' })).isError, true);
  assert.equal((await call('list_findings', { sessionId: 'missing' })).isError, true);
  assert.equal((await call('get_scan', { sessionId: 'two', scanId: 'scan' })).isError, true);
  assert.equal((await call('start_scan', { sessionId: 'one' })).isError, true);
  assert.equal((await call('start_scan', { sessionId: 'one', confirm: true })).isError, undefined);
});
it('Streamable HTTP initializes without a protocol session and is protected by the gateway review permission', async t => {
  assert.equal(requiredPermission('POST', '/api/mcp'), 'review');
  const app = express(); app.use(express.json()); registerMcpRoutes(app, dependencies());
  const server = app.listen(0, '127.0.0.1'); await new Promise(resolve => server.once('listening', resolve));
  t.after(() => new Promise(resolve => server.close(resolve)));
  const url = `http://127.0.0.1:${server.address().port}/api/mcp`;
  const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-11-25', capabilities: {}, clientInfo: { name: 'test', version: '1' } } }) });
  assert.equal(response.status, 200); assert.equal((await response.json()).result.serverInfo.name, 'threatlint');
  assert.equal(response.headers.has('mcp-session-id'), false);
  const tools = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-11-25' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }) });
  assert.equal(tools.status, 200);
  assert.ok((await tools.json()).result.tools.some(tool => tool.name === 'list_findings'));
  assert.equal((await fetch(url)).status, 405);
});

it('active tool admission is shared across transports and releases capacity after failures', async t => {
  const deps = dependencies(); deps.mcpActivity = { active: 0 };
  let release;
  const blocked = new Promise(resolve => { release = resolve; });
  deps.scm.repositories = async () => { await blocked; throw new Error('Synthetic source failure'); };
  async function connect() {
    const server = createMcpServer(deps), client = new Client({ name: 'capacity-test', version: '1' });
    const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
    t.after(async () => { await client.close(); await server.close(); });
    await server.connect(serverTransport); await client.connect(clientTransport);
    return client;
  }
  const first = await connect(), second = await connect();
  const calls = Array.from({ length: 8 }, () => first.callTool({ name: 'list_repositories', arguments: { connectionId: 'source' } }));
  t.after(release);
  while (deps.mcpActivity.active < 8) await new Promise(resolve => setImmediate(resolve));
  const rejected = await second.callTool({ name: 'list_agents', arguments: {} });
  assert.equal(rejected.isError, true); assert.match(rejected.content[0].text, /Too many active/);
  release(); assert.ok((await Promise.all(calls)).every(result => result.isError));
  assert.equal(deps.mcpActivity.active, 0);
  assert.equal((await second.callTool({ name: 'list_agents', arguments: {} })).structuredContent.result.length, 23);
});

it('tool errors redact complete long credentials before truncating diagnostics', async t => {
  const deps = dependencies();
  const secret = 'synthetic-secret-'.repeat(100);
  deps.sources = { connect: async () => { throw new Error(`Rejected credential ${secret}`); } };
  const server = createMcpServer(deps), client = new Client({ name: 'redaction-test', version: '1' });
  const [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  t.after(async () => { await client.close(); await server.close(); });
  await server.connect(serverTransport); await client.connect(clientTransport);
  const result = await client.callTool({ name: 'connect_source', arguments: { provider: 'github', token: secret, confirm: true } });
  assert.equal(result.isError, true); assert.match(result.content[0].text, /\[REDACTED\]/);
  assert.doesNotMatch(result.content[0].text, /synthetic-secret/);
});

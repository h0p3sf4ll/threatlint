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

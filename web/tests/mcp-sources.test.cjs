'use strict';

const { it, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { InMemoryTransport } = require('@modelcontextprotocol/sdk/inMemory.js');
const { z } = require('zod');
const { createStore } = require('../lib/store.cjs');
const { registerSourceRoutes } = require('../lib/routes/sources.cjs');
const { registerSourceTools } = require('../lib/mcp-sources.cjs');

const home = fs.mkdtempSync(path.join(os.tmpdir(), 'threatlint-mcp-sources-'));
process.env.THREATLINT_HOME = home;
for (const name of ['THREATLINT_GITHUB_APP_ID', 'THREATLINT_GITHUB_APP_INSTALLATION_ID', 'THREATLINT_GITHUB_APP_PRIVATE_KEY_FILE', 'THREATLINT_GITHUB_APP_PRIVATE_KEY', 'THREATLINT_GITHUB_API_URL']) delete process.env[name];
after(() => {
  assert.ok(path.resolve(home).startsWith(path.resolve(os.tmpdir()) + path.sep));
  fs.rmSync(home, { recursive: true, force: true });
});

function fixture() {
  const store = createStore(null), connections = [], calls = [], routes = new Map();
  let shared = false, nextId = 0;
  const summary = item => ({ id: item.id, provider: item.provider, account: item.organization?.toLowerCase() || 'developer', host: item.provider === 'github' ? 'github.com' : 'dev.azure.com' });
  const scm = {
    list: () => connections.map(summary),
    connect: async input => { calls.push(['connect', input]); const item = { ...input, id: `source-${++nextId}` }; connections.push(item); return summary(item); },
    disconnect: id => { const index = connections.findIndex(item => item.id === id); if (index < 0) return false; connections.splice(index, 1); return true; },
    repositories: async (id, input) => { assert.ok(connections.some(item => item.id === id)); calls.push(['repositories', id, input]); return { repositories: [{ id: 'repo', name: 'test' }], page: 1, hasMore: false }; },
    branches: async (id, repoId, input) => { calls.push(['branches', id, repoId, input]); return { branches: ['main'], page: 1, hasMore: false }; },
    checkout: async (id, input) => { calls.push(['checkout', id, input]); return { repoPath: '/managed/repo', tempDir: '/managed', provenance: { provider: 'azure-devops', repository: 'test', branch: input.branch || 'main', commit: 'abc' } }; },
  };
  const app = {};
  for (const method of ['get', 'post', 'delete']) app[method] = (route, handler) => routes.set(`${method} ${route}`, handler);
  const sources = registerSourceRoutes(app, { store, scm, integrations: { threatlintCli: async args => {
    if (args[1] === 'status') return { code: 0, stdout: JSON.stringify({ organizations: [{ name: 'Contoso' }], serviceAccount: { parameter: shared ? '/shared/pat' : '' } }) };
    if (args[1] === 'token') return { code: 0, stdout: shared ? 'shared-secret' : 'personal-secret' };
    throw new Error('Unexpected CLI request');
  } } });
  return { sources, store, connections, calls, routes, useShared: () => { shared = true; } };
}

async function clientFor(t, sources) {
  const server = new McpServer({ name: 'test', version: '1' });
  const tool = (name, description, inputSchema, action, options = {}) => server.registerTool(name, { description, inputSchema,
    annotations: { readOnlyHint: options.readOnly ?? true, destructiveHint: options.destructive ?? false, openWorldHint: options.openWorld ?? false } }, async input => {
    try { return { content: [{ type: 'text', text: JSON.stringify(await action(input)) }] }; }
    catch (error) { return { isError: true, content: [{ type: 'text', text: error.message }] }; }
  });
  registerSourceTools({ tool, z, id: z.string().min(1).max(200), sources });
  const client = new Client({ name: 'test', version: '1' }), [serverTransport, clientTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport); await client.connect(clientTransport);
  t.after(async () => { await client.close(); await server.close(); });
  return { client, call: (name, args = {}) => client.callTool({ name, arguments: args }) };
}
const value = result => { assert.equal(result.isError, undefined, result.content[0]?.text); return JSON.parse(result.content[0].text); };

it('MCP activates saved sources, browses branches, and opens a provenance-bound workspace without HTTP', async t => {
  const f = fixture(), { call } = await clientFor(t, f.sources);
  assert.ok(value(await call('list_source_providers')).providers.github);
  const first = value(await call('list_sources'));
  assert.equal(first.length, 1);
  assert.equal(first[0].connected, true);
  assert.equal(JSON.stringify(first).includes('personal-secret'), false);
  await call('list_sources');
  assert.equal(f.calls.filter(item => item[0] === 'connect').length, 1);
  const connectionId = first[0].id;
  assert.equal(value(await call('list_repositories', { connectionId, search: 'test', page: 1 })).repositories[0].id, 'repo');
  assert.deepEqual(value(await call('list_branches', { connectionId, repositoryId: 'repo' })).branches, ['main']);
  assert.equal((await call('checkout_repository', { connectionId, repositoryId: 'repo' })).isError, true);
  assert.equal(f.store.sessions.size, 0, 'unconfirmed checkout must not create a workspace');
  const opened = value(await call('checkout_repository', { connectionId, repositoryId: 'repo', branch: 'main', confirm: true }));
  assert.equal(f.store.sessions.get(opened.sessionId).repoPath, '/managed/repo');
  assert.deepEqual(f.store.sessions.get(opened.sessionId).provenance, opened.provenance);
  assert.deepEqual(f.calls.find(item => item[0] === 'checkout')[2], { repositoryId: 'repo', branch: 'main' });
});

it('MCP refreshes saved credentials and rejects stale connection selections before repository access', async t => {
  const f = fixture(), { call } = await clientFor(t, f.sources);
  const previous = value(await call('list_sources'))[0].id;
  f.useShared();
  const stale = await call('list_repositories', { connectionId: previous });
  assert.equal(stale.isError, true);
  assert.match(stale.content[0].text, /credentials were refreshed/i);
  assert.equal(f.calls.some(item => item[0] === 'repositories'), false);
  const current = value(await call('list_sources'))[0];
  assert.notEqual(current.id, previous);
  assert.equal(current.source, 'AWS Parameter Store (service account)');
  value(await call('list_repositories', { connectionId: current.id }));
  assert.equal(f.connections[0].token, 'shared-secret');
  assert.equal((await call('connect_source', { provider: 'azure-devops', organization: 'Contoso', token: 'manual-secret', confirm: true })).isError, true,
    'manual credentials cannot replace the configured service-account source');
});

it('MCP validates source mutations and removes protocol-only confirmation before SCM input validation', async t => {
  const f = fixture(), { client, call } = await clientFor(t, f.sources);
  const tools = (await client.listTools()).tools;
  assert.equal(tools.find(item => item.name === 'disconnect_source').annotations.destructiveHint, true);
  assert.equal((await call('connect_source', { provider: 'github', token: 'session-secret' })).isError, true);
  assert.equal((await call('connect_source', { provider: 'github', token: '', confirm: true })).isError, true);
  assert.equal(f.connections.length, 0);
  const source = value(await call('connect_source', { provider: 'github', token: 'session-secret', confirm: true }));
  assert.deepEqual(f.calls.find(item => item[0] === 'connect')[1], { provider: 'github', token: 'session-secret' });
  assert.equal(JSON.stringify(source).includes('session-secret'), false);
  assert.equal((await call('disconnect_source', { connectionId: source.id })).isError, true);
  assert.equal(value(await call('disconnect_source', { connectionId: source.id, confirm: true })).disconnected, true);
  assert.equal(value(await call('disconnect_source', { connectionId: source.id, confirm: true })).disconnected, false);
  assert.equal((await call('list_branches', { connectionId: 'source', repositoryId: 'repo', page: 101 })).isError, true);
  assert.equal((await call('reconnect_source', { provider: 'azure-devops', confirm: true })).isError, true);
});

it('HTTP source discovery delegates to the same saved-source facade', async () => {
  const f = fixture();
  let payload;
  const res = { headersSent: false, status() { return this; }, json(value) { payload = value; this.headersSent = true; }, end() { this.headersSent = true; } };
  await f.routes.get('get /api/scm/connections')({}, res);
  assert.equal(payload[0].account, 'contoso');
  assert.equal((await f.sources.list())[0].id, payload[0].id);
  assert.equal(f.calls.filter(item => item[0] === 'connect').length, 1, 'HTTP and MCP reuse one activated account');
});

it('MCP refreshes expiring GitHub App tokens and retries a revoked-token checkout without changing its selection', async t => {
  const config = path.join(home, 'github-app.json');
  fs.writeFileSync(config, JSON.stringify({ appId: '123', installationId: '456', privateKeyFile: path.join(home, 'fixture.pem') }));
  t.after(() => fs.rmSync(config, { force: true }));
  let minted = 0, token = '', checkouts = 0;
  const selections = [], store = createStore(null);
  const summary = { id: 'github-app', provider: 'github', account: 'app', host: 'github.com' };
  const scm = { list: () => token ? [summary] : [], connect: async input => { token = input.token; return summary; }, disconnect: () => { token = ''; },
    refreshCredential: async (id, input) => { assert.equal(id, summary.id); token = input.token; return summary; },
    repositories: async () => { assert.equal(token, 'app-token-2'); return { repositories: [{ id: 'repo' }] }; },
    checkout: async (id, input) => {
      selections.push({ id, ...input });
      if (++checkouts === 1) throw Object.assign(new Error('Credential revoked'), { code: 'SCM_AUTHORIZATION_FAILED' });
      assert.equal(token, 'app-token-3');
      return { repoPath: '/managed/github', tempDir: '/managed', provenance: { provider: 'github', repository: 'owner/repo', branch: 'main', commit: 'abc' } };
    } };
  const app = { get() {}, post() {}, delete() {} };
  const sources = registerSourceRoutes(app, { store, scm, integrations: {
    threatlintCli: async () => ({ code: 0, stdout: '{"organizations":[]}' }),
    githubApp: { installationToken: async () => ({ token: `app-token-${++minted}`, expiresAt: Date.now() + (minted === 1 ? 60_000 : 3_600_000) }), clearTokens() {} },
  } });
  const { call } = await clientFor(t, sources);
  const connected = value(await call('list_sources'));
  assert.equal(connected[0].source, 'GitHub App');
  value(await call('list_repositories', { connectionId: summary.id }));
  const opened = value(await call('checkout_repository', { connectionId: summary.id, repositoryId: 'repo', branch: 'main', confirm: true }));
  assert.equal(minted, 3);
  assert.deepEqual(selections, [selections[0], selections[0]], 'retry retains the same repository and branch');
  assert.equal(store.sessions.get(opened.sessionId).provenance.commit, 'abc');
  assert.equal(JSON.stringify(opened).includes('app-token'), false);
});

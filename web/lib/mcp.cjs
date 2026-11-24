'use strict';

const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StreamableHTTPServerTransport } = require('@modelcontextprotocol/sdk/server/streamableHttp.js');
const { z } = require('zod');
const { AGENT_META } = require('./agents.cjs');

/** A fresh protocol server per transport, bound to one existing Workbench profile. */
function createMcpServer({ store, intelligence, reports, scm, securityScanner }) {
  const server = new McpServer({ name: 'threatlint', version: require('../package.json').version });
  const id = z.string().min(1).max(200);
  const workspace = sessionId => {
    const session = store.sessions.get(sessionId);
    if (!session) throw new Error('Workspace not found in this profile');
    return session;
  };
  const tool = (name, description, inputSchema, action, readOnly = true) => server.registerTool(name, {
    description, inputSchema, annotations: { readOnlyHint: readOnly, destructiveHint: false, openWorldHint: !readOnly },
  }, async input => {
    try {
      const result = await action(input), output = JSON.stringify(result);
      if (Buffer.byteLength(output) > 2 * 1024 * 1024) throw new Error('Result is too large; narrow the request');
      return { content: [{ type: 'text', text: output }] };
    } catch (error) { return { isError: true, content: [{ type: 'text', text: error.message || 'Threatlint could not complete this tool' }] }; }
  });
  tool('list_agents', 'List available security review specialists.', {}, () => AGENT_META);
  tool('list_workspaces', 'List workspaces in the current profile.', {}, () => [...store.sessions.values()].map(session => ({ id: session.id, repoPath: session.repoPath, reportCount: session.reports?.length || 0 })));
  tool('list_findings', 'Read revision-bound findings and their review status in a workspace.', {
    sessionId: id, branch: z.string().max(500).optional(), commit: z.string().max(200).optional(),
  }, ({ sessionId, branch, commit }) => intelligence.overview({ repoId: workspace(sessionId).repoPath, branch, commit }));
  tool('get_finding', 'Read one finding, its evidence, and its review history.', { sessionId: id, findingId: id }, ({ sessionId, findingId }) => {
    const finding = intelligence.getFinding(findingId);
    if (!finding || finding.provenance.repo.id !== workspace(sessionId).repoPath) throw new Error('Finding not found in this workspace');
    return finding;
  });
  tool('list_reports', 'List saved review reports for a workspace.', { sessionId: id }, ({ sessionId }) => (workspace(sessionId).reports || []).map(reports.metadata));
  tool('get_report', 'Read a saved structured report from the selected workspace.', { sessionId: id, reportId: id }, ({ sessionId, reportId }) => {
    const report = workspace(sessionId).reports?.find(item => item.id === reportId);
    if (!report) throw new Error('Report not found in this workspace');
    return reports.read(report);
  });
  tool('list_sources', 'List active source sessions. Credentials are never returned.', {}, () => scm.list());
  tool('list_repositories', 'Browse repositories through a previously connected source account.', {
    connectionId: id, search: z.string().max(200).optional(), page: z.number().int().min(1).max(100).optional(),
  }, ({ connectionId, ...input }) => scm.repositories(connectionId, input));
  tool('start_scan', 'Start a security scan of an existing workspace after explicit authorization; poll get_scan for results.', {
    sessionId: id, confirm: z.literal(true),
  }, ({ sessionId }) => { workspace(sessionId); return securityScanner.start({ sessionId }); }, false);
  tool('get_scan', 'Read a scan belonging to the selected workspace.', { sessionId: id, scanId: id }, ({ sessionId, scanId }) => {
    workspace(sessionId); const scan = securityScanner.get(scanId);
    if (scan.sessionId !== sessionId) throw new Error('Scan not found in this workspace');
    return scan;
  });
  return server;
}

function registerMcpRoutes(app, dependencies) {
  let active = 0;
  app.post('/api/mcp', async (req, res) => {
    if (active >= 8) return res.status(429).json({ error: 'Too many concurrent MCP requests' });
    if (Buffer.byteLength(JSON.stringify(req.body || {})) > 128 * 1024) return res.status(413).json({ error: 'MCP request is too large' });
    active++;
    const server = createMcpServer(dependencies);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    let closed = false;
    const close = () => { if (!closed) { closed = true; active--; void server.close(); } };
    res.once('close', close);
    try { await server.connect(transport); await transport.handleRequest(req, res, req.body); }
    catch { if (!res.headersSent) res.status(500).json({ error: 'MCP request could not complete' }); close(); }
  });
  app.all('/api/mcp', (_req, res) => res.set('Allow', 'POST').status(405).json({ jsonrpc: '2.0', error: { code: -32000, message: 'Use Streamable HTTP POST; this endpoint is stateless.' }, id: null }));
}

module.exports = { createMcpServer, registerMcpRoutes };

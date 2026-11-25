'use strict';

/**
 * Threatlint Workbench runner. The browser and the Electron app both call createWorkbench();
 * routes live in lib/routes, the WebSocket protocol in lib/socket.cjs.
 */

const express = require('express');
const http = require('node:http');
const os = require('node:os');
const path = require('node:path');
const { createStore } = require('./lib/store.cjs');
const { createSourceManagers } = require('./lib/scm.cjs');
const { createRuntimeScanner } = require('./lib/runtime.cjs');
const { createDashboardStore } = require('./lib/metrics.cjs');
const { createTrackerMetrics } = require('./lib/tracker-metrics.cjs');
const { createAvitAggregateStore } = require('./lib/avit-aggregate-store.cjs');
const { createReportWriter } = require('./lib/report-writer.cjs');
const { createPipeline, buildUserMessage, validateAttachment } = require('./lib/pipeline.cjs');
const { createConversations } = require('./lib/chat.cjs');
const { attachSocket } = require('./lib/socket.cjs');
const { securityHeaders, localRequest, activeRequestCount, handle } = require('./lib/http.cjs');
const { registerWorkspaceRoutes } = require('./lib/routes/workspace.cjs');
const { registerModelPreferenceRoutes } = require('./lib/routes/model-preferences.cjs');
const { registerUiPreferenceRoutes } = require('./lib/routes/ui-preferences.cjs');
const { registerSourceRoutes } = require('./lib/routes/sources.cjs');
const { registerRuntimeRoutes, createRuntimeHistory } = require('./lib/routes/runtime.cjs');
const { registerInsightRoutes } = require('./lib/routes/insights.cjs');
const { prepareProcess } = require('./lib/system-env.cjs');
const { createAvitBatch } = require('./lib/avit-batch.cjs');
const { createAvitRuns } = require('./lib/avit-runs.cjs');
const { registerTriageRoutes } = require('./lib/routes/triage.cjs');
const { registerSidekickRoutes } = require('./lib/routes/sidekick.cjs');
const { registerScanImportRoutes, scanImportBodyParsers } = require('./lib/routes/scan-import.cjs');
const { createScanImports } = require('./lib/scan-import.cjs');
const { createDesignInputs } = require('./lib/design-inputs.cjs');
const { registerDesignInputRoutes, designInputBodyParsers } = require('./lib/routes/design-inputs.cjs');
const { createScannerBatch } = require('./lib/scanner-batch.cjs');
const { registerScannerRoutes } = require('./lib/routes/scanners.cjs');
const { registerManagementRoutes } = require('./lib/routes/management.cjs');
const { createSavedSourceActivator } = require('./lib/saved-sources.cjs');
const { createSecurityScanner } = require('./lib/security-scanner.cjs');
const { registerSecurityScannerRoutes } = require('./lib/routes/security-scanner.cjs');
const { createFindingIntelligenceStore, ingestionFromScan } = require('./lib/finding-intelligence.cjs');
const { registerFindingIntelligenceRoutes } = require('./lib/routes/finding-intelligence.cjs');

const BODY_LIMIT = '7mb';
const DEFAULT_PORT = 3000;

function defaultStorageDir() {
  if (process.env.NODE_TEST_CONTEXT) return null;
  return process.env.THREATLINT_STATE_DIR || path.join(os.homedir(), '.threatlint', 'workbench');
}

function buildInfo() {
  try {
    const stamped = JSON.parse(process.env.THREATLINT_BUILD_INFO || 'null');
    if (stamped) return stamped;
  } catch { /* fall through to live source */ }
  return { fingerprint: 'source', commit: 'live', version: require('./package.json').version };
}

/**
 * options: storageDir, sourceManagers, runtimeScanner (test seams),
 * runProvider (replaces model calls for reviews and conversations in tests/recordings),
 * integrations ({ semgrepVersion, fetchImpl, readParameterStore, semgrepToken, threatlintCli, convertToWord } for external I/O).
 */
function createWorkbench(options = {}) {
  // OS certificate store and the user's PATH, so gateways behind TLS inspection and CLIs like `gh` work from the Dock.
  prepareProcess();
  const app = express();
  app.disable('x-powered-by');
  const server = http.createServer(app);
  const store = createStore(options.storageDir ?? defaultStorageDir());
  const reports = createReportWriter(store, { convertToWord: options.integrations?.convertToWord });
  const scm = options.sourceManagers || createSourceManagers();
  const activateSavedSource = createSavedSourceActivator(scm);
  const resolveSource = require('./lib/source-context.cjs').createSourceResolver({ scm, store });
  const runtime = require('./lib/runtime-sandbox.cjs').createSandboxRuntime({ live: options.runtimeScanner || createRuntimeScanner(), store, resolveSource, spawnImpl: options.integrations?.runtimeSpawn });
  const history = createRuntimeHistory(runtime);
  const dashboards = createDashboardStore(store.directory);
  const trackerMetrics = createTrackerMetrics(store.directory);
  const scannerPolicies = require('./lib/scanner-policies.cjs').createScannerPolicies(store.directory);
  const avitAggregate = createAvitAggregateStore(store.directory);
  const designInputs = createDesignInputs();
  const intelligence = createFindingIntelligenceStore({ directory: store.directory });
  let securityScanner;
  const pipeline = createPipeline({ sessions: store.sessions, reports, override: options.runProvider, integrations: options.integrations, designInputs,
    isSessionBusy: sessionId => securityScanner?.isBusy(sessionId) || false });
  securityScanner = createSecurityScanner({ store, scannerPolicies, integrations: options.integrations,
    isSessionBusy: sessionId => pipeline.isSessionBusy(sessionId),
    onScanComplete: (scan, session) => intelligence.ingest(ingestionFromScan(scan, session)) });
  const conversations = createConversations({ store, reports, runtime, override: options.runProvider });
  const scanImports = createScanImports({ store, reports, override: options.runProvider, integrations: { ...options.integrations, resolveSource } });
  const issueTrackers = require('./lib/ticket-ingestion.cjs');
  const scannerBatch = createScannerBatch({ store, reports, override: options.runProvider, integrations: options.integrations });
  // A disconnected socket can leave an aborting provider operation in flight. Keep the worker busy
  // until those promises settle, in addition to background jobs that intentionally outlive a page.
  let socketOperations = 0;
  for (const [service, method] of [[pipeline, 'run'], [conversations, 'ask'], [scannerBatch, 'run']]) {
    const execute = service[method];
    service[method] = async (...args) => { socketOperations++; try { return await execute(...args); } finally { socketOperations--; } };
  }

  app.use(securityHeaders(server));
  // Scan reports and design inputs upload up to 25 MB; every other route keeps the 7 MB JSON limit.
  scanImportBodyParsers(app);
  designInputBodyParsers(app);
  app.use(express.json({ limit: BODY_LIMIT }));
  app.get('/vendor/marked.js', (_req, res) => res.sendFile(path.join(__dirname, 'node_modules/marked/lib/marked.umd.js')));
  app.get('/vendor/purify.js', (_req, res) => res.sendFile(path.join(__dirname, 'node_modules/dompurify/dist/purify.min.js')));
  app.use(express.static(path.join(__dirname, 'public')));

  registerWorkspaceRoutes(app, { store, reports, build: buildInfo(), integrations: options.integrations });
  const awsParameters = require('./lib/aws-parameters.cjs').registerAwsParameterRoutes(app, options.integrations?.awsParameters || {});
  server.once('listening', () => { if (awsParameters.autoLoad()) void awsParameters.pull().catch(() => {}); });
  registerModelPreferenceRoutes(app, { store });
  registerUiPreferenceRoutes(app, { store });
  registerSourceRoutes(app, { store, scm, integrations: options.integrations });
  registerRuntimeRoutes(app, { runtime, history });
  registerInsightRoutes(app, { store, history, dashboards, conversations, trackerMetrics, avitAggregate, integrations: options.integrations });
  registerTriageRoutes(app, { reports, scannerPolicies, integrations: options.integrations });
  const sidekick = registerSidekickRoutes(app, { integrations: options.integrations });
  registerScanImportRoutes(app, { scanImports });
  issueTrackers.registerIssueTrackerRoutes(app, { scanImports, integrations: options.integrations });
  registerDesignInputRoutes(app, { designInputs });
  registerScannerRoutes(app, { scannerBatch, integrations: options.integrations });
  registerSecurityScannerRoutes(app, { securityScanner });
  registerFindingIntelligenceRoutes(app, { intelligence, store });
  const mcpDependencies = { store, intelligence, reports, scm, securityScanner };
  require('./lib/mcp.cjs').registerMcpRoutes(app, mcpDependencies);

  // Native desktop remains an individually owned application. Company authorization and shared
  // connections are handled by the authenticated gateway before requests reach a profile worker.
  app.get('/api/access', (_req, res) => res.json({ role: 'administrator',
    permissions: { read: true, manageSettings: true, manageMembers: false, review: true, manageFindings: true },
    roles: ['administrator', 'analyst', 'viewer'], members: [], local: true }));
  registerManagementRoutes(app, { directory: store.directory, reports, integrations: options.integrations,
    activateSource: (_req, connection) => activateSavedSource(connection) });

  // Only the gateway can call these endpoints, using the private worker transport credential.
  // Never expose local report paths or source credentials in the response.
  app.get('/internal/management/report/:id', (req, res) => {
    if (process.env.THREATLINT_PROFILE_WORKER !== '1') return res.status(404).json({ error: 'Not found' });
    const located = reports.find(req.params.id);
    if (!located) return res.status(404).json({ error: 'Report not found' });
    res.json({ report: reports.metadata(located.report), parsed: reports.read(located.report) });
  });
  app.post('/internal/management/source', async (req, res) => {
    if (process.env.THREATLINT_PROFILE_WORKER !== '1') return res.status(404).json({ error: 'Not found' });
    try {
      res.json(await activateSavedSource({ provider: req.body?.provider, token: req.body?.token, organization: req.body?.organization }));
    } catch { res.status(502).json({ error: 'Source connection could not be activated. Check its credentials and permissions.' }); }
  });
  app.get('/internal/management/servicenow/source', (_req, res) => {
    if (process.env.THREATLINT_PROFILE_WORKER !== '1') return res.status(404).json({ error: 'Not found' });
    try { const credentials = require('./lib/servicenow.cjs').validateCredentials({}); res.json({ instance: credentials.instance, available: true }); }
    catch { res.json({ available: false }); }
  });
  app.post('/internal/management/servicenow/page', handle(async (req, res) => {
    if (process.env.THREATLINT_PROFILE_WORKER !== '1') return res.status(404).json({ error: 'Not found' });
    try {
      const serviceNow = require('./lib/servicenow.cjs'), credentials = serviceNow.validateCredentials({});
      if (credentials.instance !== req.body?.instance) return res.status(409).json({ error: 'ServiceNow instance changed' });
      res.json(await serviceNow.fetchAvitPage(credentials, { filters: req.body?.filters || {}, offset: req.body?.offset ?? 0,
        fetchImpl: options.integrations?.fetchImpl || fetch, signal: AbortSignal.timeout(25_000) }));
    } catch { res.status(502).json({ error: 'ServiceNow issues could not be read. Check this profile’s ServiceNow Settings and filters.' }); }
  }));

  // Only the gateway's private worker credential can reach this endpoint. Desktop does not expose it.
  app.get('/internal/activity', (_req, res) => {
    if (process.env.THREATLINT_PROFILE_WORKER !== '1') return res.status(404).json({ error: 'Not found' });
    res.json({ busy: activeRequestCount() > 0 || socketOperations > 0 || avitRuns.active || scanImports.active || [...store.sessions.keys()].some(id => securityScanner.isBusy(id)) || sidekick.active || runtime.active === true || wss.clients.size > 0 });
  });

  app.use('/api', (_req, res) => res.status(404).json({ error: 'Unknown API route' }));
  app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
  app.use((error, _req, res, _next) => res.status(error.status || 500).json({ error: error.status === 413 ? 'Request exceeds the 7 MB limit' : 'Request could not be processed' }));

  const avitBatch = createAvitBatch({ store, reports, override: options.runProvider, integrations: options.integrations });
  server.once('listening', () => { void avitBatch.retryCleanup(); });
  const avitRuns = createAvitRuns(avitBatch);
  const wss = attachSocket(server, { pipeline, conversations, avitRuns, scannerBatch });
  // Scan-import progress goes to every open Workbench connection; polling GET /api/scan-import/:id works too.
  const unsubscribe = scanImports.subscribe(event => { for (const socket of wss.clients) if (socket.readyState === 1) socket.send(JSON.stringify(event)); });

  async function close() {
    awsParameters.close();
    pipeline.abortAll();
    const avitClosing = avitRuns.close();
    unsubscribe();
    await Promise.all([avitClosing, pipeline.close(), scanImports.close(), securityScanner.close()]);
    await runtime.close?.();
    for (const socket of wss.clients) socket.terminate();
    await new Promise(resolve => wss.close(resolve));
    if (server.listening) await new Promise(resolve => server.close(resolve));
  }
  return { app, server, wss, store, close, scanImports, securityScanner, intelligence, generateReport: reports.save,
    createMcpServer: () => require('./lib/mcp.cjs').createMcpServer(mcpDependencies) };
}

const workbench = createWorkbench();
if (require.main === module) {
  const port = Number(process.env.PORT || DEFAULT_PORT);
  workbench.server.listen(port, '127.0.0.1', () => console.log(`Threatlint Workbench: http://127.0.0.1:${workbench.server.address().port}\nReports and saved integrations remain local. Model keys are session-only.`));
  process.once('SIGINT', () => workbench.close().then(() => process.exit(0)));
  process.once('SIGTERM', () => workbench.close().then(() => process.exit(0)));
}

module.exports = { ...workbench, createWorkbench, buildUserMessage, validateAttachment, localRequest };

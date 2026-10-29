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
const { createReportWriter } = require('./lib/report-writer.cjs');
const { createPipeline, buildUserMessage, validateAttachment } = require('./lib/pipeline.cjs');
const { createConversations } = require('./lib/chat.cjs');
const { attachSocket } = require('./lib/socket.cjs');
const { securityHeaders, localRequest } = require('./lib/http.cjs');
const { registerWorkspaceRoutes } = require('./lib/routes/workspace.cjs');
const { registerSourceRoutes } = require('./lib/routes/sources.cjs');
const { registerRuntimeRoutes, createRuntimeHistory } = require('./lib/routes/runtime.cjs');
const { registerInsightRoutes } = require('./lib/routes/insights.cjs');
const { prepareProcess } = require('./lib/system-env.cjs');
const { createAvitBatch } = require('./lib/avit-batch.cjs');
const { registerTriageRoutes } = require('./lib/routes/triage.cjs');
const { registerSidekickRoutes } = require('./lib/routes/sidekick.cjs');
const { registerScanImportRoutes, scanImportBodyParsers } = require('./lib/routes/scan-import.cjs');
const { createScanImports } = require('./lib/scan-import.cjs');

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
 * integrations ({ semgrepVersion, fetchImpl, readParameterStore, semgrepToken, threatlintCli } for Semgrep, ServiceNow, and the AVIT batch).
 */
function createWorkbench(options = {}) {
  // OS certificate store and the user's PATH, so gateways behind TLS inspection and CLIs like `gh` work from the Dock.
  prepareProcess();
  const app = express();
  app.disable('x-powered-by');
  const server = http.createServer(app);
  const store = createStore(options.storageDir ?? defaultStorageDir());
  const reports = createReportWriter(store);
  const scm = options.sourceManagers || createSourceManagers();
  const runtime = options.runtimeScanner || createRuntimeScanner();
  const history = createRuntimeHistory(runtime);
  const dashboards = createDashboardStore(store.directory);
  const pipeline = createPipeline({ sessions: store.sessions, reports, override: options.runProvider, integrations: options.integrations });
  const conversations = createConversations({ store, reports, runtime, override: options.runProvider });
  const scanImports = createScanImports({ store, reports, override: options.runProvider, integrations: options.integrations });

  app.use(securityHeaders(server));
  // Scan reports upload up to 25 MB; every other route keeps the 7 MB JSON limit.
  scanImportBodyParsers(app);
  app.use(express.json({ limit: BODY_LIMIT }));
  app.get('/vendor/marked.js', (_req, res) => res.sendFile(path.join(__dirname, 'node_modules/marked/lib/marked.umd.js')));
  app.get('/vendor/purify.js', (_req, res) => res.sendFile(path.join(__dirname, 'node_modules/dompurify/dist/purify.min.js')));
  app.use(express.static(path.join(__dirname, 'public')));

  registerWorkspaceRoutes(app, { store, reports, build: buildInfo(), integrations: options.integrations });
  registerSourceRoutes(app, { store, scm, integrations: options.integrations });
  registerRuntimeRoutes(app, { runtime, history });
  registerInsightRoutes(app, { store, history, dashboards, conversations });
  registerTriageRoutes(app, { reports, integrations: options.integrations });
  registerSidekickRoutes(app, { integrations: options.integrations });
  registerScanImportRoutes(app, { scanImports });

  app.use('/api', (_req, res) => res.status(404).json({ error: 'Unknown API route' }));
  app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public/index.html')));
  app.use((error, _req, res, _next) => res.status(error.status || 500).json({ error: error.status === 413 ? 'Request exceeds the 7 MB limit' : 'Request could not be processed' }));

  const avitBatch = createAvitBatch({ store, reports, override: options.runProvider, integrations: options.integrations });
  const wss = attachSocket(server, { pipeline, conversations, avitBatch });
  // Scan-import progress goes to every open Workbench connection; polling GET /api/scan-import/:id works too.
  const unsubscribe = scanImports.subscribe(event => { for (const socket of wss.clients) if (socket.readyState === 1) socket.send(JSON.stringify(event)); });

  async function close() {
    pipeline.abortAll();
    unsubscribe();
    await runtime.close?.();
    for (const socket of wss.clients) socket.terminate();
    await new Promise(resolve => wss.close(resolve));
    if (server.listening) await new Promise(resolve => server.close(resolve));
  }
  return { app, server, wss, store, close, scanImports, generateReport: reports.save };
}

const workbench = createWorkbench();
if (require.main === module) {
  const port = Number(process.env.PORT || DEFAULT_PORT);
  workbench.server.listen(port, '127.0.0.1', () => console.log(`Threatlint Workbench: http://127.0.0.1:${workbench.server.address().port}\nReports remain local. Provider credentials are never saved.`));
  process.once('SIGINT', () => workbench.close().then(() => process.exit(0)));
  process.once('SIGTERM', () => workbench.close().then(() => process.exit(0)));
}

module.exports = { ...workbench, createWorkbench, buildUserMessage, validateAttachment, localRequest };

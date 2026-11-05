'use strict';

/** Metrics, user-defined dashboards, in-app help, and conversation history. */

const fs = require('node:fs');
const path = require('node:path');
const { AGENTS } = require('../agents.cjs');
const { collectFacts, aggregate, matrix, overview, DIMENSIONS, METRICS, CHARTS } = require('../metrics.cjs');
const { SOURCE_META, avitMetricsItems } = require('../tracker-metrics.cjs');
const servicenow = require('../servicenow.cjs');
const defectdojo = require('../defectdojo-metrics.cjs');
const { HELP_TOPICS, TOOLTIPS, VIDEOS } = require('../help.cjs');
const { handle, HttpError } = require('../http.cjs');

const MEDIA = path.join(__dirname, '../../public/media');
const CSV_COLUMNS = ['timestamp', 'source', 'workspace', 'agentId', 'category', 'findingId', 'title', 'severity', 'confidence', 'disposition', 'hasEvidence'];
const TRACKER_SYNC_TIMEOUT_MS = 180_000;

// Leading = + - @ would make a spreadsheet evaluate the cell as a formula.
function csvCell(value) {
  const text = String(value ?? '').replaceAll('"', '""');
  return /^[=+\-@\t\r]/.test(text) ? `"'${text}"` : `"${text}"`;
}

function registerInsightRoutes(app, { store, history, dashboards, conversations, trackerMetrics, avitAggregate, integrations = {} }) {
  const facts = () => collectFacts({ sessions: store.sessions, runtimeScans: history.finished(), agents: AGENTS, trackerFacts: trackerMetrics.facts() });
  const sourceIds = new Set(['all', 'report', 'runtime', ...Object.keys(SOURCE_META)]);
  function source(value) {
    const selected = typeof value === 'string' && value ? value : 'all';
    if (!sourceIds.has(selected)) throw new HttpError('Unknown metrics source');
    return selected;
  }
  const selectedFacts = selected => selected === 'all' ? facts() : facts().filter(item => item.source === selected);
  const connected = async id => {
    if (id === 'servicenow-avit') {
      try { servicenow.validateCredentials({}); return true; } catch { return false; }
    }
    return !!(await defectdojo.connectionStatus()).connected;
  };
  const tracker = async id => {
    const snapshot = trackerMetrics.snapshot(id);
    const isConnected = await connected(id);
    return { id, label: SOURCE_META[id].label, kind: SOURCE_META[id].kind, available: true, connected: isConnected,
      status: !isConnected ? 'not-connected' : snapshot ? 'synced' : 'not-synced',
      count: snapshot?.items.length || 0, lastSyncedAt: snapshot?.lastSyncedAt || null,
      createdThrough: snapshot?.createdThrough || null, scope: snapshot?.scope || null };
  };
  const trackers = async () => ({ trackers: [await tracker('servicenow-avit'), await tracker('defectdojo'),
    { id: 'jira', label: 'Jira', kind: 'defect-tracker', available: false, connected: false, status: 'not-supported', count: 0, lastSyncedAt: null },
    { id: 'azure-devops', label: 'Azure DevOps Boards', kind: 'defect-tracker', available: false, connected: false, status: 'not-supported', count: 0, lastSyncedAt: null }] });
  const inFlight = new Map();
  let aggregateInFlight = null;
  async function loadAvitAggregate(filters) {
    if (aggregateInFlight) throw new HttpError('An AVIT summary is already loading', 409);
    const run = (async () => {
      const selected = servicenow.validateAggregateFilters(filters);
      const credentials = servicenow.validateCredentials({});
      const signal = AbortSignal.timeout(TRACKER_SYNC_TIMEOUT_MS);
      try {
        const summary = await servicenow.fetchAvitAggregate(credentials, { filters: selected,
          fetchImpl: integrations.fetchImpl || fetch, signal });
        if (signal.aborted) throw new HttpError('AVIT summary timed out; previous summary preserved', 504);
        return avitAggregate.replace(summary);
      } catch (error) {
        if (signal.aborted) throw new HttpError('AVIT summary timed out; previous summary preserved', 504);
        throw error;
      }
    })();
    aggregateInFlight = run;
    try { return await run; } finally { aggregateInFlight = null; }
  }
  async function sync(id, requestedScope) {
    if (!SOURCE_META[id]) throw new HttpError('Unknown defect tracker', 404);
    if (inFlight.has(id)) return inFlight.get(id);
    const run = (async () => {
      const timeoutMs = Number.isInteger(integrations.trackerSyncTimeoutMs) && integrations.trackerSyncTimeoutMs > 0
        ? integrations.trackerSyncTimeoutMs : TRACKER_SYNC_TIMEOUT_MS;
      const signal = AbortSignal.timeout(timeoutMs);
      try {
        let items, createdThrough = null, scope = null;
        if (id === 'servicenow-avit') {
          scope = servicenow.validateMetricsScope(requestedScope);
          const credentials = servicenow.validateCredentials({});
          const result = await servicenow.fetchAvitMetrics(credentials, { scope, fetchImpl: integrations.fetchImpl || fetch, signal });
          items = avitMetricsItems(result.items);
          createdThrough = result.createdThrough;
        } else {
          if (!(await defectdojo.connectionStatus()).connected) throw new HttpError('Connect DefectDojo in Settings before syncing metrics', 412);
          items = (await defectdojo.fetchMetrics({ fetchImpl: integrations.fetchImpl || fetch, signal })).items;
        }
        if (signal.aborted) throw new HttpError('Tracker metrics sync timed out; previous snapshot preserved', 504);
        return trackerMetrics.replace(id, items, { createdThrough, scope });
      } catch (error) {
        if (signal.aborted) throw new HttpError('Tracker metrics sync timed out; previous snapshot preserved', 504);
        throw error;
      }
    })();
    inFlight.set(id, run);
    try { return await run; } finally { inFlight.delete(id); }
  }

  app.get('/api/metrics/schema', (_req, res) => res.json({ dimensions: DIMENSIONS, metrics: METRICS, charts: CHARTS }));
  app.get('/api/metrics/sources', handle(async () => {
    const all = facts();
    const trackerSources = await Promise.all(Object.keys(SOURCE_META).map(tracker));
    return { selected: 'all', sources: [
      { id: 'all', label: 'All sources', kind: 'aggregate', available: true, connected: true, status: 'ready', count: all.filter(item => !item.empty).length, lastSyncedAt: null },
      ...[['report', 'Threatlint reports'], ['runtime', 'Runtime scans']].map(([id, label]) => ({ id, label, kind: 'local', available: true, connected: true,
        status: 'ready', count: all.filter(item => item.source === id && !item.empty).length, lastSyncedAt: null })),
      ...trackerSources,
    ] };
  }));
  app.get('/api/trackers', handle(trackers));
  app.get('/api/metrics/trackers', handle(trackers));
  app.get('/api/trackers/servicenow-avit/aggregate', handle(() => ({ summary: avitAggregate.get() })));
  app.post('/api/trackers/servicenow-avit/aggregate', handle(req => loadAvitAggregate(req.body?.filters || {})));
  // Type-ahead suggestions for the organization / repository / branch / project filters (server-side group-by).
  app.get('/api/trackers/servicenow-avit/context-values', handle(req => {
    const credentials = servicenow.validateCredentials({});
    const context = {};
    for (const name of ['scm', 'organization', 'project', 'repository', 'branch']) {
      if (typeof req.query[name] === 'string' && req.query[name]) context[name] = req.query[name];
    }
    return servicenow.fetchAvitContextValues(credentials, { field: req.query.field, q: typeof req.query.q === 'string' ? req.query.q : '',
      context, fetchImpl: integrations.fetchImpl || fetch, signal: AbortSignal.timeout(15_000) });
  }, { fallback: 'Suggestions unavailable' }));
  app.post('/api/trackers/:id/sync', handle(req => sync(req.params.id, req.body?.scope)));
  app.get('/api/metrics/overview', handle(req => {
    const chosen = source(req.query.source);
    const selected = selectedFacts(chosen);
    const summary = overview(selected, chosen === 'all' || chosen === 'report' ? store.sessions : new Map());
    if (chosen !== 'all' && chosen !== 'report') summary.workspaces = new Set(selected.map(item => item.workspace)).size;
    return summary;
  }));
  app.post('/api/metrics/query', handle(req => {
    const { chart, metric, groupBy, columns, filters } = req.body || {};
    const chosen = source(filters?.source);
    const rest = { ...(filters || {}) };
    delete rest.source;
    return chart === 'heatmap' ? matrix(selectedFacts(chosen), { rows: groupBy, columns, filters: rest })
      : aggregate(selectedFacts(chosen), { metric, groupBy: groupBy || null, filters: rest });
  }, { fallback: 'Invalid metric query' }));
  app.get('/api/metrics/export', handle((req, res) => {
    const rows = selectedFacts(source(req.query.source)).filter(fact => !fact.empty).map(fact => CSV_COLUMNS.map(column => csvCell(column === 'timestamp' ? new Date(fact.timestamp).toISOString() : fact[column])).join(','));
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', 'attachment; filename="threatlint-findings.csv"');
    res.send([CSV_COLUMNS.join(','), ...rows].join('\n'));
  }));

  app.get('/api/dashboards', (_req, res) => res.json(dashboards.list()));
  app.post('/api/dashboards', handle(req => dashboards.save(req.body), { status: 201, fallback: 'Invalid dashboard' }));
  app.put('/api/dashboards/:id', handle(req => dashboards.save(req.body, req.params.id), { fallback: 'Invalid dashboard' }));
  app.delete('/api/dashboards/:id', (req, res) => res.status(dashboards.remove(req.params.id) ? 204 : 404).end());

  app.get('/api/help', (_req, res) => res.json({ topics: HELP_TOPICS, tooltips: TOOLTIPS,
    videos: VIDEOS.map(video => ({ ...video, available: fs.existsSync(path.join(MEDIA, video.file)) })) }));

  app.get('/api/conversations', (req, res) => res.json(conversations.list(typeof req.query.sessionId === 'string' ? req.query.sessionId : undefined)));
  app.get('/api/conversations/:id', handle(req => conversations.get(req.params.id)));
  app.delete('/api/conversations/:id', (req, res) => res.status(conversations.remove(req.params.id) ? 204 : 404).end());
}

module.exports = { registerInsightRoutes, csvCell };
